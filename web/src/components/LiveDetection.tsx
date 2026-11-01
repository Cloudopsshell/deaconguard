import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, ShieldCheck } from "lucide-react";
import { Link } from "react-router";
import {
  api,
  type HostSummary,
  type LiveAlert,
  type LiveState,
  type LiveStatus,
} from "../api";
import { useCan } from "../lib/role";
import { dateTime, normalizeSeverity, timeAgo } from "../lib/format";
import {
  Button,
  Card,
  CardHeader,
  EmptyState,
  ErrorMessage,
  Loading,
  SeverityBadge,
  Table,
  Td,
  Th,
  cx,
} from "./ui";

const liveDocs = "https://docs.deaconguard.io/usage/live-detection";

/** How each state looks: a label, a pill style, and its dot. */
export const liveStyle: Record<
  LiveState,
  { label: string; pill: string; dot: string }
> = {
  active: {
    label: "Live",
    pill: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300 dark:ring-emerald-400/30",
    dot: "bg-emerald-500 dark:bg-emerald-400",
  },
  stopped: {
    label: "Stopped",
    pill: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300 dark:ring-red-400/30",
    dot: "bg-red-500 dark:bg-red-400",
  },
  off: {
    label: "Off",
    pill: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-500/30",
    dot: "bg-slate-400",
  },
  unsupported: {
    label: "Not supported",
    pill: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-500/30",
    dot: "bg-slate-400",
  },
  agent_too_old: {
    label: "Agent too old",
    pill: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-400/30",
    dot: "bg-amber-500",
  },
  waiting: {
    label: "Starting",
    pill: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-500/30",
    dot: "bg-slate-400",
  },
  starting: {
    label: "Starting",
    pill: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-500/30",
    dot: "bg-slate-400",
  },
};

/** The state as a pill, on the Hosts list. A cluster counts its nodes. */
export function LiveBadge({ live }: { live?: LiveStatus }) {
  if (!live) return <span className="text-xs text-slate-400">–</span>;
  const style = liveStyle[live.state] ?? liveStyle.stopped;
  const label =
    live.nodes !== undefined && live.nodes > 0
      ? live.nodes_active === live.nodes
        ? `Live on ${live.nodes} of ${live.nodes} nodes`
        : `Live on ${live.nodes_active ?? 0} of ${live.nodes} nodes`
      : style.label;
  return (
    <span
      title={live.reason || undefined}
      className={cx(
        "inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset",
        style.pill,
      )}
    >
      <span className={cx("size-1.5 rounded-full", style.dot)} aria-hidden />
      {label}
    </span>
  );
}

/** The last day's alerts under the Hosts list's badge, when there are any. */
export function LiveAlertCounts({ live }: { live?: LiveStatus }) {
  const counts = live?.alerts_24h;
  if (!counts) return null;
  const parts = [
    counts.critical > 0 && `${counts.critical} critical`,
    counts.high > 0 && `${counts.high} high`,
    counts.medium > 0 && `${counts.medium} medium`,
    counts.low > 0 && `${counts.low} low`,
  ].filter(Boolean);
  if (parts.length === 0) return null;
  return (
    <p
      className={cx(
        "mt-1 text-xs font-medium",
        counts.critical + counts.high > 0
          ? "text-red-700 dark:text-red-300"
          : "text-slate-500 dark:text-slate-400",
      )}
    >
      {parts.join(" · ")} in 24 h
    </p>
  );
}

/** What a state means, in a sentence, for the host's Runtime tab. */
function stateSentence(status: LiveStatus): { title: string; text: string } {
  switch (status.state) {
    case "active":
      return {
        title: "Live detection is active",
        text: `Watching since ${dateTime(status.since)}`,
      };
    case "off":
      return {
        title: "Live detection is off",
        text: "An administrator turned it off for this host. Programs that start and files that change aren't watched.",
      };
    case "unsupported":
      return {
        title: "Live detection can't run on this machine",
        text: `${status.reason ?? ""}.`,
      };
    case "agent_too_old":
      return {
        title: "Upgrade the agent for live detection",
        text: `${status.reason ?? ""}. The Agents page has the upgrade command.`,
      };
    case "waiting":
    case "starting":
      return {
        title: "Live detection is starting",
        text: "Waiting for the agent's first report; it reports every 15 seconds.",
      };
    default:
      return {
        title: "Live detection stopped",
        text: `Since ${dateTime(status.since)}: ${status.reason ?? "unknown reason"}. Attacks on this machine aren't seen as they happen until it runs again.`,
      };
  }
}

function formatCount(value: number) {
  return new Intl.NumberFormat().format(value);
}

/** The host's Runtime tab: is detection running, what it costs, and its alerts. */
export function RuntimeTab({ hostId }: { hostId: string }) {
  const queryClient = useQueryClient();
  const canTest = useCan("operator");
  const canToggle = useCan("admin");
  const { data, error, isPending } = useQuery({
    queryKey: ["live", hostId],
    queryFn: () => api.live(hostId),
    refetchInterval: 15_000,
  });
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ["live", hostId] });
    void queryClient.invalidateQueries({ queryKey: ["hosts"] });
  };
  const test = useMutation({
    mutationFn: () => api.testLive(hostId),
    onSettled: refresh,
  });
  const toggle = useMutation({
    mutationFn: (enabled: boolean) => api.setLive(hostId, enabled),
    onSettled: refresh,
  });

  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;
  const status = data.status;
  if (!status) {
    return (
      <Card>
        <EmptyState
          icon={<Activity className="size-6" />}
          title="No live detection here"
          description="Live detection runs on machines with the DeaconGuard agent, and on Kubernetes nodes with the node agent."
        />
      </Card>
    );
  }
  const sentence = stateSentence(status);
  const style = liveStyle[status.state] ?? liveStyle.stopped;
  const alerts = status.alerts_24h;
  const alertCount =
    alerts.critical + alerts.high + alerts.medium + alerts.low + alerts.unknown;
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-start justify-between gap-4 px-5 py-4">
          <div className="min-w-64 flex-1">
            <div className="flex flex-wrap items-center gap-2">
              <span className="relative flex size-2.5" aria-hidden>
                {status.state === "active" && (
                  <span className="absolute inline-flex size-full animate-ping rounded-full bg-emerald-400 opacity-60" />
                )}
                <span
                  className={cx(
                    "relative inline-flex size-2.5 rounded-full",
                    style.dot,
                  )}
                />
              </span>
              <h3 className="font-semibold">{sentence.title}</h3>
              <LiveBadge live={status} />
            </div>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
              {sentence.text}
              {status.updated_at &&
                ` · last report ${timeAgo(status.updated_at)}`}
              {status.kernel && ` · Linux ${status.kernel}`}
            </p>
            {status.test_error && (
              <p className="mt-1 text-sm text-red-600 dark:text-red-400">
                The last test alert couldn't run: {status.test_error}
              </p>
            )}
            {test.isSuccess && status.state === "active" && (
              <p className="mt-1 text-sm text-emerald-700 dark:text-emerald-300">
                Asked for a test alert; it appears below within about 20
                seconds.
              </p>
            )}
            {(test.error || toggle.error) && (
              <ErrorMessage error={test.error ?? toggle.error} />
            )}
          </div>
          <div className="flex flex-wrap gap-2">
            {canTest && status.state === "active" && (
              <Button
                variant="secondary"
                loading={test.isPending}
                onClick={() => test.mutate()}
              >
                Send a test alert
              </Button>
            )}
            {canToggle && status.state !== "agent_too_old" && (
              <Button
                variant="secondary"
                loading={toggle.isPending}
                onClick={() => toggle.mutate(!status.enabled)}
              >
                {status.enabled ? "Turn off" : "Turn on"}
              </Button>
            )}
          </div>
        </div>
        {status.state === "active" && (
          <dl className="grid grid-cols-2 border-t border-slate-200 text-sm sm:grid-cols-4 dark:border-slate-800">
            <div className="px-5 py-3">
              <dt className="text-slate-500 dark:text-slate-400">
                Events checked, last hour
              </dt>
              <dd className="mt-0.5 text-lg font-semibold tabular-nums">
                {formatCount(status.events_last_hour)}
              </dd>
            </div>
            <div className="px-5 py-3">
              <dt className="text-slate-500 dark:text-slate-400">
                Alerts, last 24 hours
              </dt>
              <dd
                className={cx(
                  "mt-0.5 text-lg font-semibold tabular-nums",
                  alertCount > 0 && "text-red-600 dark:text-red-300",
                )}
              >
                {formatCount(alertCount)}
              </dd>
            </div>
            <div className="px-5 py-3">
              <dt
                className="text-slate-500 dark:text-slate-400"
                title="Events the kernel dropped because the agent fell behind; usually a sign of an unusually busy machine"
              >
                Missed events
              </dt>
              <dd
                className={cx(
                  "mt-0.5 text-lg font-semibold tabular-nums",
                  status.lost > 0 && "text-amber-600 dark:text-amber-300",
                )}
              >
                {formatCount(status.lost + status.suppressed)}
              </dd>
            </div>
            <div className="px-5 py-3">
              <dt
                className="text-slate-500 dark:text-slate-400"
                title="The agent's own CPU and memory, scans included"
              >
                Agent's cost
              </dt>
              <dd className="mt-0.5 text-lg font-semibold tabular-nums">
                {status.cpu_percent.toFixed(1)}% CPU ·{" "}
                {Math.round(status.memory_bytes / (1 << 20))} MB
              </dd>
            </div>
          </dl>
        )}
      </Card>
      <AlertsTable alerts={data.alerts} />
      <p className="text-xs text-slate-500 dark:text-slate-400">
        What live detection watches, and what it doesn't:{" "}
        <a
          className="underline"
          href={liveDocs}
          target="_blank"
          rel="noreferrer"
        >
          Live detection
        </a>
        .
      </p>
    </div>
  );
}

function AlertsTable({ alerts }: { alerts: LiveAlert[] }) {
  return (
    <Card>
      <CardHeader
        title="Alerts"
        description="Newest first. Only alerts leave the machine, never what programs read or write."
      />
      {alerts.length === 0 ? (
        <EmptyState
          icon={<ShieldCheck className="size-6" />}
          title="No alerts"
          description="Nothing suspicious has started or changed on this machine."
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>When</Th>
              <Th>Severity</Th>
              <Th>What happened</Th>
              <Th>Process</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {alerts.map((alert) => (
              <tr
                key={alert.id}
                className="align-top hover:bg-slate-50 dark:hover:bg-slate-800/50"
              >
                <Td className="whitespace-nowrap text-slate-500 dark:text-slate-400">
                  <span title={dateTime(alert.at)}>{timeAgo(alert.at)}</span>
                </Td>
                <Td>
                  {alert.test ? (
                    <span className="rounded-md bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 ring-1 ring-slate-500/20 ring-inset dark:bg-slate-800 dark:text-slate-300">
                      Test
                    </span>
                  ) : (
                    <SeverityBadge
                      severity={normalizeSeverity(alert.severity)}
                    />
                  )}
                </Td>
                <Td className="max-w-lg">
                  <p className="font-medium">{alert.title}</p>
                  <p className="mt-0.5 text-xs leading-relaxed text-slate-500 dark:text-slate-400">
                    {alert.detail} Rule {alert.rule}.
                    {alert.repeats
                      ? ` Repeated ${alert.repeats} more times before this.`
                      : ""}
                  </p>
                </Td>
                <Td className="max-w-md font-mono text-xs break-all text-slate-700 dark:text-slate-300">
                  {alert.parent && <span>{alert.parent} › </span>}
                  {alert.command || alert.program}
                  {alert.path && <span> › {alert.path}</span>}
                  <span className="block text-slate-500 dark:text-slate-400">
                    pid {alert.pid}
                    {alert.user && ` · ${alert.user}`}
                  </span>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

/** The dashboard's card: how many hosts are watched live, and which aren't. */
export function LiveCard({
  hosts,
  className,
}: {
  hosts: HostSummary[];
  className?: string;
}) {
  const watched = hosts.filter(
    (host) => host.live && host.kind !== "cluster" && host.live.state !== "off",
  );
  if (watched.length === 0) return null;
  const active = watched.filter((host) => host.live?.state === "active");
  const others = watched.filter((host) => host.live?.state !== "active");
  const percent = Math.round((active.length / watched.length) * 100);
  return (
    <Card className={className}>
      <div className="flex flex-wrap items-start justify-between gap-3 px-5 py-4">
        <div>
          <h2 className="text-base font-semibold">Live detection</h2>
          <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
            Watching for attacks as they happen
          </p>
        </div>
        <p className="text-3xl font-semibold tabular-nums">
          {active.length}{" "}
          <span className="text-base font-normal text-slate-500 dark:text-slate-400">
            of {watched.length} hosts active
          </span>
        </p>
      </div>
      <div
        className="h-1.5 bg-slate-100 dark:bg-slate-800"
        role="img"
        aria-label={`${percent}% of hosts active`}
      >
        <div
          className="h-full bg-emerald-500"
          style={{ width: `${percent}%` }}
        />
      </div>
      {others.length > 0 && (
        <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
          {others.slice(0, 8).map((host) => (
            <li
              key={host.id}
              className="flex items-center justify-between gap-3 px-5 py-2.5"
            >
              <span className="min-w-0">
                <span
                  className={cx(
                    "mr-2 inline-block size-2 rounded-full",
                    (liveStyle[host.live!.state] ?? liveStyle.stopped).dot,
                  )}
                  aria-hidden
                />
                <span className="font-medium">{host.address}</span>{" "}
                <span className="text-slate-500 dark:text-slate-400">
                  · {(liveStyle[host.live!.state] ?? liveStyle.stopped).label}
                  {host.live?.reason ? `: ${host.live.reason}` : ""}
                </span>
              </span>
              <Link
                className="shrink-0 text-indigo-600 hover:underline dark:text-indigo-300"
                to={`/hosts/${host.id}?tab=runtime`}
              >
                Open
              </Link>
            </li>
          ))}
          {others.length > 8 && (
            <li className="px-5 py-2.5 text-slate-500 dark:text-slate-400">
              And {others.length - 8} more on the Hosts page.
            </li>
          )}
        </ul>
      )}
    </Card>
  );
}
