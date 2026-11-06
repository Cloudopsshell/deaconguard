import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Activity, ShieldCheck } from "lucide-react";
import { useMemo, useState } from "react";
import { Link } from "react-router";
import { AllowDialog, alertWhere, type AllowScope } from "./LiveAllowlist";
import {
  api,
  type HostSummary,
  type LiveAlert,
  type LiveDetail,
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
    live.nodes !== undefined && live.nodes > 0 && live.state !== "off"
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
        text: "An administrator turned it off for this host. Programs, files, connections and privilege changes aren't watched.",
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
/**
 * A host's live detection. A cluster's shows all its nodes; a node's says it
 * follows its cluster, whose switch turns it on and off.
 */
export function RuntimeTab({
  hostId,
  follows,
}: {
  hostId: string;
  follows?: { id: string; name: string; excluded?: boolean };
}) {
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
  const cluster = data.nodes !== undefined;
  // Where a rule made from an alert can apply: its machine, its cluster, or everywhere.
  const scopesFor = (alert: LiveAlert): AllowScope[] => [
    cluster ? { value: alert.host_id, label: `This node, ${alert.host ?? ""}` } : { value: hostId, label: "This host" },
    ...(cluster ? [{ value: hostId, label: "This cluster" }] : follows ? [{ value: follows.id, label: `Its cluster, ${follows.name}` }] : []),
    { value: "", label: "All hosts" },
  ];
  const allowNote = data.allow && data.allow.rules > 0 && (
    <p className="text-xs text-slate-500 dark:text-slate-400">
      {data.allow.rules === 1 ? "1 allowlist rule applies" : `${data.allow.rules} allowlist rules apply`} here
      {data.allow.skipped > 0
        ? `; ${cluster ? "on its nodes, " : ""}they skipped ${formatCount(data.allow.skipped)} expected ${data.allow.skipped === 1 ? "alert" : "alerts"}${data.allow.last_at ? `, the last ${timeAgo(data.allow.last_at)}` : ""}`
        : "; none skipped an alert yet"}
      .{" "}
      <Link className="underline" to="/settings#live-allowlist">
        Allowlist
      </Link>
    </p>
  );
  const clusterLink = follows && (
    <Link className="text-indigo-600 hover:underline dark:text-indigo-300" to={`/hosts/${follows.id}?tab=runtime`}>
      {follows.name}
    </Link>
  );
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
  if (status.state === "off") {
    return (
      <div className="space-y-4">
        <Card>
          <div className="flex flex-wrap items-start justify-between gap-6 px-5 py-5">
            <div className="max-w-2xl min-w-64 flex-1">
              <div className="flex flex-wrap items-center gap-2">
                <span
                  className="size-2.5 rounded-full bg-slate-400"
                  aria-hidden
                />
                <h3 className="text-lg font-semibold">
                  {follows?.excluded
                    ? "Live detection is off: this node is excluded"
                    : follows
                      ? "Live detection is off for this cluster"
                      : "Live detection is off"}
                </h3>
                <LiveBadge live={status} />
              </div>
              {follows && (
                <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                  {follows.excluded ? (
                    <>This node is left out of {clusterLink}'s scans and live detection; bring it back from its page's header.</>
                  ) : (
                    <>This node follows its cluster, {clusterLink}: turn live detection on there, for every node at once.</>
                  )}
                </p>
              )}
              <p className="mt-2 text-sm text-slate-600 dark:text-slate-300">
                Scans, schedules and notifications work as before. Turn live
                detection on to also watch {cluster ? "every node of this cluster, nodes that join later included," : "this machine"}{" "}
                <strong>between scans</strong>, as attacks happen: programs
                started from temporary folders, shells started by web servers,
                crypto miners, reverse shells and suspicious connections out,
                changes to accounts, sudo rules, SSH keys and scheduled jobs,
                processes becoming root outside sudo, kernel modules loaded and
                processes taking over others. Alerts arrive within seconds and
                name the container or pod they came from.
              </p>
              <ul className="mt-3 space-y-1 text-sm text-slate-500 dark:text-slate-400">
                {status.kernel && (
                  <li>✓ This machine can run it: Linux {status.kernel}</li>
                )}
                {cluster && (status.nodes ?? 0) > 0 && (
                  <li>✓ {status.nodes === 1 ? "Its node has" : `Its ${status.nodes} nodes have`} a node agent to run it</li>
                )}
                <li>
                  ✓ Light: about 20 ms of CPU a minute at rest, and about 25 MB
                  of memory
                </li>
                <li>
                  ✓ Only alerts leave the machine; turn it off again at any time
                </li>
              </ul>
              <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
                {follows ? null : canToggle ? (
                  <>
                    To turn it on for every host at once, use{" "}
                    <Link className="underline" to="/settings">
                      Settings
                    </Link>
                    .{" "}
                  </>
                ) : (
                  "An administrator can turn it on. "
                )}
                <a
                  className="underline"
                  href={liveDocs}
                  target="_blank"
                  rel="noreferrer"
                >
                  What it watches
                </a>
              </p>
              {toggle.error && <ErrorMessage error={toggle.error} />}
            </div>
            {canToggle && !follows && (
              <Button
                loading={toggle.isPending}
                onClick={() => toggle.mutate(true)}
              >
                {cluster ? "Turn on for the cluster" : "Turn on live detection"}
              </Button>
            )}
          </div>
        </Card>
        {data.alerts.length > 0 && <AlertsTable alerts={data.alerts} scopesFor={scopesFor} />}
        {allowNote}
      </div>
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
            {follows && (
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Follows its cluster, {clusterLink}: turn it on or off there.</p>
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
            {canToggle && !follows && status.state !== "agent_too_old" && (
              <Button
                variant="secondary"
                loading={toggle.isPending}
                onClick={() => toggle.mutate(!status.enabled)}
              >
                {status.enabled ? "Turn off" : "Turn on"}
                {cluster && " for the cluster"}
              </Button>
            )}
          </div>
        </div>
        {cluster && <NodeLiveTable nodes={data.nodes ?? []} />}
        {!cluster && status.state === "active" && (
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
      <AlertsTable alerts={data.alerts} cluster={cluster} scopesFor={scopesFor} />
      {allowNote}
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

/** A cluster's nodes: each one's state, and what live detection costs it. */
function NodeLiveTable({ nodes }: { nodes: NonNullable<LiveDetail["nodes"]> }) {
  if (nodes.length === 0) {
    return (
      <p className="border-t border-slate-200 px-5 py-3 text-sm text-slate-500 dark:border-slate-800 dark:text-slate-400">
        No node has a node agent yet: turn on agent.enabled in the chart, and each node's agent follows this switch.
      </p>
    );
  }
  return (
    <Table>
      <thead>
        <tr>
          <Th>Node</Th>
          <Th>State</Th>
          <Th className="text-right">Events, last hour</Th>
          <Th className="text-right">Agent's cost</Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
        {nodes.map((node) => (
          <tr key={node.host_id}>
            <Td>
              <Link className="font-medium text-indigo-600 hover:underline dark:text-indigo-300" to={`/hosts/${node.host_id}?tab=runtime`}>
                {node.host}
              </Link>
              {node.excluded && <span className="ml-2 text-xs text-slate-500 dark:text-slate-400">excluded</span>}
            </Td>
            <Td>
              <LiveBadge live={node.status ?? undefined} />
              {node.status?.state === "stopped" && node.status.reason && (
                <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">{node.status.reason}</p>
              )}
            </Td>
            <Td className="text-right tabular-nums">{node.status?.state === "active" ? formatCount(node.status.events_last_hour) : "–"}</Td>
            <Td className="text-right tabular-nums">
              {node.status?.state === "active"
                ? `${node.status.cpu_percent.toFixed(1)}% CPU · ${Math.round(node.status.memory_bytes / (1 << 20))} MB`
                : "–"}
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

/** "" shows every alert, "host" those outside containers, else one container's. */
type ContainerFilter = string;

function AlertsTable({
  alerts: all,
  cluster = false,
  scopesFor,
}: {
  alerts: LiveAlert[];
  cluster?: boolean;
  scopesFor: (alert: LiveAlert) => AllowScope[];
}) {
  const canAllow = useCan("admin");
  const [allowing, setAllowing] = useState<LiveAlert | null>(null);
  const [filter, setFilter] = useState<ContainerFilter>("");
  // The containers alerts came from, by where they ran.
  const places = useMemo(() => {
    const seen = new Map<string, string>();
    for (const alert of all) {
      const where = alertWhere(alert);
      if (where) seen.set(where, where);
    }
    return [...seen.keys()].sort();
  }, [all]);
  const alerts = filter === "" ? all : all.filter((alert) => (filter === "host" ? !alert.container_id : alertWhere(alert) === filter));
  return (
    <Card>
      <CardHeader
        title="Alerts"
        description={
          cluster
            ? "Newest first, from every node. Only alerts leave the nodes, never what programs read or write."
            : "Newest first. Only alerts leave the machine, never what programs read or write."
        }
        action={
          places.length > 0 && (
            <label className="flex items-center gap-2 text-sm">
              <span className="text-slate-500 dark:text-slate-400">Show</span>
              <select
                aria-label="Show alerts from"
                className="rounded-lg border-0 bg-white py-1.5 pr-8 pl-3 text-sm shadow-sm ring-1 ring-slate-300 ring-inset dark:bg-slate-950 dark:ring-slate-700"
                value={filter}
                onChange={(event) => setFilter(event.target.value)}
              >
                <option value="">All alerts</option>
                <option value="host">Outside containers</option>
                {places.map((place) => (
                  <option key={place} value={place}>
                    {place}
                  </option>
                ))}
              </select>
            </label>
          )
        }
      />
      {allowing && <AllowDialog alert={allowing} scopes={scopesFor(allowing)} onClose={() => setAllowing(null)} />}
      {alerts.length === 0 && all.length > 0 ? (
        <p className="px-5 pb-5 text-sm text-slate-500 dark:text-slate-400">No alerts from there.</p>
      ) : alerts.length === 0 ? (
        <EmptyState
          icon={<ShieldCheck className="size-6" />}
          title="No alerts"
          description={cluster ? "Nothing suspicious has started or changed on the cluster's nodes." : "Nothing suspicious has started or changed on this machine."}
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>When</Th>
              <Th>Severity</Th>
              <Th>What happened</Th>
              {cluster && <Th>Node</Th>}
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
                  {canAllow && !alert.test && (
                    <button
                      type="button"
                      className="mt-1 text-xs font-medium text-indigo-600 hover:underline dark:text-indigo-300"
                      onClick={() => setAllowing(alert)}
                    >
                      Don't alert on this again
                    </button>
                  )}
                </Td>
                {cluster && (
                  <Td className="whitespace-nowrap">
                    <Link className="text-indigo-600 hover:underline dark:text-indigo-300" to={`/hosts/${alert.host_id}?tab=runtime`}>
                      {alert.host}
                    </Link>
                  </Td>
                )}
                <Td className="max-w-md font-mono text-xs break-all text-slate-700 dark:text-slate-300">
                  {alert.parent && <span>{alert.parent} › </span>}
                  {alert.command || alert.program}
                  {alert.path && <span> › {alert.path}</span>}
                  {alert.remote && <span> → {alert.remote}</span>}
                  <span className="block text-slate-500 dark:text-slate-400">
                    pid {alert.pid}
                    {alert.user && ` · ${alert.user}`}
                  </span>
                  {alert.container_id && (
                    <span className="mt-1 block font-sans text-slate-600 dark:text-slate-300" title={alert.container_id}>
                      In {alertWhere(alert)}
                      {alert.image && <span className="block font-mono text-slate-500 dark:text-slate-400">{alert.image}</span>}
                    </span>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

/** The dashboard's card: how many hosts are watched, which could be, and which stopped. */
export function LiveCard({
  hosts,
  className,
}: {
  hosts: HostSummary[];
  className?: string;
}) {
  const canToggle = useCan("admin");
  // A cluster counts once, with its nodes; its nodes aren't counted again.
  const machines = hosts.filter((host) => host.live && !host.cluster_id);
  if (machines.length === 0) return null;
  const clusters = machines.filter((host) => host.kind === "cluster");
  const servers = machines.length - clusters.length;
  const state = (host: HostSummary) => host.live!.state;
  const active = machines.filter((host) => state(host) === "active");
  const off = machines.filter((host) => state(host) === "off");
  const tooOld = machines.filter((host) => state(host) === "agent_too_old");
  const stopped = machines.filter((host) => state(host) === "stopped");
  const percent = Math.round((active.length / machines.length) * 100);
  return (
    <Card className={className}>
      <div className="flex flex-wrap items-start justify-between gap-3 px-5 py-4">
        <div>
          <h2 className="text-base font-semibold">Live detection</h2>
          <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">
            Watching for attacks as they happen, on the servers and clusters it's turned on for
          </p>
        </div>
        <p className="text-3xl font-semibold tabular-nums">
          {active.length}{" "}
          <span className="text-base font-normal text-slate-500 dark:text-slate-400">
            of {[servers > 0 && `${servers} ${servers === 1 ? "server" : "servers"}`, clusters.length > 0 && `${clusters.length} ${clusters.length === 1 ? "cluster" : "clusters"}`]
              .filter(Boolean)
              .join(" and ")}{" "}
            watched
          </span>
        </p>
      </div>
      <div
        className="h-1.5 bg-slate-100 dark:bg-slate-800"
        role="img"
        aria-label={`${percent}% of hosts watched`}
      >
        <div
          className="h-full bg-emerald-500"
          style={{ width: `${percent}%` }}
        />
      </div>
      <ul className="divide-y divide-slate-200 text-sm dark:divide-slate-800">
        {stopped.slice(0, 8).map((host) => (
          <li
            key={host.id}
            className="flex items-center justify-between gap-3 px-5 py-2.5"
          >
            <span className="min-w-0">
              <span
                className={cx(
                  "mr-2 inline-block size-2 rounded-full",
                  liveStyle.stopped.dot,
                )}
                aria-hidden
              />
              <span className="font-medium">{host.address}</span>{" "}
              <span className="text-slate-500 dark:text-slate-400">
                · Stopped{host.live?.reason ? `: ${host.live.reason}` : ""}
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
        {off.length > 0 && (
          <li className="flex items-center justify-between gap-3 px-5 py-2.5">
            <span className="text-slate-500 dark:text-slate-400">
              {off.length === 1
                ? `${off[0].address} could run it but has it off.`
                : `${off.length} servers and clusters could run it but have it off.`}
            </span>
            {canToggle && (
              <Link
                className="shrink-0 text-indigo-600 hover:underline dark:text-indigo-300"
                to="/settings"
              >
                Turn on in Settings
              </Link>
            )}
          </li>
        )}
        {tooOld.length > 0 && (
          <li className="flex items-center justify-between gap-3 px-5 py-2.5">
            <span className="text-slate-500 dark:text-slate-400">
              {tooOld.length === 1
                ? "1 agent needs"
                : `${tooOld.length} agents need`}{" "}
              upgrading to 1.27.0 or later to run it.
            </span>
            <Link
              className="shrink-0 text-indigo-600 hover:underline dark:text-indigo-300"
              to="/agents"
            >
              Agents
            </Link>
          </li>
        )}
      </ul>
    </Card>
  );
}

/** Settings → Live detection: on for new servers, and on or off for all at once. */
export function LiveSettings() {
  const queryClient = useQueryClient();
  const { data, error, isPending } = useQuery({
    queryKey: ["live-settings"],
    queryFn: api.liveSettings,
  });
  const update = (overview: unknown) => {
    queryClient.setQueryData(["live-settings"], overview);
    void queryClient.invalidateQueries({ queryKey: ["hosts"] });
    void queryClient.invalidateQueries({ queryKey: ["summary"] });
  };
  const newHosts = useMutation({
    mutationFn: api.setLiveNewHosts,
    onSuccess: update,
  });
  const all = useMutation({ mutationFn: api.setLiveAll, onSuccess: update });
  if (isPending) return null;
  if (error) return <ErrorMessage error={error} />;
  const counts = [
    `${data.on} on`,
    `${data.off} off`,
    data.unsupported > 0 && `${data.unsupported} can't run it`,
    data.agent_too_old > 0 &&
      `${data.agent_too_old} ${data.agent_too_old === 1 ? "needs its agent" : "need their agents"} upgraded to 1.27.0`,
  ].filter(Boolean);
  return (
    <Card className="mb-6">
      <CardHeader
        title="Live detection"
        description={
          <>
            Watch machines between scans, as attacks happen. Off unless you turn
            it on; scans, schedules and notifications don't depend on it.{" "}
            <a
              className="underline"
              href={liveDocs}
              target="_blank"
              rel="noreferrer"
            >
              What it watches
            </a>
          </>
        }
      />
      <div className="divide-y divide-slate-200 dark:divide-slate-800">
        <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
          <div>
            <p className="font-medium">Turn on for new servers</p>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              Servers enrolled from now on start with live detection on. A cluster's nodes follow their cluster's own switch.
            </p>
          </div>
          <button
            type="button"
            role="switch"
            aria-checked={data.new_hosts}
            aria-label="Turn on live detection for new servers"
            disabled={newHosts.isPending}
            onClick={() => newHosts.mutate(!data.new_hosts)}
            className={cx(
              "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-60",
              data.new_hosts
                ? "bg-indigo-600"
                : "bg-slate-300 dark:bg-slate-700",
            )}
          >
            <span
              className={cx(
                "inline-block size-4 rounded-full bg-white shadow transition-transform",
                data.new_hosts ? "translate-x-4.5" : "translate-x-0.5",
              )}
            />
          </button>
        </div>
        <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
          <div>
            <p className="font-medium">Existing servers and clusters</p>
            <p className="text-sm text-slate-500 dark:text-slate-400">
              {counts.join(", ")}, a cluster counted once with its nodes. Each can also be turned on or off on its
              Runtime tab.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="secondary"
              disabled={data.on === 0}
              loading={all.isPending && all.variables === false}
              onClick={() => all.mutate(false)}
            >
              Turn off for all
            </Button>
            <Button
              disabled={data.off === 0}
              loading={all.isPending && all.variables === true}
              onClick={() => all.mutate(true)}
            >
              Turn on for all {data.off > 0 ? data.off : ""}
            </Button>
          </div>
        </div>
      </div>
      {(newHosts.error || all.error) && (
        <div className="px-5 pb-4">
          <ErrorMessage error={newHosts.error ?? all.error} />
        </div>
      )}
    </Card>
  );
}
