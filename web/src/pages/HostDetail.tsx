import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Activity,
  ArrowLeft,
  CalendarClock,
  ClipboardCheck,
  Container,
  FileText,
  Pencil,
  Play,
  Ship,
  ShieldCheck,
  TerminalSquare,
  Trash2,
  XCircle,
} from "lucide-react";
import { RunAuditDialog } from "../components/RunAuditDialog";
import { GradeBadge } from "../lib/audit";
import { useCan } from "../lib/role";
import { api, type CheckId, type Host, type HostDetail as HostDetailData, type Scan } from "../api";
import { LiveBadge, RuntimeTab, liveStyle } from "../components/LiveDetection";
import { CheckResultView } from "../components/CheckResultView";
import { ScanConsole } from "../components/ScanConsole";
import { ScanDialog } from "../components/ScanDialog";
import {
  Button,
  Card,
  CardHeader,
  Dialog,
  EmptyState,
  ErrorMessage,
  Field,
  Loading,
  PageHeader,
  StatusBadge,
  Table,
  Td,
  Th,
  cx,
} from "../components/ui";
import { checkBadgeText, checkMeta, checksFor, topSeverity } from "../lib/checks";
import { PackageCountsInline, packageBadge } from "../lib/fixes";
import { useRefreshAll } from "../lib/hooks";
import { ReportBody } from "./ScanReport";
import { HostLog } from "../components/HostLog";
import { ClusterBadge, NodeBadge, ThisServerBadge, agentOnline, connectionLabel } from "../lib/hosts";
import { ClusterOverview } from "../components/ClusterOverview";
import { TagEditor } from "../components/Tags";
import { TrendChart } from "../components/TrendChart";
import { AgentStatus, DisconnectedNote } from "./Agents";
import { dateTime, isActive, severityStyle, timeAgo } from "../lib/format";
import { ReleaseBadge } from "../components/ReleaseSupport";
import { HostUpgradeNotice } from "../components/AgentUpgrade";

export function HostDetail() {
  const canOperate = useCan("operator");
  const canRemove = useCan("admin");
  const { hostId = "" } = useParams();
  const [removing, setRemoving] = useState(false);
  const [renaming, setRenaming] = useState(false);
  const [auditing, setAuditing] = useState(false);
  const [scanning, setScanning] = useState<{ initial?: CheckId[] } | null>(null);
  const [logScan, setLogScan] = useState<Scan | null>(null);
  const [deleting, setDeleting] = useState<Scan | null>(null);
  const capabilities = useQuery({ queryKey: ["capabilities"], queryFn: api.capabilities, staleTime: Infinity });
  const { data, error, isPending } = useQuery({
    queryKey: ["host", hostId],
    queryFn: () => api.host(hostId),
    refetchInterval: (query) => (isActive(query.state.data?.last_scan?.status) ? 2000 : false),
  });

  const cluster = useQuery({
    queryKey: ["host", data?.cluster_id],
    queryFn: () => api.host(data!.cluster_id!),
    enabled: !!data?.cluster_id,
  });

  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;

  const running = isActive(data.last_scan?.status);
  return (
    <>
      <div className="mb-4 flex items-center gap-1 text-sm text-slate-500 dark:text-slate-400">
        <Link to="/hosts" className="inline-flex items-center gap-1 hover:text-slate-900 dark:hover:text-slate-100">
          <ArrowLeft className="size-4" /> Hosts
        </Link>
        {data.cluster_id && cluster.data && (
          <>
            <span aria-hidden>/</span>
            <Link to={`/hosts/${cluster.data.id}`} className="hover:text-slate-900 dark:hover:text-slate-100">
              {cluster.data.address}
            </Link>
            <span aria-hidden>/</span>
            <span>{data.address}</span>
          </>
        )}
      </div>
      <PageHeader
        title={
          <span className="inline-flex flex-wrap items-center gap-x-3 gap-y-1">
            {data.address}
            {data.kind === "cluster" && <ClusterBadge />}
            {data.cluster_id && <NodeBadge />}
            {data.this_server && <ThisServerBadge />}
            {canOperate && (
              <button
                type="button"
                onClick={() => setRenaming(true)}
                className="inline-flex items-center gap-1 text-xs font-semibold text-indigo-600 hover:text-indigo-500 dark:text-indigo-400"
              >
                <Pencil className="size-3" aria-hidden /> Rename
              </button>
            )}
          </span>
        }
        description={
          <>
            {data.name && data.hostname && data.hostname !== data.name && (
              <span className="block">
                {data.kind === "cluster" ? "Cluster" : "Hostname"}: <span className="font-mono">{data.hostname}</span>
              </span>
            )}
            {connectionLabel(data)}
            {data.last_report?.lifecycle && data.last_report.lifecycle.state !== "unknown" && (
              <span className="mt-1 flex flex-wrap items-center gap-1.5 text-sm">
                <ReleaseBadge lifecycle={data.last_report.lifecycle} />
                {data.last_report.os}: {data.last_report.lifecycle.note}
              </span>
            )}
            <span className="mt-1.5 block">
              {/* A node carries its cluster's tags. */}
              <TagEditor key={data.tags.join(",")} hostId={data.id} tags={data.tags} canEdit={canOperate && !data.cluster_id} />
            </span>
            {data.transport === "local" && <SudoToggle host={data} />}
            {data.transport === "agent" && data.kind !== "cluster" && !data.cluster_id && <ContainerScanToggle host={data} />}
            {data.transport === "agent" && (
              <span className="mt-1 block">
                <AgentStatus online={agentOnline(data)} lastSeen={data.agent?.last_seen_at} disconnected={!!data.disconnected} />
              </span>
            )}
            {/* A cluster's and its nodes' schedule is in the cluster's settings below. */}
            {data.kind !== "cluster" && !data.cluster_id && (
            <span className="mt-1 flex items-center gap-1.5 text-sm">
              <CalendarClock className="size-4 text-slate-400" aria-hidden />
              {data.next_scan ? (
                <span>
                  Next scheduled scan {dateTime(data.next_scan.at)} ·{" "}
                  <Link to="/schedules" className="text-indigo-600 hover:underline dark:text-indigo-400">
                    {data.next_scan.schedule}
                  </Link>
                </span>
              ) : (
                <span>
                  Not on a schedule; scanned only when someone presses Scan now.{" "}
                  {canOperate && (
                    <Link to="/schedules" className="text-indigo-600 hover:underline dark:text-indigo-400">
                      Add a schedule
                    </Link>
                  )}
                </span>
              )}
            </span>
            )}
          </>
        }
        action={
          <>
            {canRemove && (
              <Button variant="secondary" onClick={() => setRemoving(true)}>
                <Trash2 className="size-4" /> Remove
              </Button>
            )}
            {canOperate && data.kind !== "cluster" && (
              <Button variant="secondary" disabled={running} onClick={() => setAuditing(true)}>
                <ClipboardCheck className="size-4" /> Run audit
              </Button>
            )}
            {canOperate && (
            <Button
              loading={running}
              onClick={() => setScanning({})}
            >
              {!running && <Play className="size-4" />}
              {data.last_scan?.status.startsWith("needs_")
                ? "Waiting for input…"
                : data.last_scan?.status === "queued"
                  ? "Waiting for agent…"
                  : running
                    ? "Scanning…"
                    : data.kind === "cluster"
                      ? "Scan cluster and nodes"
                      : data.cluster_id
                        ? "Scan this node"
                        : "Scan now"}
            </Button>
            )}
          </>
        }
      />

      {data.disconnected && (
        <Card className="mb-6 border-l-4 border-amber-500">
          <div className="p-5 text-sm">
            <h2 className="font-semibold">This host was disconnected</h2>
            <DisconnectedNote host={data} />
          </div>
        </Card>
      )}

      {data.agent?.upgrade && !data.disconnected && (
        <Card className="mb-6 border-l-4 border-amber-500">
          <div className="p-5">
            <HostUpgradeNotice host={data} />
          </div>
        </Card>
      )}

      {data.kind === "cluster" && <ClusterSettings host={data} />}
      {data.cluster_id && cluster.data && <FollowsCluster node={data} cluster={cluster.data} />}

      {data.kind === "cluster" && <ClusterOverview hostId={data.id} />}

      {data.transport === "agent" && !data.disconnected && !agentOnline(data) && (
        <Card className="mb-6 border-l-4 border-amber-500">
          <div className="p-5 text-sm">
            <h2 className="font-semibold">The agent is offline</h2>
            <p className="mt-1 text-slate-600 dark:text-slate-300">
              It last checked in {data.agent ? timeAgo(data.agent.last_seen_at) : "never"}. Scans you start wait up to an hour for it to
              reconnect. On the machine, check it with: sudo systemctl status deaconguard-agent
            </p>
          </div>
        </Card>
      )}

      {data.last_scan?.status === "failed" && (
        <Card className="mb-6 border-l-4 border-red-500">
          <div className="flex gap-3 p-5">
            <XCircle className="mt-0.5 size-5 shrink-0 text-red-600" aria-hidden />
            <div className="min-w-0">
              <h2 className="font-semibold">The last scan failed</h2>
              <p className="mt-1 text-sm break-words text-slate-600 dark:text-slate-300">{data.last_scan.error}</p>
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                A failed scan is not a clean result. Earlier successful results are shown below.
              </p>
            </div>
          </div>
        </Card>
      )}

      {data.transport === "local" && capabilities.data?.agents && (
        <div className="mb-6 flex gap-3 rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm text-amber-900 dark:border-amber-500/40 dark:bg-amber-500/10 dark:text-amber-100">
          <ShieldCheck className="mt-0.5 size-5 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden />
          <div>
            <p className="font-semibold">This machine is scanned without root, so its results are partial</p>
            <p className="mt-1">
              The server scans it itself, as the {data.username} user, and the server never runs as root. To scan it fully, give it an agent of
              its own, as every other machine has. Its scan history and schedules move to the agent host:
            </p>
            <code className="mt-2 inline-block rounded-md bg-white/70 px-2 py-1 font-mono text-xs dark:bg-slate-900/60">
              sudo deaconguard setup server --with-agent
            </code>
          </div>
        </div>
      )}

      {data.kind === "cluster" ? (
        <details className="group mb-6">
          <summary className="cursor-pointer text-sm font-semibold text-indigo-600 hover:text-indigo-500 dark:text-indigo-400">
            Show all findings as a list, with the scan's notes
          </summary>
          <div className="mt-4">
            <Results host={data} onRun={(check) => setScanning({ initial: [check] })} />
          </div>
        </details>
      ) : (
        <Results host={data} cluster={cluster.data} onRun={(check) => setScanning({ initial: [check] })} />
      )}

      <TrendChart host={data.id} title="This host's vulnerabilities over time" />

      <HostAudits hostId={data.id} />

      <Card className="mt-6">
        <CardHeader
          title="Scan history"
          description="The 10 most recent scans are kept, plus any older scan that still holds a check's latest result. Audits are kept until deleted."
        />
        {data.scans.length === 0 ? (
          <EmptyState
            icon={<FileText className="size-6" />}
            title="No scans yet"
            description="Start a scan and choose which checks to run."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Started</Th>
                <Th>Status</Th>
                <Th>Checks</Th>
                <Th>Vulnerabilities</Th>
                <Th>
                  <span className="sr-only">Log</span>
                </Th>
                <Th>
                  <span className="sr-only">Report</span>
                </Th>
                <Th>
                  <span className="sr-only">Delete</span>
                </Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.scans.map((scan) => (
                <tr key={scan.id}>
                  <Td className="whitespace-nowrap">
                    {dateTime(scan.started_at)}
                    <p className="text-xs text-slate-500 dark:text-slate-400">{timeAgo(scan.started_at)}</p>
                  </Td>
                  <Td>
                    <StatusBadge status={scan.status} />
                  </Td>
                  <Td className="text-xs text-slate-600 dark:text-slate-300">
                    {scan.checks.map((check) => checkMeta[check]?.short ?? check).join(", ")}
                  </Td>
                  <Td>
                    {scan.status !== "succeeded" ? (
                      <span className="line-clamp-2 max-w-sm text-xs text-slate-500 dark:text-slate-400">{scan.error}</span>
                    ) : scan.checks.includes("packages") ? (
                      <PackageCountsInline summary={scan} />
                    ) : (
                      <span className="text-xs text-slate-500 dark:text-slate-400">Not checked</span>
                    )}
                  </Td>
                  <Td className="text-right">
                    {(scan.has_log || isActive(scan.status)) && (
                      <button
                        type="button"
                        onClick={() => setLogScan(scan)}
                        className="inline-flex items-center gap-1 text-sm font-semibold whitespace-nowrap text-slate-600 hover:text-indigo-600 dark:text-slate-300 dark:hover:text-indigo-400"
                      >
                        <TerminalSquare className="size-4" /> {isActive(scan.status) ? "Watch live" : "View logs"}
                      </button>
                    )}
                  </Td>
                  <Td className="text-right">
                    {scan.status === "succeeded" && (
                      <Link
                        to={`/scans/${scan.id}`}
                        className="text-sm font-semibold whitespace-nowrap text-indigo-600 hover:text-indigo-500 dark:text-indigo-400"
                      >
                        View report
                      </Link>
                    )}
                  </Td>
                  <Td className="w-px pl-0 text-right">
                    {canOperate && (
                    <Button
                      variant="ghost"
                      className="px-2"
                      disabled={isActive(scan.status) && scan.status !== "queued"}
                      title={
                        scan.status === "queued"
                          ? "Cancel this scan"
                          : isActive(scan.status)
                            ? "A running scan cannot be deleted"
                            : "Delete this scan"
                      }
                      aria-label={`Delete the scan from ${dateTime(scan.started_at)}`}
                      onClick={() => setDeleting(scan)}
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <HostLog host={data} />

      <ScanDialog host={data} open={scanning !== null} initial={scanning?.initial} onClose={() => setScanning(null)} />
      <ScanConsole host={data} requested={logScan} onRequestClosed={() => setLogScan(null)} />
      <RemoveHostDialog host={data} open={removing} onClose={() => setRemoving(false)} />
      {renaming && <RenameDialog host={data} onClose={() => setRenaming(false)} />}
      <RunAuditDialog host={data} open={auditing} onClose={() => setAuditing(false)} />
      <DeleteScanDialog
        scan={deleting}
        onClose={() => setDeleting(null)}
        onDeleted={(scan) => {
          if (logScan?.id === scan.id) setLogScan(null);
          setDeleting(null);
        }}
      />
    </>
  );
}

function SudoToggle({ host }: { host: Host }) {
  const canOperate = useCan("operator");
  const refresh = useRefreshAll();
  const update = useMutation({ mutationFn: (allow: boolean) => api.setAllowSudo(host.id, allow), onSuccess: refresh });
  return (
    <span className="mt-2 flex items-center gap-2">
      <button
        type="button"
        role="switch"
        aria-checked={host.allow_sudo}
        disabled={update.isPending || !canOperate}
        title={canOperate ? undefined : "Operators and admins can change this"}
        onClick={() => update.mutate(!host.allow_sudo)}
        className={cx(
          "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-60",
          host.allow_sudo ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-700",
        )}
      >
        <span className={cx("inline-block size-4 rounded-full bg-white shadow transition-transform", host.allow_sudo ? "translate-x-4.5" : "translate-x-0.5")} />
      </button>
      <ShieldCheck className="size-4" aria-hidden />
      <span>
        {host.allow_sudo
          ? "DeaconGuard may use sudo on this host for deeper checks"
          : "Use sudo for deeper checks: off · turn on to let checks read protected files and all processes"}
      </span>
      {update.error && <span className="text-red-600">{update.error.message}</span>}
    </span>
  );
}

function Switch({ on, label, disabled, onClick }: { on: boolean; label: string; disabled?: boolean; onClick: () => void }) {
  return (
    <button
      type="button"
      role="switch"
      aria-checked={on}
      aria-label={label}
      disabled={disabled}
      onClick={onClick}
      className={cx(
        "relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-60",
        on ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-700",
      )}
    >
      <span className={cx("inline-block size-4 rounded-full bg-white shadow transition-transform", on ? "translate-x-4.5" : "translate-x-0.5")} />
    </button>
  );
}

/**
 * A cluster's settings, which every node follows, nodes that join later
 * included: live detection, scanning as it changes, and its schedule.
 */
function ClusterSettings({ host }: { host: HostDetailData }) {
  const canAdmin = useCan("admin");
  const canOperate = useCan("operator");
  const refresh = useRefreshAll();
  const live = host.live;
  const setLive = useMutation({ mutationFn: (on: boolean) => api.setLive(host.id, on), onSettled: refresh });
  const setAuto = useMutation({ mutationFn: (on: boolean) => api.setAutoScanContainers(host.id, on), onSettled: refresh });
  const auto = host.auto_scan_containers ?? false;
  const nodes = live?.nodes ?? 0;
  return (
    <Card className="mb-6">
      <p className="border-b border-slate-200 px-5 py-2.5 text-sm text-slate-600 dark:border-slate-800 dark:text-slate-300">
        These settings, and the cluster's tags, apply to the cluster and <strong>every node in it</strong>, nodes that join later included.
      </p>
      <div className="grid divide-y divide-slate-200 md:grid-cols-3 md:divide-x md:divide-y-0 dark:divide-slate-800">
        <div className="flex gap-3 p-4">
          <Switch
            on={live?.enabled ?? false}
            label="Live detection for the cluster"
            disabled={!canAdmin || setLive.isPending}
            onClick={() => setLive.mutate(!(live?.enabled ?? false))}
          />
          <div className="min-w-0 text-sm">
            <p className="font-medium">
              <Link to="?tab=runtime" className="hover:underline">
                Live detection: {live?.enabled ? "on" : "off"}
              </Link>
            </p>
            <p className="mt-0.5 flex flex-wrap items-center gap-1.5 text-slate-500 dark:text-slate-400">
              {live?.enabled && nodes > 0 && <LiveBadge live={live} />}
              {nodes === 0 ? "no node has a node agent yet" : live?.enabled ? "new nodes start watched" : `${nodes} ${nodes === 1 ? "node" : "nodes"} could run it`}
            </p>
            {!canAdmin && <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">An administrator can change this.</p>}
            {setLive.error && <ErrorMessage error={setLive.error} />}
          </div>
        </div>
        <div className="flex gap-3 p-4">
          <Switch on={auto} label="Scan when the cluster changes" disabled={!canOperate || setAuto.isPending} onClick={() => setAuto.mutate(!auto)} />
          <div className="min-w-0 text-sm">
            <p className="font-medium">Scan when the cluster changes: {auto ? "on" : "off"}</p>
            <p className="mt-0.5 text-slate-500 dark:text-slate-400">
              {auto
                ? "Workloads, roles and policies checked within a minute; nodes' new containers within 10"
                : "Turn on to check the cluster, and nodes' new containers, as they change"}
            </p>
            {setAuto.error && <ErrorMessage error={setAuto.error} />}
          </div>
        </div>
        <div className="flex gap-3 p-4">
          <CalendarClock className="mt-0.5 size-5 shrink-0 text-slate-400" aria-hidden />
          <div className="min-w-0 text-sm">
            <p className="font-medium">{host.next_scan ? `Schedule: ${host.next_scan.schedule}` : "Not on a schedule"}</p>
            <p className="mt-0.5 text-slate-500 dark:text-slate-400">
              {host.next_scan ? `Next ${dateTime(host.next_scan.at)}, the cluster and its nodes · ` : "Scanned when someone presses Scan · "}
              <Link to="/schedules" className="text-indigo-600 hover:underline dark:text-indigo-400">
                {host.next_scan ? "Change" : "Add a schedule"}
              </Link>
            </p>
          </div>
        </div>
      </div>
    </Card>
  );
}

/** A node's settings come from its cluster; it can only be excluded. */
function FollowsCluster({ node, cluster }: { node: HostDetailData; cluster: HostDetailData }) {
  const canAdmin = useCan("admin");
  const refresh = useRefreshAll();
  const exclude = useMutation({ mutationFn: (on: boolean) => api.setExcluded(node.id, on), onSettled: refresh });
  const excluded = node.excluded ?? false;
  const clusterLink = (
    <Link to={`/hosts/${cluster.id}`} className="text-indigo-600 hover:underline dark:text-indigo-400">
      {cluster.address}
    </Link>
  );
  return (
    <Card className="mb-6">
      <div className="flex flex-wrap items-start justify-between gap-4 p-4">
        <div className="min-w-64 flex-1 text-sm">
          <p className="font-medium">
            {excluded ? <>Excluded from {clusterLink}'s scans and live detection</> : <>Follows {clusterLink}'s settings</>}
          </p>
          <p className="mt-0.5 text-slate-500 dark:text-slate-400">
            {excluded ? (
              "Its cluster's schedules and scans leave it out, and live detection is off here. Scan it yourself with Scan this node."
            ) : (
              <>
                Live detection {cluster.live?.enabled ? "on" : "off"} · scan when the cluster changes {cluster.auto_scan_containers ? "on" : "off"} ·{" "}
                {cluster.next_scan ? `schedule ${cluster.next_scan.schedule}` : "no schedule"}
                {cluster.tags.length > 0 && ` · tags ${cluster.tags.join(", ")}`} ·{" "}
                <Link to={`/hosts/${cluster.id}`} className="text-indigo-600 hover:underline dark:text-indigo-400">
                  change on the cluster
                </Link>
              </>
            )}
          </p>
          {node.left_cluster_at && (
            <p className="mt-1 text-amber-700 dark:text-amber-300">
              The cluster stopped listing this node {timeAgo(node.left_cluster_at)}; it's removed 3 days after it left, unless its agent checks in again.
            </p>
          )}
          {exclude.error && <ErrorMessage error={exclude.error} />}
        </div>
        <label className="flex items-center gap-2 text-sm">
          <Switch on={excluded} label="Exclude this node" disabled={!canAdmin || exclude.isPending} onClick={() => exclude.mutate(!excluded)} />
          <span>
            Exclude this node
            <span className="block text-xs text-slate-500 dark:text-slate-400">no cluster scans, no live detection</span>
          </span>
        </label>
      </div>
    </Card>
  );
}

/** Whether new containers on an agent host get scanned as they start. */
function ContainerScanToggle({ host }: { host: Host }) {
  const canOperate = useCan("operator");
  const refresh = useRefreshAll();
  const on = host.auto_scan_containers ?? false;
  const cluster = host.kind === "cluster";
  const update = useMutation({ mutationFn: (value: boolean) => api.setAutoScanContainers(host.id, value), onSuccess: refresh });
  const label = cluster ? "Scan when the cluster changes" : "Scan new containers automatically";
  const Icon = cluster ? Ship : Container;
  return (
    <span className="mt-2 flex items-center gap-2">
      <button
        type="button"
        role="switch"
        aria-checked={on}
        aria-label={label}
        disabled={update.isPending || !canOperate}
        title={canOperate ? undefined : "Operators and admins can change this"}
        onClick={() => update.mutate(!on)}
        className={cx(
          "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-60",
          on ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-700",
        )}
      >
        <span className={cx("inline-block size-4 rounded-full bg-white shadow transition-transform", on ? "translate-x-4.5" : "translate-x-0.5")} />
      </button>
      <Icon className="size-4" aria-hidden />
      <span>
        {cluster
          ? on
            ? `${label}: on · when a workload, role, namespace or network policy changes, the cluster is checked within about a minute`
            : `${label}: off · turn on to check the cluster as it changes (cluster agent 1.5.0 or later)`
          : on
            ? `${label}: on · when containers start, the running containers are checked, at most every 10 minutes`
            : `${label}: off · turn on to check containers as they start (agent 1.2.0 or later)`}
      </span>
      {update.error && <span className="text-red-600">{update.error.message}</span>}
    </span>
  );
}

/** One tab per check, each showing that check's newest successful result on this host. */
function Results({ host, onRun, cluster }: { host: HostDetailData; onRun: (check: CheckId) => void; cluster?: HostDetailData }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("tab") as CheckId | null;
  const tabs = checksFor(host);
  const active: CheckId = requested && tabs.includes(requested) ? requested : tabs[0];
  const checks = host.checks ?? {};
  // Live detection has its own tab, right after the first, on machines with an agent.
  const runtime = host.live !== undefined && host.kind !== "cluster";
  const runtimeOpen = runtime && searchParams.get("tab") === "runtime";
  const liveAlerts = host.live ? host.live.alerts_24h.critical + host.live.alerts_24h.high : 0;
  const runtimeTab = runtime ? (
    <button
      key="runtime"
      type="button"
      role="tab"
      aria-selected={runtimeOpen}
      onClick={() => setSearchParams({ tab: "runtime" }, { replace: true })}
      className={cx(
        "-mb-px flex items-center gap-2 border-b-2 px-3 py-2.5 text-sm font-medium whitespace-nowrap transition-colors",
        runtimeOpen
          ? "border-indigo-600 text-indigo-700 dark:border-indigo-400 dark:text-indigo-300"
          : "border-transparent text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100",
      )}
    >
      <Activity className="size-4" />
      Runtime
      {liveAlerts > 0 ? (
        <span className="rounded-full bg-red-100 px-1.5 text-xs font-semibold text-red-700 tabular-nums dark:bg-red-500/15 dark:text-red-300">{liveAlerts}</span>
      ) : (
        <span className={cx("size-1.5 rounded-full", (liveStyle[host.live!.state] ?? liveStyle.stopped).dot)} aria-hidden />
      )}
    </button>
  ) : null;

  return (
    <section>
      <div className="mb-4 flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-800" role="tablist">
        {tabs.map((check, index) => {
          const Icon = checkMeta[check].icon;
          const summary = checks[check];
          const packages = check === "packages" && summary ? packageBadge(summary) : undefined;
          const severity = summary ? topSeverity(packages ? (packages.severity ?? { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 }) : summary.severity) : undefined;
          const button = (
            <button
              key={check}
              type="button"
              role="tab"
              aria-selected={!runtimeOpen && active === check}
              onClick={() => setSearchParams(check === "packages" ? {} : { tab: check }, { replace: true })}
              className={cx(
                "-mb-px flex items-center gap-2 border-b-2 px-3 py-2.5 text-sm font-medium whitespace-nowrap transition-colors",
                !runtimeOpen && active === check
                  ? "border-indigo-600 text-indigo-700 dark:border-indigo-400 dark:text-indigo-300"
                  : "border-transparent text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100",
              )}
            >
              <Icon className="size-4" />
              {checkMeta[check].label}
              {summary ? (
                <span
                  title={packages?.title}
                  className={cx(
                    "rounded-full px-1.5 text-xs font-semibold tabular-nums",
                    summary.status === "skipped" || summary.status === "failed"
                      ? "bg-slate-100 font-normal text-slate-500 dark:bg-slate-800 dark:text-slate-400"
                      : (packages ? packages.text === "✓" : summary.finding_count === 0)
                        ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
                        : severity
                          ? severityStyle[severity].badge
                          : "bg-slate-100 font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300",
                  )}
                >
                  {packages && summary.status !== "skipped" && summary.status !== "failed" ? packages.text : checkBadgeText(summary)}
                </span>
              ) : (
                <span className="text-xs text-slate-400">–</span>
              )}
            </button>
          );
          return index === 0 && runtimeTab ? [button, runtimeTab] : button;
        })}
      </div>
      {runtimeOpen ? (
        <RuntimeTab hostId={host.id} follows={cluster ? { id: cluster.id, name: cluster.address, excluded: host.excluded } : undefined} />
      ) : (
        <CheckTab host={host} check={active} onRun={onRun} />
      )}
    </section>
  );
}

/** Turns on the host's sudo setting and reruns one check in a single step. */
function RescanWithSudo({ host, check }: { host: Host; check: CheckId }) {
  const refresh = useRefreshAll();
  const rescan = useMutation({
    mutationFn: async () => {
      await api.setAllowSudo(host.id, true);
      return api.startScan(host.id, [check]);
    },
    onSettled: refresh,
  });
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-900 ring-1 ring-amber-600/20 ring-inset dark:bg-amber-500/10 dark:text-amber-200">
      <p className="flex gap-2">
        <ShieldCheck className="mt-0.5 size-4 shrink-0" aria-hidden />
        This check ran without sudo, so it only saw part of the system.
      </p>
      <div className="flex items-center gap-2">
        {rescan.error && <span className="text-red-600">{rescan.error.message}</span>}
        <Button loading={rescan.isPending} onClick={() => rescan.mutate()}>
          Turn on sudo and scan again
        </Button>
      </div>
    </div>
  );
}

function CheckTab({ host, check, onRun }: { host: HostDetailData; check: CheckId; onRun: (check: CheckId) => void }) {
  const summary = host.checks?.[check];
  const scanId = check === "packages" ? host.last_report?.id : summary?.scan_id;
  const { data, error, isPending } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.scan(scanId!),
    enabled: Boolean(scanId),
  });
  const Icon = checkMeta[check].icon;
  const canOperate = useCan("operator");

  if (!scanId) {
    return (
      <Card>
        <EmptyState
          icon={<Icon className="size-6" />}
          title={`${checkMeta[check].label} has not been checked yet`}
          description={canOperate ? "Run a scan that includes this check to see results here." : "Results appear here once an operator runs a scan that includes this check."}
          action={
            canOperate && (
              <Button onClick={() => onRun(check)}>
                <Play className="size-4" /> Run this check
              </Button>
            )
          }
        />
      </Card>
    );
  }
  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;
  if (!data.report) return null;

  const scannedAt = check === "packages" ? host.last_report?.finished_at : summary?.scanned_at;
  const result = check === "packages" ? undefined : data.report.check_results?.[check];
  return (
    <div>
      <p className="mb-3 text-sm text-slate-500 dark:text-slate-400">
        From the latest scan that included this check ·{" "}
        <Link to={`/scans/${scanId}`} className="hover:underline">
          {dateTime(scannedAt)} ({timeAgo(scannedAt)})
        </Link>
      </p>
      {canOperate && result && !result.privileged && result.status !== "skipped" && !host.allow_sudo && (
        <RescanWithSudo host={host} check={check} />
      )}
      {check === "packages" ? (
        <ReportBody report={data.report} />
      ) : data.report.check_results?.[check] ? (
        <CheckResultView check={check} name={checkMeta[check].label} result={data.report.check_results[check]} />
      ) : (
        <ErrorMessage error="This scan has no result for the check." />
      )}
    </div>
  );
}

function DeleteScanDialog({ scan, onClose, onDeleted }: { scan: Scan | null; onClose: () => void; onDeleted: (scan: Scan) => void }) {
  const refresh = useRefreshAll();
  const remove = useMutation({
    mutationFn: (target: Scan) => api.deleteScan(target.id),
    onSuccess: (_, target) => {
      refresh();
      onDeleted(target);
    },
  });
  return (
    <Dialog open={scan !== null} onClose={onClose} title="Delete scan">
      {scan && (
        <>
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Delete the scan from <span className="font-semibold">{dateTime(scan.started_at)}</span> (
            {scan.checks.map((check) => checkMeta[check]?.label ?? check).join(", ")})? Its results and activity log are removed
            permanently. If it held a check's latest result, that tab shows the previous result for the check instead.
          </p>
          <div className="mt-4">
            <ErrorMessage error={remove.error} />
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(scan)}>
              Delete scan
            </Button>
          </div>
        </>
      )}
    </Dialog>
  );
}

export function RemoveHostDialog({ host, open, onClose }: { host: Host; open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const refresh = useRefreshAll();
  const remove = useMutation({
    mutationFn: () => api.removeHost(host.id),
    onSuccess: () => {
      refresh();
      navigate("/hosts");
    },
  });
  return (
    <Dialog open={open} onClose={onClose} title="Remove host">
      <p className="text-sm text-slate-600 dark:text-slate-300">
        Remove <span className="font-semibold">{host.address}</span> from DeaconGuard? It will no longer appear on the dashboard. Earlier
        reports stay stored and can still be opened with the CLI.
        {host.transport === "agent" &&
          " Its agent is disconnected at once and cannot reconnect; to scan the machine again, enroll it with a new token."}
      </p>
      <div className="mt-4">
        <ErrorMessage error={remove.error} />
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
          Remove host
        </Button>
      </div>
    </Dialog>
  );
}

/** Gives a host a display name, or takes it away so its hostname shows again. */
function RenameDialog({ host, onClose }: { host: Host; onClose: () => void }) {
  const refresh = useRefreshAll();
  const [name, setName] = useState(host.name);
  const rename = useMutation({
    mutationFn: () => api.renameHost(host.id, name),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  const what = host.kind === "cluster" ? "cluster name" : "hostname";
  return (
    <Dialog open onClose={onClose} title={`Rename ${host.address}`}>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          rename.mutate();
        }}
        className="space-y-4"
      >
        <Field
          label="Name"
          autoFocus
          maxLength={80}
          value={name}
          onChange={(event) => setName(event.target.value)}
          placeholder={host.hostname}
          hint={`Shown everywhere instead of its ${what}, ${host.hostname}, which stays under the name on this page. Leave it empty to show the ${what} again.`}
        />
        <ErrorMessage error={rename.error} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={rename.isPending}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/** The host's audits, newest first; hidden until it has one. */
function HostAudits({ hostId }: { hostId: string }) {
  const { data } = useQuery({
    queryKey: ["audits", hostId],
    queryFn: () => api.auditList(hostId),
    refetchInterval: (query) => (query.state.data?.some((item) => isActive(item.status)) ? 3000 : 30_000),
  });
  if (!data || data.length === 0) return null;
  return (
    <Card className="mt-6">
      <CardHeader title="Audits" description="Full checks of this machine, graded A to F. Open one for every control and the inventory." />
      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
        {data.slice(0, 5).map((item) => (
          <li key={item.id}>
            <Link to={`/audits/${item.id}`} className="flex items-center gap-4 px-5 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/40">
              <GradeBadge grade={item.grade} />
              <span className="min-w-0 flex-1 text-sm">
                <span className="font-medium">{dateTime(item.started_at)}</span>
                <span className="block text-xs text-slate-500 dark:text-slate-400">
                  {item.grade ? `Score ${item.score} · ${item.failed} ${item.failed === 1 ? "control" : "controls"} failed` : "Running…"}
                </span>
              </span>
              {!item.grade && <StatusBadge status={item.status} />}
            </Link>
          </li>
        ))}
      </ul>
      {data.length > 5 && (
        <p className="px-5 py-3 text-sm">
          <Link to="/audits" className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
            All {data.length} audits
          </Link>
        </p>
      )}
    </Card>
  );
}
