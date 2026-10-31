import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Flame, Play, Plus, RadioTower, Server, Trash2 } from "lucide-react";
import { TagChips, TagFilter } from "../components/Tags";
import { useCan } from "../lib/role";
import { api, type HostSummary } from "../api";
import {
  Button,
  Card,
  CoverageNotes,
  Dialog,
  EmptyState,
  ErrorMessage,
  Loading,
  PageHeader,
  StatusBadge,
  Table,
  Td,
  Th,
  cx,
} from "../components/ui";
import { useRefreshAll } from "../lib/hooks";
import { isActive, severityStyle, timeAgo } from "../lib/format";
import { checkBadgeText, checkMeta, checkOrder, topSeverity } from "../lib/checks";
import { PackageCountsInline } from "../lib/fixes";
import { ScanDialog } from "../components/ScanDialog";
import { ClusterBadge, NodeBadge, ThisServerBadge, agentOnline, disconnectedText, groupByCluster, shortConnectionLabel } from "../lib/hosts";
import { RemoveHostDialog } from "./HostDetail";
import { ReleaseBadge } from "../components/ReleaseSupport";

export function Hosts() {
  const canEnroll = useCan("admin");
  const [searchParams, setSearchParams] = useSearchParams();
  const adding = searchParams.get("add") === "1";
  const tag = searchParams.get("tag") ?? "";
  const setAdding = (open: boolean) => setSearchParams(open ? { add: "1" } : tag ? { tag } : {}, { replace: true });
  const setTag = (value: string) => setSearchParams(value ? { tag: value } : {}, { replace: true });

  const capabilities = useQuery({ queryKey: ["capabilities"], queryFn: api.capabilities, staleTime: Infinity });
  const network = capabilities.data?.agents ?? false;
  const { data, error, isPending } = useQuery({
    queryKey: ["hosts"],
    queryFn: api.hosts,
    refetchInterval: (query) => (query.state.data?.some((host) => isActive(host.last_scan?.status)) ? 2000 : false),
  });

  return (
    <>
      <PageHeader
        title="Hosts"
        description={
          network
            ? "Every machine running the DeaconGuard agent, this server's own machine included. Each is scanned as root by its own agent."
            : "The machine DeaconGuard runs on. Run it as a server to scan other machines with the agent."
        }
        action={
          <>
            {!network && (
              <Button onClick={() => setAdding(true)}>
                <Plus className="size-4" /> Add this machine
              </Button>
            )}
            {network && canEnroll && (
              <Link
                to="/agents?enroll=1"
                className="inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-3.5 py-2 text-sm font-semibold whitespace-nowrap text-white shadow-sm hover:bg-indigo-500"
              >
                <RadioTower className="size-4" /> Enroll a machine
              </Link>
            )}
          </>
        }
      />
      <Card>
        {isPending ? (
          <Loading />
        ) : error ? (
          <div className="p-5">
            <ErrorMessage error={error} />
          </div>
        ) : data.length === 0 ? (
          <EmptyState
            icon={<Server className="size-6" />}
            title="No hosts yet"
            description={
              network
                ? "Enroll machines with the DeaconGuard agent. The install script gives this server's own machine an agent too; if it is missing, run: sudo deaconguard setup server --with-agent"
                : "Register the Linux machine DeaconGuard runs on to scan it."
            }
            action={
              network && !canEnroll ? undefined : network ? (
                <Link
                  to="/agents?enroll=1"
                  className="inline-flex items-center justify-center gap-2 rounded-lg bg-indigo-600 px-3.5 py-2 text-sm font-semibold whitespace-nowrap text-white shadow-sm hover:bg-indigo-500"
                >
                  <RadioTower className="size-4" /> Enroll a machine
                </Link>
              ) : (
                <Button onClick={() => setAdding(true)}>
                  <Plus className="size-4" /> Add this machine
                </Button>
              )
            }
          />
        ) : (
          <>
          <TagFilter tags={[...new Set(data.flatMap((host) => host.tags))].sort()} selected={tag} onSelect={setTag} />
          <Table>
            <thead>
              <tr>
                <Th>Host</Th>
                <Th>Operating system</Th>
                <Th>Last scan</Th>
                <Th>Findings</Th>
                <Th className="text-right">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {groupByCluster(data)
                .filter(({ host, nodes }) => !tag || [host, ...nodes].some((item) => item.tags.includes(tag)))
                .map(({ host, nodes }) => (
                  <HostGroupRows key={host.id} host={host} nodes={nodes} />
                ))}
            </tbody>
          </Table>
          </>
        )}
      </Card>
      <AddHostDialog
        open={adding}
        onClose={() => setAdding(false)}
        registered={data?.some((host) => host.transport === "local") ?? false}
      />
    </>
  );
}

/** A host, and when it is a cluster, its nodes under it. */
function HostGroupRows({ host, nodes }: { host: HostSummary; nodes: HostSummary[] }) {
  return (
    <>
      <HostRow host={host} nodes={nodes.length} />
      {nodes.map((node) => (
        <HostRow key={node.id} host={node} node />
      ))}
    </>
  );
}

function HostRow({ host, node = false, nodes = 0 }: { host: HostSummary; node?: boolean; nodes?: number }) {
  const navigate = useNavigate();
  const [removing, setRemoving] = useState(false);
  const [scanning, setScanning] = useState(false);
  const canScan = useCan("operator");
  const canRemove = useCan("admin");
  const running = isActive(host.last_scan?.status);
  return (
    <tr
      onClick={() => navigate(`/hosts/${host.id}`)}
      className={cx(
        "cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50",
        (node || host.kind === "cluster") && "bg-sky-50/40 dark:bg-sky-500/[0.04]",
      )}
    >
      <Td className={node ? "pl-10" : undefined}>
        {/* Name and label stay on one line, so a wide Findings column cannot push the label down. */}
        <div className="flex items-center gap-2 whitespace-nowrap">
          {node && (
            <span className="text-slate-400 dark:text-slate-500" aria-hidden>
              └
            </span>
          )}
          {node && <NodeBadge />}
          <Link to={`/hosts/${host.id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
            {host.address}
          </Link>
          {host.kind === "cluster" && <ClusterBadge />}
          {host.this_server && <ThisServerBadge />}
        </div>
        {host.name && host.hostname && host.hostname !== host.name && (
          <p className="font-mono text-xs text-slate-500 dark:text-slate-400" title="Hostname">
            {host.hostname}
          </p>
        )}
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {host.transport === "agent" && (
            <span
              className={cx("mr-1 inline-block size-1.5 rounded-full align-middle", agentOnline(host) ? "bg-emerald-500" : "bg-slate-400")}
              title={agentOnline(host) ? "Agent online" : "Agent offline"}
            />
          )}
          {host.kind === "cluster" ? "cluster agent" : node ? "node agent" : shortConnectionLabel(host)}
          {host.transport === "agent" && (host.disconnected ? " · disconnected" : agentOnline(host) ? " · online" : " · offline")}
          {host.kind === "cluster" && nodes > 0 && ` · ${nodes} ${nodes === 1 ? "node" : "nodes"} with an agent`}
        </p>
        {host.disconnected && (
          <p className="mt-1 max-w-md text-xs whitespace-normal text-amber-700 dark:text-amber-300">{disconnectedText(host)}</p>
        )}
        <TagChips tags={host.tags} className="mt-1" />
      </Td>
      <Td className="text-slate-600 dark:text-slate-300">
        {host.last_report?.os || host.agent?.os || "—"}
        <ReleaseBadge lifecycle={host.last_report?.lifecycle} onlyProblems className="ml-2" />
      </Td>
      <Td>
        {host.last_scan ? (
          <div className="space-y-1">
            <StatusBadge status={host.last_scan.status} />
            <p className="text-xs text-slate-500 dark:text-slate-400">{timeAgo(host.last_scan.started_at)}</p>
          </div>
        ) : (
          <span className="text-sm text-slate-500 dark:text-slate-400">Never scanned</span>
        )}
      </Td>
      <Td>
        {host.last_report ? (
          <div className="space-y-1">
            <PackageCountsInline summary={host.last_report} />
            {(host.last_report.exploit?.known ?? 0) > 0 && (
              <span className="inline-flex items-center gap-1 text-xs font-semibold text-red-700 dark:text-red-300">
                <Flame className="size-3.5" aria-hidden />
                {host.last_report.exploit!.known} known exploited
              </span>
            )}
            <CoverageNotes scan={host.last_report} />
          </div>
        ) : host.kind === "cluster" ? null : (
          <span className="text-sm text-slate-500 dark:text-slate-400">No vulnerability results</span>
        )}
        <CheckChips host={host} />
      </Td>
      <Td className="text-right">
        <div className="flex items-center justify-end gap-1">
          {!canScan && running && <span className="text-sm text-slate-500 dark:text-slate-400">Scanning…</span>}
          {canScan && (
            <Button
              variant="secondary"
              loading={running}
              onClick={(event) => {
                event.stopPropagation();
                setScanning(true);
              }}
            >
              {!running && <Play className="size-4" />}
              {host.last_scan?.status.startsWith("needs_")
                ? "Waiting for input"
                : host.last_scan?.status === "queued"
                  ? "Waiting for agent"
                  : running
                    ? "Scanning"
                    : "Scan"}
            </Button>
          )}
          {canRemove && (
            <Button
              variant="ghost"
              className="px-2"
              title={`Remove ${host.address}`}
              aria-label={`Remove ${host.address}`}
              onClick={(event) => {
                event.stopPropagation();
                setRemoving(true);
              }}
            >
              <Trash2 className="size-4" />
            </Button>
          )}
        </div>
        <div className="text-left" onClick={(event) => event.stopPropagation()}>
          <RemoveHostDialog host={host} open={removing} onClose={() => setRemoving(false)} />
          <ScanDialog host={host} open={scanning} onClose={() => setScanning(false)} />
        </div>
      </Td>
    </tr>
  );
}

/** Compact results of the other checks, linking to the host's tab for each. */
function CheckChips({ host }: { host: HostSummary }) {
  const checks = checkOrder.filter((check) => check !== "packages" && host.checks?.[check]);
  if (checks.length === 0) return null;
  return (
    <div className="mt-1.5 flex flex-wrap gap-1.5">
      {checks.map((check) => {
        const summary = host.checks![check]!;
        const severity = topSeverity(summary.severity);
        return (
          <Link
            key={check}
            to={`/hosts/${host.id}?tab=${check}`}
            onClick={(event) => event.stopPropagation()}
            title={`${checkMeta[check].label}: ${summary.summary}`}
            className={cx(
              "rounded-md px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset",
              summary.status === "skipped" || summary.status === "failed"
                ? "text-slate-500 ring-slate-300 dark:text-slate-400 dark:ring-slate-700"
                : summary.finding_count === 0
                  ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-400/30"
                  : severity
                    ? severityStyle[severity].badge
                    : "",
            )}
          >
            {checkMeta[check].short} {checkBadgeText(summary)}
            {summary.status === "partial" && <span title="Partial coverage">*</span>}
          </Link>
        );
      })}
    </div>
  );
}

function AddHostDialog({ open, onClose, registered }: { open: boolean; onClose: () => void; registered: boolean }) {
  const navigate = useNavigate();
  const refresh = useRefreshAll();
  const capabilities = useQuery({ queryKey: ["capabilities"], queryFn: api.capabilities, staleTime: Infinity });
  const [allowSudo, setAllowSudo] = useState(false);
  const addHost = useMutation({
    mutationFn: api.addHost,
    onSuccess: (host) => {
      refresh();
      setAllowSudo(false);
      navigate(`/hosts/${host.id}`);
    },
  });
  const unavailable = capabilities.data?.local_scanning === false;

  function submit(event: FormEvent) {
    event.preventDefault();
    addHost.mutate({ transport: "local", allow_sudo: allowSudo });
  }

  return (
    <Dialog open={open} onClose={onClose} title="Add this machine">
      <form onSubmit={submit} className="space-y-4">
        {unavailable ? (
          <ErrorMessage error={`This machine cannot be scanned: ${capabilities.data?.local_reason}.`} />
        ) : registered ? (
          <p className="text-sm text-slate-600 dark:text-slate-300">This machine is already registered. Open it from the hosts list to scan it.</p>
        ) : (
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Registers <span className="font-semibold">{capabilities.data?.hostname ?? "this machine"}</span>, the Linux machine DeaconGuard runs on. Scans run
            fixed, read-only commands directly on it as <span className="font-semibold">{capabilities.data?.username}</span>.
          </p>
        )}
        <p className="rounded-lg bg-slate-50 p-3 text-xs leading-relaxed text-slate-500 dark:bg-slate-800/50 dark:text-slate-400">
          To scan other machines, install DeaconGuard on them and enroll them as agents with a token from the Agents page (needs the DeaconGuard server
          running on the network).
        </p>
        {!unavailable && !registered && (
          <label className="flex cursor-pointer gap-2 text-sm">
            <input
              type="checkbox"
              checked={allowSudo}
              onChange={(event) => setAllowSudo(event.target.checked)}
              className="mt-0.5 size-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
            />
            <span>
              <span className="font-medium">Allow sudo for deeper checks</span>
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                Integrity, malware, configuration, and antivirus checks can read protected files and processes using fixed read-only commands. You can change
                this later.
              </span>
            </span>
          </label>
        )}
        <ErrorMessage error={addHost.error} />
        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            {unavailable || registered ? "Close" : "Cancel"}
          </Button>
          {!unavailable && !registered && (
            <Button type="submit" loading={addHost.isPending}>
              Add this machine
            </Button>
          )}
        </div>
      </form>
    </Dialog>
  );
}
