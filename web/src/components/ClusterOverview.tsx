import { useMemo, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Bug, ChevronDown, ChevronRight, Info } from "lucide-react";
import {
  api,
  type CheckFinding,
  type ClusterContainerView,
  type ClusterNamespaceView,
  type ClusterPodView,
  type ClusterView,
  type ClusterWorkloadView,
  type ViewCounts,
} from "../api";
import { Card, ErrorMessage, Loading, SearchBox, SeverityBadge, Table, Td, Th, cx } from "./ui";
import { AgentStatus } from "../pages/Agents";
import { agentOnline } from "../lib/hosts";
import { timeAgo } from "../lib/format";

/**
 * A Kubernetes cluster with what it runs beneath it: its namespaces, their
 * workloads, pods and containers, and its nodes. Problems add up from the
 * containers to their pods, workloads and namespaces.
 */
export function ClusterOverview({ hostId }: { hostId: string }) {
  const { data, error, isPending } = useQuery({ queryKey: ["cluster", hostId], queryFn: () => api.clusterView(hostId), refetchInterval: 30_000 });
  const [tab, setTab] = useState<"workloads" | "nodes" | "images" | "settings">("workloads");
  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;
  if (!data.scan_id) {
    return (
      <Card className="mb-6">
        <p className="p-5 text-sm text-slate-600 dark:text-slate-300">
          Not scanned yet. Press Scan now: the cluster agent lists the cluster's nodes, namespaces and pods, and checks its settings.
        </p>
      </Card>
    );
  }
  const tabs: { id: typeof tab; label: string }[] = [
    { id: "workloads", label: "Workloads" },
    { id: "nodes", label: `Nodes (${data.nodes.length})` },
    { id: "images", label: `Images (${data.images.length})` },
    { id: "settings", label: `Cluster settings (${data.findings.length})` },
  ];
  return (
    <div className="mb-6">
      <SummaryCards view={data} />
      {data.notes.map((note) => (
        <p key={note} className="mt-3 flex gap-2 rounded-lg bg-slate-50 px-3 py-2 text-sm text-slate-600 ring-1 ring-slate-200 ring-inset dark:bg-slate-900 dark:text-slate-300 dark:ring-slate-800">
          <Info className="mt-0.5 size-4 shrink-0 text-slate-400" aria-hidden />
          {note}
        </p>
      ))}
      <div className="mt-6 flex gap-6 overflow-x-auto border-b border-slate-200 text-sm dark:border-slate-800" role="tablist">
        {tabs.map((item) => (
          <button
            key={item.id}
            type="button"
            role="tab"
            aria-selected={tab === item.id}
            onClick={() => setTab(item.id)}
            className={cx(
              "-mb-px border-b-2 pb-2 whitespace-nowrap",
              tab === item.id
                ? "border-indigo-500 font-medium text-slate-900 dark:text-white"
                : "border-transparent text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200",
            )}
          >
            {item.label}
          </button>
        ))}
      </div>
      <div className="mt-4">
        {tab === "workloads" && <WorkloadTree view={data} />}
        {tab === "nodes" && <NodeTable view={data} />}
        {tab === "images" && <ImageTable view={data} />}
        {tab === "settings" && <ClusterFindings findings={data.findings} />}
      </div>
    </div>
  );
}

/** Adds up the problems of some namespaces. */
function total(namespaces: ClusterNamespaceView[]): ViewCounts {
  const sum: ViewCounts = { critical: 0, high: 0, medium: 0, low: 0, fixable: 0, settings: 0, malware: 0 };
  for (const namespace of namespaces) {
    for (const key of Object.keys(sum) as (keyof ViewCounts)[]) sum[key] += namespace.counts[key];
  }
  return sum;
}

function SummaryCards({ view }: { view: ClusterView }) {
  const withAgent = view.nodes.filter((node) => node.host).length;
  const ready = view.nodes.filter((node) => node.ready).length;
  const namespaces = view.namespaces.filter((namespace) => !namespace.system).length;
  // The cards count your namespaces and the cluster's own settings;
  // Kubernetes' own namespaces, hidden in the tree at first, are counted apart.
  const own = total(view.namespaces.filter((namespace) => !namespace.system));
  own.settings += view.findings.length;
  const system = total(view.namespaces.filter((namespace) => namespace.system));
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-5">
      <SummaryCard label="Nodes" value={view.nodes.length}>
        <span className={cx(ready === view.nodes.length && withAgent === view.nodes.length ? "text-emerald-700 dark:text-emerald-300" : "text-amber-700 dark:text-amber-300")}>
          {ready === view.nodes.length ? "all Ready" : `${ready} Ready`}, {withAgent === view.nodes.length ? "all with an agent" : `${withAgent} with an agent`}
        </span>
      </SummaryCard>
      <SummaryCard label="Namespaces" value={namespaces}>
        {view.pods} pods, {view.containers} containers
      </SummaryCard>
      <SummaryCard
        label="Critical / high"
        value={
          <>
            <span className="text-red-600 dark:text-red-300">{own.critical}</span>
            <span className="text-slate-400"> / </span>
            <span className="text-orange-600 dark:text-orange-300">{own.high}</span>
          </>
        }
      >
        {system.critical + system.high > 0
          ? `in your containers; ${system.critical} / ${system.high} more in Kubernetes' own`
          : "vulnerabilities in containers"}
      </SummaryCard>
      <SummaryCard label="Misconfigurations" value={<span className="text-amber-600 dark:text-amber-300">{own.settings}</span>}>
        settings to fix
      </SummaryCard>
      <SummaryCard
        label="Malware"
        value={<span className={own.malware + system.malware > 0 ? "text-red-600 dark:text-red-300" : "text-emerald-600 dark:text-emerald-300"}>{own.malware + system.malware}</span>}
      >
        in containers' files
      </SummaryCard>
    </div>
  );
}

function SummaryCard({ label, value, children }: { label: string; value: ReactNode; children: ReactNode }) {
  return (
    <div className="rounded-xl border border-slate-200 bg-white p-4 dark:border-slate-800 dark:bg-slate-900">
      <p className="text-xs text-slate-500 dark:text-slate-400">{label}</p>
      <p className="mt-1 text-2xl font-semibold">{value}</p>
      <p className="text-xs text-slate-500 dark:text-slate-400">{children}</p>
    </div>
  );
}

function hasProblems(counts: ViewCounts) {
  return counts.critical + counts.high + counts.medium + counts.low + counts.settings + counts.malware > 0;
}

/** The problems in a part of the cluster, worst first, on one line. */
export function ProblemsInline({ counts, clean = "no problems found" }: { counts: ViewCounts; clean?: string }) {
  const parts: ReactNode[] = [];
  if (counts.malware > 0) parts.push(<span key="m" className="font-semibold text-red-700 dark:text-red-300">{counts.malware} malware</span>);
  if (counts.critical > 0) parts.push(<span key="c" className="font-semibold text-red-600 dark:text-red-300">{counts.critical} critical</span>);
  if (counts.high > 0) parts.push(<span key="h" className="font-semibold text-orange-600 dark:text-orange-300">{counts.high} high</span>);
  if (counts.settings > 0)
    parts.push(
      <span key="s" className="text-amber-700 dark:text-amber-300">
        {counts.settings} {counts.settings === 1 ? "setting" : "settings"}
      </span>,
    );
  if (counts.medium > 0) parts.push(<span key="md" className="text-slate-600 dark:text-slate-300">{counts.medium} medium</span>);
  if (parts.length === 0) return <span className="text-emerald-700 dark:text-emerald-300">{clean}</span>;
  return (
    <span className="text-xs">
      {parts.map((part, index) => (
        <span key={index}>
          {index > 0 && <span className="text-slate-400"> · </span>}
          {part}
        </span>
      ))}
    </span>
  );
}

const kindStyle = "rounded px-1.5 py-0.5 text-[11px] font-medium whitespace-nowrap";

function Kind({ kind, tone = "slate" }: { kind: string; tone?: "violet" | "slate" | "faint" }) {
  return (
    <span
      className={cx(
        kindStyle,
        tone === "violet" && "bg-violet-50 font-semibold text-violet-700 dark:bg-violet-500/15 dark:text-violet-300",
        tone === "slate" && "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
        tone === "faint" && "bg-slate-50 text-slate-500 dark:bg-slate-800/60 dark:text-slate-400",
      )}
    >
      {kind}
    </span>
  );
}

function Toggle({ open, onClick, label }: { open: boolean; onClick: () => void; label: string }) {
  return (
    <button type="button" onClick={onClick} aria-expanded={open} aria-label={`${open ? "Collapse" : "Expand"} ${label}`} className="text-slate-400 hover:text-slate-700 dark:hover:text-slate-200">
      {open ? <ChevronDown className="size-4" /> : <ChevronRight className="size-4" />}
    </button>
  );
}

/** Whether text matches the filter, ignoring case. */
function matches(filter: string, ...texts: (string | undefined)[]) {
  const needle = filter.trim().toLowerCase();
  return needle === "" || texts.some((text) => text?.toLowerCase().includes(needle));
}

function WorkloadTree({ view }: { view: ClusterView }) {
  const [filter, setFilter] = useState("");
  const [onlyProblems, setOnlyProblems] = useState(true);
  const [system, setSystem] = useState(false);
  const [open, setOpen] = useState<Record<string, boolean>>(() => {
    // The namespace with the worst problems starts open.
    const first = view.namespaces.find((namespace) => !namespace.system && hasProblems(namespace.counts));
    return first ? { [first.name]: true } : {};
  });
  const toggle = (key: string) => setOpen((current) => ({ ...current, [key]: !current[key] }));
  const filtering = filter.trim() !== "";

  const namespaces = useMemo(
    () =>
      view.namespaces
        .filter((namespace) => system || !namespace.system || filtering)
        .map((namespace) => {
          const nameMatches = matches(filter, namespace.name);
          const workloads = namespace.workloads.filter(
            (workload) =>
              (!onlyProblems || hasProblems(workload.counts)) &&
              (nameMatches ||
                matches(filter, workload.name, workload.kind) ||
                workload.pods.some((pod) => matches(filter, pod.name, pod.node) || pod.containers.some((container) => matches(filter, container.name, container.image)))),
          );
          return { namespace, workloads, visible: (nameMatches || workloads.length > 0) && (!onlyProblems || hasProblems(namespace.counts) || filtering) };
        })
        .filter((item) => item.visible),
    [view, filter, onlyProblems, system, filtering],
  );
  const hidden = view.namespaces.filter((namespace) => !namespace.system && !hasProblems(namespace.counts)).map((namespace) => namespace.name);

  if (!view.inventory) {
    return <ClusterFindings findings={view.namespaces.flatMap((namespace) => [...namespace.findings, ...namespace.workloads.flatMap((workload) => workload.findings)])} />;
  }
  return (
    <>
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2 text-sm">
        <div className="w-full sm:w-72">
          <SearchBox value={filter} onChange={setFilter} placeholder="Filter namespaces, pods, images…" label="Filter the workloads" />
        </div>
        <label className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
          <input type="checkbox" className="accent-indigo-600" checked={onlyProblems} onChange={(event) => setOnlyProblems(event.target.checked)} /> Only with
          problems
        </label>
        <label className="flex items-center gap-1.5 text-slate-600 dark:text-slate-300">
          <input type="checkbox" className="accent-indigo-600" checked={system} onChange={(event) => setSystem(event.target.checked)} /> Show Kubernetes'
          own namespaces
        </label>
      </div>
      <Card className="mt-3 overflow-x-auto">
        <div className="min-w-[760px] text-sm">
          <div className="grid grid-cols-[minmax(0,1fr)_200px_240px] border-b border-slate-200 px-5 py-2.5 text-xs font-medium tracking-wider text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
            <span>Namespace / workload / pod / container</span>
            <span>Where</span>
            <span>Problems</span>
          </div>
          {namespaces.length === 0 && <p className="px-5 py-6 text-slate-500 dark:text-slate-400">Nothing matches.</p>}
          {namespaces.map(({ namespace, workloads }) => (
            <NamespaceRows
              key={namespace.name}
              namespace={namespace}
              workloads={workloads}
              open={open[namespace.name] || filtering}
              isOpen={(key) => open[key] || filtering}
              toggle={toggle}
            />
          ))}
          {onlyProblems && !filtering && hidden.length > 0 && (
            <div className="grid grid-cols-[minmax(0,1fr)_200px_240px] px-5 py-3 text-slate-500 dark:text-slate-400">
              <button type="button" className="text-left hover:text-slate-800 dark:hover:text-slate-200" onClick={() => setOnlyProblems(false)}>
                {hidden.join(", ")}: no problems found
              </button>
              <span />
              <span className="text-xs text-emerald-700 dark:text-emerald-300">clean</span>
            </div>
          )}
          {view.pods_left_out ? (
            <p className="px-5 py-3 text-xs text-slate-500 dark:text-slate-400">
              {view.pods_left_out} more pods aren't listed: a scan keeps the first 5000, to stay light.
            </p>
          ) : null}
        </div>
      </Card>
    </>
  );
}

const row = "grid grid-cols-[minmax(0,1fr)_200px_240px] items-start gap-2 border-b border-slate-100 px-5 py-2.5 dark:border-slate-800/70";

function NamespaceRows({
  namespace,
  workloads,
  open,
  isOpen,
  toggle,
}: {
  namespace: ClusterNamespaceView;
  workloads: ClusterWorkloadView[];
  open: boolean;
  isOpen: (key: string) => boolean;
  toggle: (key: string) => void;
}) {
  return (
    <>
      <div className={cx(row, "py-3")}>
        <span className="flex min-w-0 items-center gap-2">
          <Toggle open={open} onClick={() => toggle(namespace.name)} label={`namespace ${namespace.name}`} />
          <Kind kind="Namespace" tone="violet" />
          <span className="truncate font-semibold">{namespace.name}</span>
          <span className="text-xs whitespace-nowrap text-slate-500 dark:text-slate-400">
            {namespace.workloads.length} {namespace.workloads.length === 1 ? "workload" : "workloads"} · {namespace.pods} {namespace.pods === 1 ? "pod" : "pods"}
          </span>
        </span>
        <span />
        <ProblemsInline counts={namespace.counts} clean="clean" />
      </div>
      {open && (
        <>
          {namespace.findings.map((finding) => (
            <FindingRow key={finding.rule + finding.title} finding={finding} indent="pl-11" />
          ))}
          {workloads.map((workload) => {
            const key = `${namespace.name}/${workload.kind}/${workload.name}`;
            // A pod no controller runs is its own workload: one row, not two.
            if (workload.kind === "Pod" && workload.pods.length === 1) {
              return <PodRows key={key} pod={workload.pods[0]} findings={workload.findings} counts={workload.counts} open={isOpen(key)} toggle={() => toggle(key)} indent="pl-6" />;
            }
            return <WorkloadRows key={key} workload={workload} open={isOpen(key)} isOpen={isOpen} toggle={toggle} id={key} />;
          })}
        </>
      )}
    </>
  );
}

function WorkloadRows({
  workload,
  open,
  isOpen,
  toggle,
  id,
}: {
  workload: ClusterWorkloadView;
  open: boolean;
  isOpen: (key: string) => boolean;
  toggle: (key: string) => void;
  id: string;
}) {
  return (
    <>
      <div className={row}>
        <span className="flex min-w-0 items-center gap-2 pl-6">
          <Toggle open={open} onClick={() => toggle(id)} label={`${workload.kind} ${workload.name}`} />
          <Kind kind={workload.kind} />
          <span className="truncate font-medium">{workload.name}</span>
          <span className="text-xs whitespace-nowrap text-slate-500 dark:text-slate-400">
            {workload.pods.length} {workload.pods.length === 1 ? "pod" : "pods"}
          </span>
        </span>
        <span />
        <ProblemsInline counts={workload.counts} clean="clean" />
      </div>
      {open && (
        <>
          {workload.findings.map((finding) => (
            <FindingRow key={finding.rule + finding.title} finding={finding} indent="pl-[4.25rem]" />
          ))}
          {workload.pods.map((pod) => {
            const key = `${id}/${pod.name}`;
            return <PodRows key={key} pod={pod} open={isOpen(key)} toggle={() => toggle(key)} />;
          })}
        </>
      )}
    </>
  );
}

function PodRows({
  pod,
  open,
  toggle,
  findings = [],
  counts = pod.counts,
  indent = "pl-12",
}: {
  pod: ClusterPodView;
  open: boolean;
  toggle: () => void;
  findings?: CheckFinding[];
  counts?: ViewCounts;
  indent?: string;
}) {
  return (
    <>
      <div className={row}>
        <span className={cx("flex min-w-0 items-center gap-2", indent)}>
          <Toggle open={open} onClick={toggle} label={`pod ${pod.name}`} />
          <Kind kind="Pod" />
          <span className="truncate">{pod.name}</span>
          {pod.phase && (
            <span
              className={cx(
                "rounded-full px-1.5 text-[11px] whitespace-nowrap",
                pod.phase === "Running" || pod.phase === "Succeeded"
                  ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
                  : "bg-amber-50 text-amber-800 dark:bg-amber-500/15 dark:text-amber-300",
              )}
            >
              {pod.phase}
            </span>
          )}
        </span>
        <span className="truncate text-xs">
          {pod.node_host_id ? (
            <Link to={`/hosts/${pod.node_host_id}`} className="text-indigo-600 hover:underline dark:text-indigo-400">
              {pod.node}
            </Link>
          ) : (
            <span className="text-slate-500 dark:text-slate-400">{pod.node || "not scheduled"}</span>
          )}
        </span>
        <span className="text-xs">
          <ProblemsInline counts={counts} clean="clean" />
          {pod.restarts > 0 && <span className="text-slate-500 dark:text-slate-400"> · {pod.restarts} restarts</span>}
        </span>
      </div>
      {open && findings.map((finding) => <FindingRow key={finding.rule + finding.title} finding={finding} indent="pl-[4.25rem]" />)}
      {open && pod.containers.map((container) => <ContainerRow key={container.name} container={container} />)}
    </>
  );
}

function ContainerRow({ container }: { container: ClusterContainerView }) {
  return (
    <>
      <div className={row}>
        <span className="flex min-w-0 items-center gap-2 pl-[5.5rem]">
          <span className="text-slate-300 dark:text-slate-600" aria-hidden>
            •
          </span>
          <Kind kind={container.init ? "Init container" : "Container"} tone="faint" />
          <span>{container.name}</span>
          <span className="truncate font-mono text-xs text-slate-500 dark:text-slate-400" title={container.digest ? `${container.image}@${container.digest}` : container.image}>
            {container.image}
          </span>
        </span>
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {container.checked === "node"
            ? "checked by its node's agent"
            : container.checked === "image"
              ? "its image checked"
              : "not checked yet"}
          {container.reason && <span className="block text-amber-700 dark:text-amber-300">{container.reason}</span>}
        </span>
        <span className="text-xs">
          {container.checked ? <ProblemsInline counts={container.counts} clean="no vulnerabilities" /> : <span className="text-slate-400">—</span>}
          {container.counts.fixable > 0 && <span className="text-slate-500 dark:text-slate-400"> · {container.counts.fixable} fixed by a newer build</span>}
        </span>
      </div>
      {container.malware?.map((finding) => (
        <div key={finding.title + finding.evidence} className={cx(row, "bg-red-50/60 dark:bg-red-500/[0.06]")}>
          <span className="flex min-w-0 items-start gap-2 pl-[7rem] text-red-800 dark:text-red-200">
            <Bug className="mt-0.5 size-3.5 shrink-0" aria-hidden />
            <span>
              {finding.title.replace(`${container.name}: `, "")}
              <span className="block font-mono text-xs opacity-80">{finding.evidence}</span>
            </span>
          </span>
          <span />
          <span>
            <SeverityBadge severity={finding.severity} />
          </span>
        </div>
      ))}
    </>
  );
}

function FindingRow({ finding, indent }: { finding: CheckFinding; indent: string }) {
  const [open, setOpen] = useState(false);
  return (
    <div className={cx(row, "bg-amber-50/40 dark:bg-amber-500/[0.04]")}>
      <span className={cx("min-w-0", indent)}>
        <button type="button" className="text-left hover:underline" onClick={() => setOpen(!open)} aria-expanded={open}>
          {finding.title}
        </button>
        {open && finding.detail && <span className="mt-1 block text-xs text-slate-600 dark:text-slate-300">{finding.detail}</span>}
      </span>
      <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{finding.rule}</span>
      <span>
        <SeverityBadge severity={finding.severity} />
      </span>
    </div>
  );
}

function NodeTable({ view }: { view: ClusterView }) {
  if (!view.inventory) {
    return <p className="text-sm text-slate-500 dark:text-slate-400">Upgrade the cluster agent to 1.21.0 or later to list the nodes.</p>;
  }
  return (
    <Card>
      <Table>
        <thead>
          <tr>
            <Th>Node</Th>
            <Th>Status</Th>
            <Th>System</Th>
            <Th>Node agent</Th>
            <Th>Problems</Th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
          {view.nodes.map((node) => (
            <tr key={node.name}>
              <Td>
                {node.host ? (
                  <Link to={`/hosts/${node.host.id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
                    {node.name}
                  </Link>
                ) : (
                  <span className="font-medium">{node.name}</span>
                )}
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {[node.roles?.join(", ") || "worker", node.address, `${node.pods} ${node.pods === 1 ? "pod" : "pods"}`].filter(Boolean).join(" · ")}
                </p>
              </Td>
              <Td>
                <span
                  className={cx(
                    "rounded-full px-2 py-0.5 text-xs font-medium",
                    node.ready
                      ? "bg-emerald-50 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
                      : "bg-red-50 text-red-700 dark:bg-red-500/15 dark:text-red-300",
                  )}
                >
                  {node.ready ? "Ready" : "Not ready"}
                </span>
              </Td>
              <Td className="text-xs text-slate-600 dark:text-slate-300">
                {node.os_image}
                <p className="text-slate-500 dark:text-slate-400">{[node.kernel && `kernel ${node.kernel}`, node.runtime].filter(Boolean).join(" · ")}</p>
              </Td>
              <Td className="text-xs">
                {node.host ? (
                  <>
                    <AgentStatus online={agentOnline(node.host)} lastSeen={node.host.agent?.last_seen_at} disconnected={!!node.host.disconnected} />
                    <p className="font-mono text-slate-500 dark:text-slate-400">{node.host.agent?.version}</p>
                  </>
                ) : (
                  <span className="text-slate-500 dark:text-slate-400">none: turn on agent.enabled in the chart</span>
                )}
              </Td>
              <Td className="text-xs">
                {node.host ? (
                  node.host.checks?.packages ? (
                    <ProblemsInline counts={node.counts} clean="no vulnerabilities" />
                  ) : (
                    <span className="text-slate-500 dark:text-slate-400">packages not scanned yet</span>
                  )
                ) : (
                  <span className="text-slate-400">—</span>
                )}
                {node.host?.last_scan && <p className="text-slate-500 dark:text-slate-400">scanned {timeAgo(node.host.last_scan.started_at)}</p>}
              </Td>
            </tr>
          ))}
        </tbody>
      </Table>
    </Card>
  );
}

function ImageTable({ view }: { view: ClusterView }) {
  const [filter, setFilter] = useState("");
  const images = view.images.filter((image) => matches(filter, image.image, ...(image.namespaces ?? [])));
  return (
    <>
      <div className="w-full sm:w-72">
        <SearchBox value={filter} onChange={setFilter} placeholder="Filter images, namespaces…" label="Filter the images" />
      </div>
      <Card className="mt-3">
        <Table>
          <thead>
            <tr>
              <Th>Image</Th>
              <Th>Run by</Th>
              <Th>Checked</Th>
              <Th>Vulnerabilities</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {images.map((image) => (
              <tr key={image.image + (image.digest ?? "")}>
                <Td>
                  <span className="font-mono text-xs break-all">{image.image}</span>
                  {image.digest && <p className="font-mono text-xs text-slate-500 dark:text-slate-400">{image.digest.slice(0, 19)}</p>}
                </Td>
                <Td className="text-xs text-slate-600 dark:text-slate-300">
                  {image.pods} {image.pods === 1 ? "pod" : "pods"} in {(image.namespaces ?? []).join(", ")}
                </Td>
                <Td className="text-xs text-slate-500 dark:text-slate-400">
                  {image.checked === "node" ? "by a node's agent" : image.checked === "image" ? "from its registry" : "not yet"}
                </Td>
                <Td>
                  {image.checked ? <ProblemsInline counts={image.counts} clean="no vulnerabilities" /> : <span className="text-slate-400">—</span>}
                  {image.counts.fixable > 0 && <p className="text-xs text-slate-500 dark:text-slate-400">{image.counts.fixable} fixed by a newer build</p>}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
    </>
  );
}

function ClusterFindings({ findings }: { findings: CheckFinding[] }) {
  if (findings.length === 0) {
    return <p className="text-sm text-emerald-700 dark:text-emerald-300">Nothing to fix in the cluster's own settings.</p>;
  }
  return (
    <Card>
      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
        {findings.map((finding) => (
          <li key={finding.rule + finding.title} className="flex gap-3 px-5 py-3 text-sm">
            <SeverityBadge severity={finding.severity} />
            <div className="min-w-0">
              <p className="font-medium">{finding.title}</p>
              {finding.detail && <p className="mt-0.5 text-slate-600 dark:text-slate-300">{finding.detail}</p>}
              <p className="mt-0.5 font-mono text-xs text-slate-500 dark:text-slate-400">{finding.rule}</p>
            </div>
          </li>
        ))}
      </ul>
    </Card>
  );
}
