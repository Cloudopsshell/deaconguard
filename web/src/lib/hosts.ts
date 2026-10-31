import { createElement } from "react";
import type { HostSummary } from "../api";

/** An agent is online if it checked in recently; it asks for work every 25 seconds. */
const onlineWindowMs = 90_000;

export function agentOnline(host: HostSummary): boolean {
  if (!host.agent || host.disconnected) return false;
  return Date.now() - new Date(host.agent.last_seen_at).getTime() < onlineWindowMs;
}

/** How a host is scanned, for page subtitles. */
export function connectionLabel(host: HostSummary): string {
  if (host.transport === "local") return `This machine · scans run locally as ${host.username}`;
  const agent = host.agent;
  if (host.kind === "cluster") {
    return `Kubernetes cluster · DeaconGuard cluster agent, read-only${agent?.version ? ` · agent ${agent.version}` : ""}${agent?.remote ? ` · from ${agent.remote}` : ""}`;
  }
  return `DeaconGuard agent · runs as ${host.username}${agent?.version ? ` · agent ${agent.version}` : ""}${agent?.remote ? ` · from ${agent.remote}` : ""}`;
}

/** Marks the machine the DeaconGuard server runs on. */
export function ThisServerBadge() {
  return createElement(
    "span",
    {
      // One piece: it moves to the next line as a whole, never breaks inside.
      className:
        "inline-flex shrink-0 items-center rounded-full bg-indigo-50 px-2 py-0.5 text-xs font-medium whitespace-nowrap text-indigo-700 ring-1 ring-indigo-600/20 ring-inset dark:bg-indigo-500/15 dark:text-indigo-300 dark:ring-indigo-400/30",
      title: "The machine the DeaconGuard server runs on. Its own agent scans it as root; the server itself runs without root.",
    },
    "This server",
  );
}

/** A short label for lists. */
export function shortConnectionLabel(host: HostSummary): string {
  if (host.transport === "local") return `this machine · as ${host.username}`;
  return "agent";
}

/** A host for lists, with the nodes of a cluster under it. */
export interface HostGroup {
  host: HostSummary;
  nodes: HostSummary[];
}

/**
 * Groups hosts for lists: each Kubernetes cluster is one entry, its nodes'
 * hosts under it. A node whose cluster isn't in the list stays on its own.
 */
export function groupByCluster(hosts: HostSummary[]): HostGroup[] {
  const clusters = new Set(hosts.filter((host) => host.kind === "cluster").map((host) => host.id));
  const nodes = new Map<string, HostSummary[]>();
  for (const host of hosts) {
    if (host.cluster_id && clusters.has(host.cluster_id)) {
      nodes.set(host.cluster_id, [...(nodes.get(host.cluster_id) ?? []), host]);
    }
  }
  return hosts
    .filter((host) => !(host.cluster_id && clusters.has(host.cluster_id)))
    .map((host) => ({ host, nodes: (nodes.get(host.id) ?? []).sort((a, b) => a.address.localeCompare(b.address)) }));
}

const badge =
  "inline-flex shrink-0 items-center rounded-md px-1.5 py-0.5 text-[11px] font-semibold whitespace-nowrap ring-1 ring-inset";

/** Marks a Kubernetes cluster. */
export function ClusterBadge() {
  return createElement(
    "span",
    { className: cx(badge, "bg-sky-50 text-sky-700 ring-sky-600/20 dark:bg-sky-500/15 dark:text-sky-300 dark:ring-sky-400/30"), title: "A Kubernetes cluster, scanned by its cluster agent" },
    "Kubernetes",
  );
}

/** Marks a node of a cluster. */
export function NodeBadge() {
  return createElement(
    "span",
    { className: cx(badge, "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300 dark:ring-slate-600/40"), title: "A node of the cluster above, scanned by its node agent" },
    "Node",
  );
}

/** Says why a disconnected host's agent may no longer connect. */
export function disconnectedText(host: HostSummary): string {
  const disconnected = host.disconnected;
  if (!disconnected) return "";
  return `Disconnected ${new Date(disconnected.at).toLocaleString()}${disconnected.by ? ` by ${disconnected.by}` : ""}: ${disconnected.reason}.`;
}

function cx(...classes: (string | false | null | undefined)[]) {
  return classes.filter(Boolean).join(" ");
}
