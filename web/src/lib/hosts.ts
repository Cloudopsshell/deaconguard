import { createElement } from "react";
import type { HostSummary } from "../api";

/** An agent is online if it checked in recently; it asks for work every 25 seconds. */
const onlineWindowMs = 90_000;

export function agentOnline(host: HostSummary): boolean {
  if (!host.agent) return false;
  return Date.now() - new Date(host.agent.last_seen_at).getTime() < onlineWindowMs;
}

/** How a host is scanned, for page subtitles. */
export function connectionLabel(host: HostSummary): string {
  if (host.transport === "local") return `This machine · scans run locally as ${host.username}`;
  const agent = host.agent;
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
