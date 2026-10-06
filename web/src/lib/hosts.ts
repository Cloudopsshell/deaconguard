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

/** A short label for lists. */
export function shortConnectionLabel(host: HostSummary): string {
  if (host.transport === "local") return `this machine · as ${host.username}`;
  return "agent";
}
