import type { Host, HostSummary } from "../api";

/** An agent is online if it checked in recently; it asks for work every 25 seconds. */
const onlineWindowMs = 90_000;

export function agentOnline(host: HostSummary): boolean {
  if (!host.agent) return false;
  return Date.now() - new Date(host.agent.last_seen_at).getTime() < onlineWindowMs;
}

/** Whether DeaconGuard can scan the host now; SSH hosts from before 0.2.0 cannot. */
export function scannable(host: Host): boolean {
  return host.transport === "local" || host.transport === "agent";
}

/** How a host is scanned, for page subtitles. */
export function connectionLabel(host: HostSummary): string {
  if (host.transport === "local") return `This machine · scans run locally as ${host.username}`;
  if (host.transport === "agent") {
    const agent = host.agent;
    return `DeaconGuard agent · runs as ${host.username}${agent?.version ? ` · agent ${agent.version}` : ""}${agent?.remote ? ` · from ${agent.remote}` : ""}`;
  }
  return `${host.username}@${host.address} · SSH host · scanning removed in 0.2.0, earlier results kept`;
}

/** A short label for lists. */
export function shortConnectionLabel(host: HostSummary): string {
  if (host.transport === "local") return `this machine · as ${host.username}`;
  if (host.transport === "agent") return "agent";
  return "SSH host · scanning removed";
}
