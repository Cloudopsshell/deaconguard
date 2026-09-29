import type { Host } from "../api";

/** How a host is scanned, for page subtitles. */
export function connectionLabel(host: Host): string {
  if (host.transport === "local") return `This machine · scans run locally as ${host.username}`;
  return `${host.username}@${host.address} · SSH host · scanning removed in 0.2.0, earlier results kept`;
}

/** A short label for lists. */
export function shortConnectionLabel(host: Host): string {
  return host.transport === "local" ? `this machine · as ${host.username}` : "SSH host · scanning removed";
}
