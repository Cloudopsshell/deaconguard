import type { Host } from "../api";

/** How a host is reached, for page subtitles. */
export function connectionLabel(host: Host): string {
  if (host.transport === "local") return `This machine · scans run locally as ${host.username}`;
  const key = host.key_path ? ` · key ${host.key_path}` : " · ssh-agent or default keys";
  return `${host.username}@${host.address}:${host.port}${key}`;
}

/** A short label for lists. */
export function shortConnectionLabel(host: Host): string {
  return host.transport === "local" ? `this machine · as ${host.username}` : `${host.username}@${host.address}:${host.port}`;
}
