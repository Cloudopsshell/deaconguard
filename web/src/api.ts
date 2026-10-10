// Types mirror the JSON returned by internal/server and internal/store.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type ScanStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "needs_sudo";

export type CheckId = "packages" | "integrity" | "malware" | "config" | "antivirus" | "yara";
export type CheckStatus = "completed" | "partial" | "skipped" | "failed";

export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
}

export interface Host {
  id: string;
  address: string;
  username: string;
  allow_sudo: boolean;
  /** "local" is the machine DeaconGuard runs on; "agent" machines run the DeaconGuard agent and
   * enrolled with this server. */
  transport: "local" | "agent";
}

export interface AgentInfo {
  enrolled_at: string;
  last_seen_at: string;
  version: string;
  os: string;
  remote: string;
}

export interface Capabilities {
  local_scanning: boolean;
  local_reason?: string;
  hostname: string;
  username: string;
  /** Agents can enroll: the server runs on the network. */
  agents: boolean;
}

export interface Session {
  /** False when DeaconGuard serves only this machine at localhost, without accounts. */
  login_required: boolean;
  authenticated: boolean;
  username?: string;
}

export interface EnrollmentToken {
  id: string;
  server_url: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  used_at: string | null;
  host_id: string | null;
  revoked_at: string | null;
  status: "active" | "used" | "expired" | "revoked";
}

/** Returned once, when a token is created: the only copy of the token. */
export interface NewEnrollmentToken extends EnrollmentToken {
  token: string;
  command: string;
}

export interface AuditEntry {
  id: number;
  at: string;
  actor: string;
  action: string;
  target: string;
  detail: string;
  remote: string;
}

export interface Scan {
  id: string;
  host_id: string;
  address: string;
  status: ScanStatus;
  error?: string;
  started_at: string;
  finished_at: string | null;
  os: string;
  finding_count: number;
  unsupported_count: number;
  severity: SeverityCounts;
  feed_stale: boolean;
  checks: CheckId[];
  has_log: boolean;
}

export interface CheckSummary {
  check: CheckId;
  scan_id: string;
  scanned_at: string;
  status: CheckStatus;
  privileged: boolean;
  summary: string;
  finding_count: number;
  severity: SeverityCounts;
}

export interface HostSummary extends Host {
  last_scan: Scan | null;
  /** Newest successful scan that checked packages. */
  last_report: Scan | null;
  /** Newest successful result of each check run on this host. */
  checks: Partial<Record<CheckId, CheckSummary>> | null;
  /** Set for agent hosts. */
  agent?: AgentInfo;
}

export interface HostDetail extends HostSummary {
  scans: Scan[];
}

export interface Finding {
  id: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  severity: Severity;
  url: string;
  title: string;
}

export interface UnsupportedRule {
  id: string;
  title: string;
  reason: string;
}

export interface CheckFinding {
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  evidence: string;
}

export interface CheckResult {
  status: CheckStatus;
  privileged: boolean;
  summary: string;
  notes: string[] | null;
  error?: string;
  findings: CheckFinding[] | null;
}

export type LogLevel = "info" | "warning" | "error";

/** One line of the server's or an agent's log. */
export interface LogEntry {
  id: number;
  at: string;
  source: "server" | "agent";
  host_id?: string;
  host?: string;
  level: LogLevel;
  message: string;
}

export interface LogFilters {
  source?: "server" | "agent";
  host?: string;
  /** The least severe level shown: warning means warnings and errors. */
  level?: LogLevel;
  q?: string;
  before?: number;
  limit?: number;
}

export interface LogPage {
  entries: LogEntry[];
  more: boolean;
}

function logParameters(filters: LogFilters) {
  const parameters = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== "") parameters.set(key, String(value));
  }
  return parameters.toString();
}

/** Downloads the matching log entries as a text file. */
export function logDownloadUrl(filters: LogFilters) {
  return `/api/logs/download?${logParameters({ ...filters, before: undefined, limit: undefined })}`;
}

/** How the previous run of the server ended. */
export interface ServerStop {
  kind: "stopped" | "reboot" | "out_of_memory" | "crashed" | "killed" | "unknown";
  message: string;
  started_at: string;
  /** When the next run found out; close to the restart. */
  detected_at: string;
  stopped_at?: string;
  version?: string;
  /** The start of a crash report. */
  detail?: string;
}

export interface ServerStatus {
  last_stop: ServerStop | null;
}

export interface CheckDefinition {
  id: CheckId;
  name: string;
  description: string;
  sudo: "none" | "recommended";
  default: boolean;
  warning?: string;
}

export interface CheckTotals {
  hosts: number;
  hosts_with_findings: number;
  incomplete: number;
  /** Hosts where the check was skipped or failed, so nothing was examined. */
  not_run: number;
  findings: number;
  severity: SeverityCounts;
}

/** Fields from the package check are absent when a scan did not include it. */
export interface Report {
  report_id: string;
  os: string;
  scanned_at: string;
  checks_run?: CheckId[];
  check_results?: Partial<Record<CheckId, CheckResult>>;
  finding_count: number;
  findings: Finding[] | null;
  unsupported_count: number;
  unsupported_cves: UnsupportedRule[] | null;
  coverage: string;
  maintenance: string;
  package_manager: string;
  advisory_database: {
    source: string;
    fetched_at: string;
    feed_stale: boolean;
    feed_age_hours: number;
    feed_refresh_error?: string;
  };
}

export interface ScanDetail {
  scan: Scan;
  report: Report | null;
}

export interface Vulnerability {
  cve: string;
  severity: Severity;
  title: string;
  url: string;
  host_count: number;
  packages: string[];
}

export interface AffectedPackage {
  host_id: string;
  address: string;
  scan_id: string;
  scanned_at: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  severity: Severity;
  url: string;
  title: string;
}

export interface Summary {
  hosts: number;
  scanned_hosts: number;
  attention_hosts: number;
  findings: number;
  unique_cves: number;
  unsupported: number;
  stale_feeds: number;
  severity: SeverityCounts;
  host_summaries: HostSummary[];
  top_vulnerabilities: Vulnerability[];
  checks: Partial<Record<CheckId, CheckTotals>>;
}

/** A question a paused scan is waiting for the user to answer. */
export interface Prompt {
  scan_id: string;
  host_id: string;
  address: string;
  username: string;
  kind: "sudo";
  retry?: string;
  created_at: string;
}

/** A running or recently finished scan shown in the live console. */
export interface Activity {
  scan_id: string;
  host_id: string;
  address: string;
  username: string;
  checks: CheckId[];
  started_at: string;
  finished_at?: string;
  status: ScanStatus;
}

/** One line of a scan's live log. It never contains command output or credentials. */
export interface ScanEvent {
  seq: number;
  time: string;
  kind: "phase" | "command" | "result" | "info" | "success" | "warning" | "error" | "finding" | "prompt" | "done";
  phase?: string;
  message: string;
  sudo?: boolean;
  status?: string;
  severity?: Severity;
}

export interface NewHost {
  transport: "local";
  allow_sudo: boolean;
}

export class ApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
  ) {
    super(message);
  }
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const init: RequestInit = { method, headers: {} };
  if (method === "POST" || method === "PATCH") {
    init.headers = { "Content-Type": "application/json" };
    init.body = JSON.stringify(body ?? {});
  }
  const response = await fetch(path, init);
  const payload = await response.json().catch(() => null);
  if (response.status === 401 && path !== "/api/login" && window.location.pathname !== "/login") {
    // The session expired or was signed out elsewhere.
    const next = window.location.pathname + window.location.search;
    window.location.assign(`/login?next=${encodeURIComponent(next)}`);
  }
  if (!response.ok) {
    throw new ApiError(payload?.error ?? `Request failed with HTTP ${response.status}`, response.status);
  }
  return payload as T;
}

export const api = {
  session: () => request<Session>("GET", "/api/session"),
  login: (username: string, password: string) => request<Session>("POST", "/api/login", { username, password }),
  logout: () => request<{ ok: boolean }>("POST", "/api/logout"),
  enrollmentTokens: () => request<EnrollmentToken[]>("GET", "/api/enrollment-tokens"),
  createEnrollmentToken: (serverUrl: string) =>
    request<NewEnrollmentToken>("POST", "/api/enrollment-tokens", { server_url: serverUrl }),
  revokeEnrollmentToken: (id: string) => request<EnrollmentToken>("DELETE", `/api/enrollment-tokens/${id}`),
  audit: () => request<AuditEntry[]>("GET", "/api/audit?limit=500"),
  summary: () => request<Summary>("GET", "/api/summary"),
  hosts: () => request<HostSummary[]>("GET", "/api/hosts"),
  host: (id: string) => request<HostDetail>("GET", `/api/hosts/${id}`),
  addHost: (host: NewHost) => request<Host>("POST", "/api/hosts", host),
  removeHost: (id: string) => request<Host>("DELETE", `/api/hosts/${id}`),
  checks: () => request<CheckDefinition[]>("GET", "/api/checks"),
  capabilities: () => request<Capabilities>("GET", "/api/capabilities"),
  serverStatus: () => request<ServerStatus>("GET", "/api/server-status"),
  logs: (filters: LogFilters) => request<LogPage>("GET", `/api/logs?${logParameters(filters)}`),
  version: () => request<{ version: string; commit?: string; date?: string }>("GET", "/api/version"),
  setAllowSudo: (hostId: string, allow: boolean) => request<Host>("PATCH", `/api/hosts/${hostId}`, { allow_sudo: allow }),
  startScan: (hostId: string, checks: CheckId[]) => request<Scan>("POST", `/api/hosts/${hostId}/scans`, { checks }),
  prompts: () => request<Prompt[]>("GET", "/api/prompts"),
  activity: () => request<Activity[]>("GET", "/api/activity"),
  respond: (scanId: string, answer: { value?: string; cancel?: boolean }) =>
    request<{ ok: boolean }>("POST", `/api/scans/${scanId}/respond`, answer),
  scan: (id: string) => request<ScanDetail>("GET", `/api/scans/${id}`),
  deleteScan: (id: string) => request<{ ok: boolean }>("DELETE", `/api/scans/${id}`),
  vulnerabilities: () => request<Vulnerability[]>("GET", "/api/vulnerabilities"),
  vulnerability: (cve: string) =>
    request<AffectedPackage[]>("GET", `/api/vulnerabilities/${encodeURIComponent(cve)}`),
};
