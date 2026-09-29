// Types mirror the JSON returned by internal/server and internal/store.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type ScanStatus =
  | "running"
  | "succeeded"
  | "failed"
  | "needs_trust"
  | "needs_passphrase"
  | "needs_password"
  | "needs_sudo";

export type CheckId = "packages" | "integrity" | "malware" | "config" | "antivirus";
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
  port: number;
  key_path: string | null;
  allow_sudo: boolean;
}

export interface Scan {
  id: string;
  host_id: string;
  address: string;
  status: ScanStatus;
  error?: string;
  host_key_fingerprint?: string;
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
  port: number;
  kind: "host_key" | "passphrase" | "password" | "sudo";
  key_path?: string;
  fingerprint?: string;
  retry?: string;
  created_at: string;
}

/** A running or recently finished scan shown in the live console. */
export interface Activity {
  scan_id: string;
  host_id: string;
  address: string;
  username: string;
  port: number;
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
  address: string;
  username: string;
  port: number;
  key_path: string;
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
  if (!response.ok) {
    throw new ApiError(payload?.error ?? `Request failed with HTTP ${response.status}`, response.status);
  }
  return payload as T;
}

export const api = {
  summary: () => request<Summary>("GET", "/api/summary"),
  hosts: () => request<HostSummary[]>("GET", "/api/hosts"),
  host: (id: string) => request<HostDetail>("GET", `/api/hosts/${id}`),
  addHost: (host: NewHost) => request<Host>("POST", "/api/hosts", host),
  removeHost: (id: string) => request<Host>("DELETE", `/api/hosts/${id}`),
  checks: () => request<CheckDefinition[]>("GET", "/api/checks"),
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
