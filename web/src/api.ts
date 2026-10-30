// Types mirror the JSON returned by internal/server and internal/store.

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";
export type ScanStatus =
  | "queued"
  | "running"
  | "succeeded"
  | "failed"
  | "needs_sudo";

export type CheckId = "packages" | "libraries" | "containers" | "integrity" | "malware" | "config" | "hardening" | "antivirus" | "yara" | "kubernetes";
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
  /** What the host is called: its display name, else its hostname. */
  address: string;
  /** What its machine calls itself, which its agent reports. */
  hostname: string;
  /** The display name given to it, if any (1.18.0 and later). */
  name: string;
  username: string;
  allow_sudo: boolean;
  /** "local" is the machine DeaconGuard runs on; "agent" machines run the DeaconGuard agent and
   * enrolled with this server. */
  transport: "local" | "agent";
  /** Scan the running containers when the agent sees new ones (1.2.0 and later). */
  auto_scan_containers?: boolean;
  /** "cluster" is a Kubernetes cluster enrolled with the cluster agent; it runs only the Kubernetes check (1.5.0 and later). */
  kind?: "machine" | "cluster" | "mac";
}

/** What the Kubernetes check read of a cluster. */
export interface ClusterInfo {
  name: string;
  version: string;
  nodes: number;
  architecture?: string;
  namespaces: number;
  workloads: number;
  images?: string[];
}

export interface AgentInfo {
  enrolled_at: string;
  last_seen_at: string;
  version: string;
  os: string;
  remote: string;
  /** The server port the agent last connected to. */
  port?: string;
}

export interface Capabilities {
  local_scanning: boolean;
  local_reason?: string;
  hostname: string;
  username: string;
  /** Agents can enroll: the server runs on the network. */
  agents: boolean;
  /** The port of the server's agent-only listener, if it has one. */
  agent_port?: string;
  /** The agents' address inside a Kubernetes cluster, set by the Helm chart. */
  cluster_agent_url?: string;
}

/** Admins manage accounts and machines, operators run scans, viewers see results. */
export type Role = "admin" | "operator" | "viewer";

export const roleLabels: Record<Role, string> = { admin: "Admin", operator: "Operator", viewer: "Viewer" };

export interface Session {
  /** False when DeaconGuard serves only this machine at localhost, without accounts. */
  login_required: boolean;
  authenticated: boolean;
  username?: string;
  /** The password was right; the second step is still needed. */
  mfa_pending?: boolean;
  /** The second steps the account can use: its authenticator app, its passkeys. */
  mfa_methods?: ("app" | "passkey")[];
  /** An admin set a temporary password, which must be changed first. */
  must_change_password?: boolean;
  /** Two-step sign-in is required for every account, and this one has none yet. */
  mfa_setup_required?: boolean;
  /** Signs in with more than a password: an authenticator app, a passkey, or both. */
  two_step?: boolean;
  /** Has an authenticator app. */
  mfa_enabled?: boolean;
  passkeys?: number;
  recovery_codes_left?: number;
  role?: Role;
  /** Single sign-on, offered on the sign-in page when it is set up. */
  sso?: { label: string };
  /** The account signs in with single sign-on and has no password. */
  sso_account?: boolean;
  /** The account's saved mode and theme, if it chose one. */
  appearance?: { mode: "system" | "light" | "dark"; theme: "indigo" | "ocean" | "teal" | "plum" | "graphite" };
}

/** A dashboard account. */
export interface Account {
  id: string;
  username: string;
  created_at: string;
  mfa_enabled: boolean;
  passkeys: number;
  /** Signs in with single sign-on, with no password. */
  sso: boolean;
  recovery_codes_left: number;
  must_change_password: boolean;
  disabled: boolean;
  last_login_at: string;
  role: Role;
}

/** One sign-in of the current account. */
export interface AccountSession {
  id: string;
  created_at: string;
  expires_at: string;
  last_seen_at: string;
  remote: string;
  user_agent: string;
  current: boolean;
}

export interface MyAccount extends Account {
  sessions: AccountSession[];
  /** Every account must use two-step sign-in. */
  mfa_required: boolean;
}

export interface EnrollmentToken {
  id: string;
  /** What a reusable token is for, such as a cluster's name. */
  name: string;
  /** Reusable tokens enroll any number of machines until they expire or are revoked. */
  reusable: boolean;
  /** How many machines the token has enrolled. */
  uses: number;
  server_url: string;
  created_by: string;
  created_at: string;
  expires_at: string;
  /** When a one-time token was used, or a reusable one last was. */
  used_at: string | null;
  /** The machine a one-time token enrolled. */
  host_id: string | null;
  revoked_at: string | null;
  status: "active" | "used" | "expired" | "revoked";
}

export interface NewTokenInput {
  server_url: string;
  reusable?: boolean;
  /** How many days a reusable token lasts, from 1 to 365. */
  days?: number;
  name?: string;
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
  /** Set when the scan checked packages. */
  fixes?: FixSummary;
  feed_stale: boolean;
  checks: CheckId[];
  has_log: boolean;
  /** A handover audit: every check, graded together. */
  audit: boolean;
  /** Package findings by what is known about them being exploited; all zero, with data false, before 0.16.0 or without KEV and EPSS data. */
  exploit?: ExploitCounts;
  /** Whether the release still got security fixes; missing before 0.19.0. */
  lifecycle?: Lifecycle;
}

/** Whether a release still gets security fixes from its vendor. */
export interface Lifecycle {
  state: "supported" | "extended" | "ended" | "unknown";
  /** When the current phase ends (or ended), as YYYY-MM or YYYY-MM-DD. */
  until?: string;
  note: string;
  /** The vendor's lifecycle page. */
  source?: string;
}

export interface ExploitCounts {
  /** In CISA's Known Exploited Vulnerabilities catalog. */
  known: number;
  known_fixable: number;
  /** EPSS of 10% or more. */
  likely: number;
  /** The scan had KEV or EPSS data, so zeros mean none. */
  data: boolean;
}

/** How urgently to fix a vulnerability: known exploited, likely exploited, critical or high, other. */
export type Priority = "exploited" | "likely" | "severe" | "other";

/** What is known about a CVE being exploited, from CISA KEV and FIRST EPSS. */
export interface Exploit {
  kev: boolean;
  kev_added?: string;
  kev_due?: string;
  ransomware?: boolean;
  /** Probability, 0 to 1, of exploitation in the next 30 days. */
  epss?: number;
  epss_percentile?: number;
}

export interface ExploitSource {
  available: boolean;
  version?: string;
  error?: string;
}

export interface TrendPoint {
  day: string;
  hosts: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  exploited: number;
  likely: number;
}

export type ChannelKind = "email" | "slack" | "teams" | "webhook" | "syslog" | "splunk" | "jira" | "servicenow";
export type NotificationEvent =
  | "exploited"
  | "critical"
  | "malware"
  | "integrity"
  | "cluster"
  | "exposure"
  | "config"
  | "image_report"
  | "scan_failed"
  | "scan_results"
  | "audit"
  | "agent_offline"
  | "digest";

/** A channel's settings. Saved secrets come back as "set" (password, secret) or the address's host (url); send them empty to keep them. */
export interface ChannelConfig {
  host?: string;
  port?: number;
  tls?: "starttls" | "tls" | "none";
  username?: string;
  password?: string;
  from?: string;
  to?: string[];
  url?: string;
  secret?: string;
  /** Syslog: tcp, tls or udp. */
  protocol?: "tcp" | "tls" | "udp";
  /** Splunk index. */
  index?: string;
  /** Jira project key and issue type. */
  project?: string;
  issue_type?: string;
  /** ServiceNow table. */
  table?: string;
}

/** Fix deadlines, in days from when a host first had a vulnerability. */
export interface SLA {
  enabled: boolean;
  exploited: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface MaintenanceWindow {
  id: string;
  name: string;
  tags: string[];
  starts_at: string;
  ends_at: string;
  skip_scans: boolean;
  created_by: string;
  created_at: string;
  status: "upcoming" | "active" | "ended";
}

export interface Delivery {
  id: number;
  channel_id: string;
  event: NotificationEvent | "test";
  title: string;
  status: "pending" | "sent" | "failed";
  attempts: number;
  next_attempt_at: string;
  error: string;
  created_at: string;
  sent_at: string;
}

export interface Channel {
  id: string;
  name: string;
  kind: ChannelKind;
  config: ChannelConfig;
  enabled: boolean;
  events: NotificationEvent[];
  tags: string[];
  digest: "" | "daily" | "weekly";
  digest_days: number[];
  digest_time: string;
  timezone: string;
  next_digest_at: string;
  created_by: string;
  last?: Delivery;
}

export interface ChannelInput {
  name: string;
  kind?: ChannelKind;
  config: ChannelConfig;
  enabled?: boolean;
  events: NotificationEvent[];
  tags: string[];
  digest: "" | "daily" | "weekly";
  digest_days: number[];
  digest_time: string;
  timezone: string;
}

/** A token for scripts and tools to use the API as an account. */
export interface APIToken {
  id: string;
  user_id: string;
  username: string;
  name: string;
  role: Role;
  created_at: string;
  /** Empty: lasts until revoked. */
  expires_at: string;
  last_used_at: string;
  last_used_from: string;
  revoked_at: string;
  status: "active" | "expired" | "revoked";
}

export interface TagCount {
  tag: string;
  hosts: number;
}

export type ControlStatus = "pass" | "fail" | "na" | "unknown" | "accepted";

/** A risk an admin accepted for a failed control, on one host or every host. */
export interface AuditException {
  id: string;
  host_id: string;
  control_id: string;
  reason: string;
  expires_at: string;
  created_by: string;
  created_at: string;
}

export interface AuditControl {
  id: string;
  category: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low";
  status: ControlStatus;
  evidence: string;
  rationale: string;
  remediation: string;
  exception?: AuditException;
}

export interface ControlCounts {
  passed: number;
  failed: number;
  accepted: number;
  not_applicable: number;
  unknown: number;
}

export interface Inventory {
  hostname: string;
  os: string;
  kernel: string;
  architecture: string;
  uptime_seconds: number;
  virtualization: string;
  cpus: number;
  memory_bytes: number;
  disks: { mount: string; size_bytes: number; used_bytes: number; used_percent: number }[] | null;
  addresses: string[] | null;
  packages: number;
  listening: { protocol: string; address: string; port: number; exposed: boolean }[] | null;
  login_users: string[] | null;
  administrators: string[] | null;
  timezone: string;
  time_synced: boolean;
}

export interface AuditSummary {
  grade: "A" | "B" | "C" | "D" | "F";
  score: number;
  caps: string[];
  incomplete: string[];
  counts: ControlCounts;
  categories: (ControlCounts & { name: string })[];
  controls: AuditControl[];
  inventory: Inventory | null;
  checks: { id: CheckId; name: string; status: CheckStatus; summary: string; findings: number; privileged: boolean }[];
  packages: FixSummary | null;
  severity: SeverityCounts;
  /** The admins' own controls; they don't change the grade. */
  policies: PolicyResult[];
}

export interface PolicyResult {
  id: string;
  name: string;
  counts: ControlCounts;
  controls: AuditControl[];
}

export type RequirementStatus = "met" | "met_accepted" | "not_met" | "not_checked" | "not_evaluated";

export interface Framework {
  id: string;
  name: string;
  short: string;
}

export interface ComplianceResult {
  framework: Framework;
  requirements: { id: string; name: string; status: RequirementStatus; controls: { id: string; title: string; status: ControlStatus }[] }[];
  met: number;
  not_met: number;
  other: number;
}

export interface Policy {
  id: string;
  name: string;
  source: string;
  enabled: boolean;
  created_by: string;
  created_at: string;
  updated_at: string;
  controls: number;
}

export interface AuditListItem extends Scan {
  grade?: AuditSummary["grade"];
  score: number;
  failed: number;
}

export interface AuditDetail {
  scan: Scan;
  host: Host;
  summary?: AuditSummary;
  compliance?: ComplianceResult[];
}

/** A frozen report of an audit or scan, downloadable in several formats. */
export interface ReportRecord {
  id: string;
  scan_id: string;
  host_id: string;
  kind: "audit" | "scan";
  client: string;
  created_by: string;
  created_at: string;
  fingerprint: string;
}

export type ReportFormat = "pdf" | "html" | "xlsx" | "csv" | "json";

/** A link that shows a report without sign-in until it expires. */
export interface ReportShare {
  id: string;
  report_id: string;
  expires_at: string;
  created_by: string;
  created_at: string;
  revoked_at: string;
  views: number;
}

export interface ReportBranding {
  company: string;
  contact: string;
  has_logo: boolean;
  logo_type?: string;
}

export interface VerifyResult {
  valid: boolean;
  message: string;
  report?: ReportRecord;
  host?: string;
  grade?: string;
}

export const reportDownloadUrl = (id: string, format: ReportFormat) => `/api/reports/${id}/download?format=${format}`;

export type SBOMFormat = "cyclonedx" | "spdx";

/** A scan's software bill of materials: every OS package and application library it found. */
export const sbomDownloadUrl = (scanId: string, format: SBOMFormat) => `/api/scans/${scanId}/sbom?format=${format}`;

export interface CheckSummary {
  check: CheckId;
  scan_id: string;
  scanned_at: string;
  status: CheckStatus;
  privileged: boolean;
  summary: string;
  finding_count: number;
  severity: SeverityCounts;
  /** Set for the package check. */
  fixes?: FixSummary;
}

export interface HostSummary extends Host {
  last_scan: Scan | null;
  /** Newest successful scan that checked packages. */
  last_report: Scan | null;
  /** Newest successful result of each check run on this host. */
  checks: Partial<Record<CheckId, CheckSummary>> | null;
  /** Set for agent hosts. */
  agent?: AgentInfo;
  /** The host's next scheduled scan, if a schedule covers it. */
  next_scan?: NextScan;
  /** The machine the DeaconGuard server runs on, scanned by its own agent. */
  this_server?: boolean;
  tags: string[];
}

export interface HostDetail extends HostSummary {
  scans: Scan[];
}

/** What clears a package finding. */
export type FixState = "available" | "reboot" | "old_kernel" | "ubuntu_pro" | "none";

/** Package findings summed by what clears them. */
export interface FixSummary {
  counts: Partial<Record<FixState, number>>;
  /** By severity, the findings that installing updates or restarting fixes. */
  actionable: SeverityCounts;
}

export interface Finding {
  id: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  /** Missing in reports from before 0.7.0. */
  fix?: FixState;
  /** The distribution's own rating. */
  severity: Severity;
  /** The generic CVSS rating, when the distribution publishes it too. */
  cvss_severity?: string;
  /** CVSS v3 base score and vector, from Ubuntu and Red Hat. */
  cvss_score?: number;
  cvss_vector?: string;
  /** Missing before 0.16.0, or when no KEV or EPSS data was available. */
  exploit?: Exploit;
  priority?: Priority;
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
  /** Set on vulnerabilities in libraries, containers and images (server 1.8.0 and later), for grouping. */
  container?: string;
  image?: string;
  /** "os" for an OS package, "library" for an application library. */
  source?: "os" | "library" | string;
  package?: string;
  version?: string;
  /** The library's ecosystem (npm, PyPI…), or the OS for a package. */
  ecosystem?: string;
  summary?: string;
  fixed?: string;
  fixable?: boolean;
  exploited?: boolean;
  /** The files it was found in; inside the container, for a container. */
  paths?: string[];
}

export interface CheckResult {
  status: CheckStatus;
  privileged: boolean;
  summary: string;
  notes: string[] | null;
  error?: string;
  findings: CheckFinding[] | null;
  /** Set by the running container check (1.2.0 and later). */
  containers?: ContainerResult[];
}

/** One container and what its check found. */
export interface ContainerResult {
  id: string;
  name: string;
  image: string;
  image_id: string;
  runtime: "docker" | "podman" | "cri" | string;
  /** running, paused, restarting, exited, created, dead or stopped; missing from agents before 1.8.0, which listed running containers only. */
  state?: string;
  created?: string;
  started_at?: string;
  finished_at?: string;
  exit_code?: number;
  restarts?: number;
  /** The configured user; empty is root. */
  user?: string;
  privileged?: boolean;
  network?: string;
  ports?: string[];
  command?: string;
  /** The user its main process runs as. */
  runs_as?: string;
  /** Every vulnerability, fixable or not (server 1.8.0 and later); findings has only those to fix. */
  vulnerabilities?: CheckFinding[];
  os?: string;
  lifecycle?: Lifecycle | null;
  packages: number;
  libraries: number;
  severity: Partial<Record<string, number>>;
  exploited: number;
  fixable: number;
  findings?: CheckFinding[];
  notes?: string[];
  error?: string;
}

/** Single sign-on with an OpenID Connect provider; the client secret is never sent back. */
export interface SSOSettings {
  enabled: boolean;
  issuer: string;
  client_id: string;
  client_secret?: string;
  secret_set: boolean;
  redirect_uri: string;
  button_label: string;
  username_claim: "email" | "preferred_username";
  groups_claim: string;
  scopes: string[] | null;
  allowed_domains: string[] | null;
  allowed_groups: string[] | null;
  admin_groups: string[] | null;
  operator_groups: string[] | null;
  default_role: Role;
}

/** A passkey of the signed-in account. */
export interface Passkey {
  id: string;
  name: string;
  transports?: string[];
  created_at: string;
  last_used_at: string;
}

/** Options for navigator.credentials, with binary values base64url-encoded. */
export interface PasskeyOptions {
  challenge: string;
  rp_id: string;
  rp_name?: string;
  user_id?: string;
  user_name?: string;
  display_name?: string;
  algorithms?: number[];
  credentials: { id: string; transports?: string[] }[];
  timeout: number;
}

/** A new passkey from navigator.credentials.create, base64url-encoded. */
export interface PasskeyRegistration {
  id: string;
  client_data_json: string;
  authenticator_data: string;
  public_key: string;
  algorithm: number;
  transports: string[];
}

/** A passkey's answer from navigator.credentials.get, base64url-encoded. */
export interface PasskeyAssertion {
  id: string;
  client_data_json: string;
  authenticator_data: string;
  signature: string;
}

/** A saved login for a container registry; the secret is never sent back. */
export interface RegistryLogin {
  id: string;
  /** The registry's host: registry-1.docker.io for Docker Hub. */
  registry: string;
  /** "ecr": username is an AWS access key ID, exchanged for ECR's 12-hour password. */
  kind: RegistryLoginKind;
  username: string;
  created_by: string;
  created_at: string;
  updated_at: string;
}

export type RegistryLoginKind = "basic" | "ecr";

/** A repository whose new pushes are scanned: each image whose tag matches the pattern, for the newest `keep` matching tags. */
export interface RepositoryWatch {
  id: string;
  registry: string;
  repository: string;
  /** A regular expression (RE2); empty matches every tag. */
  tag_pattern: string;
  platform: string;
  keep: number;
  /** How many of the images it added are kept, with their scans. */
  history: number;
  notify_level: NotifyLevel;
  /** Channel ids its reports go to; empty: every channel subscribed to image scan reports. */
  notify_channels: string[];
  checked_at?: string;
  watch_error?: string;
  created_by: string;
  created_at: string;
  /** How many images it added. */
  images: number;
}

/** Which new pushes a repository watch reports: none, all, or those with a vulnerability this severe or known to be exploited. */
export type NotifyLevel = "off" | "any" | "low" | "medium" | "high" | "critical" | "exploited";

/** A watch's settings that can change. */
export interface RepositoryWatchSettings {
  tag_pattern: string;
  keep: number;
  history: number;
  notify_level: NotifyLevel;
  notify_channels: string[];
}

export interface RepositoryWatchInput extends RepositoryWatchSettings {
  registry: string;
  repository: string;
  platform: string;
}

/** One scan of an image a repository watch added: a build of the repository. */
export interface WatchBuild extends ImageScan {
  image_id: string;
  reference: string;
  /** Whether the image is still among the newest tags the watch rescans. */
  watched: boolean;
}

export interface RepositoryWatchDetail extends RepositoryWatch {
  /** Every scan of the images it added, newest first, at most 1,000. */
  builds: WatchBuild[];
}

/** A notification channel a watch's reports can go to. */
export interface ReportChannel {
  id: string;
  name: string;
  kind: ChannelKind;
  enabled: boolean;
  /** Whether it takes image scan reports at all. */
  subscribed: boolean;
}

/** What a registry login can see: its repositories, unless the registry won't list them. */
export interface RepositoryListing {
  registry: string;
  repositories: string[];
  listed: boolean;
  message?: string;
}

/** A repository's tags, newest first, and which ones a tag pattern matches. */
export interface TagListing {
  repository: string;
  matched: number;
  tags: { tag: string; digest?: string; pushed_at?: string; created?: string; matches: boolean; reference: string }[];
  /** Why the registry's own API couldn't list the tags, when the registry API did instead, without push times. */
  note?: string;
}

/** The result of logging in to a registry with a saved login. */
export interface RegistryLoginCheck {
  /** "ok": the registry accepted it; "unchecked": the registry didn't ask for a login. */
  status: "ok" | "failed" | "unchecked";
  message: string;
  checked_at: string;
}

export interface RegistryLoginInput {
  registry: string;
  kind: RegistryLoginKind;
  username: string;
  /** A password or access token; empty keeps the saved one. */
  secret: string;
}

/** One check of a registry image. Only a succeeded scan has a digest and a result. */
export interface ImageScan {
  id: string;
  image_id: string;
  status: "queued" | "running" | "succeeded" | "failed";
  error?: string;
  digest?: string;
  os?: string;
  severity: SeverityCounts;
  exploited: number;
  fixable: number;
  /** Only GET /api/image-scans/{id} includes it. */
  result?: ContainerResult;
  started_by: string;
  started_at: string;
  finished_at?: string;
}

/** An image in a registry that DeaconGuard checks, read as data and never run. */
export interface RegistryImage {
  id: string;
  reference: string;
  platform: string;
  /** Checked for a new build every 15 minutes, and scanned again daily. */
  watch: boolean;
  tag_digest?: string;
  checked_at?: string;
  /** Why the last check for a new build failed. */
  watch_error?: string;
  /** The repository watch that added it, if one did. */
  repository_watch_id?: string;
  created_by: string;
  created_at: string;
  latest?: ImageScan;
}

/** A finding of a config, cluster, TLS or network scan. */
export interface ScanFinding {
  rule: string;
  severity: Severity;
  title: string;
  detail: string;
  file: string;
  stig?: string[];
}

/** Addresses, ranges and names the server scans for open ports and TLS. */
export interface NetworkTarget {
  id: string;
  name: string;
  targets: string[];
  ports: string;
  tls: boolean;
  /** 0 scans on request only. */
  interval_hours: number;
  created_by: string;
  created_at: string;
  latest?: NetworkScan;
}

export type NetworkTargetInput = Pick<NetworkTarget, "name" | "targets" | "ports" | "tls" | "interval_hours">;

export interface NetworkService {
  port: number;
  name: string;
  banner?: string;
  tls: boolean;
}

export interface NetworkResult {
  addresses: number;
  ports: number;
  hosts: { address: string; name?: string; services: NetworkService[] }[];
  tls?: { target: string; version: string; cipher: string; subject: string; issuer: string; dns_names?: string[]; not_after: string; trusted: boolean; protocols: string[] }[];
  findings: ScanFinding[];
  notes?: string[];
}

export interface NetworkScan {
  id: string;
  target_id: string;
  status: "queued" | "running" | "succeeded" | "failed";
  error?: string;
  hosts: number;
  open_ports: number;
  severity: SeverityCounts;
  result?: NetworkResult;
  started_by: string;
  started_at: string;
  finished_at?: string;
}

/** Runs scans of its hosts on chosen days at a time of day. */
export interface Schedule {
  id: string;
  name: string;
  enabled: boolean;
  checks: CheckId[];
  /** Scans run with root privileges: agents as root, the server's own machine through sudo. */
  run_as_root: boolean;
  /** Every host, including those added later. */
  all_hosts: boolean;
  host_ids: string[];
  /** Days of the week, Sunday being 0. */
  days: number[];
  time: string;
  timezone: string;
  /** Empty while the schedule is off. */
  next_run_at: string;
  last_run_at: string;
  created_at: string;
  created_by: string;
  /** Such as "Every day at 02:30 (Europe/Stockholm)". */
  description: string;
}

export type ScheduleInput = Pick<Schedule, "name" | "enabled" | "checks" | "run_as_root" | "all_hosts" | "host_ids" | "days" | "time" | "timezone">;

export interface NextScan {
  schedule_id: string;
  schedule: string;
  at: string;
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
  kind: "stopped" | "reboot" | "out_of_memory" | "crashed" | "killed" | "start_failed" | "unknown";
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
  /** Whether the scan recorded packages or libraries for a software bill of materials (1.1.0 and later). */
  sbom_available?: boolean;
  scanned_at: string;
  checks_run?: CheckId[];
  check_results?: Partial<Record<CheckId, CheckResult>>;
  finding_count: number;
  findings: Finding[] | null;
  fix_counts?: Partial<Record<FixState, number>>;
  unsupported_count: number;
  unsupported_cves: UnsupportedRule[] | null;
  coverage: string;
  maintenance: string;
  /** Missing before 0.19.0. */
  lifecycle?: Lifecycle;
  package_manager: string;
  advisory_database: {
    source: string;
    fetched_at: string;
    feed_stale: boolean;
    feed_age_hours: number;
    feed_refresh_error?: string;
  };
  /** Missing before 0.16.0. */
  exploit_data?: { kev: ExploitSource; epss: ExploitSource };
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
  /** Hosts where installing updates or restarting fixes it. */
  fixable_host_count: number;
  packages: string[];
  /** Empty for findings from before 0.16.0. */
  priority: Priority | "";
  kev: boolean;
  kev_due?: string;
  ransomware?: boolean;
  epss?: number;
  cvss_score?: number;
  first_seen?: string;
  due_at?: string;
  overdue_host_count: number;
}

export interface AffectedPackage {
  host_id: string;
  address: string;
  scan_id: string;
  scanned_at: string;
  package: string;
  installed_version: string;
  fixed_version: string;
  fix: FixState;
  severity: Severity;
  url: string;
  title: string;
  priority?: Priority | "";
  kev?: boolean;
  kev_due?: string;
  ransomware?: boolean;
  epss?: number;
  cvss_score?: number;
  first_seen?: string;
  due_at?: string;
  overdue?: boolean;
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
  fixes: FixSummary;
  /** Hosts where updating or restarting fixes something. */
  hosts_to_update: number;
  /** Hosts whose latest package results are older than 7 days. */
  stale_hosts?: { id: string; address: string; scanned_at: string; scheduled: boolean }[];
  /** Hosts whose release is past regular support (extended) or gets no security fixes (ended). Missing before 0.19.0. */
  release_hosts?: { id: string; address: string; os: string; state: "extended" | "ended"; note: string }[];
  host_summaries: HostSummary[];
  top_vulnerabilities: Vulnerability[];
  checks: Partial<Record<CheckId, CheckTotals>>;
  exploit: { known: number; known_fixable: number; likely: number; hosts_with_known: number; hosts_without_data: number };
  sla: { enabled: boolean; overdue: number; hosts_overdue: number; due_soon: number };
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
  if (body instanceof Blob) {
    // A file uploaded as itself, such as the report logo.
    init.headers = { "Content-Type": body.type };
    init.body = body;
  } else if (method === "POST" || method === "PATCH" || method === "PUT") {
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
  loginMFA: (code: string) => request<Session>("POST", "/api/login/mfa", { code }),
  passkeyLoginOptions: () => request<PasskeyOptions>("POST", "/api/login/passkey/options", {}),
  passkeyLogin: (assertion: PasskeyAssertion) => request<Session>("POST", "/api/login/passkey", assertion),
  passkeys: () => request<Passkey[]>("GET", "/api/account/passkeys"),
  ssoSettings: () => request<SSOSettings>("GET", "/api/settings/sso"),
  saveSSOSettings: (settings: Omit<SSOSettings, "secret_set" | "redirect_uri">) => request<SSOSettings>("PUT", "/api/settings/sso", settings),
  passkeyOptions: () => request<PasskeyOptions>("POST", "/api/account/passkeys/options", {}),
  addPasskey: (name: string, password: string, registration: PasskeyRegistration) =>
    request<Passkey>("POST", "/api/account/passkeys", { name, password, ...registration }),
  renamePasskey: (id: string, name: string) => request<{ ok: boolean }>("PATCH", `/api/account/passkeys/${id}`, { name }),
  removePasskey: (id: string) => request<{ ok: boolean }>("DELETE", `/api/account/passkeys/${id}`),
  account: () => request<MyAccount>("GET", "/api/account"),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ ok: boolean }>("POST", "/api/account/password", { current_password: currentPassword, new_password: newPassword }),
  startMFA: (password: string) => request<{ secret: string; uri: string }>("POST", "/api/account/mfa", { password }),
  confirmMFA: (code: string) => request<{ recovery_codes: string[] }>("POST", "/api/account/mfa/confirm", { code }),
  removeMFA: (password: string) => request<{ ok: boolean }>("POST", "/api/account/mfa/remove", { password }),
  newRecoveryCodes: (password: string) => request<{ recovery_codes: string[] }>("POST", "/api/account/recovery-codes", { password }),
  endSession: (id: string) => request<{ ended: number }>("DELETE", `/api/account/sessions/${id}`),
  users: () => request<{ users: Account[]; mfa_required: boolean }>("GET", "/api/users"),
  createUser: (username: string, password: string, role: Role) => request<Account>("POST", "/api/users", { username, password, role }),
  setUserRole: (id: string, role: Role) => request<Account>("PATCH", `/api/users/${id}`, { role }),
  saveAppearance: (appearance: { mode: string; theme: string }) => request<unknown>("PATCH", "/api/account/appearance", appearance),
  setUserDisabled: (id: string, disabled: boolean) => request<Account>("PATCH", `/api/users/${id}`, { disabled }),
  removeUser: (id: string) => request<null>("DELETE", `/api/users/${id}`),
  resetUserMFA: (id: string) => request<{ ok: boolean }>("POST", `/api/users/${id}/reset-mfa`),
  setTemporaryPassword: (id: string, password: string) =>
    request<{ ok: boolean }>("POST", `/api/users/${id}/temporary-password`, { password }),
  setRequireMFA: (required: boolean) => request<{ require_mfa: boolean }>("PATCH", "/api/settings/security", { require_mfa: required }),
  enrollmentTokens: () => request<EnrollmentToken[]>("GET", "/api/enrollment-tokens"),
  createEnrollmentToken: (input: NewTokenInput) => request<NewEnrollmentToken>("POST", "/api/enrollment-tokens", input),
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
  schedules: () => request<Schedule[]>("GET", "/api/schedules"),
  createSchedule: (input: ScheduleInput) => request<Schedule>("POST", "/api/schedules", input),
  updateSchedule: (id: string, input: ScheduleInput) => request<Schedule>("PATCH", `/api/schedules/${id}`, input),
  deleteSchedule: (id: string) => request<null>("DELETE", `/api/schedules/${id}`),
  runSchedule: (id: string) => request<{ started: number; skipped: number }>("POST", `/api/schedules/${id}/run`),
  networkTargets: () => request<NetworkTarget[]>("GET", "/api/network-targets"),
  networkTarget: (id: string) => request<{ target: NetworkTarget; scans: NetworkScan[] }>("GET", `/api/network-targets/${id}`),
  createNetworkTarget: (input: NetworkTargetInput) => request<NetworkTarget>("POST", "/api/network-targets", input),
  updateNetworkTarget: (id: string, input: NetworkTargetInput) => request<NetworkTarget>("PATCH", `/api/network-targets/${id}`, input),
  deleteNetworkTarget: (id: string) => request<null>("DELETE", `/api/network-targets/${id}`),
  scanNetworkTarget: (id: string) => request<NetworkScan>("POST", `/api/network-targets/${id}/scans`),
  networkScan: (id: string) => request<NetworkScan>("GET", `/api/network-scans/${id}`),
  images: () => request<RegistryImage[]>("GET", "/api/images"),
  image: (id: string) => request<{ image: RegistryImage; scans: ImageScan[] }>("GET", `/api/images/${id}`),
  addImage: (reference: string, platform: string, watch: boolean) => request<RegistryImage>("POST", "/api/images", { reference, platform, watch }),
  setImageWatch: (id: string, watch: boolean) => request<RegistryImage>("PATCH", `/api/images/${id}`, { watch }),
  deleteImage: (id: string) => request<null>("DELETE", `/api/images/${id}`),
  scanImage: (id: string) => request<ImageScan>("POST", `/api/images/${id}/scans`),
  imageScan: (id: string) => request<ImageScan>("GET", `/api/image-scans/${id}`),
  registryLogins: () => request<RegistryLogin[]>("GET", "/api/registry-logins"),
  createRegistryLogin: (input: RegistryLoginInput) => request<RegistryLogin>("POST", "/api/registry-logins", input),
  updateRegistryLogin: (id: string, input: RegistryLoginInput) => request<RegistryLogin>("PATCH", `/api/registry-logins/${id}`, input),
  deleteRegistryLogin: (id: string) => request<null>("DELETE", `/api/registry-logins/${id}`),
  checkRegistryLogin: (id: string) => request<RegistryLoginCheck>("POST", `/api/registry-logins/${id}/check`),
  browseRepositories: (loginID: string) => request<RepositoryListing>("GET", `/api/registry-logins/${loginID}/repositories`),
  /** With a platform, the matching tags are ordered by when their images were built where the registry gives no push times. */
  browseTags: (loginID: string, repository: string, pattern: string, platform?: string) =>
    request<TagListing>("GET", `/api/registry-logins/${loginID}/tags?${new URLSearchParams({ repository, pattern, ...(platform ? { platform } : {}) })}`),
  repositoryWatches: () => request<RepositoryWatch[]>("GET", "/api/repository-watches"),
  addRepositoryWatch: (input: RepositoryWatchInput) => request<RepositoryWatch>("POST", "/api/repository-watches", input),
  repositoryWatch: (id: string) => request<RepositoryWatchDetail>("GET", `/api/repository-watches/${id}`),
  reportChannels: () => request<ReportChannel[]>("GET", "/api/repository-watches/report-channels"),
  updateRepositoryWatch: (id: string, settings: RepositoryWatchSettings) => request<RepositoryWatch>("PATCH", `/api/repository-watches/${id}`, settings),
  deleteRepositoryWatch: (id: string) => request<null>("DELETE", `/api/repository-watches/${id}`),
  checkRepositoryWatch: (id: string) => request<RepositoryWatch>("POST", `/api/repository-watches/${id}/check`),
  version: () => request<{ version: string; commit?: string; date?: string }>("GET", "/api/version"),
  setAllowSudo: (hostId: string, allow: boolean) => request<Host>("PATCH", `/api/hosts/${hostId}`, { allow_sudo: allow }),
  setAutoScanContainers: (hostId: string, on: boolean) => request<Host>("PATCH", `/api/hosts/${hostId}`, { auto_scan_containers: on }),
  renameHost: (hostId: string, name: string) => request<Host>("PATCH", `/api/hosts/${hostId}`, { name }),
  startScan: (hostId: string, checks: CheckId[]) => request<Scan>("POST", `/api/hosts/${hostId}/scans`, { checks }),
  prompts: () => request<Prompt[]>("GET", "/api/prompts"),
  activity: () => request<Activity[]>("GET", "/api/activity"),
  respond: (scanId: string, answer: { value?: string; cancel?: boolean }) =>
    request<{ ok: boolean }>("POST", `/api/scans/${scanId}/respond`, answer),
  scan: (id: string) => request<ScanDetail>("GET", `/api/scans/${id}`),
  startAudit: (hostId: string, advanced: boolean) => request<Scan>("POST", `/api/hosts/${hostId}/audits`, { advanced }),
  auditList: (hostId?: string) => request<AuditListItem[]>("GET", `/api/audits${hostId ? `?host_id=${hostId}` : ""}`),
  auditDetail: (id: string) => request<AuditDetail>("GET", `/api/audits/${id}`),
  addException: (input: { host_id: string; control_id: string; reason: string; expires_at: string }) =>
    request<AuditException>("POST", "/api/exceptions", input),
  removeException: (id: string) => request<null>("DELETE", `/api/exceptions/${id}`),
  auditSettings: () => request<{ audit_on_enroll: boolean }>("GET", "/api/settings/audit"),
  createReport: (input: { scan_id: string; client: string; notes: string; compare_with: string; frameworks: string[] }) =>
    request<ReportRecord>("POST", "/api/reports", input),
  frameworks: () => request<Framework[]>("GET", "/api/frameworks"),
  policies: () => request<{ policies: Policy[]; example: string; files: string[] }>("GET", "/api/policies"),
  addPolicy: (source: string) => request<Policy>("POST", "/api/policies", { source }),
  updatePolicy: (id: string, change: { source?: string; enabled?: boolean }) => request<Policy>("PATCH", `/api/policies/${id}`, change),
  deletePolicy: (id: string) => request<null>("DELETE", `/api/policies/${id}`),
  reports: (query: { scanId?: string; hostId?: string }) =>
    request<ReportRecord[]>("GET", `/api/reports?${new URLSearchParams({ scan_id: query.scanId ?? "", host_id: query.hostId ?? "" })}`),
  deleteReport: (id: string) => request<null>("DELETE", `/api/reports/${id}`),
  verifyReport: (reportId: string, fingerprint: string) => request<VerifyResult>("POST", "/api/reports/verify", { report_id: reportId, fingerprint }),
  shares: (reportId: string) => request<ReportShare[]>("GET", `/api/reports/${reportId}/shares`),
  createShare: (reportId: string, days: number) => request<{ share: ReportShare; url: string }>("POST", `/api/reports/${reportId}/shares`, { days }),
  revokeShare: (id: string) => request<ReportShare>("DELETE", `/api/shares/${id}`),
  branding: () => request<ReportBranding>("GET", "/api/settings/reports"),
  saveBranding: (company: string, contact: string) => request<ReportBranding>("PUT", "/api/settings/reports", { company, contact }),
  uploadLogo: (file: File) => request<ReportBranding>("PUT", "/api/settings/reports/logo", file),
  removeLogo: () => request<ReportBranding>("DELETE", "/api/settings/reports/logo"),
  setAuditOnEnroll: (on: boolean) => request<{ audit_on_enroll: boolean }>("PATCH", "/api/settings/audit", { audit_on_enroll: on }),
  deleteScan: (id: string) => request<{ ok: boolean }>("DELETE", `/api/scans/${id}`),
  vulnerabilities: () => request<Vulnerability[]>("GET", "/api/vulnerabilities"),
  tags: () => request<TagCount[]>("GET", "/api/tags"),
  sla: () => request<SLA>("GET", "/api/settings/sla"),
  setSLA: (sla: SLA) => request<SLA>("PUT", "/api/settings/sla", sla),
  maintenance: () => request<MaintenanceWindow[]>("GET", "/api/maintenance"),
  addMaintenance: (input: { name: string; tags: string[]; starts_at: string; ends_at: string; skip_scans: boolean }) =>
    request<MaintenanceWindow>("POST", "/api/maintenance", input),
  deleteMaintenance: (id: string) => request<MaintenanceWindow>("DELETE", `/api/maintenance/${id}`),
  apiTokens: () => request<APIToken[]>("GET", "/api/account/tokens"),
  createAPIToken: (input: { name: string; role: Role; days: number }) => request<APIToken & { token: string }>("POST", "/api/account/tokens", input),
  revokeOwnAPIToken: (id: string) => request<APIToken>("DELETE", `/api/account/tokens/${id}`),
  allAPITokens: () => request<APIToken[]>("GET", "/api/tokens"),
  revokeAPIToken: (id: string) => request<APIToken>("DELETE", `/api/tokens/${id}`),
  notifications: () =>
    request<{ channels: Channel[]; deliveries: Delivery[]; dashboard_url: string; events: NotificationEvent[] }>("GET", "/api/notifications"),
  createChannel: (input: ChannelInput) => request<Channel>("POST", "/api/notifications/channels", input),
  updateChannel: (id: string, input: Partial<ChannelInput>) => request<Channel>("PATCH", `/api/notifications/channels/${id}`, input),
  deleteChannel: (id: string) => request<Channel>("DELETE", `/api/notifications/channels/${id}`),
  testChannel: (id: string) => request<Delivery>("POST", `/api/notifications/channels/${id}/test`),
  setDashboardURL: (url: string) => request<{ dashboard_url: string }>("PUT", "/api/notifications/settings", { dashboard_url: url }),
  setHostTags: (id: string, tags: string[]) => request<{ tags: string[] }>("PUT", `/api/hosts/${id}/tags`, { tags }),
  trends: (days: number, filter: { host?: string; tag?: string } = {}) => {
    const parameters = new URLSearchParams({ days: String(days) });
    if (filter.host) parameters.set("host", filter.host);
    if (filter.tag) parameters.set("tag", filter.tag);
    return request<TrendPoint[]>("GET", `/api/trends?${parameters}`);
  },
  vulnerability: (cve: string) =>
    request<AffectedPackage[]>("GET", `/api/vulnerabilities/${encodeURIComponent(cve)}`),
};
