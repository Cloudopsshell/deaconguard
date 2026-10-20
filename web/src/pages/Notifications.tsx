import { useState, type FormEvent, type ReactNode } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { BellRing, CheckCircle2, Clock, Database, Mail, MessageSquare, Pencil, Plus, Send, Ticket, Trash2, Webhook, XCircle } from "lucide-react";
import {
  api,
  type Channel,
  type ChannelConfig,
  type ChannelInput,
  type ChannelKind,
  type Delivery,
  type NotificationEvent,
} from "../api";
import { Button, Card, CardHeader, Dialog, EmptyState, ErrorMessage, Field, Loading, PageHeader, Table, Td, Th, cx } from "../components/ui";
import { dateTime, timeAgo } from "../lib/format";
import { browserTimezone, timezones } from "../lib/zones";

const kinds: { kind: ChannelKind; label: string; detail: string; icon: ReactNode }[] = [
  { kind: "email", label: "Email", detail: "Through your mail server (SMTP)", icon: <Mail className="size-4" /> },
  { kind: "slack", label: "Slack", detail: "An incoming webhook", icon: <MessageSquare className="size-4" /> },
  { kind: "teams", label: "Microsoft Teams", detail: "A Workflows webhook", icon: <MessageSquare className="size-4" /> },
  { kind: "webhook", label: "Webhook", detail: "JSON to any address, signed", icon: <Webhook className="size-4" /> },
  { kind: "syslog", label: "Syslog", detail: "RFC 5424 to your SIEM", icon: <Database className="size-4" /> },
  { kind: "splunk", label: "Splunk", detail: "HTTP Event Collector", icon: <Database className="size-4" /> },
  { kind: "jira", label: "Jira", detail: "Opens an issue per event", icon: <Ticket className="size-4" /> },
  { kind: "servicenow", label: "ServiceNow", detail: "Opens an incident per event", icon: <Ticket className="size-4" /> },
];

const selectClass =
  "mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700";

const eventMeta: Record<NotificationEvent, { label: string; detail: string }> = {
  exploited: { label: "Known exploited vulnerabilities", detail: "A host has vulnerabilities in CISA's KEV catalog it didn't have at its last scan" },
  critical: { label: "New critical vulnerabilities", detail: "A host has new critical vulnerabilities an update fixes" },
  malware: { label: "Malware", detail: "A scan found malware or signs of compromise" },
  integrity: { label: "Changed system files", detail: "System files differ from what their packages installed" },
  cluster: { label: "New cluster findings", detail: "A Kubernetes cluster has new critical or high findings, such as a privileged workload" },
  exposure: { label: "New network findings", detail: "A network scan found new critical or high findings, such as an exposed database or an expiring certificate" },
  scan_failed: { label: "Failed scans", detail: "A scan failed, so its host's results are out of date" },
  audit: { label: "Audits", detail: "An audit finished, with its grade" },
  agent_offline: { label: "Agents offline", detail: "An agent stopped checking in" },
  digest: { label: "Digest", detail: "A summary of every host, daily or weekly; email attaches the open vulnerabilities as CSV" },
};

const instantEvents: NotificationEvent[] = ["exploited", "critical", "malware", "integrity", "cluster", "exposure", "scan_failed", "audit", "agent_offline"];
const days = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

/** The editable fields of a channel, with saved secrets left empty so the server keeps them. */
function inputOf(channel: Channel): ChannelInput {
  const config: ChannelConfig = { ...channel.config, password: "", secret: "", url: "" };
  return {
    name: channel.name,
    config,
    enabled: channel.enabled,
    events: channel.events,
    tags: channel.tags,
    digest: channel.digest,
    digest_days: channel.digest_days,
    digest_time: channel.digest_time,
    timezone: channel.timezone,
  };
}

function KindIcon({ kind }: { kind: ChannelKind }) {
  return (
    <span className="self-start rounded-lg bg-indigo-50 p-2 text-indigo-600 dark:bg-indigo-500/15 dark:text-indigo-300">
      {kinds.find((item) => item.kind === kind)?.icon}
    </span>
  );
}

function DeliveryStatus({ delivery }: { delivery: Delivery }) {
  if (delivery.status === "sent")
    return (
      <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400">
        <CheckCircle2 className="size-3.5" aria-hidden /> Sent {timeAgo(delivery.sent_at)}
      </span>
    );
  if (delivery.status === "failed")
    return (
      <span className="inline-flex items-center gap-1 text-red-700 dark:text-red-400" title={delivery.error}>
        <XCircle className="size-3.5" aria-hidden /> Failed {timeAgo(delivery.created_at)}
      </span>
    );
  return (
    <span className="inline-flex items-center gap-1 text-amber-700 dark:text-amber-400" title={delivery.error}>
      <Clock className="size-3.5" aria-hidden /> {delivery.attempts > 0 ? `Retrying ${timeAgo(delivery.next_attempt_at)}` : "Sending"}
    </span>
  );
}

function where(channel: Channel) {
  if (channel.kind === "email") return (channel.config.to ?? []).join(", ");
  if (channel.kind === "syslog") return `${channel.config.protocol?.toUpperCase()} ${channel.config.host}:${channel.config.port}`;
  if (channel.kind === "jira") return `${channel.config.url} · project ${channel.config.project}`;
  return channel.config.url ?? "";
}

/** Admins' notification channels: where DeaconGuard sends alerts and digests. */
export function Notifications() {
  const queryClient = useQueryClient();
  const { data, error, isPending } = useQuery({ queryKey: ["notifications"], queryFn: api.notifications, refetchInterval: 15000 });
  const [editing, setEditing] = useState<Channel | "new" | null>(null);
  const [tested, setTested] = useState<Record<string, Delivery>>({});
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["notifications"] });
  const toggle = useMutation({
    mutationFn: (channel: Channel) => api.updateChannel(channel.id, { ...inputOf(channel), enabled: !channel.enabled }),
    onSettled: refresh,
  });
  const test = useMutation({
    mutationFn: (channel: Channel) => api.testChannel(channel.id),
    onSuccess: (delivery, channel) => setTested((current) => ({ ...current, [channel.id]: delivery })),
    onSettled: refresh,
  });
  const [removing, setRemoving] = useState<Channel | null>(null);
  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;
  const names = new Map(data.channels.map((channel) => [channel.id, channel.name]));

  return (
    <>
      <PageHeader
        title="Notifications"
        description="Where DeaconGuard tells you about what needs attention: newly exploited vulnerabilities, malware, failed scans, agents going offline, and a daily or weekly digest."
        action={
          <Button onClick={() => setEditing("new")}>
            <Plus className="size-4" /> Add channel
          </Button>
        }
      />
      <DashboardAddress current={data.dashboard_url} />
      <Card>
        <CardHeader title="Channels" description="Each channel gets the events you choose, optionally only for hosts with certain tags." />
        {data.channels.length === 0 ? (
          <EmptyState
            icon={<BellRing className="size-6" />}
            title="No channels yet"
            description="Add an email list, a Slack or Teams channel, or a webhook, choose its events, and send a test."
            action={
              <Button onClick={() => setEditing("new")}>
                <Plus className="size-4" /> Add channel
              </Button>
            }
          />
        ) : (
          <ul className="divide-y divide-slate-200 dark:divide-slate-800">
            {data.channels.map((channel) => {
              const result = tested[channel.id];
              return (
                <li key={channel.id} className="flex flex-col gap-3 px-5 py-4 lg:flex-row lg:items-start lg:justify-between">
                  <div className="flex min-w-0 gap-3">
                    <KindIcon kind={channel.kind} />
                    <div className="min-w-0">
                      <p className="font-medium">
                        {channel.name}
                        {!channel.enabled && <span className="ml-2 text-xs font-normal text-slate-500 dark:text-slate-400">off</span>}
                      </p>
                      <p className="truncate text-xs text-slate-500 dark:text-slate-400">
                        {kinds.find((item) => item.kind === channel.kind)?.label} · {where(channel)}
                      </p>
                      <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">
                        {channel.events.length === 0
                          ? "No events chosen"
                          : channel.events.map((event) => (event === "digest" ? `${channel.digest} digest` : eventMeta[event].label)).join(" · ")}
                        {channel.tags.length > 0 && <> · hosts tagged {channel.tags.join(" or ")}</>}
                      </p>
                      {channel.digest && channel.next_digest_at && (
                        <p className="text-xs text-slate-500 dark:text-slate-400">Next digest {dateTime(channel.next_digest_at)}</p>
                      )}
                      <p className="mt-1 text-xs">
                        {result ? (
                          <span className={result.status === "sent" ? "text-emerald-700 dark:text-emerald-400" : "text-red-700 dark:text-red-400"}>
                            {result.status === "sent" ? "Test sent." : `Test failed: ${result.error}`}
                          </span>
                        ) : channel.last ? (
                          <>
                            <DeliveryStatus delivery={channel.last} />
                            <span className="text-slate-500 dark:text-slate-400"> · {channel.last.title}</span>
                          </>
                        ) : (
                          <span className="text-slate-500 dark:text-slate-400">Nothing sent yet</span>
                        )}
                      </p>
                    </div>
                  </div>
                  <div className="flex shrink-0 items-center gap-1">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={channel.enabled}
                      aria-label={`${channel.name} on`}
                      onClick={() => toggle.mutate(channel)}
                      className={cx(
                        "relative mr-2 inline-flex h-6 w-11 shrink-0 rounded-full transition-colors",
                        channel.enabled ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-700",
                      )}
                    >
                      <span
                        className={cx(
                          "absolute top-0.5 size-5 rounded-full bg-white shadow transition-transform",
                          channel.enabled ? "translate-x-5.5" : "translate-x-0.5",
                        )}
                      />
                    </button>
                    <Button variant="ghost" loading={test.isPending && test.variables?.id === channel.id} onClick={() => test.mutate(channel)}>
                      <Send className="size-4" /> Test
                    </Button>
                    <Button variant="ghost" onClick={() => setEditing(channel)}>
                      <Pencil className="size-4" /> Edit
                    </Button>
                    <Button variant="ghost" onClick={() => setRemoving(channel)} aria-label={`Delete ${channel.name}`}>
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                </li>
              );
            })}
          </ul>
        )}
        {(toggle.error || test.error) && (
          <div className="px-5 pb-4">
            <ErrorMessage error={toggle.error ?? test.error} />
          </div>
        )}
      </Card>

      <Card className="mt-6">
        <CardHeader
          title="Recently sent"
          description="The last 100 notifications, kept for 30 days. Failed ones are retried after 1, 5 and 30 minutes."
        />
        {data.deliveries.length === 0 ? (
          <p className="px-5 py-6 text-sm text-slate-500 dark:text-slate-400">Nothing sent yet.</p>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Notification</Th>
                <Th>Channel</Th>
                <Th>Status</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.deliveries.map((delivery) => (
                <tr key={delivery.id}>
                  <Td>
                    <p className="text-sm">{delivery.title}</p>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {delivery.event === "test" ? "Test" : eventMeta[delivery.event]?.label} · {dateTime(delivery.created_at)}
                    </p>
                  </Td>
                  <Td className="text-sm text-slate-600 dark:text-slate-300">{names.get(delivery.channel_id) ?? "Removed channel"}</Td>
                  <Td className="text-xs">
                    <DeliveryStatus delivery={delivery} />
                    {delivery.error && <p className="mt-0.5 max-w-sm break-words text-slate-500 dark:text-slate-400">{delivery.error}</p>}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      {editing && <ChannelDialog channel={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
      <RemoveDialog channel={removing} onClose={() => setRemoving(null)} />
    </>
  );
}

function DashboardAddress({ current }: { current: string }) {
  const queryClient = useQueryClient();
  const [value, setValue] = useState(current || window.location.origin);
  const save = useMutation({
    mutationFn: () => api.setDashboardURL(value),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["notifications"] }),
  });
  return (
    <Card className="mb-6">
      <form
        className="flex flex-col gap-3 px-5 py-4 sm:flex-row sm:items-end"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <div className="flex-1">
          <Field
            label="Dashboard address, for links in notifications"
            hint={current ? "Notifications link to the host or scan here." : "Not set yet: notifications go out without links until you save it."}
            value={value}
            onChange={(event) => setValue(event.target.value)}
            placeholder="https://deaconguard.example.com"
          />
        </div>
        <Button type="submit" variant="secondary" loading={save.isPending} disabled={value === current}>
          Save
        </Button>
      </form>
      {save.error && (
        <div className="px-5 pb-4">
          <ErrorMessage error={save.error} />
        </div>
      )}
    </Card>
  );
}

function ChannelDialog({ channel, onClose }: { channel: Channel | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [kind, setKind] = useState<ChannelKind>(channel?.kind ?? "email");
  const [input, setInput] = useState<ChannelInput>(
    channel
      ? inputOf(channel)
      : {
          name: "",
          config: { port: 587, tls: "starttls", to: [] },
          events: ["exploited", "malware", "scan_failed"],
          tags: [],
          digest: "",
          digest_days: [1],
          digest_time: "08:00",
          timezone: browserTimezone(),
        },
  );
  const [recipients, setRecipients] = useState((input.config.to ?? []).join(", "));
  const [tags, setTags] = useState(input.tags.join(", "));
  const save = useMutation({
    mutationFn: () => {
      const c = input.config;
      const config: ChannelConfig =
        kind === "email"
          ? { host: c.host, port: c.port, tls: c.tls, username: c.username, password: c.password, from: c.from, to: recipients.split(/[,;\s]+/).filter(Boolean) }
          : kind === "syslog"
            ? { host: c.host, port: c.port, protocol: c.protocol ?? "tcp" }
            : kind === "splunk"
              ? { url: c.url, secret: c.secret, index: c.index }
              : kind === "jira"
                ? { url: c.url, username: c.username, password: c.password, project: c.project, issue_type: c.issue_type }
                : kind === "servicenow"
                  ? { url: c.url, username: c.username, password: c.password, table: c.table }
                  : { url: c.url, secret: kind === "webhook" ? c.secret : undefined };
      const events = input.events.filter((event) => event !== "digest");
      const body: ChannelInput = {
        ...input,
        config,
        events: input.digest ? [...events, "digest"] : events,
        tags: tags.split(/[,\s]+/).filter(Boolean),
      };
      return channel ? api.updateChannel(channel.id, body) : api.createChannel({ ...body, kind });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
      onClose();
    },
  });
  const set = <K extends keyof ChannelInput>(key: K, value: ChannelInput[K]) => setInput((current) => ({ ...current, [key]: value }));
  const setConfig = <K extends keyof ChannelConfig>(key: K, value: ChannelConfig[K]) =>
    setInput((current) => ({ ...current, config: { ...current.config, [key]: value } }));
  const saved = channel?.config;

  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate();
  }

  return (
    <Dialog open onClose={onClose} title={channel ? `Edit ${channel.name}` : "Add a channel"} wide>
      <form onSubmit={submit} className="space-y-5">
        {!channel && (
          <div role="radiogroup" aria-label="Type" className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            {kinds.map((item) => (
              <button
                key={item.kind}
                type="button"
                role="radio"
                aria-checked={kind === item.kind}
                onClick={() => {
                  setKind(item.kind);
                  // Each type's usual port.
                  if (item.kind === "syslog") setInput((current) => ({ ...current, config: { ...current.config, port: 514, protocol: current.config.protocol ?? "tcp" } }));
                  if (item.kind === "email") setInput((current) => ({ ...current, config: { ...current.config, port: 587 } }));
                }}
                className={cx(
                  "rounded-lg px-3 py-2 text-left ring-1 ring-inset transition-colors",
                  kind === item.kind
                    ? "bg-indigo-50/60 ring-2 ring-indigo-600 dark:bg-indigo-500/10 dark:ring-indigo-400"
                    : "ring-slate-200 hover:bg-slate-50 dark:ring-slate-700 dark:hover:bg-slate-800/60",
                )}
              >
                <span className="flex items-center gap-1.5 text-sm font-semibold">
                  {item.icon} {item.label}
                </span>
                <span className="block text-xs text-slate-500 dark:text-slate-400">{item.detail}</span>
              </button>
            ))}
          </div>
        )}
        <Field label="Name" required maxLength={80} value={input.name} onChange={(event) => set("name", event.target.value)} placeholder="Security team" />

        {kind === "syslog" ? (
          <div className="grid gap-3 sm:grid-cols-[1fr_6rem_8rem]">
            <Field label="Syslog server" required value={input.config.host ?? ""} onChange={(event) => setConfig("host", event.target.value)} placeholder="siem.example.com" />
            <Field label="Port" type="number" required min={1} max={65535} value={input.config.port ?? 514} onChange={(event) => setConfig("port", Number(event.target.value))} />
            <label className="block">
              <span className="text-sm font-medium">Protocol</span>
              <select value={input.config.protocol ?? "tcp"} onChange={(event) => setConfig("protocol", event.target.value as ChannelConfig["protocol"])} className={selectClass}>
                <option value="tcp">TCP</option>
                <option value="tls">TLS</option>
                <option value="udp">UDP</option>
              </select>
            </label>
            <p className="text-xs text-slate-500 dark:text-slate-400 sm:col-span-3">
              RFC 5424 messages from facility local0, with the event as JSON; TCP and TLS frame each with its length. The server's certificate must be trusted for TLS.
            </p>
          </div>
        ) : kind === "splunk" ? (
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <Field
                label="HTTP Event Collector address"
                required={!saved?.url}
                value={input.config.url ?? ""}
                onChange={(event) => setConfig("url", event.target.value)}
                placeholder={saved?.url ? `Saved (${saved.url}); leave empty to keep it` : "https://splunk.example.com:8088/services/collector/event"}
              />
            </div>
            <Field
              label="HEC token"
              type="password"
              autoComplete="new-password"
              required={!saved?.secret}
              value={input.config.secret ?? ""}
              onChange={(event) => setConfig("secret", event.target.value)}
              placeholder={saved?.secret ? "Saved; leave empty to keep it" : ""}
            />
            <Field label="Index (optional)" value={input.config.index ?? ""} onChange={(event) => setConfig("index", event.target.value)} placeholder="security" />
          </div>
        ) : kind === "jira" || kind === "servicenow" ? (
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="sm:col-span-2">
              <Field
                label={kind === "jira" ? "Jira address" : "ServiceNow instance"}
                required={!saved?.url}
                value={input.config.url ?? ""}
                onChange={(event) => setConfig("url", event.target.value)}
                placeholder={saved?.url ? `Saved (${saved.url}); leave empty to keep it` : kind === "jira" ? "https://acme.atlassian.net" : "https://acme.service-now.com"}
              />
            </div>
            <Field
              label={kind === "jira" ? "Email (Jira Cloud)" : "Username"}
              required={kind === "servicenow"}
              autoComplete="off"
              value={input.config.username ?? ""}
              onChange={(event) => setConfig("username", event.target.value)}
              hint={kind === "jira" ? "Leave empty on Jira Data Center, with a personal access token below." : undefined}
            />
            <Field
              label={kind === "jira" ? "API token" : "Password"}
              type="password"
              autoComplete="new-password"
              required={!saved?.password}
              value={input.config.password ?? ""}
              onChange={(event) => setConfig("password", event.target.value)}
              placeholder={saved?.password ? "Saved; leave empty to keep it" : ""}
            />
            {kind === "jira" ? (
              <>
                <Field label="Project key" required value={input.config.project ?? ""} onChange={(event) => setConfig("project", event.target.value.toUpperCase())} placeholder="SEC" />
                <Field label="Issue type" value={input.config.issue_type ?? ""} onChange={(event) => setConfig("issue_type", event.target.value)} placeholder="Task" />
              </>
            ) : (
              <Field label="Table" value={input.config.table ?? ""} onChange={(event) => setConfig("table", event.target.value)} placeholder="incident" hint="Records go here; the account needs to create them." />
            )}
            <p className="text-xs text-slate-500 dark:text-slate-400 sm:col-span-2">
              Each event opens one {kind === "jira" ? "issue, labelled deaconguard," : "record"} with the message and a link. Choose events that need someone to act, such as known exploited vulnerabilities and malware.
            </p>
          </div>
        ) : kind === "email" ? (
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Mail server" required value={input.config.host ?? ""} onChange={(event) => setConfig("host", event.target.value)} placeholder="smtp.example.com" />
            <div className="grid grid-cols-[6rem_1fr] gap-3">
              <Field label="Port" type="number" required min={1} max={65535} value={input.config.port ?? 587} onChange={(event) => setConfig("port", Number(event.target.value))} />
              <label className="block">
                <span className="text-sm font-medium">Encryption</span>
                <select
                  value={input.config.tls}
                  onChange={(event) => setConfig("tls", event.target.value as ChannelConfig["tls"])}
                  className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
                >
                  <option value="starttls">STARTTLS (usually 587)</option>
                  <option value="tls">TLS (usually 465)</option>
                  <option value="none">None (a local relay)</option>
                </select>
              </label>
            </div>
            <Field label="Username (optional)" autoComplete="off" value={input.config.username ?? ""} onChange={(event) => setConfig("username", event.target.value)} />
            <Field
              label="Password"
              type="password"
              autoComplete="new-password"
              value={input.config.password ?? ""}
              onChange={(event) => setConfig("password", event.target.value)}
              placeholder={saved?.password ? "Saved; leave empty to keep it" : ""}
            />
            <Field label="From" required value={input.config.from ?? ""} onChange={(event) => setConfig("from", event.target.value)} placeholder="DeaconGuard <deaconguard@example.com>" />
            <Field label="To" required value={recipients} onChange={(event) => setRecipients(event.target.value)} placeholder="security@example.com, ops@example.com" hint="Up to 20 addresses, separated by commas" />
          </div>
        ) : (
          <div className="space-y-3">
            <Field
              label="Webhook address"
              required={!saved?.url}
              value={input.config.url ?? ""}
              onChange={(event) => setConfig("url", event.target.value)}
              placeholder={
                saved?.url
                  ? `Saved (${saved.url}); leave empty to keep it`
                  : kind === "slack"
                    ? "https://hooks.slack.com/services/…"
                    : kind === "teams"
                      ? "https://….logic.azure.com/workflows/…"
                      : "https://example.com/deaconguard"
              }
              hint={
                kind === "slack"
                  ? "In Slack: create an app with an incoming webhook for the channel, and paste its address. Keep it secret: anyone with it can post."
                  : kind === "teams"
                    ? "In Teams: on the channel, Workflows, \"Post to a channel when a webhook request is received\", and paste its address."
                    : "DeaconGuard posts JSON here. HTTPS is best; plain HTTP is allowed for internal tools."
              }
            />
            {kind === "webhook" && (
              <Field
                label="Signing secret (optional)"
                type="password"
                autoComplete="new-password"
                value={input.config.secret ?? ""}
                onChange={(event) => setConfig("secret", event.target.value)}
                placeholder={saved?.secret ? "Saved; leave empty to keep it" : ""}
                hint="Each request then carries X-DeaconGuard-Signature: sha256= and the HMAC-SHA256 of its timestamp, a dot, and the body."
              />
            )}
          </div>
        )}

        <fieldset>
          <legend className="text-sm font-medium">Send</legend>
          <div className="mt-2 grid gap-2 sm:grid-cols-2">
            {instantEvents.map((event) => (
              <label key={event} className="flex gap-2 rounded-lg p-2 text-sm ring-1 ring-slate-200 ring-inset dark:ring-slate-700">
                <input
                  type="checkbox"
                  className="mt-0.5 accent-indigo-600"
                  checked={input.events.includes(event)}
                  onChange={(change) =>
                    set("events", change.target.checked ? [...input.events, event] : input.events.filter((item) => item !== event))
                  }
                />
                <span>
                  <span className="block font-medium">{eventMeta[event].label}</span>
                  <span className="block text-xs text-slate-500 dark:text-slate-400">{eventMeta[event].detail}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>

        <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
          <Field
            label="Only hosts tagged (optional)"
            value={tags}
            onChange={(event) => setTags(event.target.value)}
            placeholder="prod, team:web"
            hint="Leave empty for every host. Digests sum up only these hosts."
          />
        </div>

        <fieldset className="space-y-3">
          <legend className="text-sm font-medium">Digest</legend>
          <div className="flex flex-wrap gap-4 text-sm">
            {(["", "daily", "weekly"] as const).map((value) => (
              <label key={value || "none"} className="flex items-center gap-2">
                <input type="radio" name="digest" className="accent-indigo-600" checked={input.digest === value} onChange={() => set("digest", value)} />
                {value === "" ? "None" : value === "daily" ? "Daily" : "Weekly"}
              </label>
            ))}
          </div>
          {input.digest && (
            <div className="grid gap-3 sm:grid-cols-[auto_8rem_1fr]">
              {input.digest === "weekly" && (
                <div role="group" aria-label="Days" className="flex flex-wrap gap-1 self-end">
                  {days.map((label, day) => (
                    <button
                      key={label}
                      type="button"
                      aria-pressed={input.digest_days.includes(day)}
                      onClick={() =>
                        set(
                          "digest_days",
                          input.digest_days.includes(day) ? input.digest_days.filter((item) => item !== day) : [...input.digest_days, day].sort(),
                        )
                      }
                      className={cx(
                        "rounded-md px-2 py-1.5 text-xs font-semibold ring-1 ring-inset",
                        input.digest_days.includes(day)
                          ? "bg-slate-900 text-white ring-slate-900 dark:bg-slate-100 dark:text-slate-900"
                          : "text-slate-600 ring-slate-300 dark:text-slate-300 dark:ring-slate-700",
                      )}
                    >
                      {label}
                    </button>
                  ))}
                </div>
              )}
              <Field label="Time" type="time" required value={input.digest_time} onChange={(event) => set("digest_time", event.target.value)} />
              <label className="block">
                <span className="text-sm font-medium">Time zone</span>
                <select
                  value={input.timezone}
                  onChange={(event) => set("timezone", event.target.value)}
                  className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
                >
                  {timezones(input.timezone).map((zone) => (
                    <option key={zone} value={zone}>
                      {zone}
                    </option>
                  ))}
                </select>
              </label>
            </div>
          )}
        </fieldset>

        <ErrorMessage error={save.error} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending}>
            {channel ? "Save" : "Add channel"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function RemoveDialog({ channel, onClose }: { channel: Channel | null; onClose: () => void }) {
  const queryClient = useQueryClient();
  const remove = useMutation({
    mutationFn: (id: string) => api.deleteChannel(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["notifications"] });
      onClose();
    },
  });
  return (
    <Dialog open={channel !== null} onClose={onClose} title="Delete channel">
      <p className="text-sm text-slate-600 dark:text-slate-300">
        Delete {channel?.name}? It stops getting notifications, and its sent messages leave the list. Its secrets are deleted from the server.
      </p>
      <ErrorMessage error={remove.error} />
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="danger" loading={remove.isPending} onClick={() => channel && remove.mutate(channel.id)}>
          Delete
        </Button>
      </div>
    </Dialog>
  );
}
