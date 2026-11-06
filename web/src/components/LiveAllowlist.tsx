import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ListChecks } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api, type LiveAlert, type LiveAllow, type LiveAllowInput } from "../api";
import { dateTime, timeAgo } from "../lib/format";
import { useCan } from "../lib/role";
import { Button, Card, CardHeader, Dialog, EmptyState, ErrorMessage, Field, Loading, Table, Td, Th } from "./ui";

/** The live detection rules, by ID, as the allowlist names them. */
export const liveRules: Record<string, string> = {
  "DG-RT-001": "Program started from a temporary folder",
  "DG-RT-002": "Shell started by a service",
  "DG-RT-003": "Crypto miner",
  "DG-RT-004": "Downloaded and run",
  "DG-RT-010": "Accounts changed",
  "DG-RT-011": "Sudo rules changed",
  "DG-RT-012": "SSH logins changed",
  "DG-RT-013": "Startup or scheduled job added",
  "DG-RT-020": "Reverse shell",
  "DG-RT-021": "Program from a temporary folder or memory connected out",
  "DG-RT-022": "Mining pool port",
  "DG-RT-030": "Became root without sudo",
  "DG-RT-031": "Kernel module loaded",
  "DG-RT-032": "Process taken over (ptrace)",
  "DG-RT-033": "Process memory written",
};

/** Where an alert happened: its pod, its container, or its container's short ID. */
export function alertWhere(alert: LiveAlert): string {
  if (alert.pod) return `pod ${alert.namespace}/${alert.pod} · ${alert.container}`;
  if (alert.container) return `container ${alert.container}`;
  if (alert.container_id) return `container ${alert.container_id.slice(0, 12)}`;
  return "";
}

/** An image without its tag or digest, which matches every tag. */
function withoutTag(image: string) {
  const at = image.indexOf("@");
  if (at >= 0) image = image.slice(0, at);
  const colon = image.lastIndexOf(":");
  return colon > image.lastIndexOf("/") ? image.slice(0, colon) : image;
}

/** What a rule matches, in a few words. */
function matches(rule: LiveAllow) {
  return [
    rule.program && ["program", rule.program],
    rule.path && ["path", rule.path],
    rule.image && ["image", rule.image],
    rule.container && ["container", rule.container],
    rule.namespace && ["namespace", rule.namespace],
  ].filter(Boolean) as [string, string][];
}

export interface AllowScope {
  /** A host's or cluster's ID; "" for every host. */
  value: string;
  label: string;
}

/**
 * Adds or changes an allowlist rule. From an alert, its fields come filled
 * in, the image without its tag; any left empty match anything.
 */
export function AllowDialog({
  alert,
  rule,
  scopes,
  onClose,
}: {
  alert?: LiveAlert;
  rule?: LiveAllow;
  scopes: AllowScope[];
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const [form, setForm] = useState<LiveAllowInput>(() =>
    rule
      ? { rule: rule.rule, program: rule.program ?? "", path: rule.path ?? "", image: rule.image ?? "", container: rule.container ?? "",
          namespace: rule.namespace ?? "", host_id: rule.host_id, note: rule.note }
      : {
          rule: alert?.rule ?? "DG-RT-001",
          program: alert?.program ?? "",
          path: alert?.path ?? "",
          image: alert?.image ? withoutTag(alert.image) : "",
          container: alert?.pod ? "" : (alert?.container ?? ""),
          namespace: alert?.namespace ?? "",
          host_id: scopes[0]?.value ?? "",
          note: "",
        },
  );
  const set = (field: keyof LiveAllowInput) => (event: { target: { value: string } }) => setForm({ ...form, [field]: event.target.value });
  const save = useMutation({
    mutationFn: () => (rule ? api.updateLiveAllow(rule.id, form) : api.addLiveAllow(form)),
    onSuccess: () => {
      void queryClient.invalidateQueries({ queryKey: ["live-allowlist"] });
      void queryClient.invalidateQueries({ queryKey: ["live"] });
      onClose();
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate();
  }
  const selectClass =
    "mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-inset ring-slate-300 focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700";
  return (
    <Dialog open onClose={onClose} title={rule ? "Change allowlist rule" : alert ? "Don't alert on this again" : "Add an allowlist rule"} wide>
      <form onSubmit={submit} className="space-y-4">
        <p className="text-sm text-slate-600 dark:text-slate-300">
          Alerts this rule matches are skipped and only counted, so expected activity doesn't hide the rest. Every field you fill in must
          match; clear a field to match anything there.
        </p>
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="text-sm font-medium">Alert</span>
            <select className={selectClass} value={form.rule} onChange={set("rule")}>
              {Object.entries(liveRules).map(([id, name]) => (
                <option key={id} value={id}>
                  {id}: {name}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="text-sm font-medium">Applies to</span>
            <select className={selectClass} value={form.host_id} onChange={set("host_id")}>
              {scopes.map((scope) => (
                <option key={scope.value} value={scope.value}>
                  {scope.label}
                </option>
              ))}
            </select>
          </label>
        </div>
        <Field label="Program" value={form.program} onChange={set("program")} placeholder="/usr/sbin/insmod" hint="The program's full path, as alerts show it." />
        <Field label="File, module or process (optional)" value={form.path} onChange={set("path")} placeholder="/opt/zfs/zfs.ko" />
        <div className="grid gap-3 sm:grid-cols-3">
          <Field label="Image (optional)" value={form.image} onChange={set("image")} placeholder="ghcr.io/acme/builder" hint="Without a tag: every tag." />
          <Field label="Container (optional)" value={form.container} onChange={set("container")} placeholder="builder" />
          <Field label="Namespace (optional)" value={form.namespace} onChange={set("namespace")} placeholder="ci" hint="Kubernetes." />
        </div>
        <Field label="Why it's expected (optional)" maxLength={500} value={form.note} onChange={set("note")} placeholder="The vendor's ZFS module, loaded at boot" />
        <ErrorMessage error={save.error} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending}>
            {rule ? "Save rule" : "Add to allowlist"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/** Every host and cluster a rule can apply to, after "All hosts". */
export function useAllowScopes(): AllowScope[] {
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: api.hosts });
  return [
    { value: "", label: "All hosts" },
    ...(hosts.data ?? [])
      .filter((host) => host.live)
      .map((host) => ({ value: host.id, label: host.kind === "cluster" ? `${host.address} (cluster)` : host.address })),
  ];
}

/** Settings → Live detection allowlist. */
export function LiveAllowlist() {
  const queryClient = useQueryClient();
  const canChange = useCan("admin");
  const scopes = useAllowScopes();
  const { data, error, isPending } = useQuery({ queryKey: ["live-allowlist"], queryFn: api.liveAllowlist });
  const [editing, setEditing] = useState<LiveAllow | "new" | null>(null);
  const remove = useMutation({
    mutationFn: api.removeLiveAllow,
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["live-allowlist"] }),
  });
  return (
    <Card className="mb-6">
      <div id="live-allowlist" className="scroll-mt-20" />
      <CardHeader
        title="Live detection allowlist"
        description="Alerts you expect, such as a backup tool loading its kernel module or a build container running programs from /tmp, are skipped here and counted, never deleted. A rule covers one alert and at least one program, file, image, container or namespace."
        action={
          canChange && (
            <Button variant="secondary" onClick={() => setEditing("new")}>
              Add a rule
            </Button>
          )
        }
      />
      {isPending ? (
        <Loading />
      ) : error ? (
        <div className="px-5 pb-4">
          <ErrorMessage error={error} />
        </div>
      ) : data.length === 0 ? (
        <EmptyState
          icon={<ListChecks className="size-6" />}
          title="No allowlist rules"
          description="Every alert is shown. Add a rule here, or with Don't alert on this again on an alert."
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Alert</Th>
              <Th>Matches</Th>
              <Th>Applies to</Th>
              <Th className="text-right">Skipped</Th>
              {canChange && <Th />}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {data.map((rule) => (
              <tr key={rule.id} className="align-top">
                <Td>
                  <p className="font-medium">{liveRules[rule.rule] ?? rule.rule}</p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">{rule.rule}</p>
                </Td>
                <Td className="max-w-md">
                  <dl className="space-y-0.5 text-xs">
                    {matches(rule).map(([name, value]) => (
                      <div key={name} className="flex gap-1.5">
                        <dt className="text-slate-500 dark:text-slate-400">{name}</dt>
                        <dd className="font-mono break-all">{value}</dd>
                      </div>
                    ))}
                  </dl>
                  {rule.note && <p className="mt-1 text-xs text-slate-600 dark:text-slate-300">{rule.note}</p>}
                  <p className="mt-1 text-xs text-slate-500 dark:text-slate-400" title={dateTime(rule.updated_at)}>
                    Added by {rule.created_by || "someone"} {timeAgo(rule.created_at)}
                  </p>
                </Td>
                <Td className="whitespace-nowrap">{rule.scope}</Td>
                <Td className="text-right whitespace-nowrap tabular-nums">
                  {new Intl.NumberFormat().format(rule.skipped)}
                  {rule.last_at && (
                    <span className="block text-xs text-slate-500 dark:text-slate-400" title={dateTime(rule.last_at)}>
                      last {timeAgo(rule.last_at)}
                    </span>
                  )}
                </Td>
                {canChange && (
                  <Td className="text-right whitespace-nowrap">
                    <button type="button" className="text-sm text-indigo-600 hover:underline dark:text-indigo-300" onClick={() => setEditing(rule)}>
                      Edit
                    </button>
                    <button
                      type="button"
                      className="ml-3 text-sm text-red-600 hover:underline disabled:opacity-50 dark:text-red-400"
                      disabled={remove.isPending}
                      onClick={() => {
                        if (window.confirm(`Remove this rule? Its alerts are shown again from the next one.`)) remove.mutate(rule.id);
                      }}
                    >
                      Remove
                    </button>
                  </Td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      {remove.error && (
        <div className="px-5 pb-4">
          <ErrorMessage error={remove.error} />
        </div>
      )}
      {editing && (
        <AllowDialog rule={editing === "new" ? undefined : editing} scopes={scopes} onClose={() => setEditing(null)} />
      )}
    </Card>
  );
}
