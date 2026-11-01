import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Network as NetworkIcon, Play, Plus } from "lucide-react";
import { api, type NetworkTarget, type NetworkTargetInput } from "../api";
import { Button, Card, Dialog, EmptyState, ErrorMessage, Field, Loading, PageHeader, SeverityCountsInline, StatusBadge, Table, Td, Th, cx } from "../components/ui";
import { timeAgo } from "../lib/format";
import { useRefreshAll } from "../lib/hooks";
import { useCan } from "../lib/role";

export const intervals: { hours: number; label: string }[] = [
  { hours: 0, label: "Only when someone presses Scan now" },
  { hours: 1, label: "Every hour" },
  { hours: 6, label: "Every 6 hours" },
  { hours: 12, label: "Every 12 hours" },
  { hours: 24, label: "Every day" },
  { hours: 168, label: "Every week" },
];

export function intervalLabel(hours: number) {
  return intervals.find((interval) => interval.hours === hours)?.label ?? `Every ${hours} hours`;
}

export function count(n: number, word: string, plural = word + "s") {
  return `${n} ${n === 1 ? word : plural}`;
}

export function scanning(target?: NetworkTarget) {
  return target?.latest?.status === "queued" || target?.latest?.status === "running";
}

/** Network targets: what the server scans for open ports, exposed services and TLS. */
export function Network() {
  const isAdmin = useCan("admin");
  const canOperate = useCan("operator");
  const refresh = useRefreshAll();
  const targets = useQuery({
    queryKey: ["network-targets"],
    queryFn: api.networkTargets,
    refetchInterval: (query) => ((query.state.data ?? []).some(scanning) ? 3_000 : 30_000),
  });
  const [editing, setEditing] = useState<NetworkTarget | "new" | null>(null);
  const scan = useMutation({ mutationFn: (target: NetworkTarget) => api.scanNetworkTarget(target.id), onSettled: refresh });

  return (
    <>
      <PageHeader
        title="Network"
        description="Scan your networks and public addresses from the server: open ports, what answers on them, exposed databases, Docker, kubelets or cleartext logins, TLS certificates and settings, and web sites that publish files they shouldn't or lack protections. DeaconGuard only connects and reads pages; it never logs in, submits forms or attacks."
        action={
          isAdmin && (
            <Button onClick={() => setEditing("new")}>
              <Plus className="size-4" /> Add target
            </Button>
          )
        }
      />
      <ErrorMessage error={scan.error} />
      {targets.isPending ? (
        <Loading />
      ) : targets.error ? (
        <ErrorMessage error={targets.error} />
      ) : targets.data.length === 0 ? (
        <Card>
          <EmptyState
            icon={<NetworkIcon className="size-6" />}
            title="No network targets yet"
            description="Add the ranges and names you own, such as 10.0.0.0/24 or shop.example.com, and how often to scan them. Scan only networks you own or may test."
            action={
              isAdmin && (
                <Button onClick={() => setEditing("new")}>
                  <Plus className="size-4" /> Add target
                </Button>
              )
            }
          />
        </Card>
      ) : (
        <Card>
          <Table>
            <thead>
              <tr>
                <Th>Target</Th>
                <Th>Last scan</Th>
                <Th>Found</Th>
                {canOperate && <Th className="text-right">Actions</Th>}
              </tr>
            </thead>
            <tbody>
              {targets.data.map((target) => (
                <tr key={target.id}>
                  <Td className="min-w-44">
                    <Link to={`/network/${target.id}`} className="font-medium text-indigo-700 hover:underline dark:text-indigo-400">
                      {target.name}
                    </Link>
                    <div className="font-mono text-xs break-all text-slate-500 dark:text-slate-400">{target.targets.join(", ")}</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">{intervalLabel(target.interval_hours)}</div>
                  </Td>
                  <Td>
                    {target.latest ? (
                      <div className="space-y-1">
                        <StatusBadge status={target.latest.status} />
                        <div className="text-xs text-slate-500 dark:text-slate-400">{timeAgo(target.latest.finished_at || target.latest.started_at)}</div>
                      </div>
                    ) : (
                      <span className="text-sm text-slate-500 dark:text-slate-400">Not scanned</span>
                    )}
                  </Td>
                  <Td>
                    {target.latest?.status === "succeeded" ? (
                      <div className="space-y-1">
                        <div className="text-sm">
                          {count(target.latest.hosts, "host")} · {count(target.latest.open_ports, "open port")}
                        </div>
                        <SeverityCountsInline counts={target.latest.severity} />
                      </div>
                    ) : target.latest?.status === "failed" ? (
                      <span className="line-clamp-2 max-w-56 text-sm break-words text-red-700 dark:text-red-400" title={target.latest.error}>
                        {target.latest.error}
                      </span>
                    ) : (
                      <span className="text-sm text-slate-500 dark:text-slate-400">—</span>
                    )}
                  </Td>
                  {canOperate && (
                    <Td className="text-right">
                      <Button variant="secondary" disabled={scanning(target)} loading={scan.isPending && scan.variables?.id === target.id} onClick={() => scan.mutate(target)}>
                        <Play className="size-4" /> Scan now
                      </Button>
                    </Td>
                  )}
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
      {editing && <NetworkTargetDialog target={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
    </>
  );
}

export function NetworkTargetDialog({ target, onClose }: { target: NetworkTarget | null; onClose: () => void }) {
  const refresh = useRefreshAll();
  const [input, setInput] = useState<NetworkTargetInput>(() =>
    target
      ? { name: target.name, targets: target.targets, ports: target.ports, tls: target.tls, web: target.web, web_paths: target.web_paths, interval_hours: target.interval_hours }
      : { name: "", targets: [], ports: "", tls: true, web: true, web_paths: true, interval_hours: 24 },
  );
  const [targetsText, setTargetsText] = useState((target?.targets ?? []).join("\n"));
  const save = useMutation({
    mutationFn: () => {
      const body = { ...input, targets: targetsText.split(/[\s,]+/).filter(Boolean) };
      return target ? api.updateNetworkTarget(target.id, body) : api.createNetworkTarget(body);
    },
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title={target ? `Edit ${target.name}` : "Add network target"}>
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <Field label="Name" value={input.name} onChange={(event) => setInput({ ...input, name: event.target.value })} placeholder="Office network" maxLength={80} required data-autofocus />
        <label className="block">
          <span className="text-sm font-medium">Addresses, ranges and names</span>
          <textarea
            value={targetsText}
            onChange={(event) => setTargetsText(event.target.value)}
            rows={4}
            required
            placeholder={"10.0.0.0/24\nshop.example.com\n203.0.113.10"}
            className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 font-mono text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
          />
          <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">One per line. At most 4096 addresses; a range at most a /20.</span>
        </label>
        <Field
          label="Ports"
          value={input.ports}
          onChange={(event) => setInput({ ...input, ports: event.target.value })}
          placeholder="default"
          hint="Empty scans about 70 well-known ports; or 22,80,443,8000-8100."
        />
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={input.tls} onChange={(event) => setInput({ ...input, tls: event.target.checked })} className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-600" />
          Check the TLS of every TLS service found (certificates, protocols, ciphers)
        </label>
        <div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={input.web} onChange={(event) => setInput({ ...input, web: event.target.checked })} className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-600" />
            Check every web site found (headers, cookies, HTTPS redirects, CORS)
          </label>
          <label className={cx("mt-2 ml-6 flex items-start gap-2 text-sm", !input.web && "opacity-50")}>
            <input
              type="checkbox"
              checked={input.web && input.web_paths}
              disabled={!input.web}
              onChange={(event) => setInput({ ...input, web_paths: event.target.checked })}
              className="mt-0.5 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
            />
            <span>
              Look for files and pages that should never be public, such as /.git and /.env
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                About 15 GET requests a site, from a fixed list; nothing is crawled or submitted. A strict web application firewall may log them.
              </span>
            </span>
          </label>
        </div>
        <label className="block">
          <span className="text-sm font-medium">Scan</span>
          <select
            value={input.interval_hours}
            onChange={(event) => setInput({ ...input, interval_hours: Number(event.target.value) })}
            className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
          >
            {intervals.map((interval) => (
              <option key={interval.hours} value={interval.hours}>
                {interval.label}
              </option>
            ))}
          </select>
        </label>
        <p className="flex gap-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900 ring-1 ring-amber-600/20 ring-inset dark:bg-amber-500/10 dark:text-amber-200">
          <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden />
          Scan only networks you own or are allowed to test. The server connects to every address and port listed, from its own network.
        </p>
        <ErrorMessage error={save.error} />
        <div className="flex justify-end gap-2 border-t border-slate-200 pt-4 dark:border-slate-800">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending}>
            {target ? "Save" : "Add and scan"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
