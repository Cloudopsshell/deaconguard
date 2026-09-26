import { useState, type ChangeEvent, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { Play, Plus, Server, Trash2 } from "lucide-react";
import { api, type HostSummary } from "../api";
import {
  Button,
  Card,
  CoverageNotes,
  Dialog,
  EmptyState,
  ErrorMessage,
  Field,
  Loading,
  PageHeader,
  SeverityCountsInline,
  StatusBadge,
  Table,
  Td,
  Th,
  cx,
} from "../components/ui";
import { useRefreshAll } from "../lib/hooks";
import { isActive, severityStyle, timeAgo } from "../lib/format";
import { checkBadgeText, checkMeta, checkOrder, topSeverity } from "../lib/checks";
import { ScanDialog } from "../components/ScanDialog";
import { RemoveHostDialog } from "./HostDetail";

export function Hosts() {
  const [searchParams, setSearchParams] = useSearchParams();
  const adding = searchParams.get("add") === "1";
  const setAdding = (open: boolean) => setSearchParams(open ? { add: "1" } : {}, { replace: true });

  const { data, error, isPending } = useQuery({
    queryKey: ["hosts"],
    queryFn: api.hosts,
    refetchInterval: (query) => (query.state.data?.some((host) => isActive(host.last_scan?.status)) ? 2000 : false),
  });

  return (
    <>
      <PageHeader
        title="Hosts"
        description="Linux machines registered for agentless scanning. Only add systems you own or are authorized to scan."
        action={
          <Button onClick={() => setAdding(true)}>
            <Plus className="size-4" /> Add host
          </Button>
        }
      />
      <Card>
        {isPending ? (
          <Loading />
        ) : error ? (
          <div className="p-5">
            <ErrorMessage error={error} />
          </div>
        ) : data.length === 0 ? (
          <EmptyState
            icon={<Server className="size-6" />}
            title="No hosts yet"
            description="Add a host with its SSH address and username. No agent or root access is needed."
            action={
              <Button onClick={() => setAdding(true)}>
                <Plus className="size-4" /> Add host
              </Button>
            }
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Host</Th>
                <Th>Operating system</Th>
                <Th>Last scan</Th>
                <Th>Findings</Th>
                <Th className="text-right">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.map((host) => (
                <HostRow key={host.id} host={host} />
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      <AddHostDialog open={adding} onClose={() => setAdding(false)} />
    </>
  );
}

function HostRow({ host }: { host: HostSummary }) {
  const navigate = useNavigate();
  const [removing, setRemoving] = useState(false);
  const [scanning, setScanning] = useState(false);
  const running = isActive(host.last_scan?.status);
  return (
    <tr onClick={() => navigate(`/hosts/${host.id}`)} className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50">
      <Td>
        <Link to={`/hosts/${host.id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
          {host.address}
        </Link>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {host.username}@{host.address}:{host.port}
        </p>
      </Td>
      <Td className="text-slate-600 dark:text-slate-300">{host.last_report?.os || "—"}</Td>
      <Td>
        {host.last_scan ? (
          <div className="space-y-1">
            <StatusBadge status={host.last_scan.status} />
            <p className="text-xs text-slate-500 dark:text-slate-400">{timeAgo(host.last_scan.started_at)}</p>
          </div>
        ) : (
          <span className="text-sm text-slate-500 dark:text-slate-400">Never scanned</span>
        )}
      </Td>
      <Td>
        {host.last_report ? (
          <div className="space-y-1">
            <SeverityCountsInline counts={host.last_report.severity} />
            <CoverageNotes scan={host.last_report} />
          </div>
        ) : (
          <span className="text-sm text-slate-500 dark:text-slate-400">No vulnerability results</span>
        )}
        <CheckChips host={host} />
      </Td>
      <Td className="text-right">
        <div className="flex items-center justify-end gap-1">
          <Button
            variant="secondary"
            loading={running}
            onClick={(event) => {
              event.stopPropagation();
              setScanning(true);
            }}
          >
            {!running && <Play className="size-4" />}
            {host.last_scan?.status.startsWith("needs_") ? "Waiting for input" : running ? "Scanning" : "Scan"}
          </Button>
          <Button
            variant="ghost"
            className="px-2"
            title={`Remove ${host.address}`}
            aria-label={`Remove ${host.address}`}
            onClick={(event) => {
              event.stopPropagation();
              setRemoving(true);
            }}
          >
            <Trash2 className="size-4" />
          </Button>
        </div>
        <div className="text-left" onClick={(event) => event.stopPropagation()}>
          <RemoveHostDialog host={host} open={removing} onClose={() => setRemoving(false)} />
          <ScanDialog host={host} open={scanning} onClose={() => setScanning(false)} />
        </div>
      </Td>
    </tr>
  );
}

/** Compact results of the other checks, linking to the host's tab for each. */
function CheckChips({ host }: { host: HostSummary }) {
  const checks = checkOrder.filter((check) => check !== "packages" && host.checks?.[check]);
  if (checks.length === 0) return null;
  return (
    <div className="mt-1.5 flex flex-wrap gap-1.5">
      {checks.map((check) => {
        const summary = host.checks![check]!;
        const severity = topSeverity(summary.severity);
        return (
          <Link
            key={check}
            to={`/hosts/${host.id}?tab=${check}`}
            onClick={(event) => event.stopPropagation()}
            title={`${checkMeta[check].label}: ${summary.summary}`}
            className={cx(
              "rounded-md px-1.5 py-0.5 text-xs font-medium ring-1 ring-inset",
              summary.status === "skipped" || summary.status === "failed"
                ? "text-slate-500 ring-slate-300 dark:text-slate-400 dark:ring-slate-700"
                : summary.finding_count === 0
                  ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-400/30"
                  : severity
                  ? severityStyle[severity].badge
                  : "",
            )}
          >
            {checkMeta[check].short} {checkBadgeText(summary)}
            {summary.status === "partial" && <span title="Partial coverage">*</span>}
          </Link>
        );
      })}
    </div>
  );
}

function AddHostDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const refresh = useRefreshAll();
  const [form, setForm] = useState({ address: "", username: "", port: "22", key_path: "" });
  const [allowSudo, setAllowSudo] = useState(false);
  const addHost = useMutation({
    mutationFn: api.addHost,
    onSuccess: (host) => {
      refresh();
      setForm({ address: "", username: "", port: "22", key_path: "" });
      setAllowSudo(false);
      navigate(`/hosts/${host.id}`);
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    addHost.mutate({
      address: form.address.trim(),
      username: form.username.trim(),
      port: Number(form.port) || 22,
      key_path: form.key_path.trim(),
      allow_sudo: allowSudo,
    });
  }

  const update = (key: keyof typeof form) => (event: ChangeEvent<HTMLInputElement>) =>
    setForm((current) => ({ ...current, [key]: event.target.value }));

  return (
    <Dialog open={open} onClose={onClose} title="Add host">
      <form onSubmit={submit} className="space-y-4">
        <Field
          label="Address"
          placeholder="ubuntu.example.com or 10.0.0.12"
          value={form.address}
          onChange={update("address")}
          required
          autoFocus
        />
        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <Field label="SSH username" placeholder="ubuntu" value={form.username} onChange={update("username")} required />
          </div>
          <Field label="Port" type="number" min={1} max={65535} value={form.port} onChange={update("port")} required />
        </div>
        <Field
          label="Private key path (optional)"
          placeholder="~/.ssh/id_ed25519"
          value={form.key_path}
          onChange={update("key_path")}
          hint="Leave empty to use ssh-agent or your default keys. Encrypted keys must be loaded with ssh-add."
        />
        <label className="flex cursor-pointer gap-2 text-sm">
          <input
            type="checkbox"
            checked={allowSudo}
            onChange={(event) => setAllowSudo(event.target.checked)}
            className="mt-0.5 size-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
          />
          <span>
            <span className="font-medium">Allow sudo for deeper checks</span>
            <span className="block text-xs text-slate-500 dark:text-slate-400">
              Integrity, malware, configuration, and antivirus checks can read protected files and processes using fixed read-only
              commands. You can change this later.
            </span>
          </span>
        </label>
        <ErrorMessage error={addHost.error} />
        <div className="flex justify-end gap-2 pt-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={addHost.isPending}>
            Add host
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
