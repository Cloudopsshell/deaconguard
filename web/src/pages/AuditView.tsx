import { useMemo, useState, type FormEvent } from "react";
import { Link, useParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { AlertTriangle, ArrowLeft, ChevronRight, Info, Loader2 } from "lucide-react";
import { api, type AuditControl, type AuditDetail, type AuditSummary, type ComplianceResult, type Inventory, type PolicyResult, type RequirementStatus, type STIGRule } from "../api";
import { Button, Card, CardHeader, Dialog, ErrorMessage, Field, Loading, SeverityBadge, StatusBadge, cx } from "../components/ui";
import { ReportsPanel } from "../components/ReportsPanel";
import { ControlStatusBadge, GradeBadge, formatBytes, formatUptime } from "../lib/audit";
import { checkStatusStyle } from "../lib/checks";
import { dateTime, isActive, normalizeSeverity } from "../lib/format";
import { useCan } from "../lib/role";
import { ReleaseBadge } from "../components/ReleaseSupport";

type Filter = "fail" | "accepted" | "pass" | "other" | "all";

/** One audit: its grade, what holds it back, every control, and the machine's inventory. */
export function AuditView() {
  const { auditId = "" } = useParams();
  const { data, error, isPending } = useQuery({
    queryKey: ["audit", auditId],
    queryFn: () => api.auditDetail(auditId),
    refetchInterval: (query) => (isActive(query.state.data?.scan.status) ? 3000 : false),
  });
  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;
  return (
    <>
      <Link to="/audits" className="mb-4 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200">
        <ArrowLeft className="size-4" /> Server audits
      </Link>
      <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-2xl font-bold tracking-tight">Audit of {data.host.address}</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
            {[data.scan.os, `started ${dateTime(data.scan.started_at)}`, data.scan.finished_at && `finished ${dateTime(data.scan.finished_at)}`]
              .filter(Boolean)
              .join(" · ")}
            <ReleaseBadge lifecycle={data.scan.lifecycle} onlyProblems className="ml-2" />
          </p>
        </div>
        <div className="flex gap-3 text-sm">
          <Link to={`/hosts/${data.host.id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
            Host page
          </Link>
          {data.summary && (
            <Link to={`/scans/${data.scan.id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
              Full scan report
            </Link>
          )}
        </div>
      </div>
      {data.summary ? <AuditResult detail={data} summary={data.summary} /> : <AuditProgress detail={data} />}
    </>
  );
}

function AuditProgress({ detail }: { detail: AuditDetail }) {
  const running = isActive(detail.scan.status);
  return (
    <Card>
      <div className="flex items-start gap-4 p-6">
        {running ? <Loader2 className="mt-0.5 size-6 shrink-0 animate-spin text-indigo-600" /> : <AlertTriangle className="mt-0.5 size-6 shrink-0 text-red-600" />}
        <div className="space-y-2 text-sm">
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold">{running ? "The audit is running" : "The audit did not finish"}</h2>
            <StatusBadge status={detail.scan.status} />
          </div>
          {running ? (
            <p className="text-slate-600 dark:text-slate-300">
              It takes a few minutes, mostly for the antivirus scan. This page updates by itself, and you can leave it: the audit continues.{" "}
              <Link to={`/hosts/${detail.host.id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
                Watch it live on the host's page
              </Link>
              .
            </p>
          ) : (
            <p className="text-slate-600 dark:text-slate-300">{detail.scan.error || "The scan stopped without a result."} Run the audit again from the host's page.</p>
          )}
        </div>
      </div>
    </Card>
  );
}

function AuditResult({ detail, summary }: { detail: AuditDetail; summary: AuditSummary }) {
  const counts = summary.counts;
  const applicable = counts.passed + counts.failed;
  return (
    <div className="space-y-6">
      <Card>
        <div className="flex flex-wrap items-center gap-6 p-6">
          <GradeBadge grade={summary.grade} size="lg" />
          <div className="min-w-0 flex-1">
            <p className="text-lg font-semibold">
              Score {summary.score} of 100 · {counts.passed} of {applicable} controls passed
            </p>
            <p className="mt-1 text-sm text-slate-600 dark:text-slate-300">
              {[
                counts.failed > 0 && `${counts.failed} failed`,
                counts.accepted > 0 && `${counts.accepted} accepted as risks`,
                counts.not_applicable > 0 && `${counts.not_applicable} not applicable`,
                counts.unknown > 0 && `${counts.unknown} not checked`,
              ]
                .filter(Boolean)
                .join(" · ") || "Every applicable control passed."}
            </p>
            <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">
              The score weighs each control by severity. The grade is A from 90, B from 80, C from 70, D from 60, then lowered by anything that should stop a
              handover.
            </p>
          </div>
        </div>
        {(summary.caps.length > 0 || summary.incomplete.length > 0) && (
          <div className="space-y-3 border-t border-slate-200 px-6 py-4 dark:border-slate-800">
            {summary.caps.length > 0 && (
              <div>
                <p className="text-sm font-semibold">What holds the grade back</p>
                <ul className="mt-1 space-y-1 text-sm text-red-700 dark:text-red-400">
                  {summary.caps.map((reason) => (
                    <li key={reason} className="flex gap-2">
                      <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden /> {reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
            {summary.incomplete.length > 0 && (
              <div>
                <p className="text-sm font-semibold">Not fully checked</p>
                <ul className="mt-1 space-y-1 text-sm text-amber-800 dark:text-amber-300">
                  {summary.incomplete.map((reason) => (
                    <li key={reason} className="flex gap-2">
                      <Info className="mt-0.5 size-4 shrink-0" aria-hidden /> {reason}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        )}
      </Card>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader title="Vulnerabilities" description="Installed packages against the distribution's own security advisories." />
          <div className="grid grid-cols-2 gap-4 px-5 py-4 text-sm sm:grid-cols-4">
            <Stat label="Critical, fix available" value={summary.packages?.actionable.critical ?? 0} tone="red" />
            <Stat label="High, fix available" value={summary.packages?.actionable.high ?? 0} tone="orange" />
            <Stat label="Medium and low, fix available" value={(summary.packages?.actionable.medium ?? 0) + (summary.packages?.actionable.low ?? 0)} />
            <Stat label="Waiting on the distribution" value={summary.packages?.counts.none ?? 0} />
          </div>
        </Card>
        <Card>
          <CardHeader title="Other checks" />
          <ul className="divide-y divide-slate-200 dark:divide-slate-800">
            {summary.checks.map((check) => (
              <li key={check.id} className="flex flex-wrap items-center justify-between gap-2 px-5 py-2.5 text-sm">
                <span className="font-medium">{check.name}</span>
                <span className="flex items-center gap-2">
                  <span className="text-slate-600 dark:text-slate-300">{check.summary}</span>
                  {check.status && (
                    <span className={cx("rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", checkStatusStyle[check.status]?.className)}>
                      {checkStatusStyle[check.status]?.label ?? check.status}
                    </span>
                  )}
                </span>
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <AuditReports detail={detail} />
      <Controls detail={detail} summary={summary} />
      {summary.policies.map((result) => (
        <PolicyCard key={result.id} detail={detail} result={result} />
      ))}
      {detail.compliance && detail.compliance.length > 0 && <ComplianceCard results={detail.compliance} />}
      {summary.inventory && <InventoryCard inventory={summary.inventory} />}
    </div>
  );
}

function Stat({ label, value, tone }: { label: string; value: number; tone?: "red" | "orange" }) {
  return (
    <div>
      <p
        className={cx(
          "text-2xl font-semibold",
          value > 0 && tone === "red" && "text-red-600 dark:text-red-400",
          value > 0 && tone === "orange" && "text-orange-600 dark:text-orange-400",
        )}
      >
        {value.toLocaleString()}
      </p>
      <p className="text-xs text-slate-500 dark:text-slate-400">{label}</p>
    </div>
  );
}

function Controls({ detail, summary }: { detail: AuditDetail; summary: AuditSummary }) {
  const [filter, setFilter] = useState<Filter>(summary.counts.failed > 0 ? "fail" : "all");
  const [accepting, setAccepting] = useState<AuditControl | null>(null);
  const filters: { id: Filter; label: string; count: number }[] = [
    { id: "fail", label: "Failed", count: summary.counts.failed },
    { id: "accepted", label: "Accepted", count: summary.counts.accepted },
    { id: "pass", label: "Passed", count: summary.counts.passed },
    { id: "other", label: "Not applicable or not checked", count: summary.counts.not_applicable + summary.counts.unknown },
    { id: "all", label: "All", count: summary.controls.length },
  ];
  const shown = summary.controls.filter((control) =>
    filter === "all" ? true : filter === "other" ? control.status === "na" || control.status === "unknown" : control.status === filter,
  );
  const grouped = useMemo(() => {
    const groups = new Map<string, AuditControl[]>();
    for (const control of shown) groups.set(control.category, [...(groups.get(control.category) ?? []), control]);
    return [...groups.entries()];
  }, [shown]);
  return (
    <Card>
      <CardHeader title="Hardening baseline" description={`${summary.controls.length} controls of the DeaconGuard Linux baseline, by category.`} />
      <div className="flex flex-wrap gap-2 border-b border-slate-200 px-5 py-3 dark:border-slate-800" role="tablist" aria-label="Show controls">
        {filters.map((option) => (
          <button
            key={option.id}
            type="button"
            role="tab"
            aria-selected={filter === option.id}
            onClick={() => setFilter(option.id)}
            className={cx(
              "rounded-full px-3 py-1 text-sm font-medium transition-colors",
              filter === option.id
                ? "bg-indigo-600 text-white"
                : "bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700",
            )}
          >
            {option.label} <span className="opacity-75">{option.count}</span>
          </button>
        ))}
      </div>
      <div className="grid grid-cols-2 gap-x-6 gap-y-1 border-b border-slate-200 px-5 py-3 text-xs sm:grid-cols-3 lg:grid-cols-5 dark:border-slate-800">
        {summary.categories
          .filter((category) => category.passed + category.failed + category.accepted + category.not_applicable + category.unknown > 0)
          .map((category) => (
            <p key={category.name} className="flex justify-between gap-2">
              <span className="truncate text-slate-600 dark:text-slate-300">{category.name}</span>
              <span className={cx("font-medium whitespace-nowrap", category.failed > 0 ? "text-red-600 dark:text-red-400" : "text-emerald-700 dark:text-emerald-400")}>
                {category.passed}/{category.passed + category.failed}
              </span>
            </p>
          ))}
      </div>
      {shown.length === 0 ? (
        <p className="px-5 py-8 text-center text-sm text-slate-500 dark:text-slate-400">No controls here.</p>
      ) : (
        grouped.map(([category, controls]) => (
          <section key={category}>
            <h3 className="bg-slate-50 px-5 py-2 text-xs font-semibold tracking-wide text-slate-500 uppercase dark:bg-slate-900/60 dark:text-slate-400">{category}</h3>
            <ul className="divide-y divide-slate-200 dark:divide-slate-800">
              {controls.map((control) => (
                <ControlRow key={control.id} control={control} onAccept={() => setAccepting(control)} />
              ))}
            </ul>
          </section>
        ))
      )}
      {accepting && <AcceptRiskDialog detail={detail} control={accepting} onClose={() => setAccepting(null)} />}
    </Card>
  );
}

/** The STIG rules a control checks, and what each asks for beyond it. */
function STIGRules({ rules }: { rules: STIGRule[] }) {
  const notes = [...new Set(rules.map((rule) => rule.note).filter(Boolean))];
  return (
    <div>
      <p>
        <span className="font-medium">{rules[0].stig}: </span>
        <span className="font-mono text-xs text-slate-600 dark:text-slate-300">{rules.map((rule) => rule.rule).join(", ")}</span>
      </p>
      {notes.map((note) => (
        <p key={note} className="mt-1 text-xs text-amber-800 dark:text-amber-200">
          {note}
        </p>
      ))}
    </div>
  );
}

function ControlRow({ control, onAccept }: { control: AuditControl; onAccept: () => void }) {
  const canAccept = useCan("admin");
  const queryClient = useQueryClient();
  const withdraw = useMutation({
    mutationFn: () => api.removeException(control.exception!.id),
    onSettled: () => queryClient.invalidateQueries(),
  });
  return (
    <li>
      <details className="group">
        <summary className="flex cursor-pointer list-none items-start gap-3 px-5 py-3 hover:bg-slate-50 dark:hover:bg-slate-800/40 [&::-webkit-details-marker]:hidden">
          <ChevronRight className="mt-0.5 size-4 shrink-0 text-slate-400 transition-transform group-open:rotate-90" aria-hidden />
          <span className="min-w-0 flex-1">
            <span className="flex flex-wrap items-center gap-2">
              <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{control.id}</span>
              <span className="text-sm font-medium">{control.title}</span>
              {control.stig?.map((rule) => (
                <span
                  key={rule.rule}
                  className="rounded bg-slate-100 px-1.5 py-0.5 font-mono text-[11px] text-slate-600 dark:bg-slate-800 dark:text-slate-300"
                  title={`${rule.stig} ${rule.rule}`}
                >
                  {rule.rule}
                </span>
              ))}
            </span>
            <span className="mt-0.5 block text-xs break-words text-slate-500 dark:text-slate-400">{control.evidence}</span>
          </span>
          <span className="flex shrink-0 items-center gap-2">
            <SeverityBadge severity={normalizeSeverity(control.severity)} />
            <ControlStatusBadge status={control.status} />
          </span>
        </summary>
        <div className="space-y-3 px-12 pb-4 text-sm">
          <p>
            <span className="font-medium">Why it matters: </span>
            <span className="text-slate-600 dark:text-slate-300">{control.rationale}</span>
          </p>
          <p>
            <span className="font-medium">How to fix: </span>
            <span className="text-slate-600 dark:text-slate-300">{control.remediation}</span>
          </p>
          {control.stig && control.stig.length > 0 && <STIGRules rules={control.stig} />}
          {control.exception && (
            <div className="rounded-lg bg-indigo-50 px-3 py-2 text-indigo-900 ring-1 ring-indigo-600/20 ring-inset dark:bg-indigo-500/10 dark:text-indigo-200">
              <p>
                <span className="font-medium">Accepted {control.exception.host_id ? "for this host" : "for every host"}</span> by {control.exception.created_by}{" "}
                on {dateTime(control.exception.created_at)}
                {control.exception.expires_at ? `, until ${dateTime(control.exception.expires_at)}` : ", with no expiry"}:
              </p>
              <p className="mt-1">{control.exception.reason}</p>
              {canAccept && (
                <Button variant="ghost" className="mt-1 -ml-3" loading={withdraw.isPending} onClick={() => withdraw.mutate()}>
                  Withdraw
                </Button>
              )}
              <ErrorMessage error={withdraw.error} />
            </div>
          )}
          {control.status === "fail" && canAccept && (
            <Button variant="secondary" onClick={onAccept}>
              Accept the risk
            </Button>
          )}
        </div>
      </details>
    </li>
  );
}

const day = 24 * 60 * 60 * 1000;

function AcceptRiskDialog({ detail, control, onClose }: { detail: AuditDetail; control: AuditControl; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [reason, setReason] = useState("");
  const [everyHost, setEveryHost] = useState(false);
  const [expires, setExpires] = useState(() => new Date(Date.now() + 90 * day).toISOString().slice(0, 10));
  const [noExpiry, setNoExpiry] = useState(false);
  const accept = useMutation({
    mutationFn: () =>
      api.addException({
        host_id: everyHost ? "" : detail.host.id,
        control_id: control.id,
        reason,
        expires_at: noExpiry ? "" : new Date(`${expires}T23:59:59`).toISOString(),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries();
      onClose();
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    accept.mutate();
  }
  return (
    <Dialog open onClose={onClose} title={`Accept the risk: ${control.id}`}>
      <form className="space-y-4 text-sm" onSubmit={submit}>
        <p className="text-slate-600 dark:text-slate-300">
          <span className="font-medium">{control.title}</span> failed. Accepting the risk shows it as accepted in this audit and later ones, and leaves it out of
          the score. The reason is shown with it and recorded in the audit log.
        </p>
        <label className="block">
          <span className="font-medium">Reason</span>
          <textarea
            required
            rows={3}
            maxLength={1000}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
            placeholder="For example: password logins are needed for the client's legacy backup tool until March."
            className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700"
            data-autofocus
          />
        </label>
        <fieldset>
          <legend className="font-medium">Applies to</legend>
          <label className="mt-1 flex items-center gap-2">
            <input type="radio" name="scope" className="accent-indigo-600" checked={!everyHost} onChange={() => setEveryHost(false)} /> {detail.host.address} only
          </label>
          <label className="mt-1 flex items-center gap-2">
            <input type="radio" name="scope" className="accent-indigo-600" checked={everyHost} onChange={() => setEveryHost(true)} /> Every host
          </label>
        </fieldset>
        <div className="flex flex-wrap items-end gap-4">
          <div className="w-44">
            <Field label="Until" type="date" value={expires} disabled={noExpiry} required={!noExpiry} onChange={(event) => setExpires(event.target.value)} />
          </div>
          <label className="mb-2 flex items-center gap-2">
            <input type="checkbox" className="accent-indigo-600" checked={noExpiry} onChange={(event) => setNoExpiry(event.target.checked)} /> No expiry
          </label>
        </div>
        <ErrorMessage error={accept.error} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={accept.isPending}>
            Accept the risk
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function InventoryCard({ inventory }: { inventory: Inventory }) {
  const facts: [string, string][] = [
    ["Host name", inventory.hostname],
    ["Operating system", inventory.os],
    ["Kernel", `${inventory.kernel} (${inventory.architecture})`],
    ["Runs on", inventory.virtualization && inventory.virtualization !== "none" ? inventory.virtualization : "physical hardware"],
    ["Processors", String(inventory.cpus || "—")],
    ["Memory", formatBytes(inventory.memory_bytes)],
    ["Up for", formatUptime(inventory.uptime_seconds)],
    ["Packages", inventory.packages.toLocaleString()],
    ["Time zone", `${inventory.timezone || "—"}${inventory.time_synced ? ", clock synchronised" : ""}`],
    ["Administrators", (inventory.administrators ?? []).join(", ") || "—"],
    ["Accounts that can log in", (inventory.login_users ?? []).join(", ") || "—"],
    ["Addresses", (inventory.addresses ?? []).join(", ") || "—"],
  ];
  return (
    <Card>
      <CardHeader title="Inventory" description="What the machine is and what runs on it, when it was audited." />
      <dl className="grid gap-x-8 gap-y-3 px-5 py-4 text-sm sm:grid-cols-2 lg:grid-cols-3">
        {facts.map(([label, value]) => (
          <div key={label} className="min-w-0">
            <dt className="text-xs text-slate-500 dark:text-slate-400">{label}</dt>
            <dd className="break-words">{value}</dd>
          </div>
        ))}
      </dl>
      <div className="grid gap-6 border-t border-slate-200 px-5 py-4 lg:grid-cols-2 dark:border-slate-800">
        <div className="min-w-0">
          <h3 className="mb-2 text-sm font-semibold">Disks</h3>
          <ul className="space-y-2 text-sm">
            {(inventory.disks ?? []).map((disk) => (
              <li key={disk.mount}>
                <div className="flex justify-between gap-2">
                  <span className="truncate font-mono text-xs">{disk.mount}</span>
                  <span className="text-xs whitespace-nowrap text-slate-500 dark:text-slate-400">
                    {formatBytes(disk.used_bytes)} of {formatBytes(disk.size_bytes)} · {disk.used_percent}%
                  </span>
                </div>
                <div className="mt-1 h-1.5 rounded-full bg-slate-200 dark:bg-slate-800">
                  <div
                    className={cx("h-1.5 rounded-full", disk.used_percent >= 90 ? "bg-red-500" : disk.used_percent >= 75 ? "bg-amber-500" : "bg-emerald-500")}
                    style={{ width: `${Math.min(disk.used_percent, 100)}%` }}
                  />
                </div>
              </li>
            ))}
            {(inventory.disks ?? []).length === 0 && <li className="text-slate-500">—</li>}
          </ul>
        </div>
        <div className="min-w-0">
          <h3 className="mb-2 text-sm font-semibold">Listening services</h3>
          <ul className="space-y-1 text-sm">
            {(inventory.listening ?? []).map((socket) => (
              <li key={`${socket.protocol}/${socket.address}/${socket.port}`} className="flex justify-between gap-2">
                <span className="font-mono text-xs">
                  {socket.protocol.toUpperCase()} {socket.port}
                </span>
                <span className={cx("text-xs", socket.exposed ? "text-amber-700 dark:text-amber-400" : "text-slate-500 dark:text-slate-400")}>
                  {socket.exposed ? "all interfaces" : socket.address}
                </span>
              </li>
            ))}
            {(inventory.listening ?? []).length === 0 && <li className="text-slate-500">Nothing listens for connections.</li>}
          </ul>
        </div>
      </div>
    </Card>
  );
}

/** Reports of this audit, offering to compare with the host's earlier audits. */
function AuditReports({ detail }: { detail: AuditDetail }) {
  const audits = useQuery({ queryKey: ["audits", detail.host.id], queryFn: () => api.auditList(detail.host.id) });
  const list = audits.data ?? [];
  const index = list.findIndex((item) => item.id === detail.scan.id);
  const earlier = index >= 0 ? list.slice(index + 1).filter((item) => item.status === "succeeded") : [];
  return <ReportsPanel scan={detail.scan} earlierAudits={earlier} />;
}

/** One custom policy's controls on this audit. */
function PolicyCard({ detail, result }: { detail: AuditDetail; result: PolicyResult }) {
  const [accepting, setAccepting] = useState<AuditControl | null>(null);
  const counts = result.counts;
  return (
    <Card>
      <CardHeader
        title={`Policy: ${result.name}`}
        description={`Your organisation's own controls, tested on the same settings; they don't change the grade. ${counts.passed} passed · ${counts.failed} failed${counts.accepted ? ` · ${counts.accepted} accepted` : ""}${counts.not_applicable + counts.unknown ? ` · ${counts.not_applicable + counts.unknown} not applicable or not checked` : ""}.`}
        action={
          <Link to="/policies" className="text-sm font-medium text-indigo-600 hover:underline dark:text-indigo-400">
            Policies
          </Link>
        }
      />
      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
        {result.controls.map((control) => (
          <ControlRow key={control.id} control={control} onAccept={() => setAccepting(control)} />
        ))}
      </ul>
      {accepting && <AcceptRiskDialog detail={detail} control={accepting} onClose={() => setAccepting(null)} />}
    </Card>
  );
}

const requirementStyle: Record<RequirementStatus, { label: string; className: string }> = {
  met: { label: "Met", className: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300" },
  met_accepted: { label: "Met, risk accepted", className: "bg-indigo-50 text-indigo-700 ring-indigo-600/20 dark:bg-indigo-500/15 dark:text-indigo-300" },
  not_met: { label: "Not met", className: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300" },
  not_checked: { label: "Not checked", className: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300" },
  not_evaluated: { label: "Not applicable", className: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300" },
  partial: { label: "Partly checked", className: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300" },
};

/** The audit read framework by framework. */
function ComplianceCard({ results }: { results: ComplianceResult[] }) {
  const [active, setActive] = useState(results[0].framework.id);
  const result = results.find((item) => item.framework.id === active) ?? results[0];
  return (
    <Card>
      <CardHeader
        title="Compliance"
        description="The requirements of each framework this audit gives evidence for. This is DeaconGuard's mapping, for guidance: frameworks also ask for policies, people and processes no scan can check, so it is not a certification."
      />
      <div className="flex flex-wrap gap-2 border-b border-slate-200 px-5 py-3 dark:border-slate-800" role="tablist" aria-label="Framework">
        {results.map((item) => (
          <button
            key={item.framework.id}
            type="button"
            role="tab"
            aria-selected={item.framework.id === active}
            onClick={() => setActive(item.framework.id)}
            className={cx(
              "rounded-full px-3 py-1 text-sm font-medium transition-colors",
              item.framework.id === active
                ? "bg-indigo-600 text-white"
                : "bg-slate-100 text-slate-700 hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700",
            )}
          >
            {item.framework.short}
          </button>
        ))}
      </div>
      <p className="px-5 pt-3 text-sm text-slate-600 dark:text-slate-300">
        {result.framework.name}: <span className="font-medium text-emerald-700 dark:text-emerald-400">{result.met} met</span> ·{" "}
        <span className={cx("font-medium", result.not_met > 0 && "text-red-600 dark:text-red-400")}>{result.not_met} not met</span>
        {result.other > 0 && ` · ${result.other} ${result.framework.id === "disa-stig" ? "partly or not checked" : "not checked"}`}
      </p>
      {result.framework.id === "disa-stig" && (
        <p className="px-5 pt-1 text-xs text-slate-500 dark:text-slate-400">
          {result.note ??
            "Only the STIG rules a baseline control checks are listed. Partly checked: the control passed, but the rule asks for more, so check the rest by hand. A STIG assessment covers many rules DeaconGuard doesn't read."}
        </p>
      )}
      <ul className="mt-2 divide-y divide-slate-200 dark:divide-slate-800">
        {result.requirements.map((requirement) => (
          <li key={requirement.id} className="flex flex-wrap items-start justify-between gap-x-4 gap-y-1 px-5 py-2.5 text-sm">
            <div className="min-w-0 flex-1">
              <p>
                <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{requirement.id}</span> <span className="font-medium">{requirement.name}</span>
              </p>
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {requirement.controls.map((control, index) => (
                  <span key={control.id}>
                    {index > 0 && ", "}
                    <span className={cx(control.status === "fail" && "text-red-600 dark:text-red-400")}>{control.id.replace("CHECK-", "")}</span>
                  </span>
                ))}
              </p>
            </div>
            <span className={cx("shrink-0 rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset", requirementStyle[requirement.status].className)}>
              {requirementStyle[requirement.status].label}
            </span>
          </li>
        ))}
      </ul>
    </Card>
  );
}
