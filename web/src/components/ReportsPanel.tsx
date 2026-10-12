import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Download, FileText, Link2, Trash2 } from "lucide-react";
import { api, reportDownloadUrl, type ReportFormat, type ReportRecord, type Scan } from "../api";
import { dateTime } from "../lib/format";
import { useCan, useRole } from "../lib/role";
import { Button, Card, CardHeader, Dialog, ErrorMessage, Field, cx } from "./ui";

const formats: { id: ReportFormat; label: string }[] = [
  { id: "pdf", label: "PDF" },
  { id: "html", label: "HTML" },
  { id: "xlsx", label: "Excel" },
  { id: "csv", label: "CSV" },
  { id: "json", label: "JSON" },
];

/** Reports made from one audit or scan: create, download, share, delete. */
export function ReportsPanel({ scan, earlierAudits = [] }: { scan: Scan; earlierAudits?: Scan[] }) {
  const canCreate = useCan("operator");
  const [creating, setCreating] = useState(false);
  const reports = useQuery({ queryKey: ["reports", scan.id], queryFn: () => api.reports({ scanId: scan.id }) });
  const kind = scan.audit ? "audit" : "scan";
  return (
    <Card>
      <CardHeader
        title="Reports"
        description={`Hand this ${kind} over as a PDF, or as HTML, Excel, CSV or JSON. A report is frozen when it's made, so later changes don't alter it. Your company's name and logo come from Settings.`}
        action={
          canCreate && (
            <Button onClick={() => setCreating(true)}>
              <FileText className="size-4" /> Create report
            </Button>
          )
        }
      />
      {reports.error ? (
        <div className="p-5">
          <ErrorMessage error={reports.error} />
        </div>
      ) : reports.data && reports.data.length > 0 ? (
        <ul className="divide-y divide-slate-200 dark:divide-slate-800">
          {reports.data.map((report) => (
            <ReportRow key={report.id} report={report} />
          ))}
        </ul>
      ) : (
        reports.data && (
          <p className="px-5 py-6 text-sm text-slate-500 dark:text-slate-400">
            No reports yet.{canCreate ? " Create one to download or share it." : " An operator or admin can create one."}
          </p>
        )
      )}
      <p className="border-t border-slate-200 px-5 py-3 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
        Each report carries a fingerprint. To check a report someone gave you, use{" "}
        <Link to="/verify" className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
          Verify a report
        </Link>
        .
      </p>
      {creating && <CreateReportDialog scan={scan} earlierAudits={earlierAudits} onClose={() => setCreating(false)} />}
    </Card>
  );
}

function ReportRow({ report }: { report: ReportRecord }) {
  const canChange = useCan("operator");
  const queryClient = useQueryClient();
  const [sharing, setSharing] = useState(false);
  const shares = useQuery({ queryKey: ["shares", report.id], queryFn: () => api.shares(report.id) });
  const remove = useMutation({
    mutationFn: () => api.deleteReport(report.id),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["reports"] }),
  });
  const revoke = useMutation({
    mutationFn: api.revokeShare,
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["shares", report.id] }),
  });
  const active = (shares.data ?? []).filter((share) => !share.revoked_at && new Date(share.expires_at) > new Date());
  return (
    <li className="px-5 py-4">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 text-sm">
          <p className="font-medium">
            {report.client ? `For ${report.client}` : "Report"} · {dateTime(report.created_at)}
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            By {report.created_by} · ID {report.id.slice(0, 8)} · fingerprint <span className="font-mono">{report.fingerprint.slice(0, 16)}…</span>
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-1.5">
          {formats.map((format) => (
            <a
              key={format.id}
              href={reportDownloadUrl(report.id, format.id)}
              className={cx(
                "inline-flex items-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-semibold ring-1 ring-inset",
                format.id === "pdf"
                  ? "bg-indigo-600 text-white ring-indigo-600 hover:bg-indigo-500"
                  : "bg-white text-slate-700 ring-slate-300 hover:bg-slate-50 dark:bg-slate-900 dark:text-slate-200 dark:ring-slate-700 dark:hover:bg-slate-800",
              )}
            >
              {format.id === "pdf" && <Download className="size-4" aria-hidden />}
              {format.label}
            </a>
          ))}
          {canChange && (
            <>
              <Button variant="ghost" onClick={() => setSharing(true)} title="Share a link that opens without sign-in">
                <Link2 className="size-4" /> Share
              </Button>
              <Button
                variant="ghost"
                className="px-2"
                aria-label={`Delete the report of ${dateTime(report.created_at)}`}
                title="Delete this report"
                loading={remove.isPending}
                onClick={() => remove.mutate()}
              >
                <Trash2 className="size-4" />
              </Button>
            </>
          )}
        </div>
      </div>
      {active.length > 0 && (
        <ul className="mt-2 space-y-1 text-xs text-slate-600 dark:text-slate-300">
          {active.map((share) => (
            <li key={share.id} className="flex flex-wrap items-center gap-2">
              <Link2 className="size-3.5 text-indigo-600 dark:text-indigo-400" aria-hidden />
              Shared link, opens until {dateTime(share.expires_at)} · {share.views} {share.views === 1 ? "view" : "views"}
              {canChange && (
                <button
                  type="button"
                  className="font-medium text-red-600 hover:underline dark:text-red-400"
                  onClick={() => revoke.mutate(share.id)}
                  disabled={revoke.isPending}
                >
                  Revoke
                </button>
              )}
            </li>
          ))}
        </ul>
      )}
      <ErrorMessage error={remove.error ?? revoke.error} />
      {sharing && <ShareDialog report={report} onClose={() => setSharing(false)} />}
    </li>
  );
}

function CreateReportDialog({ scan, earlierAudits, onClose }: { scan: Scan; earlierAudits: Scan[]; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [client, setClient] = useState("");
  const [notes, setNotes] = useState("");
  const [compareWith, setCompareWith] = useState(earlierAudits.length > 0 ? "previous" : "");
  const [frameworks, setFrameworks] = useState<string[]>([]);
  const available = useQuery({ queryKey: ["frameworks"], queryFn: api.frameworks, staleTime: Infinity, enabled: scan.audit });
  const create = useMutation({
    mutationFn: () => api.createReport({ scan_id: scan.id, client, notes, compare_with: compareWith, frameworks }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["reports"] });
      onClose();
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate();
  }
  return (
    <Dialog open onClose={onClose} title={`Report of ${scan.address}`}>
      <form className="space-y-4 text-sm" onSubmit={submit}>
        <Field
          label="Prepared for"
          hint="The client or team receiving it. Optional."
          maxLength={200}
          value={client}
          onChange={(event) => setClient(event.target.value)}
          placeholder="Acme Corp"
          data-autofocus
        />
        <label className="block">
          <span className="font-medium">Notes</span>
          <textarea
            rows={3}
            maxLength={2000}
            value={notes}
            onChange={(event) => setNotes(event.target.value)}
            placeholder="For example: handover of the new web server, built from the standard image."
            className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700"
          />
          <span className="text-xs text-slate-500 dark:text-slate-400">Shown on the report's summary page. Optional.</span>
        </label>
        {scan.audit && earlierAudits.length > 0 && (
          <label className="block">
            <span className="font-medium">Compare with</span>
            <select
              value={compareWith}
              onChange={(event) => setCompareWith(event.target.value)}
              className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700"
            >
              <option value="previous">The audit before this one</option>
              {earlierAudits.map((audit) => (
                <option key={audit.id} value={audit.id}>
                  The audit of {dateTime(audit.started_at)}
                </option>
              ))}
              <option value="">Nothing</option>
            </select>
            <span className="text-xs text-slate-500 dark:text-slate-400">The report lists the controls fixed since then, and any that started failing.</span>
          </label>
        )}
        {scan.audit && available.data && (
          <fieldset>
            <legend className="font-medium">Include a compliance mapping for</legend>
            <div className="mt-1 grid grid-cols-2 gap-1">
              {available.data.map((framework) => (
                <label key={framework.id} className="flex items-center gap-2">
                  <input
                    type="checkbox"
                    className="accent-indigo-600"
                    checked={frameworks.includes(framework.id)}
                    onChange={(event) =>
                      setFrameworks((current) => (event.target.checked ? [...current, framework.id] : current.filter((id) => id !== framework.id)))
                    }
                  />
                  {framework.name}
                </label>
              ))}
            </div>
            <span className="text-xs text-slate-500 dark:text-slate-400">
              Lists each framework requirement the audit gives evidence for, with its status. For guidance, not a certification.
            </span>
          </fieldset>
        )}
        <ErrorMessage error={create.error} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={create.isPending}>
            Create report
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function ShareDialog({ report, onClose }: { report: ReportRecord; onClose: () => void }) {
  const queryClient = useQueryClient();
  const role = useRole();
  const [days, setDays] = useState(7);
  const [copied, setCopied] = useState(false);
  const share = useMutation({
    mutationFn: () => api.createShare(report.id, days),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["shares", report.id] }),
  });
  return (
    <Dialog open onClose={onClose} title="Share a link to this report">
      <div className="space-y-4 text-sm">
        {share.data ? (
          <>
            <p className="text-slate-600 dark:text-slate-300">
              Anyone with this link can open the report, and download it as PDF, Excel, CSV or JSON, without signing in until{" "}
              <span className="font-medium">{dateTime(share.data.share.expires_at)}</span>. It's shown only now; send it privately.
            </p>
            <div className="flex gap-2">
              <input
                readOnly
                value={share.data.url}
                aria-label="Share link"
                className="block w-full min-w-0 rounded-lg border-0 bg-slate-50 px-3 py-2 font-mono text-xs ring-1 ring-slate-300 ring-inset dark:bg-slate-950 dark:ring-slate-700"
                onFocus={(event) => event.target.select()}
              />
              <Button
                variant="secondary"
                onClick={() => {
                  navigator.clipboard?.writeText(share.data.url).then(() => setCopied(true));
                }}
              >
                {copied ? <Check className="size-4" /> : <Copy className="size-4" />} {copied ? "Copied" : "Copy"}
              </Button>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              The client must be able to reach this server's dashboard address. If it's only reachable over your VPN, send the PDF instead.
              {role !== "viewer" && " You can revoke the link at any time from the report's row."}
            </p>
            <div className="flex justify-end">
              <Button onClick={onClose}>Done</Button>
            </div>
          </>
        ) : (
          <>
            <p className="text-slate-600 dark:text-slate-300">
              Creates a link that opens this report without signing in, for clients without an account. Every view is recorded in the audit log.
            </p>
            <label className="block">
              <span className="font-medium">The link works for</span>
              <select
                value={days}
                onChange={(event) => setDays(Number(event.target.value))}
                className="mt-1 block w-48 rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700"
              >
                {[1, 3, 7, 14, 30].map((value) => (
                  <option key={value} value={value}>
                    {value} {value === 1 ? "day" : "days"}
                  </option>
                ))}
              </select>
            </label>
            <ErrorMessage error={share.error} />
            <div className="flex justify-end gap-2">
              <Button variant="secondary" onClick={onClose}>
                Cancel
              </Button>
              <Button loading={share.isPending} onClick={() => share.mutate()}>
                <Link2 className="size-4" /> Create link
              </Button>
            </div>
          </>
        )}
      </div>
    </Dialog>
  );
}
