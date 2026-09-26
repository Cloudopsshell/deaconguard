import { Info, ShieldCheck } from "lucide-react";
import type { CheckId, CheckResult } from "../api";
import { checkStatusStyle } from "../lib/checks";
import { normalizeSeverity, severityOrder } from "../lib/format";
import { Card, CardHeader, EmptyState, ErrorMessage, SeverityBadge, Table, Td, Th, cx } from "./ui";

/** Shows one non-package check: its coverage, notes, and findings. */
export function CheckResultView({ check, name, result }: { check: CheckId; name: string; result: CheckResult }) {
  const findings = [...(result.findings ?? [])].sort(
    (a, b) => severityOrder.indexOf(normalizeSeverity(a.severity)) - severityOrder.indexOf(normalizeSeverity(b.severity)),
  );
  const notes = result.notes ?? [];
  const status = checkStatusStyle[result.status] ?? checkStatusStyle.failed;
  return (
    <div className="space-y-4">
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3 px-5 py-4">
          <div>
            <h3 className="font-semibold">{name}</h3>
            <p className="text-sm text-slate-500 dark:text-slate-400">{result.summary}</p>
          </div>
          <div className="flex flex-wrap gap-2">
            <span className={cx("rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", status.className)}>{status.label}</span>
            {result.status !== "skipped" && (
              <span className="rounded-full bg-slate-100 px-2 py-0.5 text-xs font-medium text-slate-600 ring-1 ring-slate-500/20 ring-inset dark:bg-slate-800 dark:text-slate-300">
                {result.privileged ? "Ran with sudo" : "Ran without sudo"}
              </span>
            )}
          </div>
        </div>
        {(result.error || notes.length > 0) && (
          <div className="space-y-2 border-t border-slate-200 px-5 py-4 dark:border-slate-800">
            {result.error && <ErrorMessage error={result.error} />}
            {notes.map((note) => (
              <p key={note} className="flex gap-2 text-sm text-slate-600 dark:text-slate-300">
                <Info className="mt-0.5 size-4 shrink-0 text-slate-400" aria-hidden /> {note}
              </p>
            ))}
          </div>
        )}
      </Card>

      {result.status !== "skipped" && result.status !== "failed" && (
        <Card>
          <CardHeader title="Findings" description={`${findings.length} ${findings.length === 1 ? "issue" : "issues"}`} />
          {findings.length === 0 ? (
            <EmptyState
              icon={<ShieldCheck className="size-6" />}
              title="Nothing found"
              description={
                result.status === "partial"
                  ? "Nothing was found in what could be read. See the notes above for what was not covered."
                  : "No issues were found by this check."
              }
            />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Severity</Th>
                  <Th>Issue</Th>
                  <Th>Evidence</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {findings.map((finding, index) => (
                  <tr key={`${check}-${finding.rule}-${index}`} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <Td>
                      <SeverityBadge severity={normalizeSeverity(finding.severity)} />
                    </Td>
                    <Td className="max-w-md">
                      <p className="font-medium">{finding.title}</p>
                      <p className="mt-0.5 text-xs leading-relaxed text-slate-500 dark:text-slate-400">{finding.detail}</p>
                    </Td>
                    <Td className="max-w-md font-mono text-xs break-all text-slate-700 dark:text-slate-300">{finding.evidence}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      )}
    </div>
  );
}
