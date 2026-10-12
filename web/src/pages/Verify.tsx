import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { useMutation } from "@tanstack/react-query";
import { CheckCircle2, XCircle } from "lucide-react";
import { api } from "../api";
import { Button, Card, ErrorMessage, Field, PageHeader } from "../components/ui";
import { dateTime } from "../lib/format";

/** Checks a report's ID and fingerprint against what this server made. */
export function Verify() {
  const [reportId, setReportId] = useState("");
  const [fingerprint, setFingerprint] = useState("");
  const verify = useMutation({ mutationFn: () => api.verifyReport(reportId.trim(), fingerprint) });
  function submit(event: FormEvent) {
    event.preventDefault();
    verify.mutate();
  }
  const result = verify.data;
  return (
    <>
      <PageHeader
        title="Verify a report"
        description="Check that a report really came from this server and wasn't changed. Copy the report ID and fingerprint from its first or last page."
      />
      <Card>
        <form className="max-w-2xl space-y-4 px-5 py-5" onSubmit={submit}>
          <Field label="Report ID" required value={reportId} onChange={(event) => setReportId(event.target.value)} placeholder="32 letters and digits" data-autofocus />
          <Field
            label="Fingerprint (SHA-256)"
            required
            value={fingerprint}
            onChange={(event) => setFingerprint(event.target.value)}
            placeholder="c7a8 22d4 5fad …"
            hint="Spaces don't matter."
            className="font-mono"
          />
          <Button type="submit" loading={verify.isPending}>
            Verify
          </Button>
          <ErrorMessage error={verify.error} />
        </form>
        {result && (
          <div
            role="status"
            className={`mx-5 mb-5 flex gap-3 rounded-lg px-4 py-3 text-sm ring-1 ring-inset ${
              result.valid
                ? "bg-emerald-50 text-emerald-900 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-200"
                : "bg-red-50 text-red-900 ring-red-600/20 dark:bg-red-500/10 dark:text-red-200"
            }`}
          >
            {result.valid ? <CheckCircle2 className="mt-0.5 size-5 shrink-0" /> : <XCircle className="mt-0.5 size-5 shrink-0" />}
            <div>
              <p className="font-semibold">{result.valid ? "Genuine" : "Not verified"}</p>
              <p>{result.valid && result.report ? `This server made this report of ${result.host} on ${dateTime(result.report.created_at)}${result.grade ? `, grade ${result.grade}` : ""}${result.report.client ? `, for ${result.report.client}` : ""}. It hasn't been changed.` : result.message}</p>
              {result.valid && result.report && (
                <p className="mt-1">
                  <Link to={`/scans/${result.report.scan_id}`} className="font-medium underline">
                    Open the scan it came from
                  </Link>
                </p>
              )}
            </div>
          </div>
        )}
      </Card>
    </>
  );
}
