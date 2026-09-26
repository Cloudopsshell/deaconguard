import { useMemo, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowLeft, ExternalLink, Search, ShieldCheck } from "lucide-react";
import { api, type CheckId, type Finding, type Report, type Severity } from "../api";
import { CheckResultView } from "../components/CheckResultView";
import { checkMeta, checkOrder } from "../lib/checks";
import {
  Card,
  CardHeader,
  EmptyState,
  ErrorMessage,
  Loading,
  PageHeader,
  SeverityBadge,
  SeverityBar,
  StatusBadge,
  Table,
  Td,
  Th,
  cx,
} from "../components/ui";
import { dateTime, normalizeSeverity, severityOrder, severityStyle } from "../lib/format";

export function ScanReport() {
  const { scanId = "" } = useParams();
  const { data, error, isPending } = useQuery({ queryKey: ["scan", scanId], queryFn: () => api.scan(scanId) });

  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;

  const { scan, report } = data;
  return (
    <>
      <Link
        to={`/hosts/${scan.host_id}`}
        className="mb-4 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
      >
        <ArrowLeft className="size-4" /> {scan.address}
      </Link>
      <PageHeader
        title={`Scan report · ${scan.address}`}
        description={`${scan.os || "Unknown OS"} · ${dateTime(scan.finished_at ?? scan.started_at)}`}
        action={<StatusBadge status={scan.status} />}
      />
      {!report ? (
        <Card className="p-5">
          <ErrorMessage error={scan.error || "This scan did not produce a report."} />
        </Card>
      ) : (
        <ScanTabs report={report} checks={scan.checks} />
      )}
    </>
  );
}

/** One tab per check that this scan ran. */
function ScanTabs({ report, checks }: { report: Report; checks: CheckId[] }) {
  const ran = checkOrder.filter((check) => checks.includes(check));
  const [active, setActive] = useState<CheckId>(ran[0] ?? "packages");
  return (
    <>
      {ran.length > 1 && (
        <div className="mb-4 flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-800" role="tablist">
          {ran.map((check) => {
            const Icon = checkMeta[check].icon;
            return (
              <button
                key={check}
                type="button"
                role="tab"
                aria-selected={active === check}
                onClick={() => setActive(check)}
                className={cx(
                  "-mb-px flex items-center gap-2 border-b-2 px-3 py-2.5 text-sm font-medium whitespace-nowrap",
                  active === check
                    ? "border-indigo-600 text-indigo-700 dark:border-indigo-400 dark:text-indigo-300"
                    : "border-transparent text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100",
                )}
              >
                <Icon className="size-4" /> {checkMeta[check].label}
              </button>
            );
          })}
        </div>
      )}
      {active === "packages" ? (
        <ReportBody report={report} />
      ) : report.check_results?.[active] ? (
        <CheckResultView check={active} name={checkMeta[active].label} result={report.check_results[active]} />
      ) : (
        <ErrorMessage error="This scan has no result for the check." />
      )}
    </>
  );
}

/** Package vulnerability results, or a notice when the report has none. */
export function ReportBody({ report }: { report: Report }) {
  if (!report.advisory_database) {
    return <ErrorMessage error="This report has no package vulnerability data. Run a scan with Package vulnerabilities selected." />;
  }
  return <PackageReport report={report} />;
}

function PackageReport({ report }: { report: Report }) {
  const findings = report.findings ?? [];
  const unsupported = report.unsupported_cves ?? [];
  const counts = useMemo(() => {
    const result = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    for (const finding of findings) {
      result[normalizeSeverity(finding.severity).toLowerCase() as keyof typeof result]++;
    }
    return result;
  }, [findings]);
  const feed = report.advisory_database;

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-5 md:col-span-1">
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">Findings</p>
          <p className="mt-2 text-3xl font-bold tabular-nums">{findings.length.toLocaleString()}</p>
          <SeverityBar counts={counts} className="mt-3" />
        </Card>
        <Card className="p-5 md:col-span-2">
          <dl className="grid gap-x-6 gap-y-3 text-sm sm:grid-cols-2">
            <Meta label="Coverage">{report.coverage}</Meta>
            <Meta label="Maintenance">{report.maintenance}</Meta>
            <Meta label="Advisory data">
              <span className={feed.feed_stale ? "font-semibold text-amber-700 dark:text-amber-400" : ""}>
                {feed.feed_stale ? "Stale" : "Current"} · fetched {dateTime(feed.fetched_at)}
              </span>
              {feed.feed_refresh_error && <span className="block text-xs text-amber-700 dark:text-amber-400">{feed.feed_refresh_error}</span>}
            </Meta>
            <Meta label="Source">
              <span className="break-all">{feed.source}</span>
            </Meta>
          </dl>
        </Card>
      </div>

      {unsupported.length > 0 && (
        <div className="flex gap-2 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-900 ring-1 ring-inset ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-200">
          <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
          <p>
            {unsupported.length === 1
              ? "1 advisory rule could not be fully evaluated, so that CVE is"
              : `${unsupported.length.toLocaleString()} advisory rules could not be fully evaluated, so those CVEs are`}{" "}
            neither confirmed present nor confirmed clean. They are listed at the bottom of this page.
          </p>
        </div>
      )}

      <FindingsTable findings={findings} />

      {unsupported.length > 0 && (
        <Card>
          <details>
            <summary className="cursor-pointer px-5 py-4 text-base font-semibold select-none">
              Rules not evaluated ({unsupported.length.toLocaleString()})
            </summary>
            <Table>
              <thead>
                <tr>
                  <Th>ID</Th>
                  <Th>Title</Th>
                  <Th>Reason</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {unsupported.map((rule) => (
                  <tr key={rule.id}>
                    <Td className="font-mono whitespace-nowrap">{rule.id}</Td>
                    <Td className="text-slate-600 dark:text-slate-300">{rule.title}</Td>
                    <Td className="text-slate-500 dark:text-slate-400">{rule.reason}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </details>
        </Card>
      )}
    </div>
  );
}

function Meta({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs font-medium tracking-wide text-slate-500 uppercase dark:text-slate-400">{label}</dt>
      <dd className="mt-0.5">{children}</dd>
    </div>
  );
}

function FindingsTable({ findings }: { findings: Finding[] }) {
  const [query, setQuery] = useState("");
  const [severities, setSeverities] = useState<Set<Severity>>(new Set());

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return findings
      .filter((finding) => severities.size === 0 || severities.has(normalizeSeverity(finding.severity)))
      .filter(
        (finding) =>
          !needle ||
          finding.id.toLowerCase().includes(needle) ||
          finding.package.toLowerCase().includes(needle) ||
          finding.title.toLowerCase().includes(needle),
      )
      .sort(
        (a, b) =>
          severityOrder.indexOf(normalizeSeverity(a.severity)) - severityOrder.indexOf(normalizeSeverity(b.severity)) ||
          a.package.localeCompare(b.package) ||
          b.id.localeCompare(a.id),
      );
  }, [findings, query, severities]);

  function toggle(severity: Severity) {
    setSeverities((current) => {
      const next = new Set(current);
      if (next.has(severity)) next.delete(severity);
      else next.add(severity);
      return next;
    });
  }

  return (
    <Card>
      <CardHeader
        title="Findings"
        description={`${filtered.length.toLocaleString()} of ${findings.length.toLocaleString()} shown`}
        action={
          <div className="relative">
            <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-slate-400" aria-hidden />
            <input
              type="search"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Search CVE, package, title"
              aria-label="Search findings"
              className="w-64 rounded-lg border-0 bg-white py-2 pr-3 pl-9 text-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700"
            />
          </div>
        }
      />
      <div className="flex flex-wrap gap-2 border-b border-slate-200 px-5 py-3 dark:border-slate-800">
        {severityOrder.map((severity) => {
          const active = severities.has(severity);
          return (
            <button
              key={severity}
              type="button"
              onClick={() => toggle(severity)}
              aria-pressed={active}
              className={cx(
                "rounded-full px-3 py-1 text-xs font-semibold ring-1 ring-inset transition-colors",
                active
                  ? severityStyle[severity].badge
                  : "text-slate-600 ring-slate-300 hover:bg-slate-100 dark:text-slate-300 dark:ring-slate-700 dark:hover:bg-slate-800",
              )}
            >
              {severityStyle[severity].label}
            </button>
          );
        })}
      </div>
      {findings.length === 0 ? (
        <EmptyState
          icon={<ShieldCheck className="size-6" />}
          title="No findings in this report"
          description="No installed package matched a published fix. Rules that were not evaluated, if any, are listed separately."
        />
      ) : filtered.length === 0 ? (
        <EmptyState icon={<Search className="size-6" />} title="No matching findings" description="Try a different search or filter." />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Severity</Th>
              <Th>CVE</Th>
              <Th>Package</Th>
              <Th>Installed</Th>
              <Th>Fixed in</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {filtered.map((finding, index) => (
              <tr key={`${finding.id}-${finding.package}-${index}`} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                <Td>
                  <SeverityBadge severity={normalizeSeverity(finding.severity)} />
                </Td>
                <Td>
                  <div className="flex items-center gap-1.5 whitespace-nowrap">
                    <Link
                      to={`/vulnerabilities/${encodeURIComponent(finding.id)}`}
                      className="font-mono font-medium text-indigo-600 hover:underline dark:text-indigo-400"
                    >
                      {finding.id}
                    </Link>
                    {finding.url && (
                      <a href={finding.url} target="_blank" rel="noreferrer" className="text-slate-400 hover:text-slate-600" title="Advisory">
                        <ExternalLink className="size-3.5" />
                      </a>
                    )}
                  </div>
                  {finding.title && (
                    <p className="mt-0.5 line-clamp-2 max-w-md text-xs text-slate-500 dark:text-slate-400">{finding.title}</p>
                  )}
                </Td>
                <Td className="font-medium">{finding.package}</Td>
                <Td className="font-mono text-xs break-all">{finding.installed_version}</Td>
                <Td className="font-mono text-xs break-all">
                  {finding.fixed_version || <span className="font-sans text-slate-500 italic">No fix published yet</span>}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}
