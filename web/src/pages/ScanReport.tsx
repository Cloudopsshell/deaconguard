import { useMemo, useState, type ReactNode } from "react";
import { Link, useParams } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, ArrowLeft, ExternalLink, Search, ShieldCheck } from "lucide-react";
import { api, type CheckId, type Finding, type FixState, type Report, type Severity } from "../api";
import { actionable, fixCommand, fixMeta, fixOf, fixOrder } from "../lib/fixes";
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
  const { counts, toFix } = useMemo(() => {
    const result = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
    let fixable = 0;
    for (const finding of findings) {
      if (!actionable(fixOf(finding))) continue;
      fixable++;
      result[normalizeSeverity(finding.severity).toLowerCase() as keyof typeof result]++;
    }
    return { counts: result, toFix: fixable };
  }, [findings]);
  const feed = report.advisory_database;

  return (
    <div className="space-y-6">
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-5 md:col-span-1">
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">To fix now</p>
          <p className="mt-2 text-3xl font-bold tabular-nums">{toFix.toLocaleString()}</p>
          <SeverityBar counts={counts} className="mt-3" />
          <p className="mt-3 text-xs text-slate-500 dark:text-slate-400">
            {toFix === 0
              ? "Nothing an update or a restart fixes."
              : "Findings an update or a restart fixes, by the distribution's own severity."}{" "}
            {findings.length - toFix > 0 && `${(findings.length - toFix).toLocaleString()} more are listed below by what clears them.`}
          </p>
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

      <WhatToDo report={report} findings={findings} />

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

/** One line per fix state: how many findings and packages, and what to run. */
function WhatToDo({ report, findings }: { report: Report; findings: Finding[] }) {
  const groups = useMemo(() => {
    const result = new Map<FixState, { findings: number; packages: Set<string> }>();
    for (const finding of findings) {
      const state = fixOf(finding);
      const group = result.get(state) ?? { findings: 0, packages: new Set<string>() };
      group.findings++;
      group.packages.add(finding.package);
      result.set(state, group);
    }
    return result;
  }, [findings]);
  if (findings.length === 0) return null;
  return (
    <Card>
      <CardHeader title="What to do" description="Every finding, by what clears it. Commands run on the machine itself." />
      <ul className="divide-y divide-slate-200 dark:divide-slate-800">
        {fixOrder
          .filter((state) => groups.has(state))
          .map((state) => {
            const group = groups.get(state)!;
            const meta = fixMeta[state];
            const Icon = meta.icon;
            const command = fixCommand(state, report.package_manager, report.os);
            const packages = [...group.packages];
            return (
              <li key={state} className="flex flex-wrap items-start gap-x-4 gap-y-2 px-5 py-4">
                <span className={cx("mt-0.5 flex size-8 shrink-0 items-center justify-center rounded-lg ring-1 ring-inset", meta.badge)}>
                  <Icon className="size-4" />
                </span>
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-semibold">
                    {meta.label}
                    <span className="ml-2 font-normal text-slate-500 dark:text-slate-400">
                      {group.findings.toLocaleString()} CVE{group.findings === 1 ? "" : "s"} in {packages.length.toLocaleString()} package
                      {packages.length === 1 ? "" : "s"}
                    </span>
                  </p>
                  <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{meta.description}</p>
                  <p className="mt-1 truncate text-xs text-slate-500 dark:text-slate-400" title={packages.join(", ")}>
                    {packages.slice(0, 6).join(", ")}
                    {packages.length > 6 && ` and ${packages.length - 6} more`}
                  </p>
                </div>
                {command && (
                  <code className="self-center rounded-md bg-slate-100 px-2.5 py-1.5 font-mono text-xs whitespace-nowrap text-slate-800 dark:bg-slate-800 dark:text-slate-200">
                    {command}
                  </code>
                )}
              </li>
            );
          })}
      </ul>
    </Card>
  );
}

type FixFilter = "all" | "now" | FixState;

function FindingsTable({ findings }: { findings: Finding[] }) {
  const [query, setQuery] = useState("");
  const [severities, setSeverities] = useState<Set<Severity>>(new Set());
  const fixCounts = useMemo(() => {
    const result: Partial<Record<FixState, number>> = {};
    for (const finding of findings) result[fixOf(finding)] = (result[fixOf(finding)] ?? 0) + 1;
    return result;
  }, [findings]);
  const nowCount = (fixCounts.available ?? 0) + (fixCounts.reboot ?? 0);
  // Open on what can be fixed now; the rest is one click away, by what clears it.
  const [fix, setFix] = useState<FixFilter>("now");

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    return findings
      .filter((finding) => fix === "all" || (fix === "now" ? actionable(fixOf(finding)) : fixOf(finding) === fix))
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
  }, [findings, query, severities, fix]);

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
      <div className="flex flex-wrap gap-2 border-b border-slate-200 px-5 py-3 dark:border-slate-800" role="group" aria-label="What clears it">
        {(
          [
            { value: "now", label: "Fix now", count: nowCount },
            ...fixOrder.map((state) => ({ value: state, label: fixMeta[state].label, count: fixCounts[state] ?? 0 })),
            { value: "all", label: "All", count: findings.length },
          ] as { value: FixFilter; label: string; count: number }[]
        )
          .filter((option) => option.count > 0 || option.value === "now" || option.value === "all")
          .map((option) => (
            <button
              key={option.value}
              type="button"
              onClick={() => setFix(option.value)}
              aria-pressed={fix === option.value}
              className={cx(
                "rounded-lg px-3 py-1.5 text-xs font-semibold ring-1 ring-inset transition-colors",
                fix === option.value
                  ? "bg-slate-900 text-white ring-slate-900 dark:bg-slate-100 dark:text-slate-900 dark:ring-slate-100"
                  : "text-slate-600 ring-slate-300 hover:bg-slate-100 dark:text-slate-300 dark:ring-slate-700 dark:hover:bg-slate-800",
              )}
            >
              {option.label}
              <span className="ml-1.5 font-normal tabular-nums opacity-75">{option.count.toLocaleString()}</span>
            </button>
          ))}
      </div>
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
      ) : filtered.length === 0 && fix === "now" && severities.size === 0 && !query ? (
        <EmptyState
          icon={<ShieldCheck className="size-6" />}
          title="Nothing to fix now"
          description="No update or restart fixes anything here. The other findings wait on the distribution or need another step; choose them above."
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
              <Th>Fix</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {filtered.map((finding, index) => (
              <tr key={`${finding.id}-${finding.package}-${index}`} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                <Td>
                  <SeverityBadge severity={normalizeSeverity(finding.severity)} />
                  {finding.cvss_severity && normalizeSeverity(finding.cvss_severity as Severity) !== normalizeSeverity(finding.severity) && (
                    <p className="mt-1 text-[11px] whitespace-nowrap text-slate-500 dark:text-slate-400" title="The generic CVSS rating; the badge is the distribution's own">
                      CVSS: {severityStyle[normalizeSeverity(finding.cvss_severity as Severity)].label}
                    </p>
                  )}
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
                <Td className="text-xs">
                  <span
                    className={cx("inline-flex rounded-md px-1.5 py-0.5 font-medium whitespace-nowrap ring-1 ring-inset", fixMeta[fixOf(finding)].badge)}
                    title={fixMeta[fixOf(finding)].description}
                  >
                    {fixMeta[fixOf(finding)].short}
                  </span>
                  {finding.fixed_version && <p className="mt-1 font-mono break-all text-slate-500 dark:text-slate-400">{finding.fixed_version}</p>}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}
