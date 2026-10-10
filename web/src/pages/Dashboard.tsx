import type { ReactNode } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, Bug, Plus, Server, ShieldAlert, ShieldCheck } from "lucide-react";
import { api, type HostSummary, type SeverityCounts, type Summary } from "../api";
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
  SeverityCountsInline,
  StatusBadge,
  Table,
  Td,
  Th,
} from "../components/ui";
import { countFor, isActive, severityOrder, severityStyle, timeAgo } from "../lib/format";
import { PackageCountsInline, packageCounts } from "../lib/fixes";

function riskScore(counts: SeverityCounts) {
  return counts.critical * 1000 + counts.high * 100 + counts.medium * 10 + counts.low;
}

function StatTile({ label, value, detail, icon, tone }: { label: string; value: number; detail: string; icon: ReactNode; tone: string }) {
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm font-medium text-slate-500 dark:text-slate-400">{label}</p>
          <p className="mt-2 text-3xl font-bold tracking-tight tabular-nums">{value.toLocaleString()}</p>
        </div>
        <div className={`rounded-lg p-2 ${tone}`}>{icon}</div>
      </div>
      <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">{detail}</p>
    </Card>
  );
}

export function Dashboard() {
  const { data, error, isPending } = useQuery({
    queryKey: ["summary"],
    queryFn: api.summary,
    refetchInterval: (query) =>
      query.state.data?.host_summaries.some((host) => isActive(host.last_scan?.status)) ? 2000 : false,
  });

  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;

  if (data.hosts === 0) {
    return (
      <>
        <PageHeader title="Dashboard" />
        <Card>
          <EmptyState
            icon={<ShieldCheck className="size-6" />}
            title="Welcome to DeaconGuard"
            description="Register the Linux machine DeaconGuard runs on. DeaconGuard reads its installed package list and checks it against the distribution's official security advisories."
            action={
              <Link
                to="/hosts?add=1"
                className="inline-flex items-center gap-2 rounded-lg bg-indigo-600 px-3.5 py-2 text-sm font-semibold text-white shadow-sm hover:bg-indigo-500"
              >
                <Plus className="size-4" /> Add this machine
              </Link>
            }
          />
        </Card>
      </>
    );
  }

  // Headline numbers count what an update or a restart fixes; the rest wait
  // on the distribution and are shown separately, never as clean.
  const toFixSeverity = data.fixes?.actionable ?? data.severity;
  const toFix = data.fixes ? (data.fixes.counts.available ?? 0) + (data.fixes.counts.reboot ?? 0) : data.findings;
  const waiting = data.findings - toFix;
  const critHigh = toFixSeverity.critical + toFixSeverity.high;
  const attention = data.host_summaries.filter(
    (host) => host.last_scan?.status === "failed",
  );
  const neverScanned = data.host_summaries.filter((host) => !host.last_report && !attention.includes(host));
  const ranked: HostSummary[] = data.host_summaries
    .filter((host) => host.last_report)
    .sort((a, b) => riskScore(packageCounts(b.last_report!).severity) - riskScore(packageCounts(a.last_report!).severity))
    .slice(0, 6);

  return (
    <>
      <PageHeader
        title="Dashboard"
        description={`Latest results from ${data.scanned_hosts} of ${data.hosts} registered host${data.hosts === 1 ? "" : "s"}.`}
      />

      {(attention.length > 0 || data.stale_feeds > 0 || data.unsupported > 0 || (data.stale_hosts?.length ?? 0) > 0) && (
        <div className="mb-6 space-y-2">
          {attention.length > 0 && (
            <Notice>
              {attention.length} host{attention.length === 1 ? "" : "s"} could not be scanned last time:{" "}
              {attention.map((host, index) => (
                <span key={host.id}>
                  {index > 0 && ", "}
                  <Link to={`/hosts/${host.id}`} className="font-semibold underline">
                    {host.address}
                  </Link>
                </span>
              ))}
              . Their earlier results may be out of date.
            </Notice>
          )}
          {data.stale_hosts && data.stale_hosts.length > 0 && (
            <Notice>
              {data.stale_hosts.length} host{data.stale_hosts.length === 1 ? " has" : "s have"} no results from the last 7 days, so
              {data.stale_hosts.length === 1 ? " its" : " their"} findings may be out of date:{" "}
              {data.stale_hosts.map((host, index) => (
                <span key={host.id}>
                  {index > 0 && ", "}
                  <Link to={`/hosts/${host.id}`} className="font-semibold underline">
                    {host.address}
                  </Link>
                </span>
              ))}
              .{" "}
              {data.stale_hosts.some((host) => !host.scheduled) ? (
                <>
                  <Link to="/schedules" className="font-semibold underline">
                    Add a schedule
                  </Link>{" "}
                  to keep results current.
                </>
              ) : (
                "Their schedules have not produced a result; check the Logs page."
              )}
            </Notice>
          )}
          {data.stale_feeds > 0 && (
            <Notice>
              {data.stale_feeds} report{data.stale_feeds === 1 ? " was" : "s were"} produced from cached advisory data because the
              feed could not be refreshed.
            </Notice>
          )}
          {data.unsupported > 0 && (
            <Notice>
              {data.unsupported.toLocaleString()} advisory rules could not be evaluated. Those CVEs are not confirmed clean.
            </Notice>
          )}
        </div>
      )}

      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatTile
          label="Hosts"
          value={data.hosts}
          detail={neverScanned.length > 0 ? `${neverScanned.length} not scanned yet` : "All hosts have results"}
          icon={<Server className="size-5" />}
          tone="bg-indigo-50 text-indigo-600 dark:bg-indigo-500/15 dark:text-indigo-300"
        />
        <StatTile
          label="To fix now"
          value={toFix}
          detail={
            waiting > 0
              ? `On ${data.hosts_to_update ?? 0} host${data.hosts_to_update === 1 ? "" : "s"}; ${waiting.toLocaleString()} more wait on the distribution`
              : `On ${data.hosts_to_update ?? 0} host${data.hosts_to_update === 1 ? "" : "s"}, with an update or a restart`
          }
          icon={<Bug className="size-5" />}
          tone="bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300"
        />
        <StatTile
          label="Critical & high to fix"
          value={critHigh}
          detail="By the distribution's own rating; start here"
          icon={<ShieldAlert className="size-5" />}
          tone="bg-red-50 text-red-600 dark:bg-red-500/15 dark:text-red-300"
        />
        <StatTile
          label="Unique CVEs"
          value={data.unique_cves}
          detail="Distinct vulnerabilities found"
          icon={<AlertTriangle className="size-5" />}
          tone="bg-amber-50 text-amber-600 dark:bg-amber-500/15 dark:text-amber-300"
        />
      </div>

      <div className="mt-6 grid gap-6 lg:grid-cols-5">
        <Card className="lg:col-span-2">
          <CardHeader title="To fix now, by severity" description="What an update or a restart fixes, from each host's latest scan" />
          <div className="space-y-4 px-5 py-5">
            <SeverityBar counts={toFixSeverity} className="h-3" />
            <ul className="space-y-3">
              {severityOrder.map((severity) => {
                const value = countFor(toFixSeverity, severity);
                const percent = toFix > 0 ? (value / toFix) * 100 : 0;
                return (
                  <li key={severity} className="text-sm">
                    <div className="flex items-center justify-between">
                      <span className="flex items-center gap-2">
                        <span className={`size-2.5 rounded-full ${severityStyle[severity].bar}`} />
                        {severityStyle[severity].label}
                      </span>
                      <span className="font-semibold tabular-nums">{value.toLocaleString()}</span>
                    </div>
                    <div className="mt-1.5 h-1.5 rounded-full bg-slate-100 dark:bg-slate-800">
                      <div className={`h-1.5 rounded-full ${severityStyle[severity].bar}`} style={{ width: `${percent}%` }} />
                    </div>
                  </li>
                );
              })}
            </ul>
            {waiting > 0 && (
              <p className="border-t border-slate-200 pt-3 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
                {waiting.toLocaleString()} more have no fix from the distribution yet, or need Ubuntu Pro or removing old kernels. Each host's page
                lists them by what clears them.
              </p>
            )}
          </div>
        </Card>

        <Card className="lg:col-span-3">
          <CardHeader
            title="Most exposed hosts"
            action={
              <Link to="/hosts" className="text-sm font-semibold text-indigo-600 hover:text-indigo-500 dark:text-indigo-400">
                All hosts
              </Link>
            }
          />
          {ranked.length === 0 ? (
            <EmptyState
              icon={<Server className="size-6" />}
              title="No completed scans yet"
              description="Open a host and start a scan to see results here."
            />
          ) : (
            <ul className="divide-y divide-slate-200 dark:divide-slate-800">
              {ranked.map((host) => (
                <li key={host.id}>
                  <Link to={`/hosts/${host.id}`} className="block px-5 py-3.5 hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <div className="flex items-center justify-between gap-4">
                      <div className="min-w-0">
                        <p className="truncate font-medium">{host.address}</p>
                        <p className="truncate text-xs text-slate-500 dark:text-slate-400">
                          {host.last_report!.os} · scanned {timeAgo(host.last_report!.finished_at)}
                        </p>
                      </div>
                      {isActive(host.last_scan?.status) ? (
                        <StatusBadge status={host.last_scan!.status} />
                      ) : (
                        <PackageCountsInline summary={host.last_report!} />
                      )}
                    </div>
                    <SeverityBar counts={packageCounts(host.last_report!).severity} className="mt-2.5" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>

      <SecurityChecks summary={data} />

      <Card className="mt-6">
        <CardHeader
          title="Top vulnerabilities"
          description="Those an update fixes first, then by severity and the number of affected hosts"
          action={
            <Link to="/vulnerabilities" className="text-sm font-semibold text-indigo-600 hover:text-indigo-500 dark:text-indigo-400">
              View all
            </Link>
          }
        />
        {data.top_vulnerabilities.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck className="size-6" />}
            title="No vulnerabilities in the latest results"
            description="Check the notices above: rules that were not evaluated and failed scans are not counted as clean."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>CVE</Th>
                <Th>Severity</Th>
                <Th>Packages</Th>
                <Th>Fix</Th>
                <Th className="text-right">Hosts</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.top_vulnerabilities.map((item) => (
                <tr key={item.cve} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <Td>
                    <Link
                      to={`/vulnerabilities/${encodeURIComponent(item.cve)}`}
                      className="font-mono font-medium text-indigo-600 hover:underline dark:text-indigo-400"
                    >
                      {item.cve}
                    </Link>
                  </Td>
                  <Td>
                    <SeverityBadge severity={item.severity} />
                  </Td>
                  <Td className="max-w-xs truncate text-slate-600 dark:text-slate-300">{item.packages.join(", ")}</Td>
                  <Td className="text-xs whitespace-nowrap text-slate-600 dark:text-slate-300">
                    {item.fixable_host_count > 0 ? `Update on ${item.fixable_host_count}` : <span title="No update or restart fixes it yet">Waiting</span>}
                  </Td>
                  <Td className="text-right font-semibold tabular-nums">{item.host_count}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}

function SecurityChecks({ summary }: { summary: Summary }) {
  const others = checkOrder.filter((check) => check !== "packages");
  return (
    <Card className="mt-6">
      <CardHeader
        title="Security checks"
        description="Latest integrity, malware, configuration, and antivirus results. Choose checks when you start a scan."
      />
      <ul className="grid divide-y divide-slate-200 sm:grid-cols-2 sm:divide-y-0 lg:grid-cols-4 dark:divide-slate-800">
        {others.map((check) => {
          const totals = summary.checks?.[check];
          const Icon = checkMeta[check].icon;
          return (
            <li key={check} className="px-5 py-4 sm:border-r sm:border-slate-200 sm:last:border-r-0 dark:sm:border-slate-800">
              <p className="flex items-center gap-2 text-sm font-semibold">
                <Icon className="size-4 text-slate-500 dark:text-slate-400" /> {checkMeta[check].label}
              </p>
              {!totals || totals.hosts === 0 ? (
                <p className="mt-2 text-sm text-slate-500 dark:text-slate-400">
                  {totals?.not_run
                    ? `Skipped or failed on ${totals.not_run} host${totals.not_run === 1 ? "" : "s"}, so nothing was checked`
                    : "Not run on any host yet"}
                </p>
              ) : (
                <>
                  <p className="mt-2 text-2xl font-bold tabular-nums">
                    {totals.findings.toLocaleString()}
                    <span className="ml-1.5 text-sm font-normal text-slate-500 dark:text-slate-400">issues</span>
                  </p>
                  <div className="mt-1">
                    <SeverityCountsInline counts={totals.severity} />
                  </div>
                  <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
                    {totals.hosts_with_findings} of {totals.hosts} checked host{totals.hosts === 1 ? "" : "s"} affected
                    {totals.incomplete > 0 && ` · ${totals.incomplete} with partial coverage`}
                    {totals.not_run > 0 && ` · skipped or failed on ${totals.not_run}`}
                  </p>
                </>
              )}
            </li>
          );
        })}
      </ul>
    </Card>
  );
}

function Notice({ children }: { children: ReactNode }) {
  return (
    <div className="flex gap-2 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-900 ring-1 ring-inset ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-200">
      <AlertTriangle className="mt-0.5 size-4 shrink-0" aria-hidden />
      <p>{children}</p>
    </div>
  );
}
