import { useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Search, ShieldCheck } from "lucide-react";
import { api } from "../api";
import { Card, CardHeader, EmptyState, ErrorMessage, Loading, PageHeader, SeverityBadge, Table, Td, Th, cx } from "../components/ui";
import { CVSSScore, ExploitBadge } from "../lib/exploit";
import { dateTime } from "../lib/format";

type Show = "fixable" | "exploited" | "overdue" | "all";

export function Vulnerabilities() {
  const [query, setQuery] = useState("");
  const [show, setShow] = useState<Show>(() => {
    const wanted = new URLSearchParams(window.location.search).get("show");
    return wanted === "exploited" || wanted === "overdue" ? wanted : "fixable";
  });
  const fixableOnly = show === "fixable";
  const { data, error, isPending } = useQuery({ queryKey: ["vulnerabilities"], queryFn: api.vulnerabilities });
  const fixableCount = data?.filter((item) => item.fixable_host_count > 0).length ?? 0;
  const exploited = (item: { priority: string }) => item.priority === "exploited" || item.priority === "likely";
  const exploitedCount = data?.filter(exploited).length ?? 0;
  const overdueCount = data?.filter((item) => item.overdue_host_count > 0).length ?? 0;

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    const shown = (data ?? []).filter((item) =>
      show === "fixable" ? item.fixable_host_count > 0 : show === "exploited" ? exploited(item) : show === "overdue" ? item.overdue_host_count > 0 : true,
    );
    if (!needle) return shown;
    return shown.filter(
      (item) =>
        item.cve.toLowerCase().includes(needle) ||
        item.title.toLowerCase().includes(needle) ||
        item.packages.some((name) => name.toLowerCase().includes(needle)),
    );
  }, [data, query, show]);

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        description="Every CVE found in the latest successful scan of each registered host, most urgent first: known exploited (CISA KEV), then likely exploited (EPSS 10% or more), then by severity. Fix now shows those an update or a restart fixes; the rest wait on the distribution."
      />
      <Card>
        <CardHeader
          title="All CVEs"
          description={data ? `${filtered.length.toLocaleString()} of ${data.length.toLocaleString()} shown` : undefined}
          action={
            <div className="flex flex-wrap items-center gap-3">
              <div className="inline-flex rounded-lg ring-1 ring-slate-300 ring-inset dark:ring-slate-700" role="group" aria-label="Show">
                {([
                  { value: "fixable", label: `Fix now (${fixableCount.toLocaleString()})` },
                  { value: "exploited", label: `Exploited (${exploitedCount.toLocaleString()})` },
                  ...(overdueCount > 0 || show === "overdue" ? [{ value: "overdue" as Show, label: `Overdue (${overdueCount.toLocaleString()})` }] : []),
                  { value: "all", label: `All (${(data?.length ?? 0).toLocaleString()})` },
                ] as { value: Show; label: string }[]).map((option) => (
                  <button
                    key={option.value}
                    type="button"
                    aria-pressed={show === option.value}
                    onClick={() => setShow(option.value)}
                    className={cx(
                      "px-3 py-1.5 text-sm first:rounded-l-lg last:rounded-r-lg",
                      show === option.value
                        ? "bg-slate-900 font-semibold text-white dark:bg-slate-100 dark:text-slate-900"
                        : "text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800",
                    )}
                  >
                    {option.label}
                  </button>
                ))}
              </div>
              <div className="relative">
              <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-slate-400" aria-hidden />
              <input
                type="search"
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                placeholder="Search CVE, package, title"
                aria-label="Search vulnerabilities"
                className="w-64 rounded-lg border-0 bg-white py-2 pr-3 pl-9 text-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700"
              />
              </div>
            </div>
          }
        />
        {isPending ? (
          <Loading />
        ) : error ? (
          <div className="p-5">
            <ErrorMessage error={error} />
          </div>
        ) : data.length > 0 && filtered.length === 0 && fixableOnly && !query ? (
          <EmptyState
            icon={<ShieldCheck className="size-6" />}
            title="Nothing to fix now"
            description={`No update or restart fixes any of the ${data.length.toLocaleString()} CVEs found; they wait on the distribution. Choose All to see them.`}
          />
        ) : data.length > 0 && filtered.length === 0 && show === "exploited" && !query ? (
          <EmptyState
            icon={<ShieldCheck className="size-6" />}
            title="Nothing known or likely to be exploited"
            description="None of the CVEs found is in CISA's Known Exploited Vulnerabilities catalog or has an EPSS of 10% or more. Hosts last scanned before 0.16.0 have no exploit data until they are scanned again."
          />
        ) : data.length === 0 ? (
          <EmptyState
            icon={<ShieldCheck className="size-6" />}
            title="No vulnerabilities found"
            description="Either no host has been scanned yet, or the latest scans found no packages with published fixes."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>CVE</Th>
                <Th>Severity</Th>
                <Th className="text-right">CVSS</Th>
                <Th>Exploitation</Th>
                <Th>Packages</Th>
                <Th>Fix</Th>
                <Th>Due</Th>
                <Th className="text-right">Hosts</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {filtered.map((item) => (
                <tr key={item.cve} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                  <Td>
                    <Link
                      to={`/vulnerabilities/${encodeURIComponent(item.cve)}`}
                      className="font-mono font-medium text-indigo-600 hover:underline dark:text-indigo-400"
                    >
                      {item.cve}
                    </Link>
                    {item.title && (
                      <p className="mt-0.5 line-clamp-1 max-w-lg text-xs text-slate-500 dark:text-slate-400">{item.title}</p>
                    )}
                  </Td>
                  <Td>
                    <SeverityBadge severity={item.severity} />
                  </Td>
                  <Td className="text-right">
                    <CVSSScore score={item.cvss_score} />
                  </Td>
                  <Td>
                    <ExploitBadge kev={item.kev} ransomware={item.ransomware} due={item.kev_due} epss={item.epss} />
                  </Td>
                  <Td className="max-w-xs text-slate-600 dark:text-slate-300">{item.packages.join(", ")}</Td>
                  <Td className="text-xs whitespace-nowrap text-slate-600 dark:text-slate-300">
                    {item.fixable_host_count > 0 ? (
                      `Update on ${item.fixable_host_count} host${item.fixable_host_count === 1 ? "" : "s"}`
                    ) : (
                      <span title="No update or restart fixes it yet">Waiting</span>
                    )}
                  </Td>
                  <Td className="text-xs whitespace-nowrap">
                    {item.overdue_host_count > 0 ? (
                      <span className="font-semibold text-red-700 dark:text-red-300" title={`Past its fix deadline on ${item.overdue_host_count} host${item.overdue_host_count === 1 ? "" : "s"}`}>
                        Overdue{item.overdue_host_count < item.host_count ? ` on ${item.overdue_host_count}` : ""}
                      </span>
                    ) : item.due_at ? (
                      <span className="text-slate-600 dark:text-slate-300" title={item.first_seen ? `First found ${dateTime(item.first_seen)}` : undefined}>
                        {dateTime(item.due_at).split(",").slice(0, 2).join(",")}
                      </span>
                    ) : (
                      <span className="text-slate-400">–</span>
                    )}
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
