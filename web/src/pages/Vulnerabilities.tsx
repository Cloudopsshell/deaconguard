import { useMemo, useState } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Search, ShieldCheck } from "lucide-react";
import { api } from "../api";
import { Card, CardHeader, EmptyState, ErrorMessage, Loading, PageHeader, SeverityBadge, Table, Td, Th } from "../components/ui";

export function Vulnerabilities() {
  const [query, setQuery] = useState("");
  const { data, error, isPending } = useQuery({ queryKey: ["vulnerabilities"], queryFn: api.vulnerabilities });

  const filtered = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!data || !needle) return data ?? [];
    return data.filter(
      (item) =>
        item.cve.toLowerCase().includes(needle) ||
        item.title.toLowerCase().includes(needle) ||
        item.packages.some((name) => name.toLowerCase().includes(needle)),
    );
  }, [data, query]);

  return (
    <>
      <PageHeader
        title="Vulnerabilities"
        description="Every CVE found in the latest successful scan of each registered host."
      />
      <Card>
        <CardHeader
          title="All CVEs"
          description={data ? `${filtered.length.toLocaleString()} of ${data.length.toLocaleString()} shown` : undefined}
          action={
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
          }
        />
        {isPending ? (
          <Loading />
        ) : error ? (
          <div className="p-5">
            <ErrorMessage error={error} />
          </div>
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
                <Th>Packages</Th>
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
                  <Td className="max-w-xs text-slate-600 dark:text-slate-300">{item.packages.join(", ")}</Td>
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
