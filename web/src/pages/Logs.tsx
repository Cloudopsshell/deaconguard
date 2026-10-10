import { useState } from "react";
import { useSearchParams } from "react-router";
import { useInfiniteQuery, useQuery } from "@tanstack/react-query";
import { Download, Logs as LogsIcon, Pause, Play, Search } from "lucide-react";
import { api, logDownloadUrl, type LogFilters, type LogLevel } from "../api";
import { LogTable } from "../components/LogTable";
import { Button, Card, EmptyState, ErrorMessage, Loading, PageHeader, cx } from "../components/ui";

const sources = [
  { value: "", label: "All" },
  { value: "server", label: "Server" },
  { value: "agent", label: "Agents" },
] as const;

const levels = [
  { value: "", label: "All levels" },
  { value: "warning", label: "Warnings and errors" },
  { value: "error", label: "Errors" },
] as const;

const selectClass =
  "rounded-lg border-0 bg-white py-1.5 pr-8 pl-3 text-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-900 dark:ring-slate-700";

/** The server's and the agents' logs, newest first, with filters and a download. */
export function Logs() {
  const [parameters, setParameters] = useSearchParams();
  const [live, setLive] = useState(true);
  const [search, setSearch] = useState(parameters.get("q") ?? "");
  const filters: LogFilters = {
    source: (parameters.get("source") || undefined) as LogFilters["source"],
    host: parameters.get("host") || undefined,
    level: (parameters.get("level") || undefined) as LogLevel | undefined,
    q: parameters.get("q") || undefined,
  };
  const capabilities = useQuery({ queryKey: ["capabilities"], queryFn: api.capabilities, staleTime: Infinity });
  const network = capabilities.data?.agents ?? false;
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: api.hosts, enabled: network });
  const logs = useInfiniteQuery({
    queryKey: ["logs", filters],
    queryFn: ({ pageParam }) => api.logs({ ...filters, before: pageParam, limit: 200 }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (page) => (page.more ? page.entries[page.entries.length - 1]?.id : undefined),
    refetchInterval: (query) => (live && (query.state.data?.pages.length ?? 1) === 1 ? 5000 : false),
  });

  function setFilter(key: string, value: string) {
    const next = new URLSearchParams(parameters);
    if (value) next.set(key, value);
    else next.delete(key);
    setParameters(next, { replace: true });
  }

  const entries = logs.data?.pages.flatMap((page) => page.entries) ?? [];
  return (
    <>
      <PageHeader
        title="Logs"
        description="What the server and each agent did: starts and stops, connections, scans, and every warning and error. Kept for 7 days."
        action={
          <div className="flex gap-2">
            <Button variant="secondary" onClick={() => setLive(!live)} aria-pressed={live}>
              {live ? <Pause className="size-4" /> : <Play className="size-4" />} {live ? "Pause" : "Follow"}
            </Button>
            <a
              href={logDownloadUrl(filters)}
              className="inline-flex items-center gap-2 rounded-lg bg-white px-3 py-2 text-sm font-semibold text-slate-900 ring-1 ring-slate-300 ring-inset hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:ring-slate-700 dark:hover:bg-slate-700"
            >
              <Download className="size-4" /> Download
            </a>
          </div>
        }
      />
      <Card>
        <div className="flex flex-wrap items-center gap-3 border-b border-slate-200 px-5 py-3 dark:border-slate-800">
          {network && (
            <div className="inline-flex rounded-lg ring-1 ring-slate-300 ring-inset dark:ring-slate-700" role="group" aria-label="Source">
              {sources.map((source) => (
                <button
                  key={source.value}
                  type="button"
                  aria-pressed={(filters.source ?? "") === source.value}
                  onClick={() => setFilter("source", source.value)}
                  className={cx(
                    "px-3 py-1.5 text-sm first:rounded-l-lg last:rounded-r-lg",
                    (filters.source ?? "") === source.value
                      ? "bg-slate-900 font-semibold text-white dark:bg-slate-100 dark:text-slate-900"
                      : "text-slate-600 hover:bg-slate-50 dark:text-slate-300 dark:hover:bg-slate-800",
                  )}
                >
                  {source.label}
                </button>
              ))}
            </div>
          )}
          {network && (
            <select aria-label="Machine" value={filters.host ?? ""} onChange={(event) => setFilter("host", event.target.value)} className={selectClass}>
              <option value="">All machines</option>
              {hosts.data?.map((host) => (
                <option key={host.id} value={host.id}>
                  {host.address}
                </option>
              ))}
            </select>
          )}
          <select aria-label="Level" value={filters.level ?? ""} onChange={(event) => setFilter("level", event.target.value)} className={selectClass}>
            {levels.map((level) => (
              <option key={level.value} value={level.value}>
                {level.label}
              </option>
            ))}
          </select>
          <form
            className="relative min-w-48 flex-1"
            onSubmit={(event) => {
              event.preventDefault();
              setFilter("q", search.trim());
            }}
          >
            <Search className="pointer-events-none absolute top-2 left-2.5 size-4 text-slate-400" aria-hidden />
            <input
              type="search"
              value={search}
              onChange={(event) => {
                setSearch(event.target.value);
                if (event.target.value === "") setFilter("q", "");
              }}
              placeholder="Search messages and machines, then press Enter"
              aria-label="Search the log"
              className="w-full rounded-lg border-0 bg-white py-1.5 pr-3 pl-8 text-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-900 dark:ring-slate-700"
            />
          </form>
          <span className="flex items-center gap-1.5 text-xs text-slate-500 dark:text-slate-400" aria-live="polite">
            <span className={cx("size-2 rounded-full", live ? "animate-pulse bg-emerald-500" : "bg-slate-400")} />
            {live ? "Following" : "Paused"}
          </span>
        </div>
        {logs.isPending ? (
          <Loading />
        ) : logs.error ? (
          <div className="p-5">
            <ErrorMessage error={logs.error} />
          </div>
        ) : entries.length === 0 ? (
          <EmptyState
            icon={<LogsIcon className="size-6" />}
            title="Nothing logged"
            description={
              filters.source || filters.host || filters.level || filters.q
                ? "No entries match these filters in the last 7 days."
                : "Entries appear here as the server and agents work."
            }
          />
        ) : (
          <>
            <LogTable entries={entries} />
            {logs.hasNextPage && (
              <div className="border-t border-slate-200 p-3 text-center dark:border-slate-800">
                <Button variant="secondary" loading={logs.isFetchingNextPage} onClick={() => logs.fetchNextPage()}>
                  Load older entries
                </Button>
              </div>
            )}
          </>
        )}
      </Card>
    </>
  );
}
