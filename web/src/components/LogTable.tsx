import { Link } from "react-router";
import { RadioTower, Server } from "lucide-react";
import type { LogEntry, LogLevel } from "../api";
import { cx } from "./ui";

const levelStyle: Record<LogLevel, { label: string; className: string }> = {
  info: { label: "Info", className: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-500/15 dark:text-slate-300 dark:ring-slate-400/30" },
  warning: {
    label: "Warning",
    className: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-400/30",
  },
  error: { label: "Error", className: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300 dark:ring-red-400/30" },
};

function LevelBadge({ level }: { level: LogLevel }) {
  const style = levelStyle[level] ?? levelStyle.info;
  return (
    <span className={cx("inline-flex rounded-md px-1.5 py-0.5 text-[11px] font-medium ring-1 ring-inset", style.className)}>
      {style.label}
    </span>
  );
}

function time(iso: string) {
  const date = new Date(iso);
  return {
    clock: date.toLocaleTimeString(undefined, { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
    day: date.toLocaleDateString(undefined, { month: "short", day: "numeric" }),
    full: date.toLocaleString(),
  };
}

/** Log entries, newest first. showHost adds which machine each entry is about. */
export function LogTable({ entries, showHost = true }: { entries: LogEntry[]; showHost?: boolean }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead className="border-b border-slate-200 text-xs font-medium tracking-wide text-slate-500 uppercase dark:border-slate-800 dark:text-slate-400">
          <tr>
            <th className="px-5 py-2.5 font-medium">Time</th>
            <th className="px-3 py-2.5 font-medium">Level</th>
            <th className="px-3 py-2.5 font-medium">From</th>
            <th className="px-5 py-2.5 font-medium">Message</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-100 dark:divide-slate-800/70">
          {entries.map((entry) => {
            const at = time(entry.at);
            return (
              <tr
                key={entry.id}
                className={cx(
                  "align-top",
                  entry.level === "error" && "bg-red-50/40 dark:bg-red-500/5",
                  entry.level === "warning" && "bg-amber-50/40 dark:bg-amber-500/5",
                )}
              >
                <td className="px-5 py-2 whitespace-nowrap" title={at.full}>
                  <span className="font-mono text-xs text-slate-700 dark:text-slate-200">{at.clock}</span>
                  <span className="ml-2 text-xs text-slate-400">{at.day}</span>
                </td>
                <td className="px-3 py-2">
                  <LevelBadge level={entry.level} />
                </td>
                <td className="px-3 py-2 text-xs whitespace-nowrap text-slate-600 dark:text-slate-300">
                  <span className="inline-flex items-center gap-1.5">
                    {entry.source === "agent" ? (
                      <RadioTower className="size-3.5 text-slate-400" aria-hidden />
                    ) : (
                      <Server className="size-3.5 text-slate-400" aria-hidden />
                    )}
                    {entry.source === "agent" ? "Agent" : "Server"}
                    {showHost && entry.host_id && (
                      <>
                        <span className="text-slate-300 dark:text-slate-600">·</span>
                        <Link to={`/hosts/${entry.host_id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
                          {entry.host || entry.host_id.slice(0, 8)}
                        </Link>
                      </>
                    )}
                  </span>
                </td>
                <td className="px-5 py-2 font-mono text-xs leading-relaxed break-words whitespace-pre-wrap text-slate-800 dark:text-slate-200">
                  {entry.message}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
