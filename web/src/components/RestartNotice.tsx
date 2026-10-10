import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { AlertTriangle, X } from "lucide-react";
import { api, type ServerStop } from "../api";
import { dateTime, timeAgo } from "../lib/format";

const storageKey = "deaconguard.dismissedRestart";
// An unexpected restart is shown for a week, or until it is dismissed.
const showFor = 7 * 24 * 60 * 60 * 1000;

const titles: Record<ServerStop["kind"], string> = {
  stopped: "The server was restarted",
  reboot: "The server's machine restarted",
  out_of_memory: "The server ran out of memory",
  crashed: "The server crashed",
  killed: "The server was stopped",
  unknown: "The server stopped unexpectedly",
};

function dismissed(): string | null {
  try {
    return localStorage.getItem(storageKey);
  } catch {
    return null;
  }
}

/** Says why the server restarted, when it did not stop cleanly. */
export function RestartNotice() {
  const status = useQuery({ queryKey: ["server-status"], queryFn: api.serverStatus, staleTime: 5 * 60_000 });
  const [hidden, setHidden] = useState(dismissed);
  const stop = status.data?.last_stop;
  if (!stop || stop.kind === "stopped" || hidden === stop.detected_at) return null;
  if (Date.now() - new Date(stop.detected_at).getTime() > showFor) return null;

  function dismiss() {
    try {
      localStorage.setItem(storageKey, stop!.detected_at);
    } catch {
      // Dismissing is a convenience only.
    }
    setHidden(stop!.detected_at);
  }

  return (
    <div
      role="status"
      className="mb-6 flex gap-3 rounded-xl border border-amber-300 bg-amber-50 p-4 text-sm dark:border-amber-500/40 dark:bg-amber-500/10"
    >
      <AlertTriangle className="mt-0.5 size-5 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden />
      <div className="min-w-0 flex-1">
        <p className="font-semibold text-amber-900 dark:text-amber-200">
          {titles[stop.kind]} · restarted {timeAgo(stop.detected_at)}
        </p>
        <p className="mt-1 text-amber-900/90 dark:text-amber-100/90">{stop.message}</p>
        <p className="mt-1 text-xs text-amber-800/80 dark:text-amber-200/70">
          Running since {dateTime(stop.started_at)}
          {stop.stopped_at ? `, stopped ${dateTime(stop.stopped_at)}` : ""}, restarted {dateTime(stop.detected_at)}
          {stop.version ? ` · version ${stop.version}` : ""}. Scans that were running then are marked failed; run them again.
        </p>
        {stop.kind === "out_of_memory" && (
          <p className="mt-1 text-xs text-amber-800/80 dark:text-amber-200/70">
            Give the server more memory or add swap; see{" "}
            <a className="underline" href="https://docs.deaconguard.io/installation/requirements" target="_blank" rel="noreferrer">
              requirements
            </a>
            .
          </p>
        )}
        {stop.detail && (
          <details className="mt-2">
            <summary className="cursor-pointer text-xs font-medium text-amber-900 dark:text-amber-200">Crash report</summary>
            <pre className="mt-2 max-h-64 overflow-auto rounded-lg bg-white/70 p-3 text-[11px] leading-relaxed text-slate-800 dark:bg-slate-950/60 dark:text-slate-200">
              {stop.detail}
            </pre>
          </details>
        )}
      </div>
      <button
        type="button"
        onClick={dismiss}
        aria-label="Dismiss"
        className="h-fit rounded-md p-1 text-amber-700 hover:bg-amber-100 dark:text-amber-300 dark:hover:bg-amber-500/20"
      >
        <X className="size-4" />
      </button>
    </div>
  );
}
