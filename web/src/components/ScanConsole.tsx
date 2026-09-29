import { useEffect, useRef, useState, type ReactNode } from "react";
import { Link } from "react-router";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { ArrowDown, Check, CheckCircle2, ChevronDown, ChevronUp, Loader2, Minus, Plug, TerminalSquare, TriangleAlert, X, XCircle } from "lucide-react";
import { api, type Activity, type CheckId, type Host, type Scan, type ScanEvent } from "../api";
import { checkMeta, checkOrder } from "../lib/checks";
import { useScanEvents } from "../lib/useScanEvents";
import { cx } from "./ui";

/**
 * A translucent console on a host's page that follows that host's scans:
 * each step, the fixed commands OpsArmor runs on the host, and findings as
 * checks complete. A running scan always shows, at least as a pill; a finished
 * one stays only while the page that watched it is open, or when its saved
 * log is opened from the scan history.
 */
export function ScanConsole({
  host,
  requested,
  onRequestClosed,
}: {
  host: Host;
  /** A scan whose log the user asked to see. */
  requested: Scan | null;
  onRequestClosed: () => void;
}) {
  const [dismissed, setDismissed] = useState<Set<string>>(new Set());
  const [selected, setSelected] = useState<string | null>(null);
  // Start tucked away; only a scan that starts while the page is open, or a
  // log the user opens, expands the console.
  const [minimized, setMinimized] = useState(true);
  // Scans seen running while this page was open; they stay after finishing.
  const [watched, setWatched] = useState<Set<string>>(new Set());
  const known = useRef<Set<string> | null>(null);
  const { data } = useQuery({
    queryKey: ["activity"],
    queryFn: api.activity,
    refetchInterval: (query) => (query.state.data?.some((item) => !item.finished_at) ? 1500 : 5000),
  });
  const hostActivity = (data ?? []).filter((item) => item.host_id === host.id);

  useEffect(() => {
    if (!data) return;
    const running = hostActivity.filter((item) => !item.finished_at);
    if (running.length > 0) setWatched((current) => new Set([...current, ...running.map((item) => item.scan_id)]));
    // The first load only records what already exists, so reloading never pops the console open.
    const fresh = known.current && running.find((item) => !known.current!.has(item.scan_id));
    known.current = new Set([...(known.current ?? []), ...hostActivity.map((item) => item.scan_id)]);
    if (fresh) {
      setSelected(fresh.scan_id);
      setMinimized(false);
    }
    // Only new activity data should change what is shown, not local UI state.
  }, [data]);

  useEffect(() => {
    if (!requested) return;
    setSelected(requested.id);
    setMinimized(false);
    setDismissed((current) => {
      const next = new Set(current);
      next.delete(requested.id);
      return next;
    });
  }, [requested]);

  const sessions = hostActivity.filter(
    (item) => (!item.finished_at || watched.has(item.scan_id)) && !dismissed.has(item.scan_id),
  );
  if (requested && !dismissed.has(requested.id) && !sessions.some((item) => item.scan_id === requested.id)) {
    sessions.unshift(activityFromScan(requested, host));
  }
  if (sessions.length === 0) return null;
  const active = sessions.find((item) => item.scan_id === selected) ?? sessions[0];
  const dismiss = (scanId: string) => {
    setDismissed((current) => new Set(current).add(scanId));
    if (requested?.id === scanId) onRequestClosed();
  };

  if (minimized) {
    return (
      <div className="pointer-events-none fixed inset-x-4 bottom-4 z-40 flex justify-end sm:inset-x-auto sm:right-5 sm:bottom-5">
        <ConsoleSession
          key={active.scan_id}
          activity={active}
          sessions={sessions}
          minimized
          onSelect={setSelected}
          onMinimize={setMinimized}
          onDismiss={dismiss}
        />
      </div>
    );
  }
  return (
    <div className="fixed inset-0 z-40 flex items-center justify-center p-4">
      {/* A light veil keeps the page visible; clicking it tucks the console away. */}
      <button
        type="button"
        aria-label="Minimize console"
        tabIndex={-1}
        onClick={() => setMinimized(true)}
        className="absolute inset-0 cursor-default bg-slate-950/25 backdrop-blur-[2px]"
      />
      <ConsoleSession
        key={active.scan_id}
        activity={active}
        sessions={sessions}
        minimized={false}
        onSelect={setSelected}
        onMinimize={setMinimized}
        onDismiss={dismiss}
      />
    </div>
  );
}

function activityFromScan(scan: Scan, host: Host): Activity {
  return {
    scan_id: scan.id,
    host_id: host.id,
    address: host.address,
    username: host.username,
    checks: scan.checks,
    started_at: scan.started_at,
    finished_at: scan.finished_at ?? undefined,
    status: scan.status,
  };
}

type PhaseState = "pending" | "active" | "completed" | "partial" | "skipped" | "failed";

function ConsoleSession({
  activity,
  sessions,
  minimized,
  onSelect,
  onMinimize,
  onDismiss,
}: {
  activity: Activity;
  sessions: Activity[];
  minimized: boolean;
  onSelect: (scanId: string) => void;
  onMinimize: (minimized: boolean) => void;
  onDismiss: (scanId: string) => void;
}) {
  const queryClient = useQueryClient();
  const { events, ended, unavailable } = useScanEvents(activity.scan_id);
  const done = events.find((event) => event.kind === "done");
  const finished = Boolean(done) || ended || Boolean(activity.finished_at);
  const failed = done?.status === "failed" || activity.status === "failed";
  const waiting = !finished && (activity.status.startsWith("needs_") || events.at(-1)?.kind === "prompt");
  const elapsed = useElapsed(activity.started_at, done?.time ?? activity.finished_at);

  useEffect(() => {
    if (minimized) return;
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onMinimize(true);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [minimized, onMinimize]);

  // Refresh the page underneath as soon as the scan's results are saved, and
  // once more shortly after in case a refresh was already in flight.
  useEffect(() => {
    if (!done) return;
    queryClient.invalidateQueries();
    const again = setTimeout(() => queryClient.invalidateQueries(), 1500);
    return () => clearTimeout(again);
  }, [done, queryClient]);

  const phases = ["connect", ...checkOrder.filter((check) => activity.checks.includes(check))];
  const states = phaseStates(phases, events, finished);
  const current = phases.find((phase) => states[phase] === "active");
  const completedCount = phases.filter((phase) => states[phase] !== "pending" && states[phase] !== "active").length;
  const progress = finished ? 100 : Math.max(4, (completedCount / phases.length) * 100);
  const resultsTab = activity.checks.find((check) => check !== "packages");

  // Once finished, the scan is summarised by its worst outcome.
  const checkPhases = phases.filter((phase) => phase !== "connect");
  const outcome: "ok" | "warning" | "failed" =
    failed || phases.some((phase) => states[phase] === "failed")
      ? "failed"
      : checkPhases.some((phase) => states[phase] === "partial" || states[phase] === "skipped")
        ? "warning"
        : "ok";
  const outcomeIcon = {
    ok: <CheckCircle2 className="size-4 shrink-0 text-emerald-400" aria-label="All checks completed" />,
    warning: <TriangleAlert className="size-4 shrink-0 text-amber-300" aria-label="Some checks were partial or skipped" />,
    failed: <XCircle className="size-4 shrink-0 text-red-400" aria-label="Failed" />,
  }[outcome];

  const orb = finished ? (
    outcomeIcon
  ) : (
    <span className="relative flex size-2.5 shrink-0">
      {!finished && (
        <span
          className={cx(
            "absolute inline-flex size-full animate-ping rounded-full opacity-60 motion-reduce:hidden",
            waiting ? "bg-amber-400" : "bg-emerald-400",
          )}
        />
      )}
      <span
        className={cx(
          "relative inline-flex size-2.5 rounded-full",
          failed ? "bg-red-500" : finished ? "bg-emerald-400" : waiting ? "bg-amber-400" : "bg-emerald-400",
        )}
      />
    </span>
  );
  const allSkipped = checkPhases.length > 0 && checkPhases.every((phase) => states[phase] === "skipped");
  const headline = !finished
    ? waiting
      ? "Waiting for you"
      : "Scanning"
    : outcome === "failed"
      ? "Scan failed"
      : allSkipped
        ? "Scan skipped"
        : outcome === "warning"
          ? "Scan completed · partial"
          : "Scan completed";
  const finishedAt = done?.time ?? activity.finished_at;
  const finishedTime = finishedAt ? finishedLabel(finishedAt) : "";

  if (minimized) {
    return (
      <div className="animate-console-in pointer-events-auto flex max-w-full items-center rounded-full bg-slate-950/80 text-sm text-slate-200 shadow-2xl ring-1 shadow-black/40 ring-white/10 backdrop-blur-xl">
      <button
        type="button"
        onClick={() => onMinimize(false)}
        className={cx(
          "flex min-w-0 items-center gap-3 rounded-full py-2.5 pl-4 hover:bg-white/5",
          finished ? "pr-2" : "pr-3",
        )}
        aria-label={finished ? "Show the finished scan's console" : "Expand live scan console"}
        title="Show console"
      >
        {orb}
        <span className="truncate font-medium">
          {headline} · {activity.address}
        </span>
        {current && !finished && <span className="hidden truncate text-slate-400 sm:inline">· {phaseLabel(current)}</span>}
        {finished && (
          <span className="flex items-center gap-1.5">
            {checkPhases.map((phase) => (
              <CheckOutcome key={phase} phase={phase} state={states[phase]} />
            ))}
          </span>
        )}
        {finished && finishedTime && (
          <span className="text-xs whitespace-nowrap text-slate-400" title={`Finished ${new Date(finishedAt!).toLocaleString()}`}>
            {finishedTime}
          </span>
        )}
        <span className="font-mono text-xs whitespace-nowrap text-slate-400 tabular-nums" title={finished ? "Time taken" : "Elapsed"}>
          {finished ? `took ${elapsed}` : elapsed}
        </span>
        {sessions.length > 1 && <span className="rounded-full bg-white/10 px-1.5 text-xs">{sessions.length}</span>}
        <ChevronUp className="size-4 text-slate-400" />
      </button>
      {finished && (
        <button
          type="button"
          onClick={() => onDismiss(activity.scan_id)}
          aria-label="Dismiss this scan's console"
          title="Dismiss"
          className="mr-1.5 rounded-full p-1.5 text-slate-400 hover:bg-white/10 hover:text-white"
        >
          <X className="size-3.5" />
        </button>
      )}
      </div>
    );
  }

  return (
    <section
      aria-label="Live scan console"
      className="animate-console-in pointer-events-auto relative flex h-[min(36rem,calc(100vh-2rem))] w-full max-w-4xl flex-col overflow-hidden rounded-2xl bg-slate-900/60 text-slate-200 shadow-2xl ring-1 shadow-black/40 ring-white/15 backdrop-blur-md"
    >
      <div className="pointer-events-none absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-indigo-400/70 to-transparent" />

      <header className="flex items-center gap-3 px-4 pt-3.5 pb-3">
        <TerminalSquare className="size-4.5 shrink-0 text-indigo-300" aria-hidden />
        <div className="min-w-0 flex-1">
          <p className="flex items-center gap-2 text-sm font-semibold text-white">
            {orb}
            <span className="truncate">
              {headline} · {activity.username}@{activity.address}
            </span>
          </p>
          <p className="mt-0.5 truncate text-xs text-slate-400">
            {finished
              ? `Finished ${finishedTime ? `at ${finishedTime}` : ""} · took ${elapsed}${failed && done ? ` · ${done.message}` : ""}`
              : current
                ? `Now: ${phaseLabel(current)}`
                : "Starting…"}
          </p>
        </div>
        <span className="font-mono text-sm text-slate-300 tabular-nums">{elapsed}</span>
        <div className="flex items-center">
          <IconButton label="Minimize console" onClick={() => onMinimize(true)}>
            <ChevronDown className="size-4" />
          </IconButton>
          {finished && (
            <IconButton label="Close this scan's console" onClick={() => onDismiss(activity.scan_id)}>
              <X className="size-4" />
            </IconButton>
          )}
        </div>
      </header>

      {sessions.length > 1 && (
        <nav className="flex gap-1 overflow-x-auto px-4 pb-2" aria-label="Scans">
          {sessions.map((session) => (
            <button
              key={session.scan_id}
              type="button"
              onClick={() => onSelect(session.scan_id)}
              className={cx(
                "flex shrink-0 items-center gap-1.5 rounded-md px-2 py-1 text-xs transition-colors",
                session.scan_id === activity.scan_id ? "bg-white/10 text-white" : "text-slate-400 hover:bg-white/5 hover:text-slate-200",
              )}
            >
              <span
                className={cx(
                  "size-1.5 rounded-full",
                  session.finished_at ? (session.status === "failed" ? "bg-red-500" : "bg-emerald-400") : "bg-amber-300",
                )}
              />
              {session.address}
            </button>
          ))}
        </nav>
      )}

      <div className="px-4 pb-3">
        <ol className="flex flex-wrap gap-1.5">
          {phases.map((phase) => (
            <PhaseChip key={phase} phase={phase} state={states[phase]} />
          ))}
        </ol>
        <div className="mt-3 h-1 overflow-hidden rounded-full bg-white/5">
          <div
            className={cx(
              "h-full rounded-full transition-[width] duration-700 ease-out",
              failed
                ? "bg-red-500"
                : finished
                  ? "bg-emerald-400"
                  : "animate-shimmer bg-gradient-to-r from-indigo-500 via-cyan-300 to-indigo-500",
            )}
            style={{ width: `${progress}%` }}
          />
        </div>
      </div>

      <LogView events={events} running={!finished} unavailable={unavailable} />

      {finished && !failed && (
        <footer className="flex items-center justify-between gap-3 border-t border-white/10 px-4 py-2.5 text-xs text-slate-400">
          <span>Results are saved to the host.</span>
          <Link
            to={`/hosts/${activity.host_id}${resultsTab ? `?tab=${resultsTab}` : ""}`}
            onClick={() => {
              onMinimize(true);
              window.scrollTo({ top: 0, behavior: "smooth" });
            }}
            className="rounded-md bg-indigo-500/90 px-2.5 py-1 font-semibold text-white hover:bg-indigo-400"
          >
            View results
          </Link>
        </footer>
      )}
    </section>
  );
}

function IconButton({ label, onClick, children }: { label: string; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="rounded-md p-1.5 text-slate-400 hover:bg-white/10 hover:text-white"
    >
      {children}
    </button>
  );
}

/** A check's icon coloured by how it ended, for the finished-scan pill. */
function CheckOutcome({ phase, state }: { phase: string; state: PhaseState }) {
  const Icon = checkMeta[phase as CheckId]?.icon ?? Minus;
  const color: Record<PhaseState, string> = {
    pending: "text-slate-600",
    active: "text-slate-400",
    completed: "text-emerald-400",
    partial: "text-amber-300",
    skipped: "text-slate-500",
    failed: "text-red-400",
  };
  const label: Record<PhaseState, string> = {
    pending: "not run",
    active: "stopped",
    completed: "completed",
    partial: "partial coverage",
    skipped: "skipped",
    failed: "failed",
  };
  return (
    <span title={`${phaseLabel(phase)}: ${label[state]}`} aria-label={`${phaseLabel(phase)}: ${label[state]}`} className={color[state]}>
      <Icon className="size-3.5" />
    </span>
  );
}

function PhaseChip({ phase, state }: { phase: string; state: PhaseState }) {
  const Icon = phase === "connect" ? Plug : checkMeta[phase as CheckId].icon;
  const style: Record<PhaseState, string> = {
    pending: "text-slate-500 ring-white/10",
    active: "bg-indigo-500/15 text-indigo-200 ring-indigo-400/40",
    completed: "bg-emerald-500/10 text-emerald-300 ring-emerald-400/25",
    partial: "bg-amber-500/10 text-amber-200 ring-amber-400/30",
    skipped: "text-slate-400 ring-white/15",
    failed: "bg-red-500/15 text-red-300 ring-red-400/40",
  };
  const marker: Record<PhaseState, ReactNode> = {
    pending: null,
    active: <Loader2 className="size-3 animate-spin" />,
    completed: <Check className="size-3" />,
    partial: <span className="text-[10px] leading-none font-bold">!</span>,
    skipped: <Minus className="size-3" />,
    failed: <X className="size-3" />,
  };
  return (
    <li
      className={cx("flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium ring-1 ring-inset", style[state])}
      title={`${phaseLabel(phase)}: ${state}`}
    >
      <Icon className="size-3" />
      {phase === "connect" ? "Connect" : checkMeta[phase as CheckId].short}
      {marker[state]}
    </li>
  );
}

function LogView({ events, running, unavailable }: { events: ScanEvent[]; running: boolean; unavailable: boolean }) {
  const scroller = useRef<HTMLDivElement>(null);
  const [following, setFollowing] = useState(true);

  useEffect(() => {
    if (following && scroller.current) scroller.current.scrollTop = scroller.current.scrollHeight;
  }, [events.length, following]);

  return (
    <div className="relative min-h-0 flex-1 border-t border-white/10 bg-black/15">
      <div
        ref={scroller}
        role="log"
        aria-label="Scan activity"
        onScroll={(event) => {
          const element = event.currentTarget;
          setFollowing(element.scrollHeight - element.scrollTop - element.clientHeight < 24);
        }}
        className="h-full overflow-y-auto px-4 py-3 font-mono text-[12.5px] leading-relaxed"
      >
        {unavailable && events.length === 0 && (
          <p className="text-slate-500">The live log for this scan is no longer available. Its results are saved on the host page.</p>
        )}
        {events.map((event) => (
          <LogLine key={event.seq} event={event} />
        ))}
        {running && (
          <p className="mt-1 flex items-center gap-2 text-slate-500">
            <span className="inline-block h-3.5 w-2 animate-pulse bg-indigo-300/80 motion-reduce:animate-none" />
          </p>
        )}
      </div>
      {!following && (
        <button
          type="button"
          onClick={() => setFollowing(true)}
          className="absolute right-4 bottom-3 flex items-center gap-1 rounded-full bg-indigo-500/90 px-2.5 py-1 text-xs font-semibold text-white shadow-lg hover:bg-indigo-400"
        >
          <ArrowDown className="size-3.5" /> Latest
        </button>
      )}
    </div>
  );
}

const findingColor: Record<string, string> = {
  CRITICAL: "bg-red-500/20 text-red-300",
  HIGH: "bg-orange-500/20 text-orange-300",
  MEDIUM: "bg-amber-500/20 text-amber-200",
  LOW: "bg-sky-500/20 text-sky-300",
};

function LogLine({ event }: { event: ScanEvent }) {
  const time = new Date(event.time).toLocaleTimeString(undefined, { hour12: false });
  const stamp = <span className="mr-3 shrink-0 text-slate-600 select-none">{time}</span>;
  switch (event.kind) {
    case "phase":
      return (
        <p className="mt-3 mb-1 flex border-t border-white/5 pt-2 font-sans text-[13px] font-semibold text-white first:mt-0 first:border-0 first:pt-0">
          {stamp}
          <span className="text-indigo-300">▸</span>&nbsp;{event.message}
        </p>
      );
    case "command":
      return (
        <p className="flex">
          {stamp}
          <span className="min-w-0 break-all">
            <span className="text-cyan-400 select-none">$ </span>
            {event.sudo && (
              <span className="mr-1.5 rounded bg-amber-400/15 px-1 py-px text-[10px] font-semibold tracking-wide text-amber-300 uppercase">
                sudo
              </span>
            )}
            <span className="text-cyan-100">{event.message}</span>
          </span>
        </p>
      );
    case "result":
      return (
        <p className="flex text-slate-500">
          {stamp}
          <span>&nbsp;&nbsp;↳ {event.message}</span>
        </p>
      );
    case "finding":
      return (
        <p className="flex">
          {stamp}
          <span className="min-w-0">
            &nbsp;&nbsp;
            <span className={cx("mr-2 rounded px-1 py-px text-[10px] font-bold", findingColor[event.severity ?? ""] ?? "bg-white/10")}>
              {event.severity}
            </span>
            <span className="text-slate-200">{event.message}</span>
          </span>
        </p>
      );
    case "prompt":
      return (
        <p className="my-1 flex rounded-md bg-violet-500/10 px-2 py-1 text-violet-200 ring-1 ring-violet-400/20">
          {stamp}? {event.message}
        </p>
      );
    case "done":
      return (
        <p
          className={cx(
            "mt-3 flex border-t border-white/10 pt-2 font-sans text-[13px] font-semibold",
            event.status === "failed" ? "text-red-300" : "text-emerald-300",
          )}
        >
          {stamp}
          {event.status === "failed" ? "✕" : "✓"}&nbsp;{event.message}
        </p>
      );
    default: {
      const tone: Record<string, [string, string]> = {
        success: ["✓", "text-emerald-300"],
        warning: ["!", "text-amber-300"],
        error: ["✕", "text-red-300"],
        info: ["·", "text-slate-400"],
      };
      const [glyph, color] = tone[event.kind] ?? tone.info;
      return (
        <p className={cx("flex", color)}>
          {stamp}
          <span className="min-w-0 break-words">
            {glyph}&nbsp;{event.message}
          </span>
        </p>
      );
    }
  }
}

function phaseLabel(phase: string) {
  return phase === "connect" ? "Connecting" : (checkMeta[phase as CheckId]?.label ?? phase);
}

function phaseStates(phases: string[], events: ScanEvent[], finished: boolean) {
  const states = Object.fromEntries(phases.map((phase) => [phase, "pending"])) as Record<string, PhaseState>;
  for (const event of events) {
    if (!event.phase || !(event.phase in states)) continue;
    if (event.kind === "phase") states[event.phase] = "active";
    if (event.status && event.kind !== "done") states[event.phase] = event.status as PhaseState;
  }
  if (finished) {
    for (const phase of phases) if (states[phase] === "active") states[phase] = "failed";
  }
  return states;
}

/** "12:33 AM" today, or "Sep 26, 11:58 PM" on another day. */
function finishedLabel(iso: string) {
  const date = new Date(iso);
  const today = new Date().toDateString() === date.toDateString();
  return date.toLocaleString(undefined, today ? { timeStyle: "short" } : { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
}

function useElapsed(startedAt: string, finishedAt?: string) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (finishedAt) return;
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, [finishedAt]);
  const end = finishedAt ? new Date(finishedAt).getTime() : now;
  const seconds = Math.max(0, Math.round((end - new Date(startedAt).getTime()) / 1000));
  const minutes = Math.floor(seconds / 60);
  return `${String(minutes).padStart(2, "0")}:${String(seconds % 60).padStart(2, "0")}`;
}
