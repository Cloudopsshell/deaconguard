import type { AuditSummary, ControlStatus } from "../api";
import { cx } from "../components/ui";

const gradeStyles: Record<AuditSummary["grade"], string> = {
  A: "bg-emerald-600 text-white",
  B: "bg-emerald-100 text-emerald-800 ring-1 ring-emerald-600/30 ring-inset dark:bg-emerald-500/20 dark:text-emerald-200",
  C: "bg-amber-100 text-amber-900 ring-1 ring-amber-600/30 ring-inset dark:bg-amber-500/20 dark:text-amber-200",
  D: "bg-orange-100 text-orange-900 ring-1 ring-orange-600/30 ring-inset dark:bg-orange-500/20 dark:text-orange-200",
  F: "bg-red-600 text-white",
};

/** A letter grade in a rounded square; large on the audit page, small in lists. */
export function GradeBadge({ grade, size = "sm" }: { grade?: AuditSummary["grade"]; size?: "sm" | "lg" }) {
  if (!grade) return <span className="text-sm text-slate-400">—</span>;
  return (
    <span
      className={cx(
        "inline-flex shrink-0 items-center justify-center rounded-lg font-bold",
        size === "lg" ? "size-16 text-4xl" : "size-8 text-base",
        gradeStyles[grade],
      )}
      aria-label={`Grade ${grade}`}
    >
      {grade}
    </span>
  );
}

export const controlStatusStyle: Record<ControlStatus, { label: string; className: string }> = {
  pass: { label: "Pass", className: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300" },
  fail: { label: "Fail", className: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300" },
  accepted: { label: "Accepted", className: "bg-indigo-50 text-indigo-700 ring-indigo-600/20 dark:bg-indigo-500/15 dark:text-indigo-300" },
  na: { label: "Not applicable", className: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300" },
  unknown: { label: "Not checked", className: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300" },
};

export function ControlStatusBadge({ status }: { status: ControlStatus }) {
  const style = controlStatusStyle[status];
  return <span className={cx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset", style.className)}>{style.label}</span>;
}

export function formatBytes(bytes: number) {
  if (!bytes) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = bytes;
  let unit = 0;
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024;
    unit++;
  }
  return `${value >= 10 || unit === 0 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`;
}

export function formatUptime(seconds: number) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  if (days > 0) return `${days} day${days === 1 ? "" : "s"}, ${hours} h`;
  const minutes = Math.floor((seconds % 3600) / 60);
  return hours > 0 ? `${hours} h ${minutes} min` : `${minutes} min`;
}
