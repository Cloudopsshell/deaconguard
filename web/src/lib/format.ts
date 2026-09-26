import type { ScanStatus, Severity, SeverityCounts } from "../api";

export const severityOrder: Severity[] = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export const severityStyle: Record<Severity, { label: string; badge: string; bar: string; text: string }> = {
  CRITICAL: {
    label: "Critical",
    badge: "bg-red-100 text-red-800 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300 dark:ring-red-400/30",
    bar: "bg-red-600",
    text: "text-red-700 dark:text-red-400",
  },
  HIGH: {
    label: "High",
    badge: "bg-orange-100 text-orange-800 ring-orange-600/20 dark:bg-orange-500/15 dark:text-orange-300 dark:ring-orange-400/30",
    bar: "bg-orange-500",
    text: "text-orange-700 dark:text-orange-400",
  },
  MEDIUM: {
    label: "Medium",
    badge: "bg-amber-100 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-400/30",
    bar: "bg-amber-400",
    text: "text-amber-700 dark:text-amber-400",
  },
  LOW: {
    label: "Low",
    badge: "bg-sky-100 text-sky-800 ring-sky-600/20 dark:bg-sky-500/15 dark:text-sky-300 dark:ring-sky-400/30",
    bar: "bg-sky-500",
    text: "text-sky-700 dark:text-sky-400",
  },
  UNKNOWN: {
    label: "Unknown",
    badge: "bg-slate-100 text-slate-700 ring-slate-500/20 dark:bg-slate-500/15 dark:text-slate-300 dark:ring-slate-400/30",
    bar: "bg-slate-400",
    text: "text-slate-600 dark:text-slate-400",
  },
};

export function countFor(counts: SeverityCounts, severity: Severity): number {
  return counts[severity.toLowerCase() as keyof SeverityCounts];
}

export function normalizeSeverity(value: string): Severity {
  const upper = value.toUpperCase();
  return (severityOrder as string[]).includes(upper) ? (upper as Severity) : "UNKNOWN";
}

const relative = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return "—";
  const seconds = (new Date(iso).getTime() - Date.now()) / 1000;
  const steps: [Intl.RelativeTimeFormatUnit, number][] = [
    ["year", 31536000],
    ["month", 2592000],
    ["week", 604800],
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
  ];
  for (const [unit, size] of steps) {
    if (Math.abs(seconds) >= size) return relative.format(Math.round(seconds / size), unit);
  }
  return "just now";
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
}

/** True while a scan is running or paused waiting for the user. */
export function isActive(status: ScanStatus | undefined): boolean {
  return status === "running" || (status?.startsWith("needs_") ?? false);
}
