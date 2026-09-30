import type { ComponentType } from "react";
import { Bug, FileCheck2, ScanSearch, SlidersHorizontal, Skull } from "lucide-react";
import type { CheckId, CheckStatus, SeverityCounts } from "../api";
import { severityOrder } from "./format";

export const checkOrder: CheckId[] = ["packages", "integrity", "malware", "config", "antivirus"];

export const checkMeta: Record<CheckId, { label: string; short: string; icon: ComponentType<{ className?: string }> }> = {
  packages: { label: "Vulnerabilities", short: "CVEs", icon: Bug },
  integrity: { label: "File integrity", short: "Integrity", icon: FileCheck2 },
  malware: { label: "Malware indicators", short: "Malware", icon: Skull },
  config: { label: "Configuration", short: "Config", icon: SlidersHorizontal },
  antivirus: { label: "Antivirus", short: "ClamAV", icon: ScanSearch },
};

export const checkStatusStyle: Record<CheckStatus, { label: string; className: string }> = {
  completed: {
    label: "Complete",
    className: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300 dark:ring-emerald-400/30",
  },
  partial: {
    label: "Partial coverage",
    className: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-400/30",
  },
  skipped: {
    label: "Skipped",
    className: "bg-slate-100 text-slate-700 ring-slate-500/20 dark:bg-slate-500/15 dark:text-slate-300 dark:ring-slate-400/30",
  },
  failed: {
    label: "Failed",
    className: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300 dark:ring-red-400/30",
  },
};

/** Short text for a check's result: a tick only when the check actually examined the host. */
export function checkBadgeText(summary: { status: CheckStatus; finding_count: number }) {
  if (summary.status === "skipped") return "skipped";
  if (summary.status === "failed") return "failed";
  return summary.finding_count === 0 ? "✓" : summary.finding_count.toLocaleString();
}

/** The highest severity present, used to colour a compact count. */
export function topSeverity(counts: SeverityCounts) {
  return severityOrder.find((severity) => counts[severity.toLowerCase() as keyof SeverityCounts] > 0);
}

const storageKey = "deaconguard.selectedChecks";

export function rememberedChecks(): CheckId[] | null {
  try {
    const value = JSON.parse(localStorage.getItem(storageKey) ?? "null");
    return Array.isArray(value) ? value.filter((id): id is CheckId => checkOrder.includes(id)) : null;
  } catch {
    return null;
  }
}

export function rememberChecks(ids: CheckId[]) {
  try {
    localStorage.setItem(storageKey, JSON.stringify(ids));
  } catch {
    // Remembering the selection is a convenience only.
  }
}
