import type { ComponentType } from "react";
import { CircleSlash, Download, HardDrive, Hourglass, RotateCw } from "lucide-react";
import type { Finding, FixState, FixSummary, SeverityCounts } from "../api";
import { SeverityCountsInline } from "../components/ui";

export const fixOrder: FixState[] = ["available", "reboot", "old_kernel", "ubuntu_pro", "none"];

/** Installing updates or restarting fixes findings in these states. */
export function actionable(state: FixState) {
  return state === "available" || state === "reboot";
}

/** A finding's fix state; reports from before 0.7.0 only say whether a fixed version exists. */
export function fixOf(finding: Pick<Finding, "fix" | "fixed_version">): FixState {
  return finding.fix ?? (finding.fixed_version ? "available" : "none");
}

export const fixMeta: Record<
  FixState,
  { label: string; short: string; description: string; icon: ComponentType<{ className?: string }>; badge: string }
> = {
  available: {
    label: "Update available",
    short: "Update",
    description: "The distribution published a fixed package. Installing updates fixes these.",
    icon: Download,
    badge: "bg-indigo-50 text-indigo-700 ring-indigo-600/20 dark:bg-indigo-500/15 dark:text-indigo-300 dark:ring-indigo-400/30",
  },
  reboot: {
    label: "Restart needed",
    short: "Restart",
    description: "The fixed kernel is already installed but not running yet. Restarting the machine fixes these.",
    icon: RotateCw,
    badge: "bg-violet-50 text-violet-700 ring-violet-600/20 dark:bg-violet-500/15 dark:text-violet-300 dark:ring-violet-400/30",
  },
  old_kernel: {
    label: "Old kernel",
    short: "Old kernel",
    description: "In older kernels that are installed but not running, kept as a fallback. Removing old kernels clears these.",
    icon: HardDrive,
    badge: "bg-slate-100 text-slate-700 ring-slate-500/20 dark:bg-slate-500/15 dark:text-slate-300 dark:ring-slate-400/30",
  },
  ubuntu_pro: {
    label: "Ubuntu Pro",
    short: "Ubuntu Pro",
    description: "Ubuntu publishes these fixes only in Ubuntu Pro (ESM), free for up to 5 machines for personal use.",
    icon: CircleSlash,
    badge: "bg-orange-50 text-orange-700 ring-orange-600/20 dark:bg-orange-500/15 dark:text-orange-300 dark:ring-orange-400/30",
  },
  none: {
    label: "No fix yet",
    short: "No fix yet",
    description:
      "The distribution knows about these but has not published a fix. Updating cannot help yet; they clear once a fix ships and you update.",
    icon: Hourglass,
    badge: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-500/15 dark:text-slate-300 dark:ring-slate-400/30",
  },
};

/** The command that applies a fix state on a machine with this package manager and OS. */
export function fixCommand(state: FixState, packageManager: string, os: string): string | undefined {
  const dpkg = packageManager === "dpkg";
  switch (state) {
    case "available":
      if (dpkg) return "sudo apt update && sudo apt upgrade";
      // Amazon Linux 2023 locks each machine to the release it was installed
      // from; fixes published since need the latest release.
      return os.startsWith("Amazon Linux") ? "sudo dnf upgrade --releasever=latest" : "sudo dnf upgrade";
    case "reboot":
      return "sudo reboot";
    case "old_kernel":
      return dpkg ? "sudo apt autoremove --purge" : "sudo dnf remove --oldinstallonly";
    case "ubuntu_pro":
      return os.startsWith("Ubuntu") ? "sudo pro attach" : undefined;
    default:
      return undefined;
  }
}

/**
 * What a package check means for someone acting on it: the findings to fix
 * now and their severities, and how many wait on the distribution. Results
 * from before 0.7.0 have no fix summary, so all their findings count.
 */
export function packageCounts(summary: { finding_count: number; severity: SeverityCounts; fixes?: FixSummary | null }) {
  const fixes = summary.fixes;
  if (!fixes) return { toFix: summary.finding_count, severity: summary.severity, noFix: 0, other: 0 };
  const counts = fixes.counts;
  const toFix = (counts.available ?? 0) + (counts.reboot ?? 0);
  return {
    toFix,
    severity: fixes.actionable,
    noFix: counts.none ?? 0,
    other: (counts.old_kernel ?? 0) + (counts.ubuntu_pro ?? 0),
  };
}

/** The badge for a package check: findings to fix now, or how many wait on the distribution. Never a tick while any remain. */
export function packageBadge(summary: { finding_count: number; severity: SeverityCounts; fixes?: FixSummary | null }) {
  const counts = packageCounts(summary);
  const waiting = counts.noFix + counts.other;
  if (counts.toFix > 0) return { text: counts.toFix.toLocaleString(), severity: counts.severity, waiting, title: `${counts.toFix.toLocaleString()} to fix now with an update or a restart${waiting ? `; ${waiting.toLocaleString()} more wait on the distribution or need another step` : ""}` };
  if (waiting > 0) return { text: `${waiting.toLocaleString()} waiting`, severity: undefined, waiting, title: "Nothing to fix now: no update or restart fixes these yet" };
  return { text: "✓", severity: undefined, waiting: 0, title: "No findings" };
}

/** Severity counts of what to fix now, then how many wait. */
export function PackageCountsInline({ summary }: { summary: { finding_count: number; severity: SeverityCounts; fixes?: FixSummary | null } }) {
  const counts = packageCounts(summary);
  const waiting = counts.noFix + counts.other;
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-1">
      {counts.toFix > 0 ? (
        <SeverityCountsInline counts={counts.severity} />
      ) : (
        <span className="text-xs font-medium text-emerald-700 dark:text-emerald-400">Nothing to fix now</span>
      )}
      {waiting > 0 && (
        <span className="text-xs whitespace-nowrap text-slate-500 dark:text-slate-400" title="No update or restart fixes these yet">
          + {waiting.toLocaleString()} waiting
        </span>
      )}
    </span>
  );
}
