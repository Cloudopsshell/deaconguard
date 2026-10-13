import type { Lifecycle } from "../api";
import { cx } from "./ui";

const styles: Record<Lifecycle["state"], { label: string; className: string }> = {
  supported: { label: "Supported", className: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-400/30" },
  extended: { label: "Extended support", className: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-400/30" },
  ended: { label: "End of life", className: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/10 dark:text-red-300 dark:ring-red-400/30" },
  unknown: { label: "Support unknown", className: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-500/10 dark:text-slate-300 dark:ring-slate-400/20" },
};

/** Whether a release still gets security fixes, as a badge; its note is the tooltip. With onlyProblems, nothing for supported or unknown releases. */
export function ReleaseBadge({ lifecycle, onlyProblems, className }: { lifecycle?: Lifecycle | null; onlyProblems?: boolean; className?: string }) {
  if (!lifecycle || !styles[lifecycle.state]) return null;
  if (onlyProblems && (lifecycle.state === "supported" || lifecycle.state === "unknown")) return null;
  const style = styles[lifecycle.state];
  return (
    <span title={lifecycle.note} className={cx("inline-flex whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset", style.className, className)}>
      {style.label}
    </span>
  );
}

/** A release's support for a details list: the badge, the note, and the vendor's lifecycle page. */
export function ReleaseSupport({ lifecycle }: { lifecycle?: Lifecycle | null }) {
  if (!lifecycle) return <span className="text-slate-500 dark:text-slate-400">Not reported by agents before 0.19.0</span>;
  return (
    <>
      <ReleaseBadge lifecycle={lifecycle} /> <span className="text-sm">{lifecycle.note}</span>
      {lifecycle.source && (
        <a href={lifecycle.source} target="_blank" rel="noreferrer" className="block text-xs text-indigo-600 hover:underline dark:text-indigo-400">
          Vendor lifecycle
        </a>
      )}
    </>
  );
}
