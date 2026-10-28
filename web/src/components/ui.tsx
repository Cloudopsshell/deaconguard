import { useEffect, useRef, useState, type ButtonHTMLAttributes, type InputHTMLAttributes, type ReactNode } from "react";
import { AlertTriangle, CheckCircle2, ChevronLeft, ChevronRight, Clock, KeyRound, Loader2, Search, X, XCircle } from "lucide-react";
import type { Scan, ScanStatus, Severity, SeverityCounts } from "../api";
import { countFor, severityOrder, severityStyle } from "../lib/format";

export function cx(...classes: (string | false | null | undefined)[]) {
  return classes.filter(Boolean).join(" ");
}

type ButtonVariant = "primary" | "secondary" | "danger" | "ghost";

const buttonVariants: Record<ButtonVariant, string> = {
  primary: "bg-indigo-600 text-white shadow-sm hover:bg-indigo-500 focus-visible:outline-indigo-600",
  secondary:
    "bg-white text-slate-900 shadow-sm ring-1 ring-inset ring-slate-300 hover:bg-slate-50 dark:bg-slate-800 dark:text-slate-100 dark:ring-slate-700 dark:hover:bg-slate-700",
  danger: "bg-red-600 text-white shadow-sm hover:bg-red-500 focus-visible:outline-red-600",
  ghost: "text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100",
};

export function Button({
  variant = "primary",
  loading,
  className,
  children,
  disabled,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant; loading?: boolean }) {
  return (
    <button
      {...props}
      disabled={disabled || loading}
      className={cx(
        "inline-flex items-center justify-center gap-2 rounded-lg px-3.5 py-2 text-sm font-semibold whitespace-nowrap transition-colors",
        "focus-visible:outline-2 focus-visible:outline-offset-2 disabled:cursor-not-allowed disabled:opacity-60",
        buttonVariants[variant],
        className,
      )}
    >
      {loading && <Loader2 className="size-4 animate-spin" aria-hidden />}
      {children}
    </button>
  );
}

export function Card({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div
      className={cx(
        "rounded-xl bg-white shadow-sm ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function CardHeader({ title, description, action }: { title: string; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-start justify-between gap-3 border-b border-slate-200 px-5 py-4 dark:border-slate-800">
      <div className="min-w-64 flex-1 basis-0">
        <h2 className="text-base font-semibold">{title}</h2>
        {description && <p className="mt-0.5 text-sm text-slate-500 dark:text-slate-400">{description}</p>}
      </div>
      {action}
    </div>
  );
}

export function PageHeader({ title, description, action }: { title: ReactNode; description?: ReactNode; action?: ReactNode }) {
  return (
    <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-2xl font-bold tracking-tight">{title}</h1>
        {description && <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">{description}</p>}
      </div>
      {action && <div className="flex shrink-0 gap-2">{action}</div>}
    </div>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  const style = severityStyle[severity] ?? severityStyle.UNKNOWN;
  return (
    <span className={cx("inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold ring-1 ring-inset", style.badge)}>
      {style.label}
    </span>
  );
}

const statusStyle: Record<ScanStatus, { label: string; className: string; icon: ReactNode }> = {
  queued: {
    label: "Waiting for agent",
    className: "bg-slate-100 text-slate-700 ring-slate-500/20 dark:bg-slate-500/15 dark:text-slate-300 dark:ring-slate-400/30",
    icon: <Clock className="size-3.5" aria-hidden />,
  },
  running: {
    label: "Scanning",
    className: "bg-indigo-50 text-indigo-700 ring-indigo-600/20 dark:bg-indigo-500/15 dark:text-indigo-300 dark:ring-indigo-400/30",
    icon: <Loader2 className="size-3.5 animate-spin" aria-hidden />,
  },
  succeeded: {
    label: "Completed",
    className: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300 dark:ring-emerald-400/30",
    icon: <CheckCircle2 className="size-3.5" aria-hidden />,
  },
  failed: {
    label: "Failed",
    className: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/15 dark:text-red-300 dark:ring-red-400/30",
    icon: <XCircle className="size-3.5" aria-hidden />,
  },
  needs_sudo: {
    label: "Sudo password needed",
    className: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-400/30",
    icon: <KeyRound className="size-3.5" aria-hidden />,
  },
};

export function StatusBadge({ status }: { status: ScanStatus }) {
  const style = statusStyle[status];
  return (
    <span
      className={cx(
        "inline-flex items-center gap-1 whitespace-nowrap rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset",
        style.className,
      )}
    >
      {style.icon}
      {style.label}
    </span>
  );
}

/** A proportional bar of findings by severity. */
export function SeverityBar({ counts, className }: { counts: SeverityCounts; className?: string }) {
  const total = severityOrder.reduce((sum, severity) => sum + countFor(counts, severity), 0);
  if (total === 0) {
    return <div className={cx("h-2 rounded-full bg-emerald-500/70", className)} title="No findings" />;
  }
  return (
    <div
      className={cx("flex h-2 gap-px overflow-hidden rounded-full bg-slate-100 dark:bg-slate-800", className)}
      role="img"
      aria-label={severityOrder.map((s) => `${countFor(counts, s)} ${severityStyle[s].label}`).join(", ")}
    >
      {severityOrder.map((severity) => {
        const value = countFor(counts, severity);
        return value > 0 ? (
          <div
            key={severity}
            className={severityStyle[severity].bar}
            style={{ width: `${(value / total) * 100}%` }}
            title={`${value} ${severityStyle[severity].label}`}
          />
        ) : null;
      })}
    </div>
  );
}

/** Inline counts such as "3 C · 5 H · 2 M". */
export function SeverityCountsInline({ counts }: { counts: SeverityCounts }) {
  const parts = severityOrder.filter((severity) => countFor(counts, severity) > 0);
  if (parts.length === 0) return <span className="text-sm text-emerald-700 dark:text-emerald-400">No findings</span>;
  return (
    <span className="flex flex-wrap gap-x-2.5 text-sm tabular-nums">
      {parts.map((severity) => (
        <span key={severity} className={severityStyle[severity].text} title={severityStyle[severity].label}>
          <span className="font-semibold">{countFor(counts, severity)}</span> {severityStyle[severity].label.toLowerCase()}
        </span>
      ))}
    </span>
  );
}

/** Explains that a scan result is incomplete, so zero findings are not read as clean. */
export function CoverageNotes({ scan }: { scan: Scan }) {
  const notes: string[] = [];
  if (scan.unsupported_count > 0) notes.push(`${scan.unsupported_count} ${scan.unsupported_count === 1 ? "rule" : "rules"} not evaluated`);
  if (scan.feed_stale) notes.push("advisory data is stale");
  if (notes.length === 0) return null;
  return (
    <span className="inline-flex items-center gap-1 text-xs text-amber-700 dark:text-amber-400">
      <AlertTriangle className="size-3.5" aria-hidden />
      {notes.join(" · ")}
    </span>
  );
}

export function Field({
  label,
  hint,
  ...props
}: InputHTMLAttributes<HTMLInputElement> & { label: string; hint?: ReactNode }) {
  return (
    <label className="block">
      <span className="text-sm font-medium">{label}</span>
      <input
        {...props}
        className={cx(
          "mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-inset ring-slate-300",
          "placeholder:text-slate-400 focus:ring-2 focus:ring-indigo-600 focus:outline-none",
          "dark:bg-slate-950 dark:ring-slate-700",
          props.className,
        )}
      />
      {hint && <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">{hint}</span>}
    </label>
  );
}

export function Dialog({
  open,
  onClose,
  title,
  children,
  wide = false,
}: {
  open: boolean;
  onClose: () => void;
  title: string;
  children: ReactNode;
  wide?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) {
      dialog.showModal();
      // showModal focuses the first control (the close button); prefer the marked field.
      dialog.querySelector<HTMLElement>("[data-autofocus]")?.focus();
    }
    if (!open && dialog.open) dialog.close();
  }, [open]);
  return (
    <dialog
      ref={ref}
      onClose={onClose}
      className={cx("m-auto w-full rounded-xl", wide ? "max-w-3xl" : "max-w-lg", "bg-white p-0 text-slate-900 shadow-xl ring-1 ring-slate-200 dark:bg-slate-900 dark:text-slate-100 dark:ring-slate-800")}
    >
      <div className="flex items-center justify-between border-b border-slate-200 px-5 py-4 dark:border-slate-800">
        <h2 className="text-base font-semibold">{title}</h2>
        <button
          type="button"
          onClick={onClose}
          className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800"
          aria-label="Close"
        >
          <X className="size-5" />
        </button>
      </div>
      <div className="px-5 py-4">{children}</div>
    </dialog>
  );
}

export function ErrorMessage({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : String(error);
  return (
    <div className="flex gap-2 rounded-lg bg-red-50 p-3 text-sm text-red-800 ring-1 ring-inset ring-red-600/20 dark:bg-red-500/10 dark:text-red-300">
      <XCircle className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span className="break-words">{message}</span>
    </div>
  );
}

export function EmptyState({ icon, title, description, action }: { icon: ReactNode; title: string; description: string; action?: ReactNode }) {
  return (
    <div className="flex flex-col items-center px-6 py-14 text-center">
      <div className="mb-3 rounded-full bg-slate-100 p-3 text-slate-500 dark:bg-slate-800 dark:text-slate-400">{icon}</div>
      <h3 className="text-sm font-semibold">{title}</h3>
      <p className="mt-1 max-w-sm text-sm text-slate-500 dark:text-slate-400">{description}</p>
      {action && <div className="mt-5">{action}</div>}
    </div>
  );
}

export function Loading() {
  return (
    <div className="flex items-center justify-center gap-2 py-20 text-sm text-slate-500">
      <Loader2 className="size-5 animate-spin" aria-hidden /> Loading…
    </div>
  );
}

export function Table({ children }: { children: ReactNode }) {
  return (
    // relative: screen-reader-only headings stay inside the scroll area instead of widening the page.
    <div className="relative overflow-x-auto">
      <table className="min-w-full divide-y divide-slate-200 text-sm dark:divide-slate-800">{children}</table>
    </div>
  );
}

export function Th({ children, className }: { children?: ReactNode; className?: string }) {
  return (
    <th
      scope="col"
      className={cx(
        "px-5 py-2.5 text-left text-xs font-semibold tracking-wide whitespace-nowrap text-slate-500 uppercase dark:text-slate-400",
        className,
      )}
    >
      {children}
    </th>
  );
}

export function Td({ children, className }: { children?: ReactNode; className?: string }) {
  return <td className={cx("px-5 py-3 align-top", className)}>{children}</td>;
}

/** One page of a list: the page starts again at the first whenever reset changes, such as a search. */
export function usePage<T>(items: T[], size: number, reset?: unknown) {
  const [page, setPage] = useState(0);
  const [lastReset, setLastReset] = useState(reset);
  if (reset !== lastReset) {
    setLastReset(reset);
    setPage(0);
  }
  const pages = Math.max(1, Math.ceil(items.length / size));
  const current = Math.min(page, pages - 1);
  return { page: current, pages, setPage, shown: items.slice(current * size, (current + 1) * size), size, total: items.length };
}

/** Previous and next under a paged list, with which items are shown. Nothing when it fits one page. */
export function Pager({ paging, noun }: { paging: { page: number; pages: number; setPage: (page: number) => void; size: number; total: number }; noun: string }) {
  if (paging.pages <= 1) return null;
  const from = paging.page * paging.size + 1;
  const to = Math.min(paging.total, from + paging.size - 1);
  return (
    <nav className="flex items-center justify-between gap-3 border-t border-slate-200 px-5 py-3 text-sm dark:border-slate-800" aria-label={`Pages of ${noun}`}>
      <span className="text-slate-500 dark:text-slate-400">
        {from.toLocaleString()}–{to.toLocaleString()} of {paging.total.toLocaleString()} {noun}
      </span>
      <div className="flex gap-2">
        <Button variant="secondary" disabled={paging.page === 0} onClick={() => paging.setPage(paging.page - 1)} aria-label="Previous page">
          <ChevronLeft className="size-4" />
        </Button>
        <Button variant="secondary" disabled={paging.page >= paging.pages - 1} onClick={() => paging.setPage(paging.page + 1)} aria-label="Next page">
          <ChevronRight className="size-4" />
        </Button>
      </div>
    </nav>
  );
}

/** A search box with a magnifier, for filtering a list. */
export function SearchBox({ value, onChange, placeholder, label, autoFocus }: { value: string; onChange: (value: string) => void; placeholder: string; label: string; autoFocus?: boolean }) {
  return (
    <label className="relative block">
      <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-slate-400" aria-hidden />
      <input
        type="search"
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        aria-label={label}
        data-autofocus={autoFocus || undefined}
        className="block w-full rounded-lg border-0 bg-white py-2 pr-3 pl-9 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
      />
    </label>
  );
}
