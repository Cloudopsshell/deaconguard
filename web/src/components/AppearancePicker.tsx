import { Check, Monitor, Moon, Sun } from "lucide-react";
import { setAppearance, themes, useAppearance, type Mode } from "../lib/appearance";
import { cx } from "./ui";

const modes: { id: Mode; label: string; icon: typeof Sun }[] = [
  { id: "system", label: "System", icon: Monitor },
  { id: "light", label: "Light", icon: Sun },
  { id: "dark", label: "Dark", icon: Moon },
];

/** Light, dark or the system's mode, as three small buttons. */
export function ModeSwitch({ compact = false }: { compact?: boolean }) {
  const { mode } = useAppearance();
  return (
    <div role="radiogroup" aria-label="Color mode" className="inline-flex rounded-lg bg-slate-100 p-0.5 ring-1 ring-slate-200 dark:bg-slate-800 dark:ring-slate-700">
      {modes.map(({ id, label, icon: Icon }) => (
        <button
          key={id}
          type="button"
          role="radio"
          aria-checked={mode === id}
          title={label}
          onClick={() => setAppearance({ mode: id })}
          className={cx(
            "flex items-center gap-1.5 rounded-md text-sm font-medium transition-colors",
            compact ? "p-1.5" : "px-3 py-1.5",
            mode === id
              ? "bg-white text-slate-900 shadow-sm dark:bg-slate-950 dark:text-slate-100"
              : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200",
          )}
        >
          <Icon className="size-4" aria-hidden />
          {compact ? <span className="sr-only">{label}</span> : label}
        </button>
      ))}
    </div>
  );
}

/** Mode and theme, with a small preview of each theme. */
export function AppearancePicker() {
  const { theme } = useAppearance();
  return (
    <div className="space-y-5">
      <div>
        <p className="mb-2 text-sm font-medium">Mode</p>
        <ModeSwitch />
        <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">System follows your computer's light or dark setting as it changes.</p>
      </div>
      <div>
        <p className="mb-2 text-sm font-medium">Theme</p>
        <div role="radiogroup" aria-label="Theme" className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-5">
          {themes.map((option) => (
            <button
              key={option.id}
              type="button"
              role="radio"
              aria-checked={theme === option.id}
              onClick={() => setAppearance({ theme: option.id })}
              className={cx(
                "relative rounded-lg p-3 text-left ring-1 transition-shadow",
                theme === option.id
                  ? "ring-2 ring-indigo-600 dark:ring-indigo-400"
                  : "ring-slate-200 hover:ring-slate-300 dark:ring-slate-700 dark:hover:ring-slate-600",
              )}
            >
              <span className="mb-3 flex h-12 overflow-hidden rounded-md ring-1 ring-black/5" aria-hidden>
                <span className="w-1/4" style={{ background: option.gray, opacity: 0.25 }} />
                <span className="flex flex-1 flex-col justify-center gap-1.5 bg-white px-2">
                  <span className="h-1.5 w-3/4 rounded-full" style={{ background: option.gray, opacity: 0.5 }} />
                  <span className="h-3 w-1/2 rounded" style={{ background: option.swatch }} />
                </span>
              </span>
              <span className="block text-sm font-medium">{option.label}</span>
              <span className="block text-xs text-slate-500 dark:text-slate-400">{option.description}</span>
              {theme === option.id && <Check className="absolute top-2 right-2 size-4 text-indigo-600 dark:text-indigo-400" aria-label="Selected" />}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
