import { useSyncExternalStore } from "react";

export type Mode = "system" | "light" | "dark";
export type Theme = "indigo" | "ocean" | "teal" | "plum" | "graphite";

export interface Appearance {
  mode: Mode;
  theme: Theme;
}

/** The themes, in the order the picker shows them. swatch is the accent in light mode. */
export const themes: { id: Theme; label: string; description: string; swatch: string; gray: string }[] = [
  { id: "indigo", label: "Indigo", description: "The default", swatch: "#4f46e5", gray: "#64748b" },
  { id: "ocean", label: "Ocean", description: "Blue on cool grays", swatch: "#2563eb", gray: "#64748b" },
  { id: "teal", label: "Teal", description: "Teal on neutral grays", swatch: "#0d9488", gray: "#71717a" },
  { id: "plum", label: "Plum", description: "Purple on warm grays", swatch: "#9333ea", gray: "#78716c" },
  { id: "graphite", label: "Graphite", description: "No color, just contrast", swatch: "#3f3f46", gray: "#737373" },
];

const storageKey = "dg-appearance";
const darkQuery = "(prefers-color-scheme: dark)";

export function savedAppearance(): Appearance {
  try {
    const saved = JSON.parse(localStorage.getItem(storageKey) ?? "{}") ?? {};
    return {
      mode: ["light", "dark"].includes(saved.mode) ? saved.mode : "system",
      theme: themes.some((theme) => theme.id === saved.theme) ? saved.theme : "indigo",
    };
  } catch {
    return { mode: "system", theme: "indigo" };
  }
}

function apply({ mode, theme }: Appearance) {
  const root = document.documentElement;
  root.dataset.mode = mode === "system" ? (window.matchMedia(darkQuery).matches ? "dark" : "light") : mode;
  if (theme === "indigo") delete root.dataset.theme;
  else root.dataset.theme = theme;
}

// One appearance for the whole page, so the sidebar and My account stay in step.
let current = savedAppearance();
const listeners = new Set<() => void>();

function followSystem() {
  if (current.mode === "system") apply(current);
}
if (typeof window !== "undefined") {
  apply(current);
  window.matchMedia(darkQuery).addEventListener("change", followSystem);
}

export function setAppearance(change: Partial<Appearance>) {
  current = { ...current, ...change };
  try {
    localStorage.setItem(storageKey, JSON.stringify(current));
  } catch {
    // Storage is blocked; the choice lasts for this page only.
  }
  apply(current);
  listeners.forEach((listener) => listener());
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** The current appearance; "system" follows the operating system as it changes. */
export function useAppearance() {
  return useSyncExternalStore(subscribe, () => current);
}
