import { useEffect, useState, type ReactNode } from "react";
import { Link, Navigate, NavLink, Outlet, useLocation } from "react-router";
import { Boxes, CalendarClock, CircleUser, ClipboardCheck, Settings as SettingsIcon, Palette, LayoutDashboard, LogOut, Logs, RadioTower, ScrollText, Server, ShieldAlert, Users, X } from "lucide-react";
import { Logo } from "./Logo";
import { PromptDialog } from "./PromptDialog";
import { RestartNotice } from "./RestartNotice";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api, roleLabels, type Session } from "../api";
import { adoptAppearance, setAppearanceSaver } from "../lib/appearance";
import { ChangePassword } from "./account/ChangePassword";
import { MFASetup } from "./account/MFASetup";
import { AppearancePicker, ModeSwitch } from "./AppearancePicker";
import { Card, Dialog, Loading, cx } from "./ui";

const navigation = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/hosts", label: "Hosts", icon: Server, end: false },
  { to: "/audits", label: "Server audits", icon: ClipboardCheck, end: false },
  { to: "/images", label: "Images", icon: Boxes, end: false },
  { to: "/agents", label: "Agents", icon: RadioTower, end: false },
  { to: "/schedules", label: "Schedules", icon: CalendarClock, end: false },
  { to: "/logs", label: "Logs", icon: Logs, end: false },
  { to: "/audit", label: "Audit log", icon: ScrollText, end: false },
  { to: "/accounts", label: "Accounts", icon: Users, end: false },
  { to: "/settings", label: "Settings", icon: SettingsIcon, end: false },
];

/** Pages that exist only on a server with agents and accounts. */
const networkPages = ["/agents", "/audit", "/accounts"];

/** Pages only admins use: the audit log, and managing accounts. */
const adminPages = ["/audit", "/accounts", "/settings"];

/** True when the account should look at My account: no two-step sign-in, or few recovery codes left. */
function needsAttention(session?: Session) {
  return !!session?.login_required && (!session.mfa_enabled || (session.recovery_codes_left ?? 10) <= 2);
}

const reminderKey = "dg-mfa-reminder-hidden";

function reminderHidden() {
  try {
    return sessionStorage.getItem(reminderKey) === "1";
  } catch {
    return false;
  }
}

/** Reminds the account to turn on two-step sign-in, or to renew its recovery codes. Hidden until the next sign-in. */
function SecurityReminder({ session }: { session: Session }) {
  const [hidden, setHidden] = useState(reminderHidden);
  const location = useLocation();
  if (hidden || !needsAttention(session) || location.pathname === "/account") return null;
  const missing = !session.mfa_enabled;
  function hide() {
    try {
      sessionStorage.setItem(reminderKey, "1");
    } catch {
      // Storage is blocked; hide it for this page view only.
    }
    setHidden(true);
  }
  return (
    <div
      role="status"
      className="mb-6 flex items-start gap-3 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-900 ring-1 ring-amber-600/20 ring-inset dark:bg-amber-500/10 dark:text-amber-200"
    >
      <ShieldAlert className="mt-0.5 size-5 shrink-0" aria-hidden />
      <p className="min-w-0 flex-1">
        {missing ? (
          <>
            <span className="font-semibold">Two-step sign-in is off for your account.</span> Anyone who learns your password can see every host and start
            scans. Turn it on with any authenticator app; it takes a minute.{" "}
          </>
        ) : (
          <>
            <span className="font-semibold">
              Only {session.recovery_codes_left} recovery {session.recovery_codes_left === 1 ? "code" : "codes"} left.
            </span>{" "}
            Create new ones so you can still sign in if you lose your phone.{" "}
          </>
        )}
        <Link to="/account" className="font-semibold whitespace-nowrap underline underline-offset-2">
          {missing ? "Set it up" : "Create new codes"}
        </Link>
      </p>
      <button
        type="button"
        onClick={hide}
        className="rounded-md p-0.5 text-amber-700 hover:bg-amber-100 dark:text-amber-300 dark:hover:bg-amber-500/20"
        title="Hide until the next sign-in"
        aria-label="Hide until the next sign-in"
      >
        <X className="size-4" />
      </button>
    </div>
  );
}

/** A full-screen step the account must finish before using the dashboard. */
function RequiredStep({ title, description, children }: { title: string; description: string; children: ReactNode }) {
  const logout = useMutation({ mutationFn: api.logout, onSettled: () => window.location.assign("/login") });
  return (
    <div className="flex min-h-screen items-start justify-center px-4 py-12 sm:py-20">
      <div className="w-full max-w-lg">
        <div className="mb-6 flex items-center gap-2">
          <Logo className="size-8 shrink-0" />
          <span className="text-lg font-bold tracking-tight">DeaconGuard</span>
        </div>
        <Card>
          <div className="px-6 py-6">
            <h1 className="text-lg font-semibold">{title}</h1>
            <p className="mt-1 mb-6 text-sm text-slate-600 dark:text-slate-300">{description}</p>
            {children}
          </div>
        </Card>
        <button type="button" onClick={() => logout.mutate()} className="mt-4 text-sm text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200">
          Sign out
        </button>
      </div>
    </div>
  );
}

function SignedInAs({ session }: { session: Session }) {
  const logout = useMutation({ mutationFn: api.logout, onSettled: () => window.location.assign("/login") });
  const attention = needsAttention(session);
  return (
    <div className="flex items-center justify-between gap-2 px-3 pb-3 lg:px-3 lg:pt-6 lg:pb-0">
      <NavLink
        to="/account"
        className={({ isActive }) =>
          cx(
            "flex min-w-0 flex-1 items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium transition-colors",
            isActive
              ? "bg-indigo-50 text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300"
              : "text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100",
          )
        }
        title={`Signed in as ${session.username}${attention ? (session.mfa_enabled ? " · few recovery codes left" : " · two-step sign-in is off") : ""}`}
      >
        <span className="relative shrink-0">
          <CircleUser className="size-4.5" aria-hidden />
          {attention && <span className="absolute -top-0.5 -right-0.5 size-2 rounded-full bg-amber-500 ring-2 ring-white dark:ring-slate-900" aria-hidden />}
        </span>
        <span className="min-w-0">
          <span className="block truncate">{session.username}</span>
          <span className={cx("block text-xs font-normal", attention ? "text-amber-700 dark:text-amber-400" : "text-slate-500 dark:text-slate-400")}>
            {attention ? (session.mfa_enabled ? "Few recovery codes left" : "Two-step sign-in off") : `My account · ${roleLabels[session.role ?? "viewer"]}`}
          </span>
        </span>
      </NavLink>
      <button
        type="button"
        onClick={() => logout.mutate()}
        className="rounded-md p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"
        title="Sign out"
        aria-label="Sign out"
      >
        <LogOut className="size-4" />
      </button>
    </div>
  );
}

/** Light, dark or system mode in one click; the palette opens the themes too. */
function AppearanceControls() {
  const [open, setOpen] = useState(false);
  return (
    <div className="hidden items-center justify-between gap-2 px-5 pt-4 lg:flex">
      <ModeSwitch compact />
      <button
        type="button"
        onClick={() => setOpen(true)}
        className="flex items-center gap-1.5 rounded-md px-2 py-1.5 text-xs font-medium text-slate-500 hover:bg-slate-100 hover:text-slate-800 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200"
      >
        <Palette className="size-4" aria-hidden /> Theme
      </button>
      <Dialog open={open} onClose={() => setOpen(false)} title="Appearance" wide>
        <AppearancePicker />
      </Dialog>
    </div>
  );
}

function VersionLabel() {
  const { data } = useQuery({ queryKey: ["version"], queryFn: api.version, staleTime: Infinity });
  if (!data) return null;
  const release = data.version !== "dev";
  return (
    <p
      className="hidden px-5 pt-3 font-mono text-[11px] text-slate-400 lg:block"
      title={[data.commit && `commit ${data.commit}`, data.date && `built ${data.date}`].filter(Boolean).join(" · ")}
    >
      {release ? `v${data.version}` : `dev build${data.commit ? ` · ${data.commit.slice(0, 7)}` : ""}`}
    </p>
  );
}

export function Layout() {
  const location = useLocation();
  const session = useQuery({ queryKey: ["session"], queryFn: api.session, staleTime: 60_000 });
  // A signed-in account's appearance follows it from browser to browser.
  const saved = session.data?.authenticated && session.data.login_required ? session.data.appearance : undefined;
  const accountSignedIn = Boolean(session.data?.authenticated && session.data.login_required);
  useEffect(() => {
    if (saved) adoptAppearance(saved);
  }, [saved]);
  useEffect(() => {
    setAppearanceSaver(accountSignedIn ? (appearance) => void api.saveAppearance(appearance).catch(() => {}) : null);
    return () => setAppearanceSaver(null);
  }, [accountSignedIn]);
  // A session still finishing a required step (new password, two-step setup) can't read anything else yet.
  const ready = session.data?.authenticated === true && !session.data.must_change_password && !session.data.mfa_setup_required;
  const capabilities = useQuery({ queryKey: ["capabilities"], queryFn: api.capabilities, staleTime: Infinity, enabled: ready });
  if (session.isPending) return <Loading />;
  if (session.data?.login_required && !session.data.authenticated) {
    return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}`} replace />;
  }
  const network = capabilities.data?.agents ?? false;
  const signedIn = session.data?.authenticated ? session.data : undefined;
  const isAdmin = !signedIn?.login_required || signedIn.role === "admin";
  const refresh = () => window.location.reload();
  if (signedIn?.must_change_password) {
    return (
      <RequiredStep title="Choose your own password" description="An admin gave you a temporary password. Choose one only you know before you continue.">
        <ChangePassword temporary onDone={refresh} />
      </RequiredStep>
    );
  }
  if (signedIn?.mfa_setup_required) {
    return (
      <RequiredStep
        title="Set up two-step sign-in"
        description="Every account on this server must use two-step sign-in. Scan the code with an authenticator app, then enter the 6-digit code it shows."
      >
        <MFASetup username={signedIn.username ?? ""} replacing={false} onDone={refresh} />
      </RequiredStep>
    );
  }
  return (
    <div className="min-h-screen lg:flex">
      <aside className="border-b border-slate-200 bg-white lg:fixed lg:inset-y-0 lg:w-60 lg:border-r lg:border-b-0 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center gap-2 px-5 py-4 lg:py-5">
          <Logo className="size-8 shrink-0" />
          <span className="text-lg font-bold tracking-tight">DeaconGuard</span>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-3 lg:flex-col lg:pb-0" aria-label="Main">
          {navigation.filter(({ to }) => (network || !networkPages.includes(to)) && (isAdmin || !adminPages.includes(to))).map(({ to, label, icon: Icon, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              className={({ isActive }) =>
                cx(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium whitespace-nowrap transition-colors",
                  isActive
                    ? "bg-indigo-50 text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300"
                    : "text-slate-600 hover:bg-slate-100 hover:text-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-100",
                )
              }
            >
              <Icon className="size-4.5" aria-hidden />
              {label}
            </NavLink>
          ))}
        </nav>
        {signedIn?.username && <SignedInAs session={signedIn} />}
        <AppearanceControls />
        <p className="hidden px-5 pt-6 text-xs leading-relaxed text-slate-400 lg:block">
          {network
            ? "Server · checks what its agents read as root against official distribution advisories."
            : "Local only · scans this machine against official distribution advisories."}
        </p>
        <VersionLabel />
      </aside>
      <main className="min-w-0 flex-1 lg:pl-60">
        <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
          {session.data?.authenticated !== false && <RestartNotice />}
          {signedIn?.login_required && <SecurityReminder session={signedIn} />}
          <Outlet />
        </div>
      </main>
      <PromptDialog />
    </div>
  );
}
