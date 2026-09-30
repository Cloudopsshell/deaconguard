import { Navigate, NavLink, Outlet, useLocation } from "react-router";
import { LayoutDashboard, LogOut, RadioTower, ScrollText, Server, ShieldCheck } from "lucide-react";
import { PromptDialog } from "./PromptDialog";
import { useMutation, useQuery } from "@tanstack/react-query";
import { api } from "../api";
import { Loading, cx } from "./ui";

const navigation = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, end: true },
  { to: "/hosts", label: "Hosts", icon: Server, end: false },
  { to: "/agents", label: "Agents", icon: RadioTower, end: false },
  { to: "/audit", label: "Audit log", icon: ScrollText, end: false },
];

function SignedInAs({ username }: { username: string }) {
  const logout = useMutation({ mutationFn: api.logout, onSettled: () => window.location.assign("/login") });
  return (
    <div className="hidden items-center justify-between gap-2 px-5 pt-6 lg:flex">
      <span className="truncate text-xs text-slate-500 dark:text-slate-400" title={`Signed in as ${username}`}>
        Signed in as <span className="font-medium text-slate-700 dark:text-slate-200">{username}</span>
      </span>
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
  const capabilities = useQuery({ queryKey: ["capabilities"], queryFn: api.capabilities, staleTime: Infinity, enabled: session.data?.authenticated === true });
  if (session.isPending) return <Loading />;
  if (session.data?.login_required && !session.data.authenticated) {
    return <Navigate to={`/login?next=${encodeURIComponent(location.pathname + location.search)}`} replace />;
  }
  const network = capabilities.data?.agents ?? false;
  return (
    <div className="min-h-screen lg:flex">
      <aside className="border-b border-slate-200 bg-white lg:fixed lg:inset-y-0 lg:w-60 lg:border-r lg:border-b-0 dark:border-slate-800 dark:bg-slate-900">
        <div className="flex items-center gap-2 px-5 py-4 lg:py-5">
          <ShieldCheck className="size-7 text-indigo-600 dark:text-indigo-400" aria-hidden />
          <span className="text-lg font-bold tracking-tight">DeaconGuard</span>
        </div>
        <nav className="flex gap-1 overflow-x-auto px-3 pb-3 lg:flex-col lg:pb-0" aria-label="Main">
          {navigation.filter(({ to }) => network || (to !== "/agents" && to !== "/audit")).map(({ to, label, icon: Icon, end }) => (
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
        {session.data?.username && <SignedInAs username={session.data.username} />}
        <p className="hidden px-5 pt-6 text-xs leading-relaxed text-slate-400 lg:block">
          {network
            ? "Server · scans this machine and enrolled agents against official distribution advisories."
            : "Local only · scans this machine against official distribution advisories."}
        </p>
        <VersionLabel />
      </aside>
      <main className="flex-1 lg:pl-60">
        <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
          <Outlet />
        </div>
      </main>
      <PromptDialog />
    </div>
  );
}
