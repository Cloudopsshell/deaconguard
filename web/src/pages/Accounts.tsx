import { useState, type FormEvent } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldAlert, ShieldCheck, UserPlus, Users } from "lucide-react";
import { api, roleLabels, type Account, type Role } from "../api";
import { Button, Card, CardHeader, Dialog, EmptyState, ErrorMessage, Field, Loading, PageHeader, Table, Td, Th, cx } from "../components/ui";
import { dateTime, timeAgo } from "../lib/format";
import { AllAPITokens } from "../components/account/APITokens";

type Action = { kind: "create" } | { kind: "password" | "reset" | "remove" | "role"; account: Account };

/** What each role may do, as the dashboard explains it. */
const roleDescriptions: Record<Role, string> = {
  viewer: "Sees hosts, findings, schedules and logs. Can't start scans or change anything.",
  operator: "Also scans, answers sudo prompts, deletes scans, and manages schedules.",
  admin: "Also enrolls and removes machines, manages accounts, and reads the audit log.",
};

function RolePicker({ value, onChange }: { value: Role; onChange: (role: Role) => void }) {
  return (
    <fieldset>
      <legend className="text-sm font-medium">Role</legend>
      <div className="mt-2 space-y-2">
        {(["viewer", "operator", "admin"] as Role[]).map((role) => (
          <label
            key={role}
            className={cx(
              "flex cursor-pointer gap-3 rounded-lg px-3 py-2.5 ring-1",
              value === role ? "bg-indigo-50 ring-indigo-600 dark:bg-indigo-500/10 dark:ring-indigo-400" : "ring-slate-200 dark:ring-slate-700",
            )}
          >
            <input type="radio" name="role" className="mt-0.5 accent-indigo-600" checked={value === role} onChange={() => onChange(role)} />
            <span>
              <span className="block text-sm font-medium">{roleLabels[role]}</span>
              <span className="block text-xs text-slate-500 dark:text-slate-400">{roleDescriptions[role]}</span>
            </span>
          </label>
        ))}
      </div>
    </fieldset>
  );
}

function Badge({ tone, children }: { tone: "green" | "amber" | "slate"; children: string }) {
  const tones = {
    green: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300",
    amber: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-300",
    slate: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300",
  };
  return <span className={cx("inline-flex rounded-full px-2 py-0.5 text-xs font-medium whitespace-nowrap ring-1 ring-inset", tones[tone])}>{children}</span>;
}

/** Admins manage everyone's accounts here; their own is on My account. */
export function Accounts() {
  const queryClient = useQueryClient();
  const users = useQuery({ queryKey: ["users"], queryFn: api.users });
  const session = useQuery({
    queryKey: ["session"],
    queryFn: api.session,
    staleTime: 60_000,
  });
  const refresh = () => queryClient.invalidateQueries({ queryKey: ["users"] });
  const [action, setAction] = useState<Action | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const [done, setDone] = useState("");
  const [managing, setManaging] = useState<Account | null>(null);
  const close = () => {
    setAction(null);
    setUsername("");
    setPassword("");
    setRole("viewer");
    run.reset();
  };
  const run = useMutation({
    mutationFn: async (current: Action) => {
      if (current.kind === "create") await api.createUser(username.trim(), password, role);
      if (current.kind === "role") await api.setUserRole(current.account.id, role);
      if (current.kind === "password") await api.setTemporaryPassword(current.account.id, password);
      if (current.kind === "reset") await api.resetUserMFA(current.account.id);
      if (current.kind === "remove") await api.removeUser(current.account.id);
    },
    onSuccess: (_, current) => {
      const name = current.kind === "create" ? username.trim() : current.account.username;
      setDone(
        {
          create: `Created ${name} as ${roleLabels[role]}. Give them the temporary password; they choose their own at the first sign-in.`,
          role: `${name} is now ${roleLabels[role]}, and was signed out so the role applies at once.`,
          password: `Set a temporary password for ${name} and signed them out. They choose a new one at the next sign-in.`,
          reset: `Reset two-step sign-in for ${name} and signed them out. They sign in with their password and set it up again.`,
          remove: `Removed ${name}.`,
        }[current.kind],
      );
      close();
    },
    onSettled: refresh,
  });
  const toggle = useMutation({
    mutationFn: (account: Account) => api.setUserDisabled(account.id, !account.disabled),
    onSettled: refresh,
  });
  const requireMFA = useMutation({
    mutationFn: api.setRequireMFA,
    onSettled: () => {
      refresh();
      queryClient.invalidateQueries({ queryKey: ["session"] });
    },
  });

  if (users.isPending) return <Loading />;
  if (users.error) return <ErrorMessage error={users.error} />;
  const { users: accounts, mfa_required: required } = users.data;
  const me = session.data?.username;
  const withoutMFA = accounts.filter((account) => !account.sso && !account.mfa_enabled && account.passkeys === 0 && !account.disabled).length;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (action) run.mutate(action);
  }

  return (
    <>
      <PageHeader
        title="Accounts"
        description="Everyone who can sign in to this dashboard, and what their role lets them do."
        action={
          <Button onClick={() => setAction({ kind: "create" })}>
            <UserPlus className="size-4" /> New account
          </Button>
        }
      />
      <div className="space-y-6">
        {done && (
          <p
            className="rounded-lg bg-emerald-50 px-4 py-3 text-sm text-emerald-800 ring-1 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300"
            role="status"
          >
            {done}
          </p>
        )}
        <Card>
          <CardHeader
            title="Require two-step sign-in"
            description={
              required
                ? "On. Anyone without it must set it up right after signing in, before they can use the dashboard."
                : `Off. ${withoutMFA === 0 ? "Every account has it today, but new ones may skip it." : `${withoutMFA} of ${accounts.length} accounts sign in with a password alone.`}`
            }
            action={
              <Button variant={required ? "secondary" : "primary"} loading={requireMFA.isPending} onClick={() => requireMFA.mutate(!required)}>
                {required ? "Turn off" : "Require it"}
              </Button>
            }
          />
          {requireMFA.error && (
            <div className="px-5 pb-4">
              <ErrorMessage error={requireMFA.error} />
              <p className="mt-2 text-sm">
                <Link to="/account" className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
                  Set up yours on My account
                </Link>
              </p>
            </div>
          )}
        </Card>
        <Card>
          {accounts.length === 0 ? (
            <EmptyState icon={<Users className="size-6" />} title="No accounts" description="Create one with deaconguard user add." />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Account</Th>
                  <Th>Role</Th>
                  <Th>Two-step sign-in</Th>
                  <Th>Last sign-in</Th>
                  <Th>
                    <span className="sr-only">Actions</span>
                  </Th>
                </tr>
              </thead>
              <tbody>
                {accounts.map((account) => {
                  const self = account.username === me;
                  return (
                    <tr key={account.id} className={cx(account.disabled && "opacity-60")}>
                      <Td>
                        <div className="flex flex-wrap items-center gap-2">
                          <span className="font-medium">{account.username}</span>
                          {self && <Badge tone="slate">You</Badge>}
                          {account.disabled && <Badge tone="slate">Disabled</Badge>}
                          {account.must_change_password && <Badge tone="amber">Must change password</Badge>}
                          {account.sso && <Badge tone="slate">Single sign-on</Badge>}
                        </div>
                        <p className="text-xs text-slate-500 dark:text-slate-400">Created {dateTime(account.created_at)}</p>
                      </Td>
                      <Td className="whitespace-nowrap">{roleLabels[account.role]}</Td>
                      <Td>
                        {account.sso ? (
                          <span className="text-sm text-slate-500 dark:text-slate-400">By the identity provider</span>
                        ) : account.mfa_enabled || account.passkeys > 0 ? (
                          <span className="inline-flex items-center gap-1.5 text-sm text-emerald-700 dark:text-emerald-400">
                            <ShieldCheck className="size-4" />{" "}
                            {[account.mfa_enabled && "App", account.passkeys > 0 && `${account.passkeys} ${account.passkeys === 1 ? "passkey" : "passkeys"}`]
                              .filter(Boolean)
                              .join(" · ")}
                            {account.mfa_enabled && account.recovery_codes_left <= 2 && (
                              <span className="text-amber-700 dark:text-amber-400">· {account.recovery_codes_left} codes left</span>
                            )}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1.5 text-sm text-amber-700 dark:text-amber-400">
                            <ShieldAlert className="size-4" /> Off
                          </span>
                        )}
                      </Td>
                      <Td className="whitespace-nowrap text-slate-600 dark:text-slate-300">
                        {account.last_login_at ? <span title={dateTime(account.last_login_at)}>{timeAgo(account.last_login_at)}</span> : "Never"}
                      </Td>
                      <Td className="text-right">
                        {self ? (
                          <Link to="/account" className="text-sm font-medium text-indigo-600 hover:underline dark:text-indigo-400">
                            My account
                          </Link>
                        ) : (
                          <Button variant="secondary" className="-my-2" onClick={() => setManaging(account)}>
                            Manage
                          </Button>
                        )}
                      </Td>
                    </tr>
                  );
                })}
              </tbody>
            </Table>
          )}
          <div className="px-5 pb-4">
            <ErrorMessage error={toggle.error} />
          </div>
        </Card>
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Lost access? Another admin can set a temporary password or reset two-step sign-in here. If you are the only admin, run{" "}
          <code className="font-mono text-xs">sudo -u deaconguard deaconguard user passwd NAME</code> or{" "}
          <code className="font-mono text-xs">sudo -u deaconguard deaconguard user mfa-reset NAME</code> on the server.
        </p>
      </div>

      <AllAPITokens />

      <Dialog open={managing !== null} onClose={() => setManaging(null)} title={managing ? `Manage ${managing.username}` : ""}>
        {managing && (
          <ul className="-my-1 divide-y divide-slate-200 dark:divide-slate-800">
            {[
              {
                label: "Change role",
                detail: managing.sso
                  ? `${roleLabels[managing.role]} now. Signs them out so the new role applies. With admin or operator groups set for single sign-on, their groups decide it again at their next sign-in.`
                  : `${roleLabels[managing.role]} now. Signs them out so the new role applies.`,
                run: () => {
                  setRole(managing.role);
                  setAction({ kind: "role", account: managing });
                },
              },
              ...(managing.sso
                ? []
                : [
                    {
                      label: "Set temporary password",
                      detail: "For a forgotten password. Signs them out; they choose a new one at the next sign-in.",
                      run: () => setAction({ kind: "password" as const, account: managing }),
                    },
                  ]),
              ...(managing.mfa_enabled || managing.passkeys > 0
                ? [
                    {
                      label: "Reset two-step sign-in",
                      detail: "For a lost phone or passkey, and lost recovery codes. Removes the app and every passkey, and signs them out; they set it up again.",
                      run: () => setAction({ kind: "reset" as const, account: managing }),
                    },
                  ]
                : []),
              {
                label: managing.disabled ? "Enable" : "Disable",
                detail: managing.disabled ? "Lets them sign in again." : "Signs them out and stops them signing in, keeping the account.",
                run: () => toggle.mutate(managing),
              },
              { label: "Remove", detail: "Deletes the account. The audit log keeps its entries.", run: () => setAction({ kind: "remove", account: managing }), danger: true },
            ].map((item) => (
              <li key={item.label}>
                <button
                  type="button"
                  onClick={() => {
                    setManaging(null);
                    item.run();
                  }}
                  className="-mx-2 block w-[calc(100%+1rem)] rounded-lg px-2 py-2.5 text-left hover:bg-slate-50 dark:hover:bg-slate-800/60"
                >
                  <span className={cx("block text-sm font-medium", "danger" in item && item.danger && "text-red-600 dark:text-red-400")}>{item.label}</span>
                  <span className="block text-xs text-slate-500 dark:text-slate-400">{item.detail}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </Dialog>

      <Dialog
        open={action !== null}
        onClose={close}
        title={
          action?.kind === "create"
            ? "New account"
            : action?.kind === "role"
              ? `Role for ${action.account.username}`
              : action?.kind === "password"
                ? `Temporary password for ${action.account.username}`
                : action?.kind === "reset"
                  ? `Reset two-step sign-in for ${action.account.username}?`
                  : `Remove ${action?.account.username}?`
        }
      >
        <form className="space-y-4" onSubmit={submit}>
          {action?.kind === "create" && (
            <Field label="Username" required autoComplete="off" value={username} onChange={(event) => setUsername(event.target.value)} data-autofocus />
          )}
          {(action?.kind === "create" || action?.kind === "role") && <RolePicker value={role} onChange={setRole} />}
          {action?.kind === "role" && (
            <p className="text-sm text-slate-600 dark:text-slate-300">They are signed out, so the new role applies when they sign in again.</p>
          )}
          {(action?.kind === "create" || action?.kind === "password") && (
            <>
              <Field
                label="Temporary password"
                type="text"
                required
                minLength={12}
                autoComplete="off"
                spellCheck={false}
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                data-autofocus={action.kind === "password" || undefined}
              />
              <p className="text-sm text-slate-600 dark:text-slate-300">
                At least 12 characters. Pass it on privately; they must choose their own the first time they sign in.
                {action.kind === "password" && " Their sessions are signed out now."}
              </p>
            </>
          )}
          {action?.kind === "reset" && (
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Use this when they lost their phone and their recovery codes. Their authenticator and recovery codes stop working, and they are signed out. They
              sign in with their password and set it up again
              {required ? ", which is required" : ""}. Check it is really them before you do this.
            </p>
          )}
          {action?.kind === "remove" && (
            <p className="text-sm text-slate-600 dark:text-slate-300">They are signed out and can't sign in again. The audit log keeps their entries.</p>
          )}
          <ErrorMessage error={run.error} />
          <div className="flex justify-end gap-2">
            <Button type="button" variant="secondary" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" variant={action?.kind === "remove" || action?.kind === "reset" ? "danger" : "primary"} loading={run.isPending}>
              {action?.kind === "create"
                ? "Create account"
                : action?.kind === "role"
                  ? "Change role"
                  : action?.kind === "password"
                    ? "Set password"
                    : action?.kind === "reset"
                      ? "Reset"
                      : "Remove"}
            </Button>
          </div>
        </form>
      </Dialog>
    </>
  );
}
