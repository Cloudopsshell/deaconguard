import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, LogOut, Monitor, ShieldCheck, ShieldOff } from "lucide-react";
import { api } from "../api";
import { ChangePassword } from "../components/account/ChangePassword";
import { MFASetup } from "../components/account/MFASetup";
import { RecoveryCodes } from "../components/account/RecoveryCodes";
import { Button, Card, CardHeader, Dialog, ErrorMessage, Field, Loading, PageHeader } from "../components/ui";
import { dateTime, timeAgo } from "../lib/format";

/** A short name for a browser, from its user agent. */
function browserName(agent: string) {
  const browser = /Edg\//.test(agent) ? "Edge" : /Firefox\//.test(agent) ? "Firefox" : /Chrome\//.test(agent) ? "Chrome" : /Safari\//.test(agent) ? "Safari" : "";
  const system = /Mac OS X/.test(agent) ? "macOS" : /Windows/.test(agent) ? "Windows" : /Android/.test(agent) ? "Android" : /iPhone|iPad/.test(agent) ? "iOS" : /Linux/.test(agent) ? "Linux" : "";
  return [browser, system].filter(Boolean).join(" on ") || agent || "Unknown browser";
}

/** The signed-in person's own account: password, two-step sign-in, sessions. */
export function Account() {
  const queryClient = useQueryClient();
  const account = useQuery({ queryKey: ["account"], queryFn: api.account });
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["account"] });
    queryClient.invalidateQueries({ queryKey: ["session"] });
  };
  const [setting, setSetting] = useState<"setup" | "replace" | null>(null);
  const [confirming, setConfirming] = useState<"remove" | "codes" | null>(null);
  const [password, setPassword] = useState("");
  const [codes, setCodes] = useState<string[] | null>(null);
  const [passwordChanged, setPasswordChanged] = useState(false);
  const remove = useMutation({ mutationFn: () => api.removeMFA(password), onSuccess: () => close(), onSettled: refresh });
  const newCodes = useMutation({
    mutationFn: () => api.newRecoveryCodes(password),
    onSuccess: (result) => {
      close();
      setCodes(result.recovery_codes);
    },
  });
  const end = useMutation({ mutationFn: api.endSession, onSettled: refresh });

  function close() {
    setConfirming(null);
    setPassword("");
  }

  if (account.isPending) return <Loading />;
  if (account.error) return <ErrorMessage error={account.error} />;
  const data = account.data;
  const others = data.sessions.filter((session) => !session.current).length;

  return (
    <>
      <PageHeader title="My account" description={`Signed in as ${data.username}. Your password, two-step sign-in and sessions.`} />
      <div className="space-y-6">
        <Card>
          <CardHeader
            title="Two-step sign-in"
            description="After your password, DeaconGuard asks for a 6-digit code from an authenticator app on your phone or computer, so a stolen password alone cannot sign in."
          />
          <div className="px-5 py-5">
            {codes ? (
              <RecoveryCodes codes={codes} username={data.username} onDone={() => (setCodes(null), refresh())} />
            ) : setting ? (
              <MFASetup username={data.username} replacing={setting === "replace"} onDone={() => (setSetting(null), refresh())} />
            ) : data.mfa_enabled ? (
              <div className="space-y-4">
                <p className="flex items-center gap-2 text-sm font-medium text-emerald-700 dark:text-emerald-400">
                  <ShieldCheck className="size-5" /> On. {data.recovery_codes_left} of 10 recovery codes left.
                </p>
                {data.recovery_codes_left <= 2 && (
                  <p className="text-sm text-amber-700 dark:text-amber-400">You are running out of recovery codes. Create new ones and save them.</p>
                )}
                <div className="flex flex-wrap gap-2">
                  <Button variant="secondary" onClick={() => setSetting("replace")}>
                    Move to a new phone or app
                  </Button>
                  <Button variant="secondary" onClick={() => setConfirming("codes")}>
                    <KeyRound className="size-4" /> New recovery codes
                  </Button>
                  {!data.mfa_required && (
                    <Button variant="secondary" onClick={() => setConfirming("remove")}>
                      <ShieldOff className="size-4" /> Turn off
                    </Button>
                  )}
                </div>
                {data.mfa_required && <p className="text-xs text-slate-500 dark:text-slate-400">Required for every account, so it can't be turned off.</p>}
              </div>
            ) : (
              <div className="space-y-4">
                <p className="text-sm text-amber-700 dark:text-amber-400">Off. Anyone who learns your password can sign in as you.</p>
                <Button onClick={() => setSetting("setup")}>
                  <ShieldCheck className="size-4" /> Set up two-step sign-in
                </Button>
              </div>
            )}
          </div>
        </Card>

        <Card>
          <CardHeader title="Password" />
          <div className="px-5 py-5">
            {passwordChanged && <p className="mb-4 text-sm text-emerald-700 dark:text-emerald-400">Password changed. Your other sessions were signed out.</p>}
            <ChangePassword onDone={() => (setPasswordChanged(true), refresh())} />
          </div>
        </Card>

        <Card>
          <CardHeader
            title="Sessions"
            description="Where your account is signed in. A session lasts 12 hours. Sign out any you don't recognize, then change your password."
            action={
              others > 0 && (
                <Button variant="secondary" loading={end.isPending && end.variables === "others"} onClick={() => end.mutate("others")}>
                  <LogOut className="size-4" /> Sign out the other {others}
                </Button>
              )
            }
          />
          <ul className="divide-y divide-slate-200 dark:divide-slate-800">
            {data.sessions.map((session) => (
              <li key={session.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3.5">
                <Monitor className="size-5 shrink-0 text-slate-400" aria-hidden />
                <div className="min-w-0 flex-1">
                  <p className="text-sm font-medium">
                    {browserName(session.user_agent)}
                    {session.current && (
                      <span className="ml-2 rounded-full bg-emerald-50 px-2 py-0.5 text-xs font-medium text-emerald-700 ring-1 ring-emerald-600/20 ring-inset dark:bg-emerald-500/10 dark:text-emerald-300">
                        This browser
                      </span>
                    )}
                  </p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {session.remote || "unknown address"} · signed in {dateTime(session.created_at)} · last used {timeAgo(session.last_seen_at)}
                  </p>
                </div>
                {!session.current && (
                  <Button variant="ghost" loading={end.isPending && end.variables === session.id} onClick={() => end.mutate(session.id)}>
                    Sign out
                  </Button>
                )}
              </li>
            ))}
          </ul>
          <ErrorMessage error={end.error} />
        </Card>
      </div>

      <Dialog
        open={confirming !== null}
        onClose={close}
        title={confirming === "remove" ? "Turn off two-step sign-in?" : "Create new recovery codes?"}
      >
        <form
          className="space-y-4"
          onSubmit={(event) => {
            event.preventDefault();
            if (confirming === "remove") remove.mutate();
            else newCodes.mutate();
          }}
        >
          <p className="text-sm text-slate-600 dark:text-slate-300">
            {confirming === "remove"
              ? "Your password alone will sign you in again. Your recovery codes stop working."
              : "Your current recovery codes stop working, and 10 new ones are shown once."}
          </p>
          <Field label="Password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} data-autofocus />
          <ErrorMessage error={remove.error ?? newCodes.error} />
          <div className="flex justify-end gap-2">
            <Button type="button" variant="secondary" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" variant={confirming === "remove" ? "danger" : "primary"} loading={remove.isPending || newCodes.isPending}>
              {confirming === "remove" ? "Turn off" : "Create new codes"}
            </Button>
          </div>
        </form>
      </Dialog>
    </>
  );
}

