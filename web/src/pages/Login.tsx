import { useState, type FormEvent } from "react";
import { Navigate, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
import { Logo } from "../components/Logo";
import { api } from "../api";
import { Button, Card, ErrorMessage, Field, Loading } from "../components/ui";

/** Only paths on this server are followed after sign-in. */
function safeNext(value: string | null): string {
  return value && value.startsWith("/") && !value.startsWith("//") ? value : "/";
}

export function Login() {
  const [searchParams] = useSearchParams();
  const next = safeNext(searchParams.get("next"));
  const queryClient = useQueryClient();
  const session = useQuery({ queryKey: ["session"], queryFn: api.session });
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [pending, setPending] = useState(false);
  function finish() {
    // A full load starts every page with the new session.
    queryClient.clear();
    // The two-step reminder comes back at every sign-in.
    try {
      sessionStorage.removeItem("dg-mfa-reminder-hidden");
    } catch {
      // Storage is blocked; the reminder shows anyway.
    }
    window.location.assign(next);
  }
  const login = useMutation({
    mutationFn: () => api.login(username, password),
    onSuccess: (result) => {
      setPassword("");
      if (result.mfa_pending) setPending(true);
      else finish();
    },
    onError: () => setPassword(""),
  });
  const verify = useMutation({
    mutationFn: () => api.loginMFA(code),
    onSuccess: finish,
    onError: () => setCode(""),
  });
  const cancel = useMutation({
    mutationFn: api.logout,
    onSettled: () => {
      setPending(false);
      setCode("");
      queryClient.invalidateQueries({ queryKey: ["session"] });
    },
  });

  if (session.isPending) return <Loading />;
  if (session.data && (!session.data.login_required || session.data.authenticated)) return <Navigate to={next} replace />;
  const secondStep = pending || session.data?.mfa_pending;

  function submit(event: FormEvent) {
    event.preventDefault();
    if (secondStep) verify.mutate();
    else login.mutate();
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2">
          <Logo className="size-10 shrink-0" />
          <span className="text-2xl font-bold tracking-tight">DeaconGuard</span>
        </div>
        <Card className="p-6">
          {secondStep ? (
            <>
              <h1 className="flex items-center gap-2 text-lg font-semibold">
                <ShieldCheck className="size-5 text-indigo-600 dark:text-indigo-400" aria-hidden /> Two-step sign-in
              </h1>
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                {useRecovery
                  ? "Enter one of the recovery codes you saved when you set up two-step sign-in. Each works once."
                  : "Enter the 6-digit code from your authenticator app."}
              </p>
              <form onSubmit={submit} className="mt-5 space-y-4">
                <Field
                  key={useRecovery ? "recovery" : "code"}
                  label={useRecovery ? "Recovery code" : "Code"}
                  name="code"
                  autoComplete="one-time-code"
                  inputMode={useRecovery ? "text" : "numeric"}
                  placeholder={useRecovery ? "abcde-fghij" : "123 456"}
                  autoFocus
                  required
                  value={code}
                  onChange={(event) => setCode(event.target.value)}
                  className="font-mono tracking-widest"
                />
                <ErrorMessage error={verify.error} />
                <Button type="submit" className="w-full" loading={verify.isPending}>
                  Verify
                </Button>
              </form>
              <div className="mt-4 flex items-center justify-between text-sm">
                <button
                  type="button"
                  onClick={() => {
                    setUseRecovery(!useRecovery);
                    setCode("");
                  }}
                  className="text-indigo-600 hover:underline dark:text-indigo-400"
                >
                  {useRecovery ? "Use the authenticator app" : "Use a recovery code"}
                </button>
                <button type="button" onClick={() => cancel.mutate()} className="text-slate-500 hover:underline dark:text-slate-400">
                  Cancel
                </button>
              </div>
              <p className="mt-4 text-xs text-slate-500 dark:text-slate-400">
                Lost your phone and your recovery codes? Ask another admin to reset your two-step sign-in on the Accounts page.
              </p>
            </>
          ) : (
            <>
              <h1 className="text-lg font-semibold">Sign in</h1>
              <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                Use your DeaconGuard account. Forgot your password? Ask another admin to set a temporary one on the Accounts page.
              </p>
              <form onSubmit={submit} className="mt-5 space-y-4">
                <Field
                  label="Username"
                  name="username"
                  autoComplete="username"
                  autoFocus
                  required
                  value={username}
                  onChange={(event) => setUsername(event.target.value)}
                />
                <Field
                  label="Password"
                  name="password"
                  type="password"
                  autoComplete="current-password"
                  required
                  value={password}
                  onChange={(event) => setPassword(event.target.value)}
                />
                <ErrorMessage error={login.error ?? session.error} />
                <Button type="submit" className="w-full" loading={login.isPending}>
                  Sign in
                </Button>
              </form>
            </>
          )}
        </Card>
      </div>
    </div>
  );
}
