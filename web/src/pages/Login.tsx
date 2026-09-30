import { useState, type FormEvent } from "react";
import { Navigate, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ShieldCheck } from "lucide-react";
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
  const login = useMutation({
    mutationFn: () => api.login(username, password),
    onSuccess: () => {
      // A full load starts every page with the new session.
      queryClient.clear();
      window.location.assign(next);
    },
    onError: () => setPassword(""),
  });

  if (session.isPending) return <Loading />;
  if (session.data && (!session.data.login_required || session.data.authenticated)) return <Navigate to={next} replace />;

  function submit(event: FormEvent) {
    event.preventDefault();
    login.mutate();
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4 py-12">
      <div className="w-full max-w-sm">
        <div className="mb-6 flex items-center justify-center gap-2">
          <ShieldCheck className="size-8 text-indigo-600 dark:text-indigo-400" aria-hidden />
          <span className="text-2xl font-bold tracking-tight">OpsArmor</span>
        </div>
        <Card className="p-6">
          <h1 className="text-lg font-semibold">Sign in</h1>
          <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">Use an account created on the server with opsarmor user add.</p>
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
        </Card>
      </div>
    </div>
  );
}
