import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy } from "lucide-react";
import { api, type Role, type SSOSettings } from "../api";
import { Button, Card, CardHeader, ErrorMessage, Field, Loading } from "./ui";

const selectClass =
  "mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700";

const list = (value: string) =>
  value
    .split(/[\n,]+/)
    .map((item) => item.trim())
    .filter(Boolean);

/** Admin settings for signing in with an OpenID Connect provider. */
export function SingleSignOn() {
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: ["sso"], queryFn: api.ssoSettings });
  const [form, setForm] = useState<SSOSettings | null>(null);
  const [secret, setSecret] = useState("");
  const [groups, setGroups] = useState({ allowed: "", admin: "", operator: "", domains: "", scopes: "" });
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!settings.data) return;
    setForm(settings.data);
    setGroups({
      allowed: (settings.data.allowed_groups ?? []).join("\n"),
      admin: (settings.data.admin_groups ?? []).join("\n"),
      operator: (settings.data.operator_groups ?? []).join("\n"),
      domains: (settings.data.allowed_domains ?? []).join("\n"),
      scopes: (settings.data.scopes ?? []).join(" "),
    });
  }, [settings.data]);
  const save = useMutation({
    mutationFn: () =>
      api.saveSSOSettings({
        enabled: form!.enabled,
        issuer: form!.issuer,
        client_id: form!.client_id,
        button_label: form!.button_label,
        username_claim: form!.username_claim,
        groups_claim: form!.groups_claim,
        default_role: form!.default_role,
        client_secret: secret,
        allowed_groups: list(groups.allowed),
        admin_groups: list(groups.admin),
        operator_groups: list(groups.operator),
        allowed_domains: list(groups.domains),
        scopes: groups.scopes.split(/[\s,]+/).filter(Boolean),
      }),
    onSuccess: (data) => {
      queryClient.setQueryData(["sso"], data);
      queryClient.invalidateQueries({ queryKey: ["session"] });
      setSecret("");
      setSaved(true);
    },
  });

  if (settings.isPending || !form) return <Loading />;
  if (settings.error) return <ErrorMessage error={settings.error} />;
  const set = (patch: Partial<SSOSettings>) => (setForm({ ...form, ...patch }), setSaved(false));
  function submit(event: FormEvent) {
    event.preventDefault();
    save.mutate();
  }
  return (
    <Card className="mb-6">
      <CardHeader
        title="Single sign-on"
        description="Let people sign in with your identity provider over OpenID Connect: Microsoft Entra ID, Google, Okta, Keycloak, Authentik, and others. Accounts are made at their first sign-in. Password accounts keep working, so keep one admin with a password in case the provider is down."
      />
      <form className="space-y-5 px-5 py-5" onSubmit={submit}>
        <div className="rounded-lg bg-slate-50 px-4 py-3 text-sm ring-1 ring-slate-200 ring-inset dark:bg-slate-800/50 dark:ring-slate-700">
          <p className="font-medium">Redirect URI to register with the provider</p>
          <div className="mt-1 flex items-center gap-2">
            <code className="min-w-0 flex-1 font-mono text-xs break-all">{form.redirect_uri}</code>
            <Button
              type="button"
              variant="ghost"
              aria-label="Copy the redirect URI"
              onClick={() => navigator.clipboard?.writeText(form.redirect_uri).then(() => setCopied(true))}
            >
              <Copy className="size-4" /> {copied ? "Copied" : "Copy"}
            </Button>
          </div>
          <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">It uses the address you opened the dashboard with; open it at the address people use.</p>
        </div>
        <div className="grid gap-4 lg:grid-cols-2">
          <Field label="Issuer URL" value={form.issuer} onChange={(event) => set({ issuer: event.target.value })} placeholder="https://login.microsoftonline.com/TENANT/v2.0" />
          <Field label="Button text" value={form.button_label} maxLength={60} onChange={(event) => set({ button_label: event.target.value })} placeholder="Sign in with single sign-on" />
          <Field label="Client ID" value={form.client_id} onChange={(event) => set({ client_id: event.target.value })} autoComplete="off" />
          <Field
            label="Client secret"
            type="password"
            autoComplete="new-password"
            value={secret}
            onChange={(event) => (setSecret(event.target.value), setSaved(false))}
            placeholder={form.secret_set ? "Saved; type to replace it" : ""}
          />
          <label className="block">
            <span className="text-sm font-medium">Name new accounts by</span>
            <select value={form.username_claim} onChange={(event) => set({ username_claim: event.target.value as SSOSettings["username_claim"] })} className={selectClass}>
              <option value="email">Email (verified by the provider)</option>
              <option value="preferred_username">Username (preferred_username)</option>
            </select>
          </label>
          <label className="block">
            <span className="text-sm font-medium">Role for everyone else</span>
            <select value={form.default_role} onChange={(event) => set({ default_role: event.target.value as Role })} className={selectClass}>
              <option value="viewer">Viewer</option>
              <option value="operator">Operator</option>
              <option value="admin">Admin</option>
            </select>
          </label>
        </div>
        <details className="rounded-lg ring-1 ring-slate-200 dark:ring-slate-700" open={!!(groups.allowed || groups.admin || groups.operator || groups.domains)}>
          <summary className="cursor-pointer px-4 py-3 text-sm font-medium">Who may sign in, and roles from groups</summary>
          <div className="grid gap-4 border-t border-slate-200 px-4 py-4 lg:grid-cols-2 dark:border-slate-700">
            {(
              [
                ["domains", "Allowed email domains", "One per line, such as example.com. Empty allows any."],
                ["allowed", "Allowed groups", "Only members of these, or of the groups below, may sign in. Empty allows anyone the provider signs in."],
                ["admin", "Admin groups", "Members are admins. With admin or operator groups, roles follow the groups at every sign-in."],
                ["operator", "Operator groups", "Members are operators, unless they are in an admin group."],
              ] as const
            ).map(([key, label, hint]) => (
              <label key={key} className="block">
                <span className="text-sm font-medium">{label}</span>
                <textarea
                  rows={3}
                  value={groups[key]}
                  onChange={(event) => (setGroups({ ...groups, [key]: event.target.value }), setSaved(false))}
                  className={`${selectClass} font-mono`}
                />
                <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">{hint}</span>
              </label>
            ))}
            <Field
              label="Extra scopes"
              value={groups.scopes}
              onChange={(event) => (setGroups({ ...groups, scopes: event.target.value }), setSaved(false))}
              placeholder="groups"
              hint="Asked for besides openid, email and profile. Dex and Okta send groups only with the groups scope."
            />
            <Field
              label="Groups claim"
              value={form.groups_claim}
              onChange={(event) => set({ groups_claim: event.target.value })}
              hint="The ID token claim that lists groups. Entra ID sends group object IDs unless set to send names."
            />
          </div>
        </details>
        <label className="flex items-center gap-2 text-sm">
          <input type="checkbox" checked={form.enabled} onChange={(event) => set({ enabled: event.target.checked })} className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-600" />
          Offer single sign-on on the sign-in page
        </label>
        <ErrorMessage error={save.error} />
        <div className="flex items-center gap-3">
          <Button type="submit" loading={save.isPending}>
            Save
          </Button>
          {saved && <span className="text-sm text-emerald-700 dark:text-emerald-400">Saved{form.enabled ? "; the provider answered" : ""}.</span>}
        </div>
      </form>
    </Card>
  );
}
