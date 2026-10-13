import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, KeyRound, Plus } from "lucide-react";
import { api, roleLabels, type APIToken, type Role } from "../../api";
import { Button, Card, CardHeader, Dialog, ErrorMessage, Field, Table, Td, Th, cx } from "../ui";
import { dateTime, timeAgo } from "../../lib/format";

const roleRank: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

const statusStyle: Record<APIToken["status"], string> = {
  active: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-400/30",
  expired: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-500/10 dark:text-slate-300 dark:ring-slate-400/20",
  revoked: "bg-red-50 text-red-700 ring-red-600/20 dark:bg-red-500/10 dark:text-red-300 dark:ring-red-400/30",
};

function TokenRows({ tokens, owner, onRevoke, revoking }: { tokens: APIToken[]; owner: boolean; onRevoke: (id: string) => void; revoking?: string }) {
  return (
    <Table>
      <thead>
        <tr>
          <Th>Token</Th>
          {owner && <Th>Account</Th>}
          <Th>Role</Th>
          <Th>Last used</Th>
          <Th>Expires</Th>
          <Th className="text-right">
            <span className="sr-only">Actions</span>
          </Th>
        </tr>
      </thead>
      <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
        {tokens.map((token) => (
          <tr key={token.id}>
            <Td>
              <span className="font-medium">{token.name}</span>
              <span className={cx("ml-2 rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset", statusStyle[token.status])}>
                {token.status}
              </span>
              <p className="text-xs text-slate-500 dark:text-slate-400">created {dateTime(token.created_at)}</p>
            </Td>
            {owner && <Td className="text-sm">{token.username}</Td>}
            <Td className="text-sm">{roleLabels[token.role]}</Td>
            <Td className="text-sm text-slate-600 dark:text-slate-300">
              {token.last_used_at ? (
                <>
                  {timeAgo(token.last_used_at)}
                  <p className="text-xs text-slate-500 dark:text-slate-400">from {token.last_used_from}</p>
                </>
              ) : (
                "never"
              )}
            </Td>
            <Td className="text-sm text-slate-600 dark:text-slate-300">
              {token.status === "revoked" ? `revoked ${timeAgo(token.revoked_at)}` : token.expires_at ? dateTime(token.expires_at) : "when revoked"}
            </Td>
            <Td className="text-right">
              {token.status === "active" && (
                <Button variant="ghost" loading={revoking === token.id} onClick={() => onRevoke(token.id)}>
                  Revoke
                </Button>
              )}
            </Td>
          </tr>
        ))}
      </tbody>
    </Table>
  );
}

/** My account: the account's own API tokens. */
export function APITokens({ role }: { role: Role }) {
  const queryClient = useQueryClient();
  const { data, error } = useQuery({ queryKey: ["api-tokens"], queryFn: api.apiTokens });
  const [creating, setCreating] = useState(false);
  const revoke = useMutation({
    mutationFn: api.revokeOwnAPIToken,
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["api-tokens"] }),
  });
  return (
    <Card>
      <CardHeader
        title="API tokens"
        description="For scripts and other tools that use DeaconGuard's API, such as CI pipelines. A token acts as you, with the role you give it, never more than yours. Tokens can't manage accounts or tokens."
        action={
          <Button variant="secondary" onClick={() => setCreating(true)}>
            <Plus className="size-4" /> Create token
          </Button>
        }
      />
      <ErrorMessage error={error ?? revoke.error} />
      {data && data.length === 0 ? (
        <p className="px-5 py-5 text-sm text-slate-500 dark:text-slate-400">No API tokens.</p>
      ) : (
        data && <TokenRows tokens={data} owner={false} onRevoke={(id) => revoke.mutate(id)} revoking={revoke.isPending ? revoke.variables : undefined} />
      )}
      {creating && <CreateTokenDialog role={role} onClose={() => setCreating(false)} />}
    </Card>
  );
}

/** Accounts: every account's API tokens, for admins to revoke. */
export function AllAPITokens() {
  const queryClient = useQueryClient();
  const { data, error } = useQuery({ queryKey: ["all-api-tokens"], queryFn: api.allAPITokens });
  const revoke = useMutation({
    mutationFn: api.revokeAPIToken,
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["all-api-tokens"] }),
  });
  if (!data || data.length === 0) return error ? <ErrorMessage error={error} /> : null;
  return (
    <Card className="mt-6">
      <CardHeader title="API tokens" description="Every account's tokens. Revoke any that shouldn't work any more; each owner creates and revokes their own under My account." />
      <ErrorMessage error={revoke.error} />
      <TokenRows tokens={data} owner onRevoke={(id) => revoke.mutate(id)} revoking={revoke.isPending ? revoke.variables : undefined} />
    </Card>
  );
}

function CreateTokenDialog({ role, onClose }: { role: Role; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [name, setName] = useState("");
  const [tokenRole, setTokenRole] = useState<Role>("viewer");
  const [days, setDays] = useState(90);
  const [copied, setCopied] = useState(false);
  const create = useMutation({
    mutationFn: () => api.createAPIToken({ name, role: tokenRole, days }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["api-tokens"] });
      queryClient.invalidateQueries({ queryKey: ["all-api-tokens"] });
    },
  });
  const roles = (["viewer", "operator", "admin"] as Role[]).filter((item) => roleRank[item] <= roleRank[role]);

  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate();
  }

  if (create.data) {
    const example = `curl -H "Authorization: Bearer ${create.data.token}" ${window.location.origin}/api/hosts`;
    return (
      <Dialog open onClose={onClose} title={`Token ${create.data.name}`}>
        <div className="space-y-4 text-sm">
          <div className="relative">
            <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3 pr-12 font-mono text-xs break-all whitespace-pre-wrap text-slate-100">{create.data.token}</pre>
            <button
              type="button"
              aria-label="Copy the token"
              onClick={async () => {
                try {
                  await navigator.clipboard.writeText(create.data!.token);
                  setCopied(true);
                } catch {
                  // The token stays selectable.
                }
              }}
              className="absolute top-2 right-2 rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
            >
              {copied ? <Check className="size-4 text-emerald-400" /> : <Copy className="size-4" />}
            </button>
          </div>
          <p className="text-slate-600 dark:text-slate-300">Send it in the Authorization header:</p>
          <pre className="overflow-x-auto rounded-lg bg-slate-100 p-3 font-mono text-xs break-all whitespace-pre-wrap dark:bg-slate-800">{example}</pre>
          <p className="flex gap-2 rounded-lg bg-amber-50 p-3 text-xs leading-relaxed text-amber-900 ring-1 ring-inset ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-200">
            <KeyRound className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span>
              This token is shown only once. It acts as you with the {roleLabels[create.data.role]} role
              {create.data.expires_at ? ` until ${dateTime(create.data.expires_at)}` : " until you revoke it"}. Keep it in a secret store; revoke it here if it leaks.
            </span>
          </p>
          <div className="flex justify-end">
            <Button onClick={onClose}>Done</Button>
          </div>
        </div>
      </Dialog>
    );
  }

  return (
    <Dialog open onClose={onClose} title="Create an API token">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Name" required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="CI pipeline" hint="Say what uses it, so you know what breaks if you revoke it." />
        <div className="grid gap-3 sm:grid-cols-2">
          <label className="block">
            <span className="text-sm font-medium">Role</span>
            <select
              value={tokenRole}
              onChange={(event) => setTokenRole(event.target.value as Role)}
              className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
            >
              {roles.map((item) => (
                <option key={item} value={item}>
                  {roleLabels[item]}
                </option>
              ))}
            </select>
          </label>
          <label className="block">
            <span className="text-sm font-medium">Lasts</span>
            <select
              value={days}
              onChange={(event) => setDays(Number(event.target.value))}
              className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
            >
              {[30, 90, 180, 365].map((choice) => (
                <option key={choice} value={choice}>
                  {choice} days
                </option>
              ))}
              <option value={0}>Until revoked</option>
            </select>
          </label>
        </div>
        <p className="text-xs text-slate-500 dark:text-slate-400">Viewer reads everything; Operator also scans, audits and tags; Admin also manages machines and settings.</p>
        <ErrorMessage error={create.error} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={create.isPending}>
            Create token
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
