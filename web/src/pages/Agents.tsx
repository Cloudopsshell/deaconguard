import { useState, type FormEvent } from "react";
import { Link, useSearchParams } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, KeyRound, Plus, RadioTower } from "lucide-react";
import { api, type EnrollmentToken, type NewEnrollmentToken } from "../api";
import {
  Button,
  Card,
  CardHeader,
  Dialog,
  EmptyState,
  ErrorMessage,
  Field,
  Loading,
  PageHeader,
  Table,
  Td,
  Th,
  cx,
} from "../components/ui";
import { dateTime, timeAgo } from "../lib/format";
import { ThisServerBadge, agentOnline } from "../lib/hosts";

export function Agents() {
  const [searchParams, setSearchParams] = useSearchParams();
  const enrolling = searchParams.get("enroll") === "1";
  const setEnrolling = (open: boolean) => setSearchParams(open ? { enroll: "1" } : {}, { replace: true });
  const capabilities = useQuery({ queryKey: ["capabilities"], queryFn: api.capabilities, staleTime: Infinity });

  if (capabilities.isPending) return <Loading />;
  if (capabilities.data && !capabilities.data.agents) {
    return (
      <>
        <PageHeader title="Agents" />
        <Card>
          <EmptyState
            icon={<RadioTower className="size-6" />}
            title="Agents need the DeaconGuard server"
            description="This DeaconGuard only serves this machine at localhost. To scan other machines, run it as a server on the network, where agents can reach it: sudo deaconguard setup server (or deaconguard serve --listen 0.0.0.0:8443)."
          />
        </Card>
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Agents"
        description="Machines running the DeaconGuard agent. Each enrolls once with a one-time token, then waits for scans from this server."
        action={
          <Button onClick={() => setEnrolling(true)}>
            <Plus className="size-4" /> Enroll a machine
          </Button>
        }
      />
      <div className="space-y-6">
        <AgentList onEnroll={() => setEnrolling(true)} />
        <TokenList />
      </div>
      <EnrollDialog open={enrolling} onClose={() => setEnrolling(false)} />
    </>
  );
}

function AgentList({ onEnroll }: { onEnroll: () => void }) {
  const { data, error, isPending } = useQuery({ queryKey: ["hosts"], queryFn: api.hosts, refetchInterval: 15_000 });
  const agents = data?.filter((host) => host.transport === "agent") ?? [];
  return (
    <Card>
      <CardHeader title="Enrolled machines" description="Scan them from the Hosts page like any other host." />
      {isPending ? (
        <Loading />
      ) : error ? (
        <div className="p-5">
          <ErrorMessage error={error} />
        </div>
      ) : agents.length === 0 ? (
        <EmptyState
          icon={<RadioTower className="size-6" />}
          title="No agents yet"
          description="Create a one-time token, then run the enroll command it shows on the machine you want to scan."
          action={
            <Button onClick={onEnroll}>
              <Plus className="size-4" /> Enroll a machine
            </Button>
          }
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Machine</Th>
              <Th>Status</Th>
              <Th>Operating system</Th>
              <Th>Agent</Th>
              <Th>Enrolled</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {agents.map((host) => {
              const online = agentOnline(host);
              return (
                <tr key={host.id}>
                  <Td>
                    <div className="flex flex-wrap items-center gap-x-2 gap-y-1">
                      <Link to={`/hosts/${host.id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
                        {host.address}
                      </Link>
                      {host.this_server && <ThisServerBadge />}
                    </div>
                    {host.agent?.remote && (
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        {host.this_server ? `${host.agent.remote}, this server's own agent` : host.agent.remote}
                      </p>
                    )}
                  </Td>
                  <Td>
                    <AgentStatus online={online} lastSeen={host.agent?.last_seen_at} />
                  </Td>
                  <Td className="text-slate-600 dark:text-slate-300">{host.agent?.os || "—"}</Td>
                  <Td className="font-mono text-xs text-slate-600 dark:text-slate-300">{host.agent?.version || "—"}</Td>
                  <Td className="text-sm text-slate-500 dark:text-slate-400">{host.agent ? dateTime(host.agent.enrolled_at) : "—"}</Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

export function AgentStatus({ online, lastSeen }: { online: boolean; lastSeen?: string }) {
  return (
    <span className="inline-flex items-center gap-1.5 text-sm">
      <span className={cx("size-2 rounded-full", online ? "bg-emerald-500" : "bg-slate-400")} aria-hidden />
      {online ? "Online" : "Offline"}
      {!online && lastSeen && <span className="text-xs text-slate-500 dark:text-slate-400">· seen {timeAgo(lastSeen)}</span>}
    </span>
  );
}

const tokenStatusStyle: Record<EnrollmentToken["status"], string> = {
  active: "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/15 dark:text-emerald-300 dark:ring-emerald-400/30",
  used: "bg-indigo-50 text-indigo-700 ring-indigo-600/20 dark:bg-indigo-500/15 dark:text-indigo-300 dark:ring-indigo-400/30",
  expired: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-500/15 dark:text-slate-400 dark:ring-slate-400/30",
  revoked: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-500/15 dark:text-slate-400 dark:ring-slate-400/30",
};

function TokenList() {
  const queryClient = useQueryClient();
  const { data, error, isPending } = useQuery({ queryKey: ["enrollment-tokens"], queryFn: api.enrollmentTokens });
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: api.hosts });
  const revoke = useMutation({
    mutationFn: api.revokeEnrollmentToken,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["enrollment-tokens"] }),
  });
  return (
    <Card>
      <CardHeader
        title="Enrollment tokens"
        description="Each token enrolls one machine, within 24 hours. The token itself is shown only when it is created."
      />
      {isPending ? (
        <Loading />
      ) : error ? (
        <div className="p-5">
          <ErrorMessage error={error} />
        </div>
      ) : data.length === 0 ? (
        <p className="px-5 py-6 text-sm text-slate-500 dark:text-slate-400">No tokens created in the last 30 days.</p>
      ) : (
        <>
          <Table>
            <thead>
              <tr>
                <Th>Token</Th>
                <Th>Status</Th>
                <Th>Created</Th>
                <Th>Expires / used</Th>
                <Th className="text-right">
                  <span className="sr-only">Actions</span>
                </Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.map((token) => {
                const host = hosts.data?.find((candidate) => candidate.id === token.host_id);
                return (
                  <tr key={token.id}>
                    <Td>
                      <span className="font-mono text-xs">{token.id.slice(0, 8)}</span>
                      <p className="text-xs text-slate-500 dark:text-slate-400">{token.server_url}</p>
                    </Td>
                    <Td>
                      <span className={cx("rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset", tokenStatusStyle[token.status])}>
                        {token.status}
                      </span>
                    </Td>
                    <Td className="text-sm text-slate-600 dark:text-slate-300">
                      {timeAgo(token.created_at)}
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        {host?.this_server && token.created_by.endsWith("(cli)") ? "by server setup, for its own agent" : `by ${token.created_by}`}
                      </p>
                    </Td>
                    <Td className="text-sm text-slate-600 dark:text-slate-300">
                      {token.status === "used" && token.used_at ? (
                        <>
                          {timeAgo(token.used_at)}
                          {host ? (
                            <p className="text-xs">
                              by{" "}
                              <Link to={`/hosts/${host.id}`} className="text-indigo-600 hover:underline dark:text-indigo-400">
                                {host.address}
                              </Link>
                            </p>
                          ) : (
                            <p className="text-xs text-slate-500 dark:text-slate-400">host since removed</p>
                          )}
                        </>
                      ) : token.status === "active" ? (
                        <>expires {dateTime(token.expires_at)}</>
                      ) : token.status === "revoked" && token.revoked_at ? (
                        <>revoked {timeAgo(token.revoked_at)}</>
                      ) : (
                        <>expired {dateTime(token.expires_at)}</>
                      )}
                    </Td>
                    <Td className="text-right">
                      {token.status === "active" && (
                        <Button
                          variant="ghost"
                          loading={revoke.isPending && revoke.variables === token.id}
                          onClick={() => revoke.mutate(token.id)}
                        >
                          Revoke
                        </Button>
                      )}
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
          {revoke.error && (
            <div className="p-5">
              <ErrorMessage error={revoke.error} />
            </div>
          )}
        </>
      )}
    </Card>
  );
}

function EnrollDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [serverUrl, setServerUrl] = useState(window.location.origin);
  const [created, setCreated] = useState<NewEnrollmentToken | null>(null);
  const create = useMutation({
    mutationFn: () => api.createEnrollmentToken(serverUrl),
    onSuccess: (token) => {
      setCreated(token);
      queryClient.invalidateQueries({ queryKey: ["enrollment-tokens"] });
    },
  });

  function close() {
    setCreated(null);
    create.reset();
    onClose();
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    create.mutate();
  }

  return (
    <Dialog open={open} onClose={close} title="Enroll a machine">
      {created ? (
        <div className="space-y-4 text-sm">
          <p className="text-slate-600 dark:text-slate-300">
            On the Linux machine to scan, run this as a user with sudo rights (as root, leave out{" "}
            <code className="font-mono">sudo -E</code>). It installs the same DeaconGuard version as this server, checks it,
            enrolls the machine, and starts the agent.
          </p>
          <CopyBlock text={created.command} label="Copy the command" />
          <details className="text-xs text-slate-500 dark:text-slate-400">
            <summary className="cursor-pointer">Keep the token out of the shell history, or DeaconGuard is already installed</summary>
            <p className="mt-2">
              Run the command without <code className="font-mono">DEACONGUARD_TOKEN=…</code>, or run{" "}
              <code className="font-mono">sudo deaconguard setup agent</code> on a machine that already has DeaconGuard. Both ask
              for this token:
            </p>
            <div className="mt-2">
              <CopyBlock text={created.token} label="Copy the token" />
            </div>
          </details>
          <p className="flex gap-2 rounded-lg bg-amber-50 p-3 text-xs leading-relaxed text-amber-900 ring-1 ring-inset ring-amber-600/20 dark:bg-amber-500/10 dark:text-amber-200">
            <KeyRound className="mt-0.5 size-4 shrink-0" aria-hidden />
            <span>
              This token is shown only once. It enrolls one machine and expires {dateTime(created.expires_at)}. Anyone with it can
              enroll a machine with this server until then, so treat it like a password.
            </span>
          </p>
          <p className="text-xs text-slate-500 dark:text-slate-400">
            The machine connects out to {created.server_url} over HTTPS and appears on the Agents and Hosts pages. It needs no
            open ports.
          </p>
          <div className="flex justify-end pt-2">
            <Button onClick={close}>Done</Button>
          </div>
        </div>
      ) : (
        <form onSubmit={submit} className="space-y-4">
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Creates a one-time token, valid for 24 hours. The machine uses it to enroll with this server.
          </p>
          <Field
            label="Server address the machine will connect to"
            hint="Must be reachable from the machine. Change it if agents reach this server by another name or address."
            value={serverUrl}
            onChange={(event) => setServerUrl(event.target.value)}
            required
            data-autofocus
          />
          <ErrorMessage error={create.error} />
          <div className="flex justify-end gap-2 pt-2">
            <Button type="button" variant="secondary" onClick={close}>
              Cancel
            </Button>
            <Button type="submit" loading={create.isPending}>
              Create token
            </Button>
          </div>
        </form>
      )}
    </Dialog>
  );
}

function CopyBlock({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be denied; the text stays selectable.
    }
  }
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3 pr-12 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap text-slate-100">
        {text}
      </pre>
      <button
        type="button"
        onClick={copy}
        className="absolute top-2 right-2 rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
        aria-label={label}
        title="Copy"
      >
        {copied ? <Check className="size-4 text-emerald-400" /> : <Copy className="size-4" />}
      </button>
    </div>
  );
}
