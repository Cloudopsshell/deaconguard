import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FileCode2, Pencil, Plus, Trash2 } from "lucide-react";
import { api, type Policy } from "../api";
import { Button, Card, Dialog, EmptyState, ErrorMessage, Loading, PageHeader } from "../components/ui";
import { dateTime } from "../lib/format";
import { useCan } from "../lib/role";

const checkHelp: [string, string][] = [
  ["sshd", "{ setting: PermitRootLogin, is: [\"no\"] } — an SSH server setting; or at_most / at_least for numbers"],
  ["sysctl", "{ setting: net.ipv4.ip_forward, is: [\"0\"] } — any kernel setting"],
  ["login_defs", "{ setting: PASS_MAX_DAYS, at_most: 90 } — a setting in /etc/login.defs"],
  ["package", "{ name: telnet, installed: false }"],
  ["service", "{ name: auditd, running: true }"],
  ["mount", "{ path: /tmp, options: [nodev, nosuid] }"],
  ["port", "{ port: 3306, exposed: false } — or listening: false; protocol tcp or udp is optional"],
  ["file", "{ path: /etc/shadow, mode_at_most: \"0640\", owner: root } — one of the key files the audit reads"],
];

/** Admins' own controls, tested in every audit next to the baseline. */
export function Policies() {
  const canEdit = useCan("admin");
  const queryClient = useQueryClient();
  const { data, error, isPending } = useQuery({ queryKey: ["policies"], queryFn: api.policies });
  const [editing, setEditing] = useState<Policy | "new" | null>(null);
  const toggle = useMutation({
    mutationFn: (policy: Policy) => api.updatePolicy(policy.id, { enabled: !policy.enabled }),
    onSettled: () => queryClient.invalidateQueries(),
  });
  const remove = useMutation({ mutationFn: api.deletePolicy, onSettled: () => queryClient.invalidateQueries() });
  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;
  return (
    <>
      <PageHeader
        title="Policies"
        description="Your organisation's own controls, written in YAML, tested in every audit next to the baseline. They read only the settings the audit already reads, and never run anything. They show on audits and reports, but don't change the grade."
        action={
          canEdit && (
            <Button onClick={() => setEditing("new")}>
              <Plus className="size-4" /> New policy
            </Button>
          )
        }
      />
      <Card>
        {data.policies.length === 0 ? (
          <EmptyState
            icon={<FileCode2 className="size-6" />}
            title="No policies yet"
            description="Add one to test your own requirements, such as a monitoring agent that must run, or a port that must stay closed."
          />
        ) : (
          <ul className="divide-y divide-slate-200 dark:divide-slate-800">
            {data.policies.map((policy) => (
              <li key={policy.id} className="flex flex-wrap items-center gap-4 px-5 py-4">
                <div className="min-w-0 flex-1">
                  <p className="font-medium">{policy.name}</p>
                  <p className="text-xs text-slate-500 dark:text-slate-400">
                    {policy.controls} {policy.controls === 1 ? "control" : "controls"} · changed {dateTime(policy.updated_at)} · added by {policy.created_by}
                  </p>
                </div>
                {canEdit ? (
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      role="switch"
                      aria-checked={policy.enabled}
                      aria-label={`${policy.name} is ${policy.enabled ? "on" : "off"}`}
                      onClick={() => toggle.mutate(policy)}
                      className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors ${policy.enabled ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-700"}`}
                    >
                      <span className={`inline-block size-5 rounded-full bg-white shadow transition-transform ${policy.enabled ? "translate-x-5.5" : "translate-x-0.5"}`} />
                    </button>
                    <Button variant="ghost" onClick={() => setEditing(policy)} aria-label={`Edit ${policy.name}`}>
                      <Pencil className="size-4" /> Edit
                    </Button>
                    <Button variant="ghost" className="px-2" onClick={() => remove.mutate(policy.id)} aria-label={`Delete ${policy.name}`}>
                      <Trash2 className="size-4" />
                    </Button>
                  </div>
                ) : (
                  <span className="text-sm text-slate-500">{policy.enabled ? "On" : "Off"}</span>
                )}
              </li>
            ))}
          </ul>
        )}
        {(toggle.error || remove.error) && (
          <div className="px-5 pb-4">
            <ErrorMessage error={toggle.error ?? remove.error} />
          </div>
        )}
      </Card>
      {editing && <PolicyEditor policy={editing === "new" ? null : editing} example={data.example} onClose={() => setEditing(null)} />}
    </>
  );
}

function PolicyEditor({ policy, example, onClose }: { policy: Policy | null; example: string; onClose: () => void }) {
  const queryClient = useQueryClient();
  const [source, setSource] = useState(policy?.source ?? example);
  const save = useMutation({
    mutationFn: () => (policy ? api.updatePolicy(policy.id, { source }) : api.addPolicy(source)),
    onSuccess: () => {
      queryClient.invalidateQueries();
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title={policy ? `Edit ${policy.name}` : "New policy"} wide>
      <div className="space-y-4 text-sm">
        <p className="text-slate-600 dark:text-slate-300">
          Each control needs an <code>id</code> (not a baseline one), a <code>title</code>, a <code>severity</code> (critical, high, medium or low), and one{" "}
          <code>check</code>. <code>rationale</code> and <code>remediation</code> are shown with it.
        </p>
        <textarea
          value={source}
          onChange={(event) => setSource(event.target.value)}
          rows={18}
          spellCheck={false}
          aria-label="Policy YAML"
          className="block w-full rounded-lg border-0 bg-slate-50 px-3 py-2 font-mono text-xs leading-relaxed ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700"
        />
        <details className="text-xs text-slate-600 dark:text-slate-300">
          <summary className="cursor-pointer font-medium">What a check can test</summary>
          <dl className="mt-2 space-y-1">
            {checkHelp.map(([name, help]) => (
              <div key={name}>
                <dt className="inline font-mono font-semibold">{name}: </dt>
                <dd className="inline font-mono">{help}</dd>
              </div>
            ))}
          </dl>
        </details>
        <ErrorMessage error={save.error} />
        <div className="flex justify-between gap-2">
          <Button type="button" variant="ghost" onClick={() => setSource(example)}>
            Start from the example
          </Button>
          <div className="flex gap-2">
            <Button type="button" variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button loading={save.isPending} onClick={() => save.mutate()}>
              {policy ? "Save" : "Add policy"}
            </Button>
          </div>
        </div>
      </div>
    </Dialog>
  );
}
