import { useState, type FormEvent } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { KeyRound, Lock, ShieldQuestion } from "lucide-react";
import { api, type Prompt } from "../api";
import { useRefreshAll } from "../lib/hooks";
import { Button, Dialog, ErrorMessage } from "./ui";

/**
 * Shows questions from paused scans on every page: trusting a new host key,
 * a key passphrase, or an SSH password. Answers go to that one scan and are
 * never stored. Closing the dialog cancels the scan.
 */
export function PromptDialog() {
  const { data } = useQuery({ queryKey: ["prompts"], queryFn: api.prompts, refetchInterval: 1500 });
  const prompt = data?.[0];
  if (!prompt) return null;
  // A new key per question resets the form, including after a rejected answer.
  return <PromptForm key={`${prompt.scan_id}-${prompt.kind}-${prompt.created_at}`} prompt={prompt} />;
}

const titles: Record<Prompt["kind"], string> = {
  host_key: "Verify SSH host key",
  passphrase: "SSH key passphrase",
  password: "SSH password",
  sudo: "Sudo password",
};

function PromptForm({ prompt }: { prompt: Prompt }) {
  const refresh = useRefreshAll();
  const [value, setValue] = useState("");
  const [confirmed, setConfirmed] = useState(false);
  const answer = useMutation({
    mutationFn: (reply: { value?: string; cancel?: boolean }) => api.respond(prompt.scan_id, reply),
    onSuccess: () => {
      setValue("");
      refresh();
    },
  });
  const target = `${prompt.username}@${prompt.address}${prompt.port === 22 ? "" : `:${prompt.port}`}`;

  function submit(event: FormEvent) {
    event.preventDefault();
    answer.mutate({ value: prompt.kind === "host_key" ? prompt.fingerprint : value });
  }

  return (
    <Dialog open onClose={() => answer.mutate({ cancel: true })} title={titles[prompt.kind]}>
      <form onSubmit={submit} className="space-y-4">
        <div className="flex gap-3">
          <div className="h-fit rounded-full bg-amber-100 p-2 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300">
            {prompt.kind === "host_key" || prompt.kind === "sudo" ? (
              <ShieldQuestion className="size-5" />
            ) : prompt.kind === "passphrase" ? (
              <KeyRound className="size-5" />
            ) : (
              <Lock className="size-5" />
            )}
          </div>
          <div className="min-w-0 text-sm text-slate-600 dark:text-slate-300">
            {prompt.kind === "host_key" && (
              <p>
                This is the first connection to <span className="font-semibold text-slate-900 dark:text-slate-100">{target}</span>.
                Compare the fingerprint below with one from a trusted source, such as your cloud console or the server's
                administrator. Once trusted, any change to this key is refused.
              </p>
            )}
            {prompt.kind === "passphrase" && (
              <p>
                The scan of <span className="font-semibold text-slate-900 dark:text-slate-100">{target}</span> needs the passphrase
                for <code className="font-mono text-xs break-all">{prompt.key_path}</code>.
              </p>
            )}
            {prompt.kind === "sudo" && (
              <p>
                Sudo on <span className="font-semibold text-slate-900 dark:text-slate-100">{target}</span> needs a password. Enter
                the password for <span className="font-semibold text-slate-900 dark:text-slate-100">{prompt.username}</span> so
                deeper checks can read protected files and processes, or continue without sudo.
              </p>
            )}
            {prompt.kind === "password" && (
              <p>
                The server did not accept a key. Enter the SSH password for{" "}
                <span className="font-semibold text-slate-900 dark:text-slate-100">{target}</span>.
              </p>
            )}
          </div>
        </div>

        {prompt.retry && <ErrorMessage error={capitalize(prompt.retry)} />}

        {prompt.kind === "host_key" ? (
          <>
            <code className="block rounded-lg bg-slate-100 px-3 py-2 font-mono text-sm break-all dark:bg-slate-800">
              {prompt.fingerprint}
            </code>
            <label className="flex items-start gap-2 text-sm">
              <input
                type="checkbox"
                checked={confirmed}
                onChange={(event) => setConfirmed(event.target.checked)}
                className="mt-0.5 size-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
              />
              I compared this fingerprint with a trusted source and it matches.
            </label>
          </>
        ) : (
          <div>
            <input
              type="password"
              value={value}
              onChange={(event) => setValue(event.target.value)}
              aria-label={titles[prompt.kind]}
              placeholder={prompt.kind === "passphrase" ? "Key passphrase" : prompt.kind === "sudo" ? "Sudo password" : "Password"}
              autoComplete="off"
              data-autofocus
              className="block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset placeholder:text-slate-400 focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700"
            />
            <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
              Used for this scan only. OpsArmor keeps it in memory until the connection is made and never saves it.
            </p>
          </div>
        )}

        <ErrorMessage error={answer.error} />

        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" variant="secondary" disabled={answer.isPending} onClick={() => answer.mutate({ cancel: true })}>
            {prompt.kind === "sudo" ? "Continue without sudo" : "Cancel scan"}
          </Button>
          <Button
            type="submit"
            loading={answer.isPending}
            disabled={prompt.kind === "host_key" ? !confirmed : value.length === 0}
          >
            {prompt.kind === "host_key" ? "Trust and continue" : "Continue scan"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function capitalize(text: string) {
  return text.charAt(0).toUpperCase() + text.slice(1) + ".";
}
