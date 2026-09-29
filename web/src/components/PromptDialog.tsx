import { useState, type FormEvent } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ShieldQuestion } from "lucide-react";
import { api, type Prompt } from "../api";
import { useRefreshAll } from "../lib/hooks";
import { Button, Dialog, ErrorMessage } from "./ui";

/**
 * Shows the sudo password question from a paused scan on every page. The
 * answer goes to that one scan and is never stored. Closing the dialog
 * continues the scan without sudo.
 */
export function PromptDialog() {
  const { data } = useQuery({ queryKey: ["prompts"], queryFn: api.prompts, refetchInterval: 1500 });
  const prompt = data?.[0];
  if (!prompt) return null;
  // A new key per question resets the form, including after a rejected answer.
  return <PromptForm key={`${prompt.scan_id}-${prompt.created_at}`} prompt={prompt} />;
}

function PromptForm({ prompt }: { prompt: Prompt }) {
  const refresh = useRefreshAll();
  const [value, setValue] = useState("");
  const answer = useMutation({
    mutationFn: (reply: { value?: string; cancel?: boolean }) => api.respond(prompt.scan_id, reply),
    onSuccess: () => {
      setValue("");
      refresh();
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    answer.mutate({ value });
  }

  return (
    <Dialog open onClose={() => answer.mutate({ cancel: true })} title="Sudo password">
      <form onSubmit={submit} className="space-y-4">
        <div className="flex gap-3">
          <div className="h-fit rounded-full bg-amber-100 p-2 text-amber-700 dark:bg-amber-500/15 dark:text-amber-300">
            <ShieldQuestion className="size-5" />
          </div>
          <p className="min-w-0 text-sm text-slate-600 dark:text-slate-300">
            Sudo on <span className="font-semibold text-slate-900 dark:text-slate-100">{prompt.address}</span> needs a password. Enter
            the password for <span className="font-semibold text-slate-900 dark:text-slate-100">{prompt.username}</span> so deeper
            checks can read protected files and processes, or continue without sudo.
          </p>
        </div>

        {prompt.retry && <ErrorMessage error={prompt.retry.charAt(0).toUpperCase() + prompt.retry.slice(1) + "."} />}

        <div>
          <input
            type="password"
            value={value}
            onChange={(event) => setValue(event.target.value)}
            aria-label="Sudo password"
            placeholder="Sudo password"
            autoComplete="off"
            data-autofocus
            className="block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset placeholder:text-slate-400 focus:ring-2 focus:ring-indigo-600 focus:outline-none dark:bg-slate-950 dark:ring-slate-700"
          />
          <p className="mt-1.5 text-xs text-slate-500 dark:text-slate-400">
            Used for this scan only. OpsArmor keeps it in memory and never saves it.
          </p>
        </div>

        <ErrorMessage error={answer.error} />

        <div className="flex justify-end gap-2 pt-1">
          <Button type="button" variant="secondary" disabled={answer.isPending} onClick={() => answer.mutate({ cancel: true })}>
            Continue without sudo
          </Button>
          <Button type="submit" loading={answer.isPending} disabled={value.length === 0}>
            Continue scan
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
