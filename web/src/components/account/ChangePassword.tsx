import { useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import { api } from "../../api";
import { Button, ErrorMessage, Field } from "../ui";

/** Changes the signed-in account's password; other sessions are signed out. */
export function ChangePassword({ onDone, temporary = false }: { onDone: () => void; temporary?: boolean }) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [mismatch, setMismatch] = useState(false);
  const change = useMutation({
    mutationFn: () => api.changePassword(current, next),
    onSuccess: () => {
      setCurrent("");
      setNext("");
      setRepeat("");
      onDone();
    },
  });

  function submit(event: FormEvent) {
    event.preventDefault();
    setMismatch(next !== repeat);
    if (next === repeat) change.mutate();
  }

  return (
    <form className="max-w-sm space-y-4" onSubmit={submit}>
      <Field
        label={temporary ? "Temporary password" : "Current password"}
        type="password"
        autoComplete="current-password"
        required
        value={current}
        onChange={(event) => setCurrent(event.target.value)}
      />
      <Field
        label="New password"
        type="password"
        autoComplete="new-password"
        hint="At least 12 characters."
        required
        minLength={12}
        value={next}
        onChange={(event) => setNext(event.target.value)}
      />
      <Field label="Repeat the new password" type="password" autoComplete="new-password" required value={repeat} onChange={(event) => setRepeat(event.target.value)} />
      <ErrorMessage error={mismatch ? "The new passwords do not match." : change.error} />
      <Button type="submit" loading={change.isPending}>
        Change password
      </Button>
      <p className="text-xs text-slate-500 dark:text-slate-400">Your other sessions are signed out.</p>
    </form>
  );
}
