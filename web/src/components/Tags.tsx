import { useState, type FormEvent, type KeyboardEvent } from "react";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Pencil, Tag, X } from "lucide-react";
import { api } from "../api";
import { Button, ErrorMessage, cx } from "./ui";

const tagPattern = /^[a-z0-9][a-z0-9._:/-]{0,39}$/;

/** A host's tags, as small chips. */
export function TagChips({ tags, className }: { tags: string[]; className?: string }) {
  if (tags.length === 0) return null;
  return (
    <span className={cx("flex flex-wrap gap-1", className)}>
      {tags.map((tag) => (
        <span
          key={tag}
          className="inline-flex items-center rounded-md bg-slate-100 px-1.5 py-0.5 text-[11px] font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300"
        >
          {tag}
        </span>
      ))}
    </span>
  );
}

/** Buttons that show only the hosts with one tag. */
export function TagFilter({ tags, selected, onSelect }: { tags: string[]; selected: string; onSelect: (tag: string) => void }) {
  if (tags.length === 0) return null;
  return (
    <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 px-5 py-3 dark:border-slate-800" role="group" aria-label="Filter by tag">
      <Tag className="size-4 text-slate-400" aria-hidden />
      {["", ...tags].map((tag) => (
        <button
          key={tag || "all"}
          type="button"
          aria-pressed={selected === tag}
          onClick={() => onSelect(tag)}
          className={cx(
            "rounded-full px-3 py-1 text-xs font-semibold ring-1 ring-inset transition-colors",
            selected === tag
              ? "bg-slate-900 text-white ring-slate-900 dark:bg-slate-100 dark:text-slate-900 dark:ring-slate-100"
              : "text-slate-600 ring-slate-300 hover:bg-slate-100 dark:text-slate-300 dark:ring-slate-700 dark:hover:bg-slate-800",
          )}
        >
          {tag || "All hosts"}
        </button>
      ))}
    </div>
  );
}

/** A host's tags, which operators and admins can change in place. */
export function TagEditor({ hostId, tags, canEdit }: { hostId: string; tags: string[]; canEdit: boolean }) {
  const queryClient = useQueryClient();
  const [editing, setEditing] = useState(false);
  const [draft, setDraft] = useState<string[]>(tags);
  const [input, setInput] = useState("");
  const [problem, setProblem] = useState("");
  const save = useMutation({
    mutationFn: (next: string[]) => api.setHostTags(hostId, next),
    onSuccess: () => {
      setEditing(false);
      queryClient.invalidateQueries({ queryKey: ["host", hostId] });
      queryClient.invalidateQueries({ queryKey: ["hosts"] });
      queryClient.invalidateQueries({ queryKey: ["tags"] });
      queryClient.invalidateQueries({ queryKey: ["summary"] });
    },
  });

  function start() {
    setDraft(tags);
    setInput("");
    setProblem("");
    save.reset();
    setEditing(true);
  }

  // Adds what is typed so far; returns the tags to save, or null when it isn't a valid tag.
  function add(): string[] | null {
    const value = input.trim().toLowerCase();
    if (!value) return draft;
    if (!tagPattern.test(value)) {
      setProblem("Use 1 to 40 lower-case letters, digits and . _ : / -, starting with a letter or digit, such as prod or team:web.");
      return null;
    }
    setProblem("");
    setInput("");
    const next = draft.includes(value) ? draft : [...draft, value].sort();
    setDraft(next);
    return next;
  }

  function keyDown(event: KeyboardEvent<HTMLInputElement>) {
    if (event.key === "," || (event.key === "Enter" && input.trim())) {
      event.preventDefault();
      add();
    } else if (event.key === "Backspace" && !input && draft.length > 0) {
      setDraft(draft.slice(0, -1));
    }
  }

  function submit(event: FormEvent) {
    event.preventDefault();
    const next = add();
    if (next) save.mutate(next);
  }

  if (!editing) {
    return (
      <div className="flex flex-wrap items-center gap-2">
        {tags.length > 0 ? (
          <TagChips tags={tags} />
        ) : (
          <span className="text-xs text-slate-500 dark:text-slate-400">{canEdit ? "No tags" : ""}</span>
        )}
        {canEdit && (
          <button
            type="button"
            onClick={start}
            className="inline-flex items-center gap-1 text-xs font-semibold text-indigo-600 hover:text-indigo-500 dark:text-indigo-400"
          >
            <Pencil className="size-3" aria-hidden /> {tags.length > 0 ? "Edit tags" : "Add tags"}
          </button>
        )}
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="max-w-xl space-y-2">
      <div className="flex flex-wrap items-center gap-1.5 rounded-lg bg-white px-2 py-1.5 ring-1 ring-slate-300 ring-inset focus-within:ring-2 focus-within:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700">
        {draft.map((tag) => (
          <span
            key={tag}
            className="inline-flex items-center gap-1 rounded-md bg-slate-100 py-0.5 pr-1 pl-1.5 text-xs font-medium text-slate-700 dark:bg-slate-800 dark:text-slate-300"
          >
            {tag}
            <button
              type="button"
              onClick={() => setDraft(draft.filter((item) => item !== tag))}
              aria-label={`Remove tag ${tag}`}
              className="rounded p-0.5 text-slate-400 hover:bg-slate-200 hover:text-slate-700 dark:hover:bg-slate-700 dark:hover:text-slate-200"
            >
              <X className="size-3" />
            </button>
          </span>
        ))}
        <input
          value={input}
          onChange={(event) => setInput(event.target.value)}
          onKeyDown={keyDown}
          aria-label="New tag"
          placeholder={draft.length === 0 ? "prod, web, team:payments…" : "Add a tag"}
          maxLength={40}
          autoFocus
          className="min-w-32 flex-1 border-0 bg-transparent p-1 text-sm focus:ring-0 focus:outline-none"
        />
      </div>
      <p className="text-xs text-slate-500 dark:text-slate-400">Press Enter or a comma after each tag. Up to 20.</p>
      {problem && <p className="text-xs text-red-600 dark:text-red-400">{problem}</p>}
      <ErrorMessage error={save.error} />
      <div className="flex gap-2">
        <Button type="submit" loading={save.isPending}>
          Save tags
        </Button>
        <Button type="button" variant="secondary" onClick={() => setEditing(false)}>
          Cancel
        </Button>
      </div>
    </form>
  );
}
