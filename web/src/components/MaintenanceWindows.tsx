import { useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2, Wrench } from "lucide-react";
import { api, type MaintenanceWindow } from "../api";
import { Button, Card, CardHeader, Dialog, ErrorMessage, Field, cx } from "./ui";
import { TagChips } from "./Tags";
import { dateTime } from "../lib/format";
import { useCan } from "../lib/role";

const statusStyle: Record<MaintenanceWindow["status"], string> = {
  active: "bg-amber-50 text-amber-800 ring-amber-600/20 dark:bg-amber-500/15 dark:text-amber-300 dark:ring-amber-400/30",
  upcoming: "bg-indigo-50 text-indigo-700 ring-indigo-600/20 dark:bg-indigo-500/15 dark:text-indigo-300 dark:ring-indigo-400/30",
  ended: "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-500/10 dark:text-slate-300 dark:ring-slate-400/20",
};

/** A datetime-local value, in the browser's time, for a Date. */
function local(date: Date) {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

/** Maintenance windows: when notifications about hosts are held back, and their scheduled scans can be skipped. */
export function MaintenanceWindows() {
  const canEdit = useCan("operator");
  const queryClient = useQueryClient();
  const { data, error } = useQuery({ queryKey: ["maintenance"], queryFn: api.maintenance, refetchInterval: 60000 });
  const [adding, setAdding] = useState(false);
  const remove = useMutation({
    mutationFn: api.deleteMaintenance,
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["maintenance"] }),
  });
  return (
    <Card className="mt-6">
      <CardHeader
        title="Maintenance windows"
        description="While hosts are patched or restarted, notifications about them are held back, and their scheduled scans can be skipped. A window covers hosts with its tags, or every host."
        action={
          canEdit && (
            <Button variant="secondary" onClick={() => setAdding(true)}>
              <Plus className="size-4" /> Add window
            </Button>
          )
        }
      />
      <ErrorMessage error={error ?? remove.error} />
      {data && data.length === 0 ? (
        <p className="flex items-center gap-2 px-5 py-5 text-sm text-slate-500 dark:text-slate-400">
          <Wrench className="size-4" aria-hidden /> No maintenance windows.
        </p>
      ) : (
        <ul className="divide-y divide-slate-200 dark:divide-slate-800">
          {data?.map((window) => (
            <li key={window.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3.5">
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium">
                  {window.name}
                  <span className={cx("ml-2 rounded-full px-2 py-0.5 text-xs font-medium capitalize ring-1 ring-inset", statusStyle[window.status])}>
                    {window.status}
                  </span>
                </p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  {dateTime(window.starts_at)} to {dateTime(window.ends_at)} · {window.skip_scans ? "skips scheduled scans" : "scans still run"} · by {window.created_by}
                </p>
                {window.tags.length > 0 ? <TagChips tags={window.tags} className="mt-1" /> : <p className="text-xs text-slate-500 dark:text-slate-400">Every host</p>}
              </div>
              {canEdit && window.status !== "ended" && (
                <Button variant="ghost" loading={remove.isPending && remove.variables === window.id} onClick={() => remove.mutate(window.id)} aria-label={`Delete ${window.name}`}>
                  <Trash2 className="size-4" /> {window.status === "active" ? "End now" : "Delete"}
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
      {adding && <AddWindowDialog onClose={() => setAdding(false)} />}
    </Card>
  );
}

function AddWindowDialog({ onClose }: { onClose: () => void }) {
  const queryClient = useQueryClient();
  const start = new Date();
  start.setMinutes(0, 0, 0);
  start.setHours(start.getHours() + 1);
  const [name, setName] = useState("");
  const [tags, setTags] = useState("");
  const [startsAt, setStartsAt] = useState(local(start));
  const [endsAt, setEndsAt] = useState(local(new Date(start.getTime() + 2 * 3600 * 1000)));
  const [skipScans, setSkipScans] = useState(true);
  const add = useMutation({
    mutationFn: () =>
      api.addMaintenance({
        name,
        tags: tags.split(/[,\s]+/).filter(Boolean),
        starts_at: new Date(startsAt).toISOString().replace(/\.\d{3}Z$/, "Z"),
        ends_at: new Date(endsAt).toISOString().replace(/\.\d{3}Z$/, "Z"),
        skip_scans: skipScans,
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["maintenance"] });
      onClose();
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    add.mutate();
  }
  return (
    <Dialog open onClose={onClose} title="Add a maintenance window">
      <form onSubmit={submit} className="space-y-4">
        <Field label="Name" required maxLength={80} value={name} onChange={(event) => setName(event.target.value)} placeholder="Monthly patching" />
        <div className="grid gap-3 sm:grid-cols-2">
          <Field label="Starts" type="datetime-local" required value={startsAt} onChange={(event) => setStartsAt(event.target.value)} />
          <Field label="Ends" type="datetime-local" required value={endsAt} onChange={(event) => setEndsAt(event.target.value)} />
        </div>
        <p className="-mt-2 text-xs text-slate-500 dark:text-slate-400">In your browser's time zone. A window lasts at most 7 days.</p>
        <Field label="Only hosts tagged (optional)" value={tags} onChange={(event) => setTags(event.target.value)} placeholder="prod, team:web" hint="Leave empty for every host." />
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" className="mt-0.5 accent-indigo-600" checked={skipScans} onChange={(event) => setSkipScans(event.target.checked)} />
          <span>
            Skip scheduled scans of these hosts
            <span className="block text-xs text-slate-500 dark:text-slate-400">Scans started by hand still run. The Logs page says which were skipped.</span>
          </span>
        </label>
        <ErrorMessage error={add.error} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={add.isPending}>
            Add window
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
