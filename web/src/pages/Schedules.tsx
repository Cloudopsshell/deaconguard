import { useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, CalendarClock, Pencil, Play, Plus, Trash2 } from "lucide-react";
import { api, type CheckId, type Schedule, type ScheduleInput } from "../api";
import { Button, Card, Dialog, EmptyState, ErrorMessage, Field, Loading, PageHeader, cx } from "../components/ui";
import { checkMeta } from "../lib/checks";
import { dateTime, timeAgo } from "../lib/format";
import { useRefreshAll } from "../lib/hooks";

const dayNames = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
const everyDay = [0, 1, 2, 3, 4, 5, 6];
const weekdays = [1, 2, 3, 4, 5];

/** The checks a schedule can run; the advanced antivirus scan is a level of the antivirus check. */
const scheduleChecks: CheckId[] = ["packages", "integrity", "malware", "config", "antivirus"];

function browserTimezone() {
  try {
    return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC";
  } catch {
    return "UTC";
  }
}

function timezones(current: string) {
  let zones: string[] = [];
  try {
    zones = (Intl as unknown as { supportedValuesOf(key: string): string[] }).supportedValuesOf("timeZone");
  } catch {
    // Older browsers list no zones; the current one and UTC remain.
  }
  return [...new Set(["UTC", current, ...zones])];
}

/** When the next run is, in words and in the viewer's time. */
function untilText(iso: string) {
  const minutes = Math.round((new Date(iso).getTime() - Date.now()) / 60_000);
  if (minutes <= 1) return "due now";
  if (minutes < 60) return `in ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `in ${hours} h`;
  return `in ${Math.round(hours / 24)} days`;
}

/** Scheduled scans: which hosts, which checks, and when. */
export function Schedules() {
  const refresh = useRefreshAll();
  const schedules = useQuery({ queryKey: ["schedules"], queryFn: api.schedules, refetchInterval: 30_000 });
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: api.hosts });
  const [editing, setEditing] = useState<Schedule | "new" | null>(null);
  const [deleting, setDeleting] = useState<Schedule | null>(null);
  const [ran, setRan] = useState<{ id: string; text: string } | null>(null);
  const toggle = useMutation({
    mutationFn: (schedule: Schedule) => api.updateSchedule(schedule.id, { ...schedule, enabled: !schedule.enabled }),
    onSettled: refresh,
  });
  const run = useMutation({
    mutationFn: (schedule: Schedule) => api.runSchedule(schedule.id),
    onSuccess: (result, schedule) =>
      setRan({
        id: schedule.id,
        text: `Started ${result.started} scan${result.started === 1 ? "" : "s"}${result.skipped ? `; skipped ${result.skipped}, see Logs` : ""}.`,
      }),
    onSettled: refresh,
  });
  const hostNames = useMemo(() => new Map((hosts.data ?? []).map((host) => [host.id, host.address])), [hosts.data]);

  return (
    <>
      <PageHeader
        title="Schedules"
        description="Scan hosts automatically on chosen days. Scheduled scans run like Scan now, with root privileges unless a schedule turns them off."
        action={
          <Button onClick={() => setEditing("new")}>
            <Plus className="size-4" /> New schedule
          </Button>
        }
      />
      <ErrorMessage error={toggle.error ?? run.error} />
      {schedules.isPending ? (
        <Loading />
      ) : schedules.error ? (
        <ErrorMessage error={schedules.error} />
      ) : schedules.data.length === 0 ? (
        <Card>
          <EmptyState
            icon={<CalendarClock className="size-6" />}
            title="No schedules yet"
            description="Without one, results only update when someone presses Scan now. A nightly scan of all hosts is a good start."
            action={
              <Button onClick={() => setEditing("new")}>
                <Plus className="size-4" /> New schedule
              </Button>
            }
          />
        </Card>
      ) : (
        <div className="space-y-4">
          {schedules.data.map((schedule) => (
            <Card key={schedule.id} className={cx("p-5", !schedule.enabled && "opacity-75")}>
              <div className="flex flex-wrap items-start justify-between gap-4">
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h2 className="text-base font-semibold">{schedule.name}</h2>
                    <span
                      className={cx(
                        "rounded-full px-2 py-0.5 text-xs font-medium ring-1 ring-inset",
                        schedule.enabled
                          ? "bg-emerald-50 text-emerald-700 ring-emerald-600/20 dark:bg-emerald-500/10 dark:text-emerald-300 dark:ring-emerald-400/30"
                          : "bg-slate-100 text-slate-600 ring-slate-500/20 dark:bg-slate-800 dark:text-slate-300",
                      )}
                    >
                      {schedule.enabled ? "On" : "Off"}
                    </span>
                  </div>
                  <p className="mt-1 text-sm text-slate-700 dark:text-slate-200">{schedule.description}</p>
                  <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">
                    {schedule.all_hosts
                      ? "All hosts, including hosts added later"
                      : schedule.host_ids.map((id) => hostNames.get(id) ?? "removed host").join(", ")}
                    {" · "}
                    {schedule.run_as_root ? "with root" : <span className="text-amber-700 dark:text-amber-400">without root: partial coverage</span>}
                    {" · "}
                    {schedule.checks
                      .filter((check) => check !== "antivirus" || !schedule.checks.includes("yara"))
                      .map((check) => (check === "yara" ? "Antivirus (advanced)" : checkMeta[check].label))
                      .join(", ")}
                  </p>
                  <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                    {schedule.enabled && schedule.next_run_at
                      ? `Next run ${dateTime(schedule.next_run_at)} (${untilText(schedule.next_run_at)})`
                      : "Off: it does not run until you turn it on"}
                    {schedule.last_run_at && ` · last ran ${timeAgo(schedule.last_run_at)}`}
                  </p>
                  {ran?.id === schedule.id && <p className="mt-1 text-xs text-emerald-700 dark:text-emerald-400">{ran.text}</p>}
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button variant="secondary" loading={run.isPending && run.variables?.id === schedule.id} onClick={() => run.mutate(schedule)}>
                    <Play className="size-4" /> Run now
                  </Button>
                  <Button variant="secondary" loading={toggle.isPending && toggle.variables?.id === schedule.id} onClick={() => toggle.mutate(schedule)}>
                    {schedule.enabled ? "Turn off" : "Turn on"}
                  </Button>
                  <Button variant="secondary" onClick={() => setEditing(schedule)} aria-label={`Edit ${schedule.name}`}>
                    <Pencil className="size-4" />
                  </Button>
                  <Button variant="secondary" onClick={() => setDeleting(schedule)} aria-label={`Delete ${schedule.name}`}>
                    <Trash2 className="size-4" />
                  </Button>
                </div>
              </div>
            </Card>
          ))}
        </div>
      )}
      {editing && <ScheduleDialog schedule={editing === "new" ? null : editing} onClose={() => setEditing(null)} />}
      {deleting && <DeleteScheduleDialog schedule={deleting} onClose={() => setDeleting(null)} />}
    </>
  );
}

function ScheduleDialog({ schedule, onClose }: { schedule: Schedule | null; onClose: () => void }) {
  const refresh = useRefreshAll();
  const hosts = useQuery({ queryKey: ["hosts"], queryFn: api.hosts });
  const defaultZone = useMemo(browserTimezone, []);
  const [input, setInput] = useState<ScheduleInput>(
    schedule ?? {
      name: "Nightly scan",
      enabled: true,
      checks: ["packages"],
      run_as_root: true,
      all_hosts: true,
      host_ids: [],
      days: everyDay,
      time: "02:00",
      timezone: defaultZone,
    },
  );
  const save = useMutation({
    mutationFn: () => (schedule ? api.updateSchedule(schedule.id, input) : api.createSchedule(input)),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  const zones = useMemo(() => timezones(input.timezone), [input.timezone]);

  function set<K extends keyof ScheduleInput>(key: K, value: ScheduleInput[K]) {
    setInput((current) => ({ ...current, [key]: value }));
  }
  function toggleDay(day: number) {
    set("days", input.days.includes(day) ? input.days.filter((value) => value !== day) : [...input.days, day].sort());
  }
  function toggleCheck(check: CheckId) {
    const without = input.checks.filter((value) => value !== check && !(check === "antivirus" && value === "yara"));
    set("checks", input.checks.includes(check) ? without : [...input.checks, check]);
  }
  function toggleHost(id: string) {
    set("host_ids", input.host_ids.includes(id) ? input.host_ids.filter((value) => value !== id) : [...input.host_ids, id]);
  }
  const advanced = input.checks.includes("yara");
  const sameDays = (a: number[], b: number[]) => a.length === b.length && a.every((day) => b.includes(day));

  return (
    <Dialog open onClose={onClose} title={schedule ? `Edit ${schedule.name}` : "New schedule"}>
      <form
        className="space-y-5"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <Field label="Name" value={input.name} onChange={(event) => set("name", event.target.value)} maxLength={80} required data-autofocus />

        <fieldset>
          <legend className="text-sm font-medium">Days</legend>
          <div className="mt-2 flex flex-wrap gap-1.5">
            {[
              { label: "Every day", days: everyDay },
              { label: "Weekdays", days: weekdays },
            ].map((preset) => (
              <button
                key={preset.label}
                type="button"
                onClick={() => set("days", preset.days)}
                aria-pressed={sameDays(input.days, preset.days)}
                className={cx(
                  "rounded-lg px-2.5 py-1.5 text-xs font-semibold ring-1 ring-inset",
                  sameDays(input.days, preset.days)
                    ? "bg-slate-900 text-white ring-slate-900 dark:bg-slate-100 dark:text-slate-900"
                    : "text-slate-600 ring-slate-300 hover:bg-slate-50 dark:text-slate-300 dark:ring-slate-700 dark:hover:bg-slate-800",
                )}
              >
                {preset.label}
              </button>
            ))}
            <span className="mx-1 w-px self-stretch bg-slate-200 dark:bg-slate-700" />
            {dayNames.map((name, day) => (
              <button
                key={name}
                type="button"
                onClick={() => toggleDay(day)}
                aria-pressed={input.days.includes(day)}
                className={cx(
                  "w-11 rounded-lg py-1.5 text-xs font-semibold ring-1 ring-inset",
                  input.days.includes(day)
                    ? "bg-indigo-600 text-white ring-indigo-600"
                    : "text-slate-600 ring-slate-300 hover:bg-slate-50 dark:text-slate-300 dark:ring-slate-700 dark:hover:bg-slate-800",
                )}
              >
                {name}
              </button>
            ))}
          </div>
        </fieldset>

        <div className="grid gap-3 sm:grid-cols-[8rem_1fr]">
          <Field label="Time" type="time" value={input.time} onChange={(event) => set("time", event.target.value)} required />
          <label className="block">
            <span className="text-sm font-medium">Time zone</span>
            <select
              value={input.timezone}
              onChange={(event) => set("timezone", event.target.value)}
              className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
            >
              {zones.map((zone) => (
                <option key={zone} value={zone}>
                  {zone}
                </option>
              ))}
            </select>
          </label>
        </div>

        <fieldset>
          <legend className="text-sm font-medium">Hosts</legend>
          <div className="mt-2 space-y-2">
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" checked={input.all_hosts} onChange={() => set("all_hosts", true)} className="text-indigo-600 focus:ring-indigo-600" />
              All hosts, including hosts added later
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" checked={!input.all_hosts} onChange={() => set("all_hosts", false)} className="text-indigo-600 focus:ring-indigo-600" />
              Only these hosts
            </label>
            {!input.all_hosts && (
              <div className="ml-6 max-h-40 space-y-1.5 overflow-y-auto rounded-lg p-2 ring-1 ring-slate-200 ring-inset dark:ring-slate-800">
                {(hosts.data ?? []).map((host) => (
                  <label key={host.id} className="flex items-center gap-2 text-sm">
                    <input
                      type="checkbox"
                      checked={input.host_ids.includes(host.id)}
                      onChange={() => toggleHost(host.id)}
                      className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
                    />
                    {host.address}
                  </label>
                ))}
                {hosts.data?.length === 0 && <p className="text-xs text-slate-500">No hosts yet.</p>}
              </div>
            )}
          </div>
        </fieldset>

        <fieldset>
          <legend className="text-sm font-medium">Checks</legend>
          <div className="mt-2 grid gap-1.5 sm:grid-cols-2">
            {scheduleChecks.map((check) => (
              <label key={check} className="flex items-center gap-2 text-sm">
                <input
                  type="checkbox"
                  checked={input.checks.includes(check)}
                  onChange={() => toggleCheck(check)}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
                />
                {checkMeta[check].label}
              </label>
            ))}
          </div>
          {input.checks.includes("antivirus") && (
            <label className="mt-2 ml-6 flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={advanced}
                onChange={() => set("checks", advanced ? input.checks.filter((value) => value !== "yara") : [...input.checks, "yara"])}
                className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
              />
              Advanced antivirus scan (adds YARA rules; agents 0.5.0 or later)
            </label>
          )}
        </fieldset>

        <fieldset>
          <legend className="text-sm font-medium">Privileges</legend>
          <label className="mt-2 flex items-start gap-2 text-sm">
            <input
              type="checkbox"
              checked={input.run_as_root}
              onChange={(event) => set("run_as_root", event.target.checked)}
              className="mt-0.5 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
            />
            <span>
              Run with root privileges (sudo)
              <span className="block text-xs text-slate-500 dark:text-slate-400">
                Every check sees everything: other users' processes, protected files and firewall rules. Agents run as root.
              </span>
            </span>
          </label>
          {!input.run_as_root && (
            <p className="mt-2 flex gap-2 rounded-lg bg-amber-50 px-3 py-2 text-xs text-amber-900 ring-1 ring-amber-600/20 ring-inset dark:bg-amber-500/10 dark:text-amber-200">
              <AlertTriangle className="mt-0.5 size-3.5 shrink-0" aria-hidden />
              Without root, checks cannot see other users' processes, protected files or firewall rules, so results show partial coverage.
            </p>
          )}
        </fieldset>

        <ErrorMessage error={save.error} />
        <div className="flex justify-end gap-2 border-t border-slate-200 pt-4 dark:border-slate-800">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending}>
            {schedule ? "Save" : "Create schedule"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteScheduleDialog({ schedule, onClose }: { schedule: Schedule; onClose: () => void }) {
  const refresh = useRefreshAll();
  const remove = useMutation({
    mutationFn: () => api.deleteSchedule(schedule.id),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title={`Delete ${schedule.name}?`}>
      <p className="text-sm text-slate-600 dark:text-slate-300">
        Its hosts are no longer scanned on this schedule. Scans it already started and their results stay.
      </p>
      <ErrorMessage error={remove.error} />
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
          <Trash2 className="size-4" /> Delete
        </Button>
      </div>
    </Dialog>
  );
}
