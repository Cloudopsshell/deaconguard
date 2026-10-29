import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, Bell, BellOff, Eye, Flame, FolderGit2, Pencil, Play, RefreshCw, Trash2 } from "lucide-react";
import { api, type NotifyLevel, type RegistryLogin, type RepositoryWatch, type RepositoryWatchSettings, type WatchBuild } from "../api";
import {
  Button,
  Card,
  CardHeader,
  Dialog,
  ErrorMessage,
  Field,
  Loading,
  PageHeader,
  Pager,
  SearchBox,
  SeverityCountsInline,
  StatusBadge,
  Table,
  Td,
  Th,
  cx,
  usePage,
} from "../components/ui";
import { dateTime, timeAgo } from "../lib/format";
import { useRefreshAll } from "../lib/hooks";
import { useCan } from "../lib/role";
import { ExpandableText, platforms } from "./Images";

/** Ready-made tag patterns: the most common ways teams tag their builds. */
const examplePatterns = [
  { label: "Every tag", pattern: "" },
  { label: "Releases (v1.2.3)", pattern: String.raw`^v?\d+\.\d+\.\d+$` },
  { label: "Main branch builds", pattern: "^main-" },
  { label: "latest", pattern: "^latest$" },
];

/** What each report setting sends. */
export const notifyLevels: { value: NotifyLevel; label: string }[] = [
  { value: "any", label: "Every new push" },
  { value: "low", label: "Pushes with a low vulnerability or worse" },
  { value: "medium", label: "Pushes with a medium vulnerability or worse" },
  { value: "high", label: "Pushes with a high or critical vulnerability" },
  { value: "critical", label: "Pushes with a critical vulnerability" },
  { value: "exploited", label: "Pushes with a known exploited vulnerability" },
  { value: "off", label: "Don't report" },
];

/** A short line of a watch's history and report settings. */
function describeSettings(watch: RepositoryWatch) {
  const level = notifyLevels.find((item) => item.value === watch.notify_level)?.label ?? watch.notify_level;
  return `history of ${watch.history} · reports: ${level.toLowerCase()}`;
}

/** The newest tags a watch rescans, its history, and which pushes it reports where. */
function WatchSettingsFields({ value, onChange }: { value: RepositoryWatchSettings; onChange: (value: RepositoryWatchSettings) => void }) {
  const channels = useQuery({ queryKey: ["report-channels"], queryFn: api.reportChannels });
  const subscribed = (channels.data ?? []).filter((channel) => channel.subscribed);
  const toggle = (id: string, on: boolean) =>
    onChange({ ...value, notify_channels: on ? [...value.notify_channels, id] : value.notify_channels.filter((item) => item !== id) });
  return (
    <div className="space-y-3">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field
          label="Rescan the newest"
          type="number"
          min={1}
          max={20}
          value={value.keep}
          onChange={(event) => onChange({ ...value, keep: Number(event.target.value) || 1 })}
          hint="Matching tags, rescanned daily for newly published vulnerabilities."
        />
        <Field
          label="Keep the history of"
          type="number"
          min={value.keep}
          max={500}
          value={value.history}
          onChange={(event) => onChange({ ...value, history: Number(event.target.value) || value.keep })}
          hint="Images, with their scans; older ones are removed. Images you added yourself never are."
        />
      </div>
      <label className="block">
        <span className="text-sm font-medium">Report new pushes</span>
        <select
          value={value.notify_level}
          onChange={(event) => onChange({ ...value, notify_level: event.target.value as NotifyLevel })}
          className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
        >
          {notifyLevels.map((level) => (
            <option key={level.value} value={level.value}>
              {level.label}
            </option>
          ))}
        </select>
        <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">
          Each scan of a new push sends its counts, what changed since the previous build, and the most urgent vulnerabilities.
        </span>
      </label>
      {value.notify_level !== "off" && channels.data && (
        <fieldset>
          <legend className="text-sm font-medium">Send reports to</legend>
          {subscribed.length === 0 ? (
            <p className="mt-1 text-xs text-amber-700 dark:text-amber-400">
              No notification channel takes Image scan reports yet: an admin turns them on for a channel under Notifications.
            </p>
          ) : (
            <div className="mt-1 space-y-1">
              {subscribed.map((channel) => (
                <label key={channel.id} className="flex items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={value.notify_channels.includes(channel.id)}
                    onChange={(event) => toggle(channel.id, event.target.checked)}
                    className="size-4 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600 dark:border-slate-700"
                  />
                  {channel.name}
                  <span className="text-xs text-slate-500 dark:text-slate-400">
                    {channel.kind}
                    {!channel.enabled && ", turned off"}
                  </span>
                </label>
              ))}
              <p className="text-xs text-slate-500 dark:text-slate-400">
                {value.notify_channels.length === 0 ? "None ticked: every channel that takes Image scan reports." : "Only the ticked channels."}
              </p>
            </div>
          )}
        </fieldset>
      )}
    </div>
  );
}

/** The repositories whose new pushes are scanned. */
export function WatchedRepositories() {
  const canOperate = useCan("operator");
  const refresh = useRefreshAll();
  const watches = useQuery({ queryKey: ["repository-watches"], queryFn: api.repositoryWatches, refetchInterval: 30_000 });
  const [editing, setEditing] = useState<RepositoryWatch | null>(null);
  const [deleting, setDeleting] = useState<RepositoryWatch | null>(null);
  const check = useMutation({ mutationFn: (watch: RepositoryWatch) => api.checkRepositoryWatch(watch.id), onSettled: refresh });
  if (watches.isPending || watches.error || watches.data.length === 0) return null;
  return (
    <div className="mt-6">
      <Card>
        <CardHeader
          title="Watched repositories"
          description="Every 15 minutes, DeaconGuard lists each repository's tags and scans each new or re-pushed image whose tag matches, keeping the newest ones rescanned daily."
        />
        <ErrorMessage error={check.error} />
        <Table>
          <thead>
            <tr>
              <Th>Repository</Th>
              <Th>Tags</Th>
              <Th>Status</Th>
              {canOperate && <Th className="text-right">Actions</Th>}
            </tr>
          </thead>
          <tbody>
            {watches.data.map((watch) => (
              <tr key={watch.id}>
                <Td className="min-w-44">
                  <Link
                    to={`/images/repositories/${watch.id}`}
                    className="font-mono text-sm font-medium break-all text-indigo-700 hover:underline dark:text-indigo-400"
                  >
                    {watch.registry}/{watch.repository}
                  </Link>
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    {watch.platform} · {watch.images} {watch.images === 1 ? "image" : "images"} · {describeSettings(watch)}
                  </div>
                </Td>
                <Td className="text-sm">
                  {watch.tag_pattern ? <code className="rounded bg-slate-100 px-1.5 py-0.5 text-xs dark:bg-slate-800">{watch.tag_pattern}</code> : "Every tag"}
                  <div className="text-xs text-slate-500 dark:text-slate-400">the newest {watch.keep}</div>
                </Td>
                <Td className="text-xs">
                  {watch.watch_error ? (
                    <div className="max-w-72 text-amber-700 dark:text-amber-400">
                      <ExpandableText text={`Can't check for new pushes: ${watch.watch_error}`} />
                    </div>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400">
                      <Eye className="size-3" aria-hidden /> Watching{watch.checked_at ? `, checked ${timeAgo(watch.checked_at)}` : ", first check soon"}
                    </span>
                  )}
                </Td>
                {canOperate && (
                  <Td className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button variant="secondary" loading={check.isPending && check.variables?.id === watch.id} onClick={() => check.mutate(watch)}>
                        <RefreshCw className="size-4" /> Check now
                      </Button>
                      <Button variant="secondary" onClick={() => setEditing(watch)} aria-label={`Change the watch of ${watch.repository}`}>
                        <Pencil className="size-4" />
                      </Button>
                      <Button variant="secondary" onClick={() => setDeleting(watch)} aria-label={`Stop watching ${watch.repository}`}>
                        <Trash2 className="size-4" />
                      </Button>
                    </div>
                  </Td>
                )}
              </tr>
            ))}
          </tbody>
        </Table>
      </Card>
      {editing && <EditWatchDialog watch={editing} onClose={() => setEditing(null)} />}
      {deleting && <DeleteWatchDialog watch={deleting} onClose={() => setDeleting(null)} />}
    </div>
  );
}

/** Browse what a registry login can see: its repositories, then a repository's tags, to scan one or watch the repository. */
export function BrowseRegistryDialog({ login, onClose }: { login: RegistryLogin; onClose: () => void }) {
  const [repository, setRepository] = useState<string | null>(null);
  return (
    <Dialog open onClose={onClose} title={`Browse ${login.registry}`} wide>
      {repository ? (
        <RepositoryTags login={login} repository={repository} onBack={() => setRepository(null)} onDone={onClose} />
      ) : (
        <RepositoryList login={login} onPick={setRepository} />
      )}
    </Dialog>
  );
}

function RepositoryList({ login, onPick }: { login: RegistryLogin; onPick: (repository: string) => void }) {
  const listing = useQuery({ queryKey: ["browse", login.id], queryFn: () => api.browseRepositories(login.id) });
  const [filter, setFilter] = useState("");
  const [typed, setTyped] = useState("");
  const shown = useMemo(
    () => (listing.data?.repositories ?? []).filter((name) => name.toLowerCase().includes(filter.trim().toLowerCase())),
    [listing.data, filter],
  );
  const paging = usePage(shown, 100, filter);
  if (listing.isPending) return <Loading />;
  if (listing.error) return <ErrorMessage error={listing.error} />;
  const typeIn = (
    <form
      className="flex items-end gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        if (typed.trim()) onPick(typed.trim().replace(/^\/+|\/+$/g, ""));
      }}
    >
      <div className="flex-1">
        <Field
          label="Repository"
          value={typed}
          onChange={(event) => setTyped(event.target.value)}
          placeholder="team/app"
          data-autofocus={!listing.data.listed}
        />
      </div>
      <Button type="submit" variant="secondary">
        Show tags
      </Button>
    </form>
  );
  if (!listing.data.listed)
    return (
      <div className="space-y-4">
        <p className="text-sm text-amber-700 dark:text-amber-400">{listing.data.message}</p>
        {typeIn}
      </div>
    );
  return (
    <div className="space-y-4">
      <SearchBox
        value={filter}
        onChange={setFilter}
        placeholder={`Filter ${listing.data.repositories.length.toLocaleString()} repositories`}
        label="Filter repositories"
        autoFocus
      />
      <div className="overflow-hidden rounded-lg ring-1 ring-slate-200 dark:ring-slate-800">
        <ul className="max-h-96 divide-y divide-slate-100 overflow-y-auto dark:divide-slate-800">
          {paging.shown.map((name) => (
            <li key={name}>
              <button
                type="button"
                onClick={() => onPick(name)}
                className="flex w-full items-center gap-2 px-3 py-2 text-left font-mono text-sm hover:bg-slate-50 dark:hover:bg-slate-800/60"
              >
                <FolderGit2 className="size-4 shrink-0 text-slate-400" aria-hidden /> {name}
              </button>
            </li>
          ))}
          {shown.length === 0 && <li className="px-3 py-2 text-sm text-slate-500 dark:text-slate-400">No repository matches.</li>}
        </ul>
        <Pager paging={paging} noun="repositories" />
      </div>
      <details className="text-sm">
        <summary className="cursor-pointer text-slate-500 dark:text-slate-400">Not listed? Type its name</summary>
        <div className="mt-2">{typeIn}</div>
      </details>
    </div>
  );
}

/** Waits a moment after typing stops, so the preview isn't fetched on every key. */
function useSettled<T>(value: T, delay = 400) {
  const [settled, setSettled] = useState(value);
  useEffect(() => {
    const timer = setTimeout(() => setSettled(value), delay);
    return () => clearTimeout(timer);
  }, [value, delay]);
  return settled;
}

function RepositoryTags({ login, repository, onBack, onDone }: { login: RegistryLogin; repository: string; onBack: () => void; onDone: () => void }) {
  const refresh = useRefreshAll();
  const canOperate = useCan("operator");
  const [pattern, setPattern] = useState(examplePatterns[1].pattern);
  const [settings, setSettings] = useState<RepositoryWatchSettings>({ tag_pattern: "", keep: 5, history: 50, notify_level: "any", notify_channels: [] });
  const keep = settings.keep;
  const [platform, setPlatform] = useState(platforms[0]);
  const settled = useSettled(pattern);
  // Operators preview a watch, which orders the matching tags as its first check will.
  const previewPlatform = canOperate ? platform : undefined;
  const tags = useQuery({
    queryKey: ["browse", login.id, repository, settled, previewPlatform],
    queryFn: () => api.browseTags(login.id, repository, settled, previewPlatform),
    placeholderData: (previous) => previous,
    retry: false,
  });
  const [scanned, setScanned] = useState<Record<string, boolean>>({});
  const scan = useMutation({
    mutationFn: (reference: string) => api.addImage(reference, platform, true),
    onSuccess: (_, reference) => {
      setScanned((current) => ({ ...current, [reference]: true }));
      refresh();
    },
  });
  const watch = useMutation({
    mutationFn: () => api.addRepositoryWatch({ ...settings, registry: login.registry, repository, tag_pattern: pattern, platform }),
    onSuccess: () => {
      refresh();
      onDone();
    },
  });
  const matched = tags.data?.tags.filter((tag) => tag.matches) ?? [];
  const tagPaging = usePage(tags.data?.tags ?? [], 100, settled);
  return (
    <div className="space-y-5">
      <button type="button" onClick={onBack} className="inline-flex items-center gap-1 text-sm text-indigo-700 hover:underline dark:text-indigo-400">
        <ArrowLeft className="size-4" /> All repositories
      </button>
      <h3 className="font-mono text-sm font-semibold break-all">
        {login.registry}/{repository}
      </h3>
      {canOperate && (
        <section className="space-y-3 rounded-lg bg-slate-50 p-4 ring-1 ring-slate-200 dark:bg-slate-800/40 dark:ring-slate-700">
          <div>
            <h4 className="text-sm font-semibold">Watch this repository</h4>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Scan each new or re-pushed image whose tag matches, as soon as it appears (checked every 15 minutes), and rescan the newest ones daily.
            </p>
          </div>
          <div className="flex flex-wrap gap-2">
            {examplePatterns.map((example) => (
              <button
                key={example.label}
                type="button"
                onClick={() => setPattern(example.pattern)}
                className={`rounded-full px-2.5 py-1 text-xs ring-1 ring-inset ${pattern === example.pattern ? "bg-indigo-600 text-white ring-indigo-600" : "bg-white ring-slate-300 hover:bg-slate-100 dark:bg-slate-900 dark:ring-slate-700"}`}
              >
                {example.label}
              </button>
            ))}
          </div>
          <div className="grid gap-3 sm:grid-cols-[1fr_auto]">
            <Field
              label="Tag pattern"
              value={pattern}
              onChange={(event) => setPattern(event.target.value)}
              placeholder="empty: every tag"
              hint={
                <>
                  A regular expression, such as <code>^production-</code>. ^ and $ anchor it to the whole tag.{" "}
                  <a href="https://docs.deaconguard.io/usage/images#tag-pattern-examples" target="_blank" rel="noreferrer" className="underline">
                    More examples
                  </a>
                </>
              }
              className="font-mono"
            />
            <label className="block">
              <span className="text-sm font-medium">Platform</span>
              <select
                value={platform}
                onChange={(event) => setPlatform(event.target.value)}
                className="mt-1 block rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
              >
                {platforms.map((value) => (
                  <option key={value}>{value}</option>
                ))}
              </select>
            </label>
          </div>
          <WatchSettingsFields value={settings} onChange={setSettings} />
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm" role="status">
              {tags.error ? (
                <span className="text-red-700 dark:text-red-400">{tags.error.message}</span>
              ) : tags.data ? (
                <>
                  <span className="font-medium">{tags.data.matched}</span> of {tags.data.tags.length} tags match
                  {matched.length > 0 && (
                    <span className="text-slate-500 dark:text-slate-400">
                      ; the first check scans the newest {Math.min(keep, matched.length)}:{" "}
                      {matched
                        .slice(0, Math.min(keep, 3))
                        .map((tag) => tag.tag)
                        .join(", ")}
                      {Math.min(keep, matched.length) > 3 && ", …"}
                    </span>
                  )}
                </>
              ) : (
                "Reading the tags…"
              )}
            </p>
            <Button loading={watch.isPending} disabled={!!tags.error} onClick={() => watch.mutate()}>
              <Eye className="size-4" /> Watch repository
            </Button>
          </div>
          <ErrorMessage error={watch.error} />
        </section>
      )}
      {tags.data && tags.data.tags.length > 0 && !tags.data.tags.some((tag) => tag.pushed_at) && (
        <p className="text-xs text-slate-500 dark:text-slate-400">
          {tags.data.tags.some((tag) => tag.created)
            ? "This registry doesn't say when each tag was pushed, so matching tags are listed by when their image was built, newest first, then by version."
            : "This registry doesn't say when each tag was pushed, so tags are listed by version, newest first."}{" "}
          A watch counts a tag that appears later as the newest.
        </p>
      )}
      {tags.isPending ? (
        <Loading />
      ) : tags.data ? (
        <div className="overflow-hidden rounded-lg ring-1 ring-slate-200 dark:ring-slate-800">
          <div className="max-h-80 overflow-y-auto">
            <Table>
              <thead>
                <tr>
                  <Th>Tag</Th>
                  <Th>Pushed</Th>
                  {canOperate && <Th className="text-right">Scan once</Th>}
                </tr>
              </thead>
              <tbody>
                {tagPaging.shown.map((tag) => (
                  <tr key={tag.tag}>
                    <Td className={`font-mono text-sm break-all ${tag.matches ? "" : "text-slate-400 dark:text-slate-500"}`}>
                      {tag.tag}
                      {tag.matches && pattern && (
                        <span className="ml-2 rounded bg-indigo-50 px-1.5 py-0.5 font-sans text-xs text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300">
                          matches
                        </span>
                      )}
                    </Td>
                    <Td className="text-xs text-slate-500 dark:text-slate-400">
                      {tag.pushed_at ? timeAgo(tag.pushed_at) : tag.created ? <span title="When the image was built">built {timeAgo(tag.created)}</span> : "—"}
                    </Td>
                    {canOperate && (
                      <Td className="text-right">
                        <Button
                          variant="secondary"
                          disabled={scanned[tag.reference]}
                          loading={scan.isPending && scan.variables === tag.reference}
                          onClick={() => scan.mutate(tag.reference)}
                        >
                          <Play className="size-4" /> {scanned[tag.reference] ? "Added" : "Scan"}
                        </Button>
                      </Td>
                    )}
                  </tr>
                ))}
              </tbody>
            </Table>
          </div>
          <Pager paging={tagPaging} noun="tags" />
        </div>
      ) : null}
      <ErrorMessage error={scan.error} />
    </div>
  );
}

function EditWatchDialog({ watch, onClose }: { watch: RepositoryWatch; onClose: () => void }) {
  const refresh = useRefreshAll();
  const [settings, setSettings] = useState<RepositoryWatchSettings>({
    tag_pattern: watch.tag_pattern,
    keep: watch.keep,
    history: watch.history,
    notify_level: watch.notify_level,
    notify_channels: watch.notify_channels,
  });
  const save = useMutation({
    mutationFn: () => api.updateRepositoryWatch(watch.id, settings),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title={`Change the watch of ${watch.repository}`}>
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <Field
          label="Tag pattern"
          value={settings.tag_pattern}
          onChange={(event) => setSettings({ ...settings, tag_pattern: event.target.value })}
          placeholder="empty: every tag"
          hint="A regular expression. Changing it, or how many tags are rescanned, starts the watch afresh: its next check scans the newest matching tags."
          className="font-mono"
          data-autofocus
        />
        <WatchSettingsFields value={settings} onChange={setSettings} />
        <ErrorMessage error={save.error} />
        <div className="flex justify-end gap-2 border-t border-slate-200 pt-4 dark:border-slate-800">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteWatchDialog({ watch, onClose, onDeleted }: { watch: RepositoryWatch; onClose: () => void; onDeleted?: () => void }) {
  const refresh = useRefreshAll();
  const remove = useMutation({
    mutationFn: () => api.deleteRepositoryWatch(watch.id),
    onSuccess: () => {
      refresh();
      onClose();
      onDeleted?.();
    },
  });
  return (
    <Dialog open onClose={onClose} title={`Stop watching ${watch.repository}?`}>
      <p className="text-sm">
        New pushes to{" "}
        <span className="font-mono">
          {watch.registry}/{watch.repository}
        </span>{" "}
        won't be scanned any more. The {watch.images} images it added stay, with their scans, but aren't rescanned; remove them from the list if you don't need
        them.
      </p>
      <ErrorMessage error={remove.error} />
      <div className="mt-4 flex justify-end gap-2 border-t border-slate-200 pt-4 dark:border-slate-800">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
          Stop watching
        </Button>
      </div>
    </Dialog>
  );
}

/** The tag of an image reference: what follows the last colon after the last slash. */
function tagOf(reference: string) {
  const name = reference.slice(reference.lastIndexOf("/") + 1);
  return name.includes(":") ? name.slice(name.indexOf(":") + 1) : reference;
}

/** A watched repository: its builds, newest first, what each one's scan found, and the trend across them. */
export function RepositoryDetail() {
  const { watchId = "" } = useParams();
  const navigate = useNavigate();
  const canOperate = useCan("operator");
  const refresh = useRefreshAll();
  const detail = useQuery({
    queryKey: ["repository-watch", watchId],
    queryFn: () => api.repositoryWatch(watchId),
    refetchInterval: (query) => ((query.state.data?.builds ?? []).some((build) => build.status === "queued" || build.status === "running") ? 3_000 : 30_000),
  });
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [search, setSearch] = useState("");
  const check = useMutation({ mutationFn: () => api.checkRepositoryWatch(watchId), onSettled: refresh });
  const builds = useMemo(
    () => (detail.data?.builds ?? []).filter((build) => build.reference.toLowerCase().includes(search.trim().toLowerCase())),
    [detail.data, search],
  );
  const paging = usePage(builds, 50, search);
  if (detail.isPending) return <Loading />;
  if (detail.error) return <ErrorMessage error={detail.error} />;
  const watch = detail.data;
  return (
    <>
      <Link
        to="/images"
        className="mb-3 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200"
      >
        <ArrowLeft className="size-4" /> Images
      </Link>
      <PageHeader
        title={
          <span className="font-mono break-all">
            {watch.registry}/{watch.repository}
          </span>
        }
        description={`Watched repository · tags ${watch.tag_pattern ? watch.tag_pattern : "of every name"}, the newest ${watch.keep} rescanned · ${watch.platform} · ${describeSettings(watch)}`}
        action={
          canOperate && (
            <div className="flex gap-2">
              <Button loading={check.isPending} onClick={() => check.mutate()}>
                <RefreshCw className="size-4" /> Check now
              </Button>
              <Button variant="secondary" onClick={() => setEditing(true)} aria-label={`Change the watch of ${watch.repository}`}>
                <Pencil className="size-4" />
              </Button>
              <Button variant="secondary" onClick={() => setDeleting(true)} aria-label={`Stop watching ${watch.repository}`}>
                <Trash2 className="size-4" />
              </Button>
            </div>
          )
        }
      />
      <ErrorMessage error={check.error} />
      <div className="-mt-2 mb-4 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs">
        {watch.watch_error ? (
          <div className="max-w-2xl text-amber-700 dark:text-amber-400">
            <ExpandableText text={`Can't check for new pushes: ${watch.watch_error}`} />
          </div>
        ) : (
          <span className="inline-flex items-center gap-1 text-emerald-700 dark:text-emerald-400">
            <Eye className="size-3" aria-hidden /> Watching{watch.checked_at ? `, checked ${timeAgo(watch.checked_at)}` : ", first check soon"}
          </span>
        )}
        <span className="inline-flex items-center gap-1 text-slate-500 dark:text-slate-400">
          {watch.notify_level === "off" ? <BellOff className="size-3" aria-hidden /> : <Bell className="size-3" aria-hidden />}
          {watch.notify_level === "off"
            ? "New pushes aren't reported"
            : `Reports to ${watch.notify_channels.length === 0 ? "every channel that takes Image scan reports" : `${watch.notify_channels.length} chosen channel${watch.notify_channels.length === 1 ? "" : "s"}`}`}
        </span>
      </div>

      <Card className="mb-6 p-5">
        <h2 className="mb-3 text-sm font-semibold">Vulnerabilities by build</h2>
        <BuildsChart builds={watch.builds} />
      </Card>

      <Card>
        <CardHeader
          title="Builds"
          description={`Every scan of the ${watch.images} image${watch.images === 1 ? "" : "s"} this watch added, newest first. Older images beyond the history of ${watch.history} are removed.`}
        />
        {watch.builds.length > 0 && (
          <div className="px-5 pb-3">
            <SearchBox value={search} onChange={setSearch} placeholder="Search by tag" label="Search builds by tag" />
          </div>
        )}
        <Table>
          <thead>
            <tr>
              <Th>Tag</Th>
              <Th>Scanned</Th>
              <Th>Vulnerabilities</Th>
              <Th>Why</Th>
            </tr>
          </thead>
          <tbody>
            {paging.shown.map((build) => (
              <tr key={build.id}>
                <Td className="min-w-36">
                  <Link
                    to={`/images/${build.image_id}`}
                    className="font-mono text-sm font-medium break-all text-indigo-700 hover:underline dark:text-indigo-400"
                  >
                    {tagOf(build.reference)}
                  </Link>
                  <div className="font-mono text-xs text-slate-500 dark:text-slate-400">
                    {build.digest ? build.digest.replace("sha256:", "").slice(0, 12) : "—"}
                  </div>
                  {build.watched && <div className="text-xs text-emerald-700 dark:text-emerald-400">Rescanned daily</div>}
                </Td>
                <Td className="text-sm whitespace-nowrap">
                  <StatusBadge status={build.status} />
                  <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">{dateTime(build.finished_at || build.started_at)}</div>
                </Td>
                <Td>
                  {build.status === "succeeded" ? (
                    <div className="space-y-1">
                      <SeverityCountsInline counts={build.severity} />
                      <div className="flex flex-wrap gap-x-3 text-xs text-slate-500 dark:text-slate-400">
                        {build.exploited > 0 && (
                          <span className="inline-flex items-center gap-1 font-medium text-red-700 dark:text-red-300">
                            <Flame className="size-3" aria-hidden /> {build.exploited} exploited
                          </span>
                        )}
                        <span>{build.fixable} fixed by an update</span>
                      </div>
                    </div>
                  ) : (
                    <span className="text-xs break-words text-slate-500 dark:text-slate-400">{build.error}</span>
                  )}
                </Td>
                <Td className="text-xs text-slate-500 dark:text-slate-400">{build.started_by.replace(/^watch: /, "")}</Td>
              </tr>
            ))}
            {paging.shown.length === 0 && (
              <tr>
                <Td className="text-sm text-slate-500 dark:text-slate-400">
                  {watch.builds.length === 0 ? "No builds yet: the first check adds the newest matching tags." : "No build matches."}
                </Td>
              </tr>
            )}
          </tbody>
        </Table>
        <Pager paging={paging} noun="builds" />
      </Card>
      {editing && <EditWatchDialog watch={watch} onClose={() => setEditing(false)} />}
      {deleting && <DeleteWatchDialog watch={watch} onClose={() => setDeleting(false)} onDeleted={() => navigate("/images")} />}
    </>
  );
}

const buildSeries = [
  { key: "critical", label: "Critical", fill: "fill-red-600", swatch: "bg-red-600" },
  { key: "high", label: "High", fill: "fill-orange-500", swatch: "bg-orange-500" },
  { key: "medium", label: "Medium", fill: "fill-amber-400", swatch: "bg-amber-400" },
  { key: "low", label: "Low", fill: "fill-sky-500", swatch: "bg-sky-500" },
  { key: "unknown", label: "Unrated", fill: "fill-slate-400", swatch: "bg-slate-400" },
] as const;

/** How many builds the chart shows: the newest. */
const chartedBuilds = 50;

/** Each build's vulnerabilities as a stacked bar, oldest on the left, with its latest succeeded scan only. */
function BuildsChart({ builds }: { builds: WatchBuild[] }) {
  const [hover, setHover] = useState<number | null>(null);
  const shown = useMemo(() => {
    const seen = new Set<string>();
    const latest: WatchBuild[] = [];
    for (const build of builds) {
      if (build.status !== "succeeded" || seen.has(build.image_id)) continue;
      seen.add(build.image_id);
      latest.push(build);
    }
    return latest.slice(0, chartedBuilds).reverse();
  }, [builds]);
  if (shown.length === 0)
    return <p className="py-6 text-center text-sm text-slate-500 dark:text-slate-400">No build has been scanned yet. Each new push adds a bar.</p>;
  const total = (build: WatchBuild) => build.severity.critical + build.severity.high + build.severity.medium + build.severity.low + build.severity.unknown;
  const max = Math.max(1, ...shown.map(total));
  const width = 720;
  const height = 180;
  const pad = { top: 10, right: 8, bottom: 8, left: 40 };
  const plotWidth = width - pad.left - pad.right;
  const plotHeight = height - pad.top - pad.bottom;
  const slot = plotWidth / shown.length;
  const bar = Math.max(2, Math.min(36, slot * 0.7));
  const y = (value: number) => pad.top + plotHeight - (value / max) * plotHeight;
  const current = shown[hover ?? shown.length - 1];
  return (
    <div>
      <div className="mb-3 flex flex-wrap items-baseline gap-x-5 gap-y-1 text-sm">
        <span className="font-mono text-slate-500 dark:text-slate-400">{tagOf(current.reference)}</span>
        <span>
          <span className="font-semibold tabular-nums">{total(current).toLocaleString()}</span> vulnerabilities
        </span>
        <span className="text-red-700 dark:text-red-300">
          <span className="font-semibold tabular-nums">{current.exploited.toLocaleString()}</span> known exploited
        </span>
        {buildSeries.map((item) => (
          <span key={item.key} className="inline-flex items-center gap-1.5 text-xs text-slate-600 dark:text-slate-300">
            <span className={cx("size-2.5 rounded-sm", item.swatch)} aria-hidden />
            {item.label} <span className="tabular-nums">{current.severity[item.key].toLocaleString()}</span>
          </span>
        ))}
      </div>
      <svg
        viewBox={`0 0 ${width} ${height}`}
        className="h-auto w-full"
        role="img"
        aria-label={`Vulnerabilities in the last ${shown.length} builds, from ${total(shown[0])} in ${tagOf(shown[0].reference)} to ${total(shown[shown.length - 1])} in ${tagOf(shown[shown.length - 1].reference)}.`}
        onMouseLeave={() => setHover(null)}
        onMouseMove={(event) => {
          const box = event.currentTarget.getBoundingClientRect();
          const position = ((event.clientX - box.left) / box.width) * width;
          setHover(Math.min(shown.length - 1, Math.max(0, Math.floor((position - pad.left) / slot))));
        }}
      >
        {[0, Math.round(max / 2), max].map((tick) => (
          <g key={tick}>
            <line x1={pad.left} x2={width - pad.right} y1={y(tick)} y2={y(tick)} className="stroke-slate-200 dark:stroke-slate-800" />
            <text x={pad.left - 6} y={y(tick) + 4} textAnchor="end" className="fill-slate-500 text-[11px] dark:fill-slate-400">
              {tick.toLocaleString()}
            </text>
          </g>
        ))}
        {shown.map((build, index) => {
          const x = pad.left + index * slot + (slot - bar) / 2;
          let base = 0;
          return (
            <g key={build.id} className={cx(hover !== null && hover !== index && "opacity-50")}>
              {buildSeries.map((item) => {
                const value = build.severity[item.key];
                const top = base + value;
                const rect = value > 0 ? <rect key={item.key} x={x} width={bar} y={y(top)} height={y(base) - y(top)} className={item.fill} /> : null;
                base = top;
                return rect;
              })}
              {total(build) === 0 && <rect x={x} width={bar} y={y(0) - 2} height={2} className="fill-emerald-500" />}
            </g>
          );
        })}
      </svg>
      <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
        The newest {chartedBuilds} builds, oldest on the left, each with its latest scan. A green line is a build with none.
      </p>
    </div>
  );
}
