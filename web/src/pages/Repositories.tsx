import { useEffect, useMemo, useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, Eye, FolderGit2, Pencil, Play, RefreshCw, Search, Trash2 } from "lucide-react";
import { api, type RegistryLogin, type RepositoryWatch } from "../api";
import { Button, Card, CardHeader, Dialog, ErrorMessage, Field, Loading, Table, Td, Th } from "../components/ui";
import { timeAgo } from "../lib/format";
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
                  <div className="font-mono text-sm font-medium break-all">
                    {watch.registry}/{watch.repository}
                  </div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    {watch.platform} · {watch.images} {watch.images === 1 ? "image" : "images"} added
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
        <Field label="Repository" value={typed} onChange={(event) => setTyped(event.target.value)} placeholder="team/app" data-autofocus={!listing.data.listed} />
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
      <label className="relative block">
        <Search className="pointer-events-none absolute top-2.5 left-3 size-4 text-slate-400" aria-hidden />
        <input
          value={filter}
          onChange={(event) => setFilter(event.target.value)}
          placeholder={`Filter ${listing.data.repositories.length} repositories`}
          aria-label="Filter repositories"
          data-autofocus
          className="block w-full rounded-lg border-0 bg-white py-2 pr-3 pl-9 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
        />
      </label>
      <ul className="max-h-96 divide-y divide-slate-100 overflow-y-auto rounded-lg ring-1 ring-slate-200 dark:divide-slate-800 dark:ring-slate-800">
        {shown.map((name) => (
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
  const [keep, setKeep] = useState(5);
  const [platform, setPlatform] = useState(platforms[0]);
  const settled = useSettled(pattern);
  const tags = useQuery({
    queryKey: ["browse", login.id, repository, settled],
    queryFn: () => api.browseTags(login.id, repository, settled),
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
    mutationFn: () => api.addRepositoryWatch({ registry: login.registry, repository, tag_pattern: pattern, platform, keep }),
    onSuccess: () => {
      refresh();
      onDone();
    },
  });
  const matched = tags.data?.tags.filter((tag) => tag.matches) ?? [];
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
          <div className="grid gap-3 sm:grid-cols-[1fr_auto_auto]">
            <Field
              label="Tag pattern"
              value={pattern}
              onChange={(event) => setPattern(event.target.value)}
              placeholder="empty: every tag"
              hint="A regular expression. ^ and $ anchor it to the whole tag."
              className="font-mono"
            />
            <Field label="Keep the newest" type="number" min={1} max={20} value={keep} onChange={(event) => setKeep(Number(event.target.value) || 1)} />
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
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-sm" role="status">
              {tags.error ? (
                <span className="text-red-700 dark:text-red-400">{tags.error.message}</span>
              ) : tags.data ? (
                <>
                  <span className="font-medium">{tags.data.matched}</span> of {tags.data.tags.length} tags match
                  {matched.length > 0 && (
                    <span className="text-slate-500 dark:text-slate-400">
                      ; the first check scans the newest {Math.min(keep, matched.length)}: {matched.slice(0, Math.min(keep, 3)).map((tag) => tag.tag).join(", ")}
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
          This registry doesn't say when each tag was pushed, so tags are listed by version, newest first. A watch counts a tag that appears later as the newest.
        </p>
      )}
      {tags.isPending ? (
        <Loading />
      ) : tags.data ? (
        <div className="max-h-80 overflow-y-auto rounded-lg ring-1 ring-slate-200 dark:ring-slate-800">
          <Table>
            <thead>
              <tr>
                <Th>Tag</Th>
                <Th>Pushed</Th>
                {canOperate && <Th className="text-right">Scan once</Th>}
              </tr>
            </thead>
            <tbody>
              {tags.data.tags.map((tag) => (
                <tr key={tag.tag}>
                  <Td className={`font-mono text-sm break-all ${tag.matches ? "" : "text-slate-400 dark:text-slate-500"}`}>
                    {tag.tag}
                    {tag.matches && pattern && <span className="ml-2 rounded bg-indigo-50 px-1.5 py-0.5 font-sans text-xs text-indigo-700 dark:bg-indigo-500/15 dark:text-indigo-300">matches</span>}
                  </Td>
                  <Td className="text-xs text-slate-500 dark:text-slate-400">{tag.pushed_at ? timeAgo(tag.pushed_at) : "—"}</Td>
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
      ) : null}
      <ErrorMessage error={scan.error} />
    </div>
  );
}

function EditWatchDialog({ watch, onClose }: { watch: RepositoryWatch; onClose: () => void }) {
  const refresh = useRefreshAll();
  const [pattern, setPattern] = useState(watch.tag_pattern);
  const [keep, setKeep] = useState(watch.keep);
  const save = useMutation({
    mutationFn: () => api.updateRepositoryWatch(watch.id, pattern, keep),
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
          value={pattern}
          onChange={(event) => setPattern(event.target.value)}
          placeholder="empty: every tag"
          hint="A regular expression. Changing it starts the watch afresh: its next check scans the newest matching tags."
          className="font-mono"
          data-autofocus
        />
        <Field label="Keep the newest" type="number" min={1} max={20} value={keep} onChange={(event) => setKeep(Number(event.target.value) || 1)} />
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

function DeleteWatchDialog({ watch, onClose }: { watch: RepositoryWatch; onClose: () => void }) {
  const refresh = useRefreshAll();
  const remove = useMutation({
    mutationFn: () => api.deleteRepositoryWatch(watch.id),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title={`Stop watching ${watch.repository}?`}>
      <p className="text-sm">
        New pushes to <span className="font-mono">{watch.registry}/{watch.repository}</span> won't be scanned any more. The {watch.images} images it added stay, with
        their scans, but aren't rescanned; remove them from the list if you don't need them.
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
