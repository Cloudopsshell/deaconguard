import { useState } from "react";
import { Link } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Boxes, CheckCircle2, Eye, Flame, FolderSearch, KeyRound, Pencil, Play, Plug, Plus, Trash2, XCircle } from "lucide-react";
import { api, type RegistryImage, type RegistryLogin, type RegistryLoginCheck, type RegistryLoginInput } from "../api";
import { Button, Card, CardHeader, Dialog, EmptyState, ErrorMessage, Field, Loading, PageHeader, SeverityCountsInline, StatusBadge, Table, Td, Th } from "../components/ui";
import { timeAgo } from "../lib/format";
import { useRefreshAll } from "../lib/hooks";
import { useCan } from "../lib/role";
import { BrowseRegistryDialog, WatchedRepositories } from "./Repositories";

/** The platforms an image can be checked for, as the server accepts them. */
export const platforms = ["linux/amd64", "linux/arm64", "linux/arm/v7", "linux/386", "linux/ppc64le", "linux/s390x"];

/** True while an image's latest scan is waiting or running. */
export function scanning(image?: RegistryImage) {
  return image?.latest?.status === "queued" || image?.latest?.status === "running";
}

/** Images in registries: what DeaconGuard checks, and what it found in each. */
export function Images() {
  const canOperate = useCan("operator");
  const isAdmin = useCan("admin");
  const refresh = useRefreshAll();
  const images = useQuery({
    queryKey: ["images"],
    queryFn: api.images,
    refetchInterval: (query) => ((query.state.data ?? []).some(scanning) ? 3_000 : 30_000),
  });
  const [adding, setAdding] = useState(false);
  const [deleting, setDeleting] = useState<RegistryImage | null>(null);
  const scan = useMutation({ mutationFn: (image: RegistryImage) => api.scanImage(image.id), onSettled: refresh });

  return (
    <>
      <PageHeader
        title="Images"
        description="Check images in your registries for vulnerable packages and libraries. DeaconGuard reads each image's layers as data, the way docker pull downloads them, and never runs it."
        action={
          canOperate && (
            <Button onClick={() => setAdding(true)}>
              <Plus className="size-4" /> Add image
            </Button>
          )
        }
      />
      <ErrorMessage error={scan.error} />
      {images.isPending ? (
        <Loading />
      ) : images.error ? (
        <ErrorMessage error={images.error} />
      ) : images.data.length === 0 ? (
        <Card>
          <EmptyState
            icon={<Boxes className="size-6" />}
            title="No images yet"
            description="Add an image by its name, such as nginx:1.27 or ghcr.io/acme/shop:4.2. Private images need a login for their registry, saved under Registry logins."
            action={
              canOperate && (
                <Button onClick={() => setAdding(true)}>
                  <Plus className="size-4" /> Add image
                </Button>
              )
            }
          />
        </Card>
      ) : (
        <Card>
          <Table>
            <thead>
              <tr>
                <Th>Image</Th>
                <Th>Last scan</Th>
                <Th>Vulnerabilities</Th>
                {canOperate && <Th className="text-right">Actions</Th>}
              </tr>
            </thead>
            <tbody>
              {images.data.map((image) => (
                <tr key={image.id}>
                  <Td className="min-w-44">
                    <Link to={`/images/${image.id}`} className="font-mono text-sm font-medium break-all text-indigo-700 hover:underline dark:text-indigo-400">
                      {image.reference}
                    </Link>
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      {image.platform}
                      {image.latest?.os && ` · ${image.latest.os}`}
                    </div>
                    <WatchState image={image} />
                    {image.repository_watch_id && <div className="text-xs text-slate-500 dark:text-slate-400">Added by a watched repository</div>}
                  </Td>
                  <Td>
                    {image.latest ? (
                      <div className="space-y-1">
                        <StatusBadge status={image.latest.status} />
                        <div className="text-xs text-slate-500 dark:text-slate-400">{timeAgo(image.latest.finished_at || image.latest.started_at)}</div>
                      </div>
                    ) : (
                      <span className="text-sm text-slate-500 dark:text-slate-400">Not scanned</span>
                    )}
                  </Td>
                  <Td>
                    <ImageCounts image={image} />
                  </Td>
                  {canOperate && (
                    <Td className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          variant="secondary"
                          disabled={scanning(image)}
                          loading={scan.isPending && scan.variables?.id === image.id}
                          onClick={() => scan.mutate(image)}
                        >
                          <Play className="size-4" /> Scan now
                        </Button>
                        <Button variant="secondary" onClick={() => setDeleting(image)} aria-label={`Remove ${image.reference}`}>
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
      )}
      <WatchedRepositories />
      {isAdmin && <RegistryLogins />}
      {adding && <AddImageDialog onClose={() => setAdding(false)} />}
      {deleting && <DeleteImageDialog image={deleting} onClose={() => setDeleting(null)} />}
    </>
  );
}

/** A message shown in two lines, with Show all for the rest, so a long error can be read whole. */
export function ExpandableText({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const long = text.length > 110;
  return (
    <span className="min-w-0 break-words" title={long && !open ? text : undefined}>
      <span className={open || !long ? "" : "line-clamp-2"}>{text}</span>
      {long && (
        <button type="button" onClick={() => setOpen(!open)} className="mt-0.5 block text-xs font-medium underline underline-offset-2 opacity-80 hover:opacity-100">
          {open ? "Show less" : "Show all"}
        </button>
      )}
    </span>
  );
}

/** Whether the server watches the image for new builds, and why the last check failed. */
export function WatchState({ image }: { image: RegistryImage }) {
  if (!image.watch) return null;
  if (image.watch_error)
    return (
      <div className="mt-1 flex items-start gap-1 text-xs text-amber-700 dark:text-amber-400" title={image.watch_error}>
        <AlertTriangle className="mt-px size-3 shrink-0" aria-hidden />
        <ExpandableText text={`Can't check for new builds: ${image.watch_error}`} />
      </div>
    );
  return (
    <div className="mt-1 inline-flex items-center gap-1 text-xs text-emerald-700 dark:text-emerald-400">
      <Eye className="size-3" aria-hidden /> Watching{image.checked_at && `, checked ${timeAgo(image.checked_at)}`}
    </div>
  );
}

/** The latest scan's counts: the last succeeded scan, or why the latest one failed. */
function ImageCounts({ image }: { image: RegistryImage }) {
  const latest = image.latest;
  if (!latest || latest.status === "queued" || latest.status === "running") return <span className="text-sm text-slate-500 dark:text-slate-400">—</span>;
  if (latest.status === "failed")
    return (
      <div className="max-w-72 text-sm text-red-700 dark:text-red-400">
        <ExpandableText text={latest.error ?? ""} />
      </div>
    );
  return (
    <div className="space-y-1">
      <SeverityCountsInline counts={latest.severity} />
      {latest.exploited > 0 && (
        <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 ring-1 ring-red-600/20 ring-inset dark:bg-red-500/15 dark:text-red-300">
          <Flame className="size-3" aria-hidden /> {latest.exploited} exploited
        </span>
      )}
      <div className="text-xs text-slate-500 dark:text-slate-400">{latest.fixable} fixed by a newer image</div>
    </div>
  );
}

function AddImageDialog({ onClose }: { onClose: () => void }) {
  const refresh = useRefreshAll();
  const [reference, setReference] = useState("");
  const [platform, setPlatform] = useState(platforms[0]);
  const [watch, setWatch] = useState(true);
  const add = useMutation({
    mutationFn: () => api.addImage(reference, platform, watch),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title="Add image">
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          add.mutate();
        }}
      >
        <Field
          label="Image"
          value={reference}
          onChange={(event) => setReference(event.target.value)}
          placeholder="ghcr.io/acme/shop:4.2"
          hint="A name with a tag or digest, as in docker pull. Without a registry it is Docker Hub; without a tag, latest."
          required
          data-autofocus
        />
        <label className="block">
          <span className="text-sm font-medium">Platform</span>
          <select
            value={platform}
            onChange={(event) => setPlatform(event.target.value)}
            className="mt-1 block w-full rounded-lg border-0 bg-white px-3 py-2 text-sm shadow-sm ring-1 ring-slate-300 ring-inset focus:ring-2 focus:ring-indigo-600 dark:bg-slate-950 dark:ring-slate-700"
          >
            {platforms.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
          <span className="mt-1 block text-xs text-slate-500 dark:text-slate-400">For images built for several platforms; add the image once per platform you run.</span>
        </label>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            checked={watch}
            onChange={(event) => setWatch(event.target.checked)}
            className="mt-0.5 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
          />
          <span>
            Watch for new builds
            <span className="block text-xs text-slate-500 dark:text-slate-400">
              Every 15 minutes, ask the registry whether the tag points to a new build, and scan it when it does; and scan once a day for newly published
              vulnerabilities.
            </span>
          </span>
        </label>
        <ErrorMessage error={add.error} />
        <div className="flex justify-end gap-2 border-t border-slate-200 pt-4 dark:border-slate-800">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={add.isPending}>
            Add and scan
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

export function DeleteImageDialog({ image, onClose, onDeleted }: { image: RegistryImage; onClose: () => void; onDeleted?: () => void }) {
  const refresh = useRefreshAll();
  const remove = useMutation({
    mutationFn: () => api.deleteImage(image.id),
    onSuccess: () => {
      refresh();
      onClose();
      onDeleted?.();
    },
  });
  return (
    <Dialog open onClose={onClose} title={`Remove ${image.reference}?`}>
      <p className="text-sm text-slate-600 dark:text-slate-300">
        DeaconGuard stops checking it, and its scan results are deleted. The image in the registry is not touched.
      </p>
      <ErrorMessage error={remove.error} />
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
          <Trash2 className="size-4" /> Remove
        </Button>
      </div>
    </Dialog>
  );
}

/** Saved registry logins, for private images. Admins only; secrets are never shown again. */
function RegistryLogins() {
  const logins = useQuery({ queryKey: ["registry-logins"], queryFn: api.registryLogins });
  const [editing, setEditing] = useState<RegistryLogin | "new" | null>(null);
  const [deleting, setDeleting] = useState<RegistryLogin | null>(null);
  const [browsing, setBrowsing] = useState<RegistryLogin | null>(null);
  // Results of checking logins, by login ID, until the page is left.
  const [checks, setChecks] = useState<Record<string, RegistryLoginCheck | "checking">>({});
  const check = async (id: string) => {
    setChecks((current) => ({ ...current, [id]: "checking" }));
    try {
      const result = await api.checkRegistryLogin(id);
      setChecks((current) => ({ ...current, [id]: result }));
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      setChecks((current) => ({ ...current, [id]: { status: "failed", message, checked_at: new Date().toISOString() } }));
    }
  };
  return (
    <div className="mt-6">
      <Card>
        <CardHeader
          title="Registry logins"
          description="For private images, with a read-only token: DeaconGuard only pulls. Browse a login's registry to scan its images or watch a repository for new pushes."
          action={
            <Button variant="secondary" onClick={() => setEditing("new")}>
              <KeyRound className="size-4" /> Add login
            </Button>
          }
        />
        {logins.isPending ? (
          <Loading />
        ) : logins.error ? (
          <div className="p-5">
            <ErrorMessage error={logins.error} />
          </div>
        ) : logins.data.length === 0 ? (
          <p className="px-5 pb-5 text-sm text-slate-500 dark:text-slate-400">No logins saved. Public images need none.</p>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Registry</Th>
                <Th>Login</Th>
                <Th>Updated</Th>
                <Th className="text-right">Actions</Th>
              </tr>
            </thead>
            <tbody>
              {logins.data.map((login) => (
                <tr key={login.id}>
                  <Td className="font-mono text-sm">{login.registry}</Td>
                  <Td>
                    {login.username}
                    {login.kind === "ecr" && <div className="text-xs text-slate-500 dark:text-slate-400">AWS access key</div>}
                    <LoginCheckResult result={checks[login.id]} />
                  </Td>
                  <Td className="text-sm text-slate-500 dark:text-slate-400">{timeAgo(login.updated_at)}</Td>
                  <Td className="text-right">
                    <div className="flex justify-end gap-2">
                      <Button
                        variant="secondary"
                        onClick={() => setBrowsing(login)}
                        aria-label={`Browse ${login.registry}`}
                        title="List this registry's repositories and tags, to scan an image or watch a repository"
                      >
                        <FolderSearch className="size-4" /> Browse
                      </Button>
                      <Button
                        variant="secondary"
                        onClick={() => check(login.id)}
                        loading={checks[login.id] === "checking"}
                        aria-label={`Check the login for ${login.registry}`}
                        title="Log in to the registry now, to see whether it accepts this login"
                      >
                        <Plug className="size-4" /> Check
                      </Button>
                      <Button variant="secondary" onClick={() => setEditing(login)} aria-label={`Edit the login for ${login.registry}`}>
                        <Pencil className="size-4" />
                      </Button>
                      <Button variant="secondary" onClick={() => setDeleting(login)} aria-label={`Delete the login for ${login.registry}`}>
                        <Trash2 className="size-4" />
                      </Button>
                    </div>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
      {editing && <RegistryLoginDialog login={editing === "new" ? null : editing} onClose={() => setEditing(null)} onSaved={(saved) => check(saved.id)} />}
      {deleting && <DeleteLoginDialog login={deleting} onClose={() => setDeleting(null)} />}
      {browsing && <BrowseRegistryDialog login={browsing} onClose={() => setBrowsing(null)} />}
    </div>
  );
}

/** What checking a login found, under the login. */
function LoginCheckResult({ result }: { result?: RegistryLoginCheck | "checking" }) {
  if (!result) return null;
  if (result === "checking") return <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">Checking the login…</div>;
  const style =
    result.status === "ok"
      ? "text-emerald-700 dark:text-emerald-400"
      : result.status === "failed"
        ? "text-rose-700 dark:text-rose-400"
        : "text-amber-700 dark:text-amber-400";
  const Icon = result.status === "ok" ? CheckCircle2 : result.status === "failed" ? XCircle : AlertTriangle;
  const label = result.status === "ok" ? "Works" : result.status === "failed" ? "Doesn't work" : "Couldn't check";
  return (
    <div className={`mt-1 flex max-w-xl items-start gap-1 text-xs ${style}`} role="status">
      <Icon className="mt-0.5 size-3.5 shrink-0" />
      <span>
        <span className="font-medium">{label}:</span> {result.message}{" "}
        <span className="text-slate-500 dark:text-slate-400">· {timeAgo(result.checked_at)}</span>
      </span>
    </div>
  );
}

function RegistryLoginDialog({ login, onClose, onSaved }: { login: RegistryLogin | null; onClose: () => void; onSaved: (login: RegistryLogin) => void }) {
  const refresh = useRefreshAll();
  const [input, setInput] = useState<RegistryLoginInput>({
    registry: login?.registry ?? "",
    kind: login?.kind ?? "basic",
    username: login?.username ?? "",
    secret: "",
  });
  const ecr = input.kind === "ecr";
  const save = useMutation({
    mutationFn: () => (login ? api.updateRegistryLogin(login.id, input) : api.createRegistryLogin(input)),
    onSuccess: (saved) => {
      refresh();
      onClose();
      // Check it at once, so a mistyped key shows here, not at the next scan.
      onSaved(saved);
    },
  });
  return (
    <Dialog open onClose={onClose} title={login ? `Edit the login for ${login.registry}` : "Add registry login"}>
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          save.mutate();
        }}
      >
        <Field
          label="Registry"
          value={input.registry}
          onChange={(event) => setInput({ ...input, registry: event.target.value })}
          placeholder="ghcr.io"
          hint="The registry's host, with its port if it has one: docker.io, ghcr.io, quay.io, registry.example.com:5000, or an ECR registry such as 123456789012.dkr.ecr.eu-north-1.amazonaws.com."
          required
          data-autofocus
        />
        <fieldset>
          <legend className="text-sm font-medium">Login with</legend>
          <div className="mt-2 space-y-1.5">
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" checked={!ecr} onChange={() => setInput({ ...input, kind: "basic" })} className="text-indigo-600 focus:ring-indigo-600" />
              A username and a password or access token
            </label>
            <label className="flex items-center gap-2 text-sm">
              <input type="radio" checked={ecr} onChange={() => setInput({ ...input, kind: "ecr" })} className="text-indigo-600 focus:ring-indigo-600" />
              An AWS access key (Amazon ECR)
            </label>
          </div>
          {ecr && (
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
              DeaconGuard exchanges it for ECR's 12-hour registry password when it needs one. Give the key's user read access only:{" "}
              <span className="font-mono">ecr:GetAuthorizationToken</span>, <span className="font-mono">ecr:BatchGetImage</span> and{" "}
              <span className="font-mono">ecr:GetDownloadUrlForLayer</span> to scan, and <span className="font-mono">ecr:DescribeRepositories</span> and{" "}
              <span className="font-mono">ecr:DescribeImages</span> to browse and watch repositories; or <span className="font-mono">AmazonEC2ContainerRegistryReadOnly</span>.
            </p>
          )}
        </fieldset>
        <Field
          label={ecr ? "Access key ID" : "Username"}
          value={input.username}
          onChange={(event) => setInput({ ...input, username: event.target.value })}
          autoComplete="off"
          required
        />
        <Field
          label={ecr ? "Secret access key" : "Password or access token"}
          type="password"
          value={input.secret}
          onChange={(event) => setInput({ ...input, secret: event.target.value })}
          autoComplete="new-password"
          required={!login}
          hint={
            login
              ? "Leave empty to keep the saved one. Saving checks the login with the registry."
              : "Stored on the server and never shown again. Saving checks the login with the registry."
          }
        />
        <ErrorMessage error={save.error} />
        <div className="flex justify-end gap-2 border-t border-slate-200 pt-4 dark:border-slate-800">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={save.isPending}>
            {login ? "Save" : "Add login"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function DeleteLoginDialog({ login, onClose }: { login: RegistryLogin; onClose: () => void }) {
  const refresh = useRefreshAll();
  const remove = useMutation({
    mutationFn: () => api.deleteRegistryLogin(login.id),
    onSuccess: () => {
      refresh();
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title={`Delete the login for ${login.registry}?`}>
      <p className="text-sm text-slate-600 dark:text-slate-300">Scans of private images in this registry will fail until a login is saved again.</p>
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
