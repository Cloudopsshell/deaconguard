import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type UpdateStatus } from "../api";
import { dateTime, timeAgo } from "../lib/format";
import { useCan } from "../lib/role";
import { Card, CardHeader, ErrorMessage, cx } from "./ui";

const upgradeDocs = "https://docs.deaconguard.io/installation/upgrade";

/** What the server last learned about new releases; asked for by admins only. */
function useUpdate() {
  const admin = useCan("admin");
  return useQuery({ queryKey: ["update"], queryFn: api.update, enabled: admin, staleTime: 60 * 60_000, refetchInterval: 6 * 60 * 60_000 });
}

/**
 * Beside the version in the sidebar: a newer release, when there is one,
 * linked to its upgrade notes. Nothing otherwise.
 */
export function UpdateHint() {
  const { data } = useUpdate();
  if (!data?.available || !data.latest) return null;
  return (
    <a
      href={data.notes_url}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1.5 font-sans font-medium text-indigo-600 hover:underline dark:text-indigo-300"
      title={`DeaconGuard ${data.latest} is out; this server runs ${data.current}. Opens what to do when upgrading.`}
    >
      <span className="size-1.5 rounded-full bg-indigo-500 dark:bg-indigo-400" aria-hidden />
      {data.latest} available
    </a>
  );
}

function status(data: UpdateStatus) {
  if (data.managed) {
    return (
      <>
        Turned off in the server's environment (<code className="font-mono text-xs">DEACONGUARD_UPDATE_CHECK=off</code>); remove that to use this
        switch.
      </>
    );
  }
  if (!data.release) return <>This server runs a local build ({data.current}), which isn't compared with releases.</>;
  if (!data.enabled) return <>Off: the server asks nothing, and new releases aren't announced here.</>;
  const checked = data.checked_at && <span title={dateTime(data.checked_at)}>Checked {timeAgo(data.checked_at)}.</span>;
  if (data.available) {
    return (
      <>
        <span className="font-medium text-slate-900 dark:text-slate-100">DeaconGuard {data.latest} is available.</span> This server runs{" "}
        {data.current}.{" "}
        <a className="font-medium text-indigo-600 hover:underline dark:text-indigo-300" href={data.notes_url} target="_blank" rel="noreferrer">
          What to do when upgrading
        </a>
        {" · "}
        <a className="font-medium text-indigo-600 hover:underline dark:text-indigo-300" href={upgradeDocs} target="_blank" rel="noreferrer">
          How to upgrade
        </a>
        {data.error ? <> The last check failed ({data.error}); it's tried again within the hour.</> : checked && <> · {checked}</>}
      </>
    );
  }
  if (data.error) return <>The last check failed: {data.error}. It's tried again within the hour.</>;
  if (data.latest) {
    return (
      <>
        This server runs the newest release, {data.latest === data.current ? data.current : `${data.current} (the newest final release is ${data.latest})`}.{" "}
        {checked}
      </>
    );
  }
  return <>Not checked yet; the first check runs about a minute after the server starts.</>;
}

/** Settings → New versions: the switch for the daily check, and its last result. */
export function UpdateSettings() {
  const queryClient = useQueryClient();
  const admin = useCan("admin");
  const { data, error } = useUpdate();
  const set = useMutation({
    mutationFn: api.setUpdateCheck,
    onSuccess: (update) => {
      queryClient.setQueryData(["update"], update);
      // Turning it on asks straight away; show the answer when it's in.
      if (update.enabled) setTimeout(() => void queryClient.invalidateQueries({ queryKey: ["update"] }), 4000);
    },
  });
  if (!admin) return null;
  if (error) return <ErrorMessage error={error} />;
  if (!data) return null;
  return (
    <Card className="mb-6">
      <CardHeader
        title="New versions"
        description="Once a day the server asks get.deaconguard.io which DeaconGuard release is the newest, and tells admins here and beside the version in the sidebar when this server is behind. The request says nothing about this server: no version, no identifier, no numbers. Nothing is installed by itself."
      />
      <div className="flex flex-wrap items-center justify-between gap-4 px-5 py-4">
        <div className="min-w-0 flex-1">
          <p className="font-medium">Check for new versions</p>
          <p className="text-sm text-slate-500 dark:text-slate-400" role="status">
            {status(data)}
          </p>
        </div>
        <button
          type="button"
          role="switch"
          aria-checked={data.enabled}
          aria-label="Check for new versions"
          disabled={set.isPending || data.managed}
          onClick={() => set.mutate(!data.enabled)}
          className={cx(
            "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-60",
            data.enabled ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-700",
          )}
        >
          <span className={cx("inline-block size-4 rounded-full bg-white shadow transition-transform", data.enabled ? "translate-x-4.5" : "translate-x-0.5")} />
        </button>
      </div>
      {set.error && (
        <div className="px-5 pb-4">
          <ErrorMessage error={set.error} />
        </div>
      )}
    </Card>
  );
}
