import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, Eye, EyeOff, Flame, Play, Trash2 } from "lucide-react";
import { api, type ImageScan } from "../api";
import { ContainerFindings } from "../components/ContainersTable";
import { ReleaseBadge } from "../components/ReleaseSupport";
import { Button, Card, CardHeader, ErrorMessage, Loading, PageHeader, SeverityCountsInline, StatusBadge, Table, Td, Th, cx } from "../components/ui";
import { dateTime, timeAgo } from "../lib/format";
import { useRefreshAll } from "../lib/hooks";
import { useCan } from "../lib/role";
import { DeleteImageDialog, WatchState, scanning } from "./Images";

function shortDigest(digest?: string) {
  return digest ? digest.replace("sha256:", "").slice(0, 12) : "—";
}

/** One registry image: what its chosen scan found, and its scan history. */
export function ImageDetail() {
  const { imageId = "" } = useParams();
  const navigate = useNavigate();
  const canOperate = useCan("operator");
  const refresh = useRefreshAll();
  const detail = useQuery({
    queryKey: ["image", imageId],
    queryFn: () => api.image(imageId),
    refetchInterval: (query) => (scanning(query.state.data?.image) ? 3_000 : 30_000),
  });
  const [chosen, setChosen] = useState<string | null>(null);
  const [deleting, setDeleting] = useState(false);
  const scan = useMutation({ mutationFn: () => api.scanImage(imageId), onSettled: refresh });
  const watch = useMutation({ mutationFn: (on: boolean) => api.setImageWatch(imageId, on), onSettled: refresh });

  const scans = detail.data?.scans ?? [];
  const latestResult = scans.find((item) => item.status === "succeeded");
  const shown = scans.find((item) => item.id === chosen) ?? latestResult;
  const result = useQuery({
    queryKey: ["image-scan", shown?.id],
    queryFn: () => api.imageScan(shown!.id),
    enabled: !!shown,
    staleTime: Infinity,
  });

  if (detail.isPending) return <Loading />;
  if (detail.error) return <ErrorMessage error={detail.error} />;
  const { image } = detail.data;
  const latest = image.latest;

  return (
    <>
      <Link to="/images" className="mb-3 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200">
        <ArrowLeft className="size-4" /> Images
      </Link>
      <PageHeader
        title={<span className="font-mono break-all">{image.reference}</span>}
        description={`${image.platform} · added by ${image.created_by} ${timeAgo(image.created_at)}. Read from the registry as data; never run.`}
        action={
          canOperate && (
            <div className="flex gap-2">
              <Button disabled={scanning(image)} loading={scan.isPending} onClick={() => scan.mutate()}>
                <Play className="size-4" /> Scan now
              </Button>
              <Button variant="secondary" loading={watch.isPending} onClick={() => watch.mutate(!image.watch)}>
                {image.watch ? <EyeOff className="size-4" /> : <Eye className="size-4" />} {image.watch ? "Stop watching" : "Watch"}
              </Button>
              <Button variant="secondary" onClick={() => setDeleting(true)} aria-label={`Remove ${image.reference}`}>
                <Trash2 className="size-4" />
              </Button>
            </div>
          )
        }
      />
      <ErrorMessage error={scan.error ?? watch.error} />
      <div className="mb-4 -mt-2">
        {image.watch ? (
          <WatchState image={image} />
        ) : (
          <p className="text-xs text-slate-500 dark:text-slate-400">Not watched: scanned only when someone presses Scan now.</p>
        )}
      </div>
      {latest && latest.status !== "succeeded" && (
        <Card className="mb-4 p-5">
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge status={latest.status} />
            <span className="text-sm text-slate-600 dark:text-slate-300">
              {latest.status === "failed"
                ? latest.error
                : latest.status === "running"
                  ? "Reading the image's layers from the registry. Layers read before are taken from the cache."
                  : "Waiting for the scan before it to finish."}
            </span>
          </div>
        </Card>
      )}

      {!shown ? (
        !latest || latest.status !== "failed" ? null : (
          <p className="text-sm text-slate-500 dark:text-slate-400">No scan of this image has succeeded yet.</p>
        )
      ) : result.isPending ? (
        <Loading />
      ) : result.error ? (
        <ErrorMessage error={result.error} />
      ) : (
        <ScanResult scan={result.data} isLatest={shown.id === latestResult?.id} />
      )}

      {scans.length > 0 && (
        <div className="mt-6">
          <Card>
            <CardHeader title="Scan history" description="The newest 20 scans. Open one to see what it found." />
            <Table>
              <thead>
                <tr>
                  <Th>Started</Th>
                  <Th>Status</Th>
                  <Th>Digest</Th>
                  <Th>Vulnerabilities</Th>
                  <Th>By</Th>
                </tr>
              </thead>
              <tbody>
                {scans.map((item) => (
                  <tr
                    key={item.id}
                    onClick={() => item.status === "succeeded" && setChosen(item.id)}
                    className={cx(
                      item.status === "succeeded" && "cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50",
                      item.id === shown?.id && "bg-indigo-50/60 dark:bg-indigo-500/10",
                    )}
                  >
                    <Td className="text-sm">{dateTime(item.started_at)}</Td>
                    <Td>
                      <StatusBadge status={item.status} />
                    </Td>
                    <Td className="font-mono text-xs">{shortDigest(item.digest)}</Td>
                    <Td>
                      {item.status === "succeeded" ? (
                        <SeverityCountsInline counts={item.severity} />
                      ) : (
                        <span className="text-xs break-words text-slate-500 dark:text-slate-400">{item.error}</span>
                      )}
                    </Td>
                    <Td className="text-sm text-slate-500 dark:text-slate-400">{item.started_by}</Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </Card>
        </div>
      )}
      {deleting && <DeleteImageDialog image={image} onClose={() => setDeleting(false)} onDeleted={() => navigate("/images")} />}
    </>
  );
}

function ScanResult({ scan, isLatest }: { scan: ImageScan; isLatest: boolean }) {
  const result = scan.result;
  if (!result) return null;
  return (
    <Card>
      <CardHeader
        title={isLatest ? "Latest result" : `Result of ${dateTime(scan.started_at)}`}
        description={
          <span className="font-mono text-xs break-all">
            {scan.digest} · scanned {timeAgo(scan.finished_at)}
          </span>
        }
      />
      <div className="space-y-4 px-5 pb-5">
        <div className="grid gap-4 sm:grid-cols-4">
          <div>
            <div className="text-xs text-slate-500 dark:text-slate-400">Operating system</div>
            <div className="text-sm font-medium">{result.os || "None found"}</div>
            <ReleaseBadge lifecycle={result.lifecycle} onlyProblems />
          </div>
          <div>
            <div className="text-xs text-slate-500 dark:text-slate-400">Contents</div>
            <div className="text-sm font-medium">
              {result.packages} packages · {result.libraries} libraries
            </div>
          </div>
          <div>
            <div className="text-xs text-slate-500 dark:text-slate-400">Vulnerabilities</div>
            <SeverityCountsInline counts={scan.severity} />
            {scan.exploited > 0 && (
              <span className="mt-1 inline-flex items-center gap-1 rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 ring-1 ring-red-600/20 ring-inset dark:bg-red-500/15 dark:text-red-300">
                <Flame className="size-3" aria-hidden /> {scan.exploited} exploited
              </span>
            )}
          </div>
          <div>
            <div className="text-xs text-slate-500 dark:text-slate-400">Fixed by a newer image</div>
            <div className="text-sm font-medium">{scan.fixable}</div>
          </div>
        </div>
        <ContainerFindings container={result} emptyText="Nothing in this image has a fix or is known to be exploited." />
      </div>
    </Card>
  );
}
