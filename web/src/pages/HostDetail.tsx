import { useState } from "react";
import { Link, useNavigate, useParams, useSearchParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, FileText, Play, ShieldCheck, TerminalSquare, Trash2, XCircle } from "lucide-react";
import { api, type CheckId, type Host, type HostDetail as HostDetailData, type Scan } from "../api";
import { CheckResultView } from "../components/CheckResultView";
import { ScanConsole } from "../components/ScanConsole";
import { ScanDialog } from "../components/ScanDialog";
import {
  Button,
  Card,
  CardHeader,
  Dialog,
  EmptyState,
  ErrorMessage,
  Loading,
  PageHeader,
  SeverityCountsInline,
  StatusBadge,
  Table,
  Td,
  Th,
  cx,
} from "../components/ui";
import { checkBadgeText, checkMeta, checkOrder, topSeverity } from "../lib/checks";
import { useRefreshAll } from "../lib/hooks";
import { ReportBody } from "./ScanReport";
import { connectionLabel } from "../lib/hosts";
import { dateTime, isActive, severityStyle, timeAgo } from "../lib/format";

export function HostDetail() {
  const { hostId = "" } = useParams();
  const [removing, setRemoving] = useState(false);
  const [scanning, setScanning] = useState<{ initial?: CheckId[] } | null>(null);
  const [logScan, setLogScan] = useState<Scan | null>(null);
  const [deleting, setDeleting] = useState<Scan | null>(null);
  const { data, error, isPending } = useQuery({
    queryKey: ["host", hostId],
    queryFn: () => api.host(hostId),
    refetchInterval: (query) => (isActive(query.state.data?.last_scan?.status) ? 2000 : false),
  });

  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;

  const running = isActive(data.last_scan?.status);
  return (
    <>
      <Link
        to="/hosts"
        className="mb-4 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100"
      >
        <ArrowLeft className="size-4" /> Hosts
      </Link>
      <PageHeader
        title={data.address}
        description={
          <>
            {connectionLabel(data)}
            <SudoToggle host={data} />
          </>
        }
        action={
          <>
            <Button variant="secondary" onClick={() => setRemoving(true)}>
              <Trash2 className="size-4" /> Remove
            </Button>
            <Button loading={running} onClick={() => setScanning({})}>
              {!running && <Play className="size-4" />}
              {data.last_scan?.status.startsWith("needs_") ? "Waiting for input…" : running ? "Scanning…" : "Scan now"}
            </Button>
          </>
        }
      />

      {data.last_scan?.status === "failed" && (
        <Card className="mb-6 border-l-4 border-red-500">
          <div className="flex gap-3 p-5">
            <XCircle className="mt-0.5 size-5 shrink-0 text-red-600" aria-hidden />
            <div className="min-w-0">
              <h2 className="font-semibold">The last scan failed</h2>
              <p className="mt-1 text-sm break-words text-slate-600 dark:text-slate-300">{data.last_scan.error}</p>
              <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">
                A failed scan is not a clean result. Earlier successful results are shown below.
              </p>
            </div>
          </div>
        </Card>
      )}

      <Results host={data} onRun={(check) => setScanning({ initial: [check] })} />

      <Card className="mt-6">
        <CardHeader
          title="Scan history"
          description="The 10 most recent scans are kept, plus any older scan that still holds a check's latest result."
        />
        {data.scans.length === 0 ? (
          <EmptyState
            icon={<FileText className="size-6" />}
            title="No scans yet"
            description="Start a scan and choose which checks to run."
          />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Started</Th>
                <Th>Status</Th>
                <Th>Checks</Th>
                <Th>Vulnerabilities</Th>
                <Th>
                  <span className="sr-only">Log</span>
                </Th>
                <Th>
                  <span className="sr-only">Report</span>
                </Th>
                <Th>
                  <span className="sr-only">Delete</span>
                </Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.scans.map((scan) => (
                <tr key={scan.id}>
                  <Td className="whitespace-nowrap">
                    {dateTime(scan.started_at)}
                    <p className="text-xs text-slate-500 dark:text-slate-400">{timeAgo(scan.started_at)}</p>
                  </Td>
                  <Td>
                    <StatusBadge status={scan.status} />
                  </Td>
                  <Td className="text-xs text-slate-600 dark:text-slate-300">
                    {scan.checks.map((check) => checkMeta[check]?.short ?? check).join(", ")}
                  </Td>
                  <Td>
                    {scan.status !== "succeeded" ? (
                      <span className="line-clamp-2 max-w-sm text-xs text-slate-500 dark:text-slate-400">{scan.error}</span>
                    ) : scan.checks.includes("packages") ? (
                      <SeverityCountsInline counts={scan.severity} />
                    ) : (
                      <span className="text-xs text-slate-500 dark:text-slate-400">Not checked</span>
                    )}
                  </Td>
                  <Td className="text-right">
                    {(scan.has_log || isActive(scan.status)) && (
                      <button
                        type="button"
                        onClick={() => setLogScan(scan)}
                        className="inline-flex items-center gap-1 text-sm font-semibold whitespace-nowrap text-slate-600 hover:text-indigo-600 dark:text-slate-300 dark:hover:text-indigo-400"
                      >
                        <TerminalSquare className="size-4" /> {isActive(scan.status) ? "Watch live" : "View logs"}
                      </button>
                    )}
                  </Td>
                  <Td className="text-right">
                    {scan.status === "succeeded" && (
                      <Link
                        to={`/scans/${scan.id}`}
                        className="text-sm font-semibold whitespace-nowrap text-indigo-600 hover:text-indigo-500 dark:text-indigo-400"
                      >
                        View report
                      </Link>
                    )}
                  </Td>
                  <Td className="w-px pl-0 text-right">
                    <Button
                      variant="ghost"
                      className="px-2"
                      disabled={isActive(scan.status)}
                      title={isActive(scan.status) ? "A running scan cannot be deleted" : "Delete this scan"}
                      aria-label={`Delete the scan from ${dateTime(scan.started_at)}`}
                      onClick={() => setDeleting(scan)}
                    >
                      <Trash2 className="size-4" />
                    </Button>
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>

      <ScanDialog host={data} open={scanning !== null} initial={scanning?.initial} onClose={() => setScanning(null)} />
      <ScanConsole host={data} requested={logScan} onRequestClosed={() => setLogScan(null)} />
      <RemoveHostDialog host={data} open={removing} onClose={() => setRemoving(false)} />
      <DeleteScanDialog
        scan={deleting}
        onClose={() => setDeleting(null)}
        onDeleted={(scan) => {
          if (logScan?.id === scan.id) setLogScan(null);
          setDeleting(null);
        }}
      />
    </>
  );
}

function SudoToggle({ host }: { host: Host }) {
  const refresh = useRefreshAll();
  const update = useMutation({ mutationFn: (allow: boolean) => api.setAllowSudo(host.id, allow), onSuccess: refresh });
  return (
    <span className="mt-2 flex items-center gap-2">
      <button
        type="button"
        role="switch"
        aria-checked={host.allow_sudo}
        disabled={update.isPending}
        onClick={() => update.mutate(!host.allow_sudo)}
        className={cx(
          "relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors disabled:opacity-60",
          host.allow_sudo ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-700",
        )}
      >
        <span className={cx("inline-block size-4 rounded-full bg-white shadow transition-transform", host.allow_sudo ? "translate-x-4.5" : "translate-x-0.5")} />
      </button>
      <ShieldCheck className="size-4" aria-hidden />
      <span>
        {host.allow_sudo
          ? "OpsArmor may use sudo on this host for deeper checks"
          : "Use sudo for deeper checks: off · turn on to let checks read protected files and all processes"}
      </span>
      {update.error && <span className="text-red-600">{update.error.message}</span>}
    </span>
  );
}

/** One tab per check, each showing that check's newest successful result on this host. */
function Results({ host, onRun }: { host: HostDetailData; onRun: (check: CheckId) => void }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const requested = searchParams.get("tab") as CheckId | null;
  const active: CheckId = requested && checkOrder.includes(requested) ? requested : "packages";
  const checks = host.checks ?? {};

  return (
    <section>
      <div className="mb-4 flex gap-1 overflow-x-auto border-b border-slate-200 dark:border-slate-800" role="tablist">
        {checkOrder.map((check) => {
          const Icon = checkMeta[check].icon;
          const summary = checks[check];
          const severity = summary ? topSeverity(summary.severity) : undefined;
          return (
            <button
              key={check}
              type="button"
              role="tab"
              aria-selected={active === check}
              onClick={() => setSearchParams(check === "packages" ? {} : { tab: check }, { replace: true })}
              className={cx(
                "-mb-px flex items-center gap-2 border-b-2 px-3 py-2.5 text-sm font-medium whitespace-nowrap transition-colors",
                active === check
                  ? "border-indigo-600 text-indigo-700 dark:border-indigo-400 dark:text-indigo-300"
                  : "border-transparent text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100",
              )}
            >
              <Icon className="size-4" />
              {checkMeta[check].label}
              {summary ? (
                <span
                  className={cx(
                    "rounded-full px-1.5 text-xs font-semibold tabular-nums",
                    summary.status === "skipped" || summary.status === "failed"
                      ? "bg-slate-100 font-normal text-slate-500 dark:bg-slate-800 dark:text-slate-400"
                      : summary.finding_count === 0
                        ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-500/15 dark:text-emerald-300"
                        : severity
                          ? severityStyle[severity].badge
                          : "bg-slate-100 text-slate-700",
                  )}
                >
                  {checkBadgeText(summary)}
                </span>
              ) : (
                <span className="text-xs text-slate-400">–</span>
              )}
            </button>
          );
        })}
      </div>
      <CheckTab host={host} check={active} onRun={onRun} />
    </section>
  );
}

/** Turns on the host's sudo setting and reruns one check in a single step. */
function RescanWithSudo({ host, check }: { host: Host; check: CheckId }) {
  const refresh = useRefreshAll();
  const rescan = useMutation({
    mutationFn: async () => {
      await api.setAllowSudo(host.id, true);
      return api.startScan(host.id, [check]);
    },
    onSettled: refresh,
  });
  return (
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-900 ring-1 ring-amber-600/20 ring-inset dark:bg-amber-500/10 dark:text-amber-200">
      <p className="flex gap-2">
        <ShieldCheck className="mt-0.5 size-4 shrink-0" aria-hidden />
        This check ran without sudo, so it only saw part of the system.
      </p>
      <div className="flex items-center gap-2">
        {rescan.error && <span className="text-red-600">{rescan.error.message}</span>}
        <Button loading={rescan.isPending} onClick={() => rescan.mutate()}>
          Turn on sudo and scan again
        </Button>
      </div>
    </div>
  );
}

function CheckTab({ host, check, onRun }: { host: HostDetailData; check: CheckId; onRun: (check: CheckId) => void }) {
  const summary = host.checks?.[check];
  const scanId = check === "packages" ? host.last_report?.id : summary?.scan_id;
  const { data, error, isPending } = useQuery({
    queryKey: ["scan", scanId],
    queryFn: () => api.scan(scanId!),
    enabled: Boolean(scanId),
  });
  const Icon = checkMeta[check].icon;

  if (!scanId) {
    return (
      <Card>
        <EmptyState
          icon={<Icon className="size-6" />}
          title={`${checkMeta[check].label} has not been checked yet`}
          description="Run a scan that includes this check to see results here."
          action={
            <Button onClick={() => onRun(check)}>
              <Play className="size-4" /> Run this check
            </Button>
          }
        />
      </Card>
    );
  }
  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;
  if (!data.report) return null;

  const scannedAt = check === "packages" ? host.last_report?.finished_at : summary?.scanned_at;
  const result = check === "packages" ? undefined : data.report.check_results?.[check];
  return (
    <div>
      <p className="mb-3 text-sm text-slate-500 dark:text-slate-400">
        From the latest scan that included this check ·{" "}
        <Link to={`/scans/${scanId}`} className="hover:underline">
          {dateTime(scannedAt)} ({timeAgo(scannedAt)})
        </Link>
      </p>
      {result && !result.privileged && result.status !== "skipped" && !host.allow_sudo && (
        <RescanWithSudo host={host} check={check} />
      )}
      {check === "packages" ? (
        <ReportBody report={data.report} />
      ) : data.report.check_results?.[check] ? (
        <CheckResultView check={check} name={checkMeta[check].label} result={data.report.check_results[check]} />
      ) : (
        <ErrorMessage error="This scan has no result for the check." />
      )}
    </div>
  );
}

function DeleteScanDialog({ scan, onClose, onDeleted }: { scan: Scan | null; onClose: () => void; onDeleted: (scan: Scan) => void }) {
  const refresh = useRefreshAll();
  const remove = useMutation({
    mutationFn: (target: Scan) => api.deleteScan(target.id),
    onSuccess: (_, target) => {
      refresh();
      onDeleted(target);
    },
  });
  return (
    <Dialog open={scan !== null} onClose={onClose} title="Delete scan">
      {scan && (
        <>
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Delete the scan from <span className="font-semibold">{dateTime(scan.started_at)}</span> (
            {scan.checks.map((check) => checkMeta[check]?.label ?? check).join(", ")})? Its results and activity log are removed
            permanently. If it held a check's latest result, that tab shows the previous result for the check instead.
          </p>
          <div className="mt-4">
            <ErrorMessage error={remove.error} />
          </div>
          <div className="mt-4 flex justify-end gap-2">
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate(scan)}>
              Delete scan
            </Button>
          </div>
        </>
      )}
    </Dialog>
  );
}

export function RemoveHostDialog({ host, open, onClose }: { host: Host; open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const refresh = useRefreshAll();
  const remove = useMutation({
    mutationFn: () => api.removeHost(host.id),
    onSuccess: () => {
      refresh();
      navigate("/hosts");
    },
  });
  return (
    <Dialog open={open} onClose={onClose} title="Remove host">
      <p className="text-sm text-slate-600 dark:text-slate-300">
        Remove <span className="font-semibold">{host.address}</span> from OpsArmor? It will no longer appear on the dashboard. Earlier
        reports stay stored and can still be opened with the CLI.
      </p>
      <div className="mt-4">
        <ErrorMessage error={remove.error} />
      </div>
      <div className="mt-4 flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
          Remove host
        </Button>
      </div>
    </Dialog>
  );
}
