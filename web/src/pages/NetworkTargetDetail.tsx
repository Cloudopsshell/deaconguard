import { useState } from "react";
import { Link, useNavigate, useParams } from "react-router";
import { useMutation, useQuery } from "@tanstack/react-query";
import { ArrowLeft, Lock, Pencil, Play, Trash2 } from "lucide-react";
import { api, type NetworkScan } from "../api";
import { Button, Card, CardHeader, Dialog, ErrorMessage, Loading, PageHeader, SeverityBadge, SeverityCountsInline, StatusBadge, Table, Td, Th, cx } from "../components/ui";
import { dateTime, timeAgo } from "../lib/format";
import { useRefreshAll } from "../lib/hooks";
import { useCan } from "../lib/role";
import { NetworkTargetDialog, count, intervalLabel, scanning } from "./Network";

/** One network target: its newest result (hosts, open ports, findings, TLS) and its scan history. */
export function NetworkTargetDetail() {
  const { targetId = "" } = useParams();
  const navigate = useNavigate();
  const isAdmin = useCan("admin");
  const canOperate = useCan("operator");
  const refresh = useRefreshAll();
  const detail = useQuery({
    queryKey: ["network-target", targetId],
    queryFn: () => api.networkTarget(targetId),
    refetchInterval: (query) => (scanning(query.state.data?.target) ? 3_000 : 30_000),
  });
  const [chosen, setChosen] = useState<string | null>(null);
  const [editing, setEditing] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const scan = useMutation({ mutationFn: () => api.scanNetworkTarget(targetId), onSettled: refresh });
  const remove = useMutation({ mutationFn: () => api.deleteNetworkTarget(targetId), onSuccess: () => navigate("/network") });

  const scans = detail.data?.scans ?? [];
  const lastResult = scans.find((item) => item.status === "succeeded");
  const shown = scans.find((item) => item.id === chosen) ?? lastResult;
  const result = useQuery({ queryKey: ["network-scan", shown?.id], queryFn: () => api.networkScan(shown!.id), enabled: !!shown, staleTime: Infinity });

  if (detail.isPending) return <Loading />;
  if (detail.error) return <ErrorMessage error={detail.error} />;
  const { target } = detail.data;
  const latest = target.latest;

  return (
    <>
      <Link to="/network" className="mb-3 inline-flex items-center gap-1 text-sm text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200">
        <ArrowLeft className="size-4" /> Network
      </Link>
      <PageHeader
        title={target.name}
        description={
          <>
            <span className="font-mono break-all">{target.targets.join(", ")}</span> · ports {target.ports || "default"} ·{" "}
            {target.tls ? "TLS checked" : "TLS not checked"} · {intervalLabel(target.interval_hours)}
          </>
        }
        action={
          <div className="flex gap-2">
            {canOperate && (
              <Button disabled={scanning(target)} loading={scan.isPending} onClick={() => scan.mutate()}>
                <Play className="size-4" /> Scan now
              </Button>
            )}
            {isAdmin && (
              <>
                <Button variant="secondary" onClick={() => setEditing(true)} aria-label={`Edit ${target.name}`}>
                  <Pencil className="size-4" />
                </Button>
                <Button variant="secondary" onClick={() => setDeleting(true)} aria-label={`Remove ${target.name}`}>
                  <Trash2 className="size-4" />
                </Button>
              </>
            )}
          </div>
        }
      />
      <ErrorMessage error={scan.error} />
      {latest && latest.status !== "succeeded" && (
        <Card className="mb-4 p-5">
          <div className="flex flex-wrap items-center gap-3">
            <StatusBadge status={latest.status} />
            <span className="text-sm text-slate-600 dark:text-slate-300">
              {latest.status === "failed" ? latest.error : latest.status === "running" ? "Connecting to each address and port." : "Waiting for the scan before it to finish."}
            </span>
          </div>
        </Card>
      )}
      {shown && (result.isPending ? <Loading /> : result.error ? <ErrorMessage error={result.error} /> : result.data && <Result scan={result.data} isLatest={shown.id === lastResult?.id} />)}

      {scans.length > 0 && (
        <div className="mt-6">
          <Card>
            <CardHeader title="Scan history" description="The newest 20 scans. Open one to see what it found." />
            <Table>
              <thead>
                <tr>
                  <Th>Started</Th>
                  <Th>Status</Th>
                  <Th>Found</Th>
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
                    <Td>
                      {item.status === "succeeded" ? (
                        <span className="text-sm">
                          {count(item.hosts, "host")} · {count(item.open_ports, "port")} · <SeverityCountsInline counts={item.severity} />
                        </span>
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
      {editing && <NetworkTargetDialog target={target} onClose={() => setEditing(false)} />}
      {deleting && (
        <Dialog open onClose={() => setDeleting(false)} title={`Remove ${target.name}?`}>
          <p className="text-sm text-slate-600 dark:text-slate-300">It is no longer scanned, and its results are deleted.</p>
          <ErrorMessage error={remove.error} />
          <div className="mt-5 flex justify-end gap-2">
            <Button variant="secondary" onClick={() => setDeleting(false)}>
              Cancel
            </Button>
            <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
              <Trash2 className="size-4" /> Remove
            </Button>
          </div>
        </Dialog>
      )}
    </>
  );
}

function Result({ scan, isLatest }: { scan: NetworkScan; isLatest: boolean }) {
  const result = scan.result;
  if (!result) return null;
  return (
    <div className="space-y-6">
      <Card>
        <CardHeader
          title={isLatest ? "Latest result" : `Result of ${dateTime(scan.started_at)}`}
          description={`${count(result.addresses, "address", "addresses")}, ${count(result.ports, "port")} each · ${count(scan.hosts, "host")} with open ports · scanned ${timeAgo(scan.finished_at)}`}
        />
        {result.findings.length === 0 ? (
          <p className="px-5 pb-5 text-sm text-slate-600 dark:text-slate-300">Nothing exposed that shouldn't be, and no TLS problems.</p>
        ) : (
          <ul className="divide-y divide-slate-200 border-t border-slate-200 dark:divide-slate-800 dark:border-slate-800">
            {result.findings.map((finding) => (
              <li key={finding.rule + finding.title} className="flex gap-3 px-5 py-3">
                <SeverityBadge severity={finding.severity} />
                <div className="min-w-0">
                  <div className="text-sm font-medium break-words">{finding.title}</div>
                  <div className="text-xs text-slate-500 dark:text-slate-400">
                    <span className="font-mono">{finding.rule}</span> · {finding.detail}
                  </div>
                </div>
              </li>
            ))}
          </ul>
        )}
        {(result.notes ?? []).length > 0 && (
          <ul className="space-y-1 border-t border-slate-200 px-5 py-3 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
            {result.notes!.map((note) => (
              <li key={note}>{note}</li>
            ))}
          </ul>
        )}
      </Card>
      <Card>
        <CardHeader title="Open ports" description="What answered, by address." />
        {result.hosts.length === 0 ? (
          <p className="px-5 pb-5 text-sm text-slate-500 dark:text-slate-400">No open ports.</p>
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>Address</Th>
                <Th>Port</Th>
                <Th>Service</Th>
              </tr>
            </thead>
            <tbody>
              {result.hosts.flatMap((host) =>
                host.services.map((service, index) => (
                  <tr key={`${host.address}:${service.port}`}>
                    <Td className="font-mono text-sm">{index === 0 ? (host.name ? `${host.name} (${host.address})` : host.address) : ""}</Td>
                    <Td className="font-mono text-sm">{service.port}/tcp</Td>
                    <Td className="text-sm">
                      <span className="inline-flex items-center gap-1">
                        {service.tls && <Lock className="size-3.5 text-emerald-600" aria-label="TLS" />}
                        {service.name}
                      </span>
                      {service.banner && <div className="font-mono text-xs break-all text-slate-500 dark:text-slate-400">{service.banner}</div>}
                    </Td>
                  </tr>
                )),
              )}
            </tbody>
          </Table>
        )}
      </Card>
      {(result.tls ?? []).length > 0 && (
        <Card>
          <CardHeader title="TLS" description="The certificate and settings of each TLS service." />
          <Table>
            <thead>
              <tr>
                <Th>Service</Th>
                <Th>Certificate</Th>
                <Th>Protocols</Th>
              </tr>
            </thead>
            <tbody>
              {result.tls!.map((info) => (
                <tr key={info.target}>
                  <Td className="font-mono text-sm">{info.target}</Td>
                  <Td className="text-sm">
                    <div>{(info.dns_names ?? []).join(", ") || info.subject}</div>
                    <div className="text-xs text-slate-500 dark:text-slate-400">
                      {info.trusted ? "Trusted" : "Not trusted"} · until {dateTime(info.not_after)}
                    </div>
                  </Td>
                  <Td className="text-sm">{info.protocols.join(", ")}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        </Card>
      )}
    </div>
  );
}
