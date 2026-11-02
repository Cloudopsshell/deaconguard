import { useState } from "react";
import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Bug, FileCheck2, ShieldCheck, Skull } from "lucide-react";
import { api, type CheckId, type ClusterFindings, type NodeVersion } from "../api";
import { Card, CardHeader, EmptyState, ErrorMessage, Loading, SeverityBadge, Table, Td, Th } from "./ui";
import { fixMeta } from "../lib/fixes";
import { normalizeSeverity } from "../lib/format";

/** How many of the cluster's nodes a finding is on, with the nodes when opened. */
function OnNodes({ nodes, of, versions = false }: { nodes: NodeVersion[]; of: number; versions?: boolean }) {
  const [open, setOpen] = useState(false);
  return (
    <div className="text-sm">
      <button type="button" onClick={() => setOpen(!open)} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400" aria-expanded={open}>
        {nodes.length === of && of > 1 ? `all ${of} nodes` : `${nodes.length} of ${of} ${of === 1 ? "node" : "nodes"}`}
      </button>
      {open && (
        <ul className="mt-1 space-y-0.5 text-xs text-slate-600 dark:text-slate-300">
          {nodes.map((node) => (
            <li key={node.host_id}>
              <Link to={`/hosts/${node.host_id}`} className="hover:underline">
                {node.host}
              </Link>
              {versions && node.installed_version && <span className="font-mono text-slate-500 dark:text-slate-400"> {node.installed_version}</span>}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

/** Which of the cluster's nodes the results come from. */
function coverage(data: ClusterFindings, what: string): string {
  const notes = [`${what} on ${data.checked} of ${data.nodes} ${data.nodes === 1 ? "node" : "nodes"}`];
  if (data.excluded > 0) notes.push(`${data.excluded} excluded`);
  return notes.join(" · ");
}

/** The cluster's nodes' vulnerable packages, each once with the nodes it's on. */
export function ClusterVulnerabilities({ hostId }: { hostId: string }) {
  const { data, error, isPending } = useQuery({ queryKey: ["cluster-findings", hostId, "packages"], queryFn: () => api.clusterFindings(hostId, "packages") });
  if (isPending) return <Loading />;
  if (error) return <ErrorMessage error={error} />;
  const items = data.vulnerabilities ?? [];
  const toFix = items.filter((item) => item.fix === "available" || item.fix === "reboot").length;
  return (
    <Card>
      <CardHeader
        title="Vulnerabilities on the nodes"
        description={`Each once, with the nodes it's on: ${items.length} in all, ${toFix} fixed by an update or a restart. ${coverage(data, "Checked")}. Containers' vulnerabilities are on Workloads and Images.`}
      />
      {items.length === 0 ? (
        <EmptyState
          icon={<Bug className="size-6" />}
          title={data.checked === 0 ? "The nodes' packages haven't been checked yet" : "No vulnerable packages on the nodes"}
          description={data.checked === 0 ? "Scan the cluster and its nodes with the Vulnerabilities check." : "Every node's latest scan found none."}
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Package</Th>
              <Th>Vulnerability</Th>
              <Th>Severity</Th>
              <Th>Fix</Th>
              <Th>On</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {items.map((item) => (
              <tr key={`${item.cve}-${item.package}`} className="align-top">
                <Td className="font-medium">{item.package}</Td>
                <Td>
                  {item.url ? (
                    <a href={item.url} target="_blank" rel="noreferrer" className="font-mono text-sm text-indigo-600 hover:underline dark:text-indigo-400">
                      {item.cve}
                    </a>
                  ) : (
                    <span className="font-mono text-sm">{item.cve}</span>
                  )}
                  {item.kev && <span className="ml-2 text-xs font-semibold text-red-700 dark:text-red-300">known exploited</span>}
                  {item.title && <p className="mt-0.5 max-w-md text-xs text-slate-500 dark:text-slate-400">{item.title}</p>}
                </Td>
                <Td>
                  <SeverityBadge severity={normalizeSeverity(item.severity)} />
                </Td>
                <Td className="text-sm">
                  {fixMeta[item.fix]?.label ?? item.fix}
                  {item.fix === "available" && item.fixed_version && (
                    <p className="font-mono text-xs text-slate-500 dark:text-slate-400">{item.fixed_version}</p>
                  )}
                </Td>
                <Td>
                  <OnNodes nodes={item.nodes} of={data.nodes} versions />
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}

/** The cluster's nodes' findings of other checks, each once with the nodes it's on. */
export function ClusterCheckFindings({ hostId, checks, title, empty }: { hostId: string; checks: CheckId[]; title: string; empty: string }) {
  const results = useQuery({
    queryKey: ["cluster-findings", hostId, checks.join(",")],
    queryFn: () => Promise.all(checks.map((check) => api.clusterFindings(hostId, check))),
  });
  if (results.isPending) return <Loading />;
  if (results.error) return <ErrorMessage error={results.error} />;
  const [first] = results.data;
  const findings = results.data.flatMap((data) => data.findings ?? []);
  const checked = Math.max(...results.data.map((data) => data.checked));
  const Icon = checks.includes("integrity") ? FileCheck2 : Skull;
  return (
    <Card>
      <CardHeader title={title} description={`Each once, with the nodes it's on. ${coverage({ ...first, checked }, "Checked")}.`} />
      {findings.length === 0 ? (
        <EmptyState
          icon={checked === 0 ? <Icon className="size-6" /> : <ShieldCheck className="size-6" />}
          title={checked === 0 ? "Not checked on the nodes yet" : empty}
          description={checked === 0 ? "Scan the cluster and its nodes with this check." : "Every node's latest scan found nothing."}
        />
      ) : (
        <Table>
          <thead>
            <tr>
              <Th>Finding</Th>
              <Th>Severity</Th>
              <Th>Where</Th>
              <Th>On</Th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
            {findings.map((item) => (
              <tr key={`${item.rule}-${item.evidence}-${item.title}`} className="align-top">
                <Td className="max-w-lg">
                  <p className="font-medium">{item.title}</p>
                  {item.detail && <p className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{item.detail}</p>}
                  <p className="mt-0.5 font-mono text-xs text-slate-400">{item.rule}</p>
                </Td>
                <Td>
                  <SeverityBadge severity={normalizeSeverity(item.severity)} />
                </Td>
                <Td className="max-w-xs font-mono text-xs break-all text-slate-600 dark:text-slate-300">{item.evidence}</Td>
                <Td>
                  <OnNodes nodes={item.nodes} of={first.nodes} />
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
    </Card>
  );
}
