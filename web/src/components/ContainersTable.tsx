import { useState } from "react";
import { ChevronDown, ChevronRight, Flame, Info } from "lucide-react";
import type { ContainerResult } from "../api";
import { normalizeSeverity, severityOrder } from "../lib/format";
import { ReleaseBadge } from "./ReleaseSupport";
import { Card, CardHeader, ErrorMessage, SeverityBadge, Table, Td, Th } from "./ui";

const runtimeName: Record<string, string> = { docker: "Docker", podman: "Podman", cri: "containerd / CRI-O" };

/** Every running container with its OS, support, and vulnerabilities; a row opens its findings. */
export function ContainersTable({ containers }: { containers: ContainerResult[] }) {
  const [open, setOpen] = useState<string | null>(null);
  return (
    <Card>
      <CardHeader
        title="Containers"
        description={`${containers.length} running ${containers.length === 1 ? "container" : "containers"}. Open one to see what to fix in its image.`}
      />
      <Table>
        <thead>
          <tr>
            <Th>Container</Th>
            <Th>OS</Th>
            <Th>Vulnerabilities</Th>
            <Th>To fix</Th>
          </tr>
        </thead>
        <tbody>
          {containers.map((container) => {
            const key = container.id || container.name;
            const isOpen = open === key;
            const total = Object.values(container.severity ?? {}).reduce<number>((sum, count) => sum + (count ?? 0), 0);
            return (
              <ContainerRows key={key} container={container} total={total} isOpen={isOpen} toggle={() => setOpen(isOpen ? null : key)} />
            );
          })}
        </tbody>
      </Table>
    </Card>
  );
}

function ContainerRows({ container, total, isOpen, toggle }: { container: ContainerResult; total: number; isOpen: boolean; toggle: () => void }) {
  const Chevron = isOpen ? ChevronDown : ChevronRight;
  const counts = severityOrder
    .map((severity) => [severity, container.severity?.[severity.toUpperCase()] ?? 0] as const)
    .filter(([, count]) => count > 0);
  return (
    <>
      <tr className="cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50" onClick={toggle}>
        <Td>
          <div className="flex items-start gap-2">
            <Chevron className="mt-0.5 size-4 shrink-0 text-slate-400" aria-hidden />
            <div>
              <div className="font-medium">{container.name}</div>
              <div className="font-mono text-xs break-all text-slate-500 dark:text-slate-400">{container.image}</div>
              <div className="text-xs text-slate-500 dark:text-slate-400">{runtimeName[container.runtime] ?? container.runtime}</div>
            </div>
          </div>
        </Td>
        <Td>
          {container.os ? (
            <div className="space-y-1">
              <div className="text-sm">{container.os}</div>
              <ReleaseBadge lifecycle={container.lifecycle} onlyProblems />
            </div>
          ) : (
            <span className="text-sm text-slate-500 dark:text-slate-400">{container.error ? "Not checked" : "No OS packages"}</span>
          )}
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {container.packages} packages · {container.libraries} libraries
          </div>
        </Td>
        <Td>
          <div className="flex flex-wrap items-center gap-1">
            {container.exploited > 0 && (
              <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 ring-1 ring-red-600/20 ring-inset dark:bg-red-500/15 dark:text-red-300">
                <Flame className="size-3" aria-hidden /> {container.exploited} exploited
              </span>
            )}
            {counts.length === 0 ? (
              <span className="text-sm text-slate-500 dark:text-slate-400">{total === 0 ? "None found" : total}</span>
            ) : (
              counts.map(([severity, count]) => (
                <span key={severity} className="inline-flex items-center gap-1 text-sm">
                  <SeverityBadge severity={severity} /> {count}
                </span>
              ))
            )}
          </div>
        </Td>
        <Td>{container.fixable}</Td>
      </tr>
      {isOpen && (
        <tr>
          <td colSpan={4} className="bg-slate-50 px-5 py-4 dark:bg-slate-900/60">
            <div className="space-y-3">
              {container.error && <ErrorMessage error={container.error} />}
              {(container.notes ?? []).map((note) => (
                <p key={note} className="flex gap-2 text-sm text-slate-600 dark:text-slate-300">
                  <Info className="mt-0.5 size-4 shrink-0 text-slate-400" aria-hidden /> {note}
                </p>
              ))}
              {(container.findings ?? []).length === 0 ? (
                <p className="text-sm text-slate-600 dark:text-slate-300">Nothing in this container has a fix or is known to be exploited.</p>
              ) : (
                <ul className="divide-y divide-slate-200 rounded-lg bg-white ring-1 ring-slate-200 dark:divide-slate-800 dark:bg-slate-900 dark:ring-slate-800">
                  {[...(container.findings ?? [])]
                    .sort(
                      (a, b) =>
                        Number(b.detail.includes("Known to be exploited")) - Number(a.detail.includes("Known to be exploited")) ||
                        severityOrder.indexOf(normalizeSeverity(a.severity)) - severityOrder.indexOf(normalizeSeverity(b.severity)),
                    )
                    .map((finding) => (
                      <li key={finding.rule + finding.title} className="flex gap-3 px-4 py-2.5">
                        <SeverityBadge severity={finding.severity} />
                        <div className="min-w-0">
                          <div className="text-sm font-medium break-words">{finding.title.replace(`${container.name}: `, "")}</div>
                          <div className="text-xs text-slate-500 dark:text-slate-400">
                            <span className="font-mono">{finding.rule}</span> · {finding.detail}
                          </div>
                        </div>
                      </li>
                    ))}
                </ul>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  );
}
