import { useMemo, useState, type ReactNode } from "react";
import { useSearchParams } from "react-router";
import { ArrowLeft, ChevronDown, ChevronRight, Flame, Info } from "lucide-react";
import type { CheckFinding, ContainerResult, Severity } from "../api";
import { dateTime, normalizeSeverity, severityOrder, severityStyle, timeAgo } from "../lib/format";
import { ReleaseBadge } from "./ReleaseSupport";
import { Card, CardHeader, ErrorMessage, SeverityBadge, Table, Td, Th, cx } from "./ui";

const runtimeName: Record<string, string> = { docker: "Docker", podman: "Podman", cri: "containerd / CRI-O" };

/** Whether a container runs a release that has ended, which the server reports as one finding instead of checking its packages. */
export function endOfLife(container: ContainerResult) {
  return [...(container.vulnerabilities ?? []), ...(container.findings ?? [])].some((finding) => finding.rule === "DG-EOL-001");
}

/** Whether a container's files were read: running or paused when the agent looked (agents before 1.8.0 sent no state). */
export function scanned(container: ContainerResult) {
  return !container.state || container.state === "running" || container.state === "paused";
}

function total(container: ContainerResult) {
  return Object.values(container.severity ?? {}).reduce<number>((sum, count) => sum + (count ?? 0), 0);
}

/**
 * Every container on the host: totals, then a row per container with its state, image, contents and
 * vulnerabilities. A row opens the container's details and its vulnerabilities as a tree (?container=ID).
 */
export function ContainersTable({ containers }: { containers: ContainerResult[] }) {
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedID = searchParams.get("container");
  const select = (id: string | null) => {
    const next = new URLSearchParams(searchParams);
    if (id) next.set("container", id);
    else next.delete("container");
    setSearchParams(next, { replace: false });
  };
  const selected = selectedID ? containers.find((container) => (container.id || container.name) === selectedID) : undefined;
  if (selected) return <ContainerDetail container={selected} back={() => select(null)} />;

  const running = containers.filter(scanned);
  const stopped = containers.length - running.length;
  const images = new Set(containers.map((container) => container.image_id || container.image)).size;
  const vulnerabilities = running.reduce((sum, container) => sum + total(container), 0);
  const exploited = running.reduce((sum, container) => sum + (container.exploited ?? 0), 0);
  const ended = running.filter((container) => container.lifecycle?.state === "ended").length;
  return (
    <Card>
      <CardHeader
        title="Containers"
        description={`${containers.length} ${containers.length === 1 ? "container" : "containers"}${stopped > 0 ? `: ${running.length} running, ${stopped} stopped` : ""}. Open one to see its details and every vulnerability in it.`}
      />
      <div className="grid grid-cols-2 gap-3 px-5 py-4 sm:grid-cols-3 lg:grid-cols-6">
        <Tile label="Running" value={running.length} />
        <Tile label="Stopped" value={stopped} />
        <Tile label="Images" value={images} />
        <Tile label="Vulnerabilities" value={vulnerabilities} />
        <Tile label="Known exploited" value={exploited} className={exploited > 0 ? "text-red-700 dark:text-red-300" : undefined} />
        <Tile label="End-of-life OS" value={ended} className={ended > 0 ? "text-amber-700 dark:text-amber-300" : undefined} />
      </div>
      <Table>
        <thead>
          <tr>
            <Th>Container</Th>
            <Th>State</Th>
            <Th>Image</Th>
            <Th>Contents</Th>
            <Th>Vulnerabilities</Th>
            <Th>Runs as</Th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
          {containers.map((container) => {
            const key = container.id || container.name;
            return <ContainerRow key={key} container={container} open={() => select(key)} />;
          })}
        </tbody>
      </Table>
    </Card>
  );
}

function Tile({ label, value, className }: { label: string; value: number; className?: string }) {
  return (
    <div className="rounded-lg bg-slate-50 px-3 py-2.5 ring-1 ring-slate-200 dark:bg-slate-950/50 dark:ring-slate-800">
      <div className="text-xs text-slate-500 dark:text-slate-400">{label}</div>
      <div className={cx("text-xl font-semibold tabular-nums", className)}>{value}</div>
    </div>
  );
}

function shortID(id: string) {
  return id.replace(/^sha256:/, "").slice(0, 12);
}

function StateLine({ container }: { container: ContainerResult }) {
  const state = container.state || "running";
  const live = state === "running";
  const label = state.charAt(0).toUpperCase() + state.slice(1);
  let when = "";
  if (live && container.started_at) when = `started ${timeAgo(container.started_at)}`;
  else if (!live && container.finished_at) when = `${state === "exited" ? `exit code ${container.exit_code ?? 0}, ` : ""}${timeAgo(container.finished_at)}`;
  else if (!live && state === "exited") when = `exit code ${container.exit_code ?? 0}`;
  return (
    <div>
      <div className="flex items-center gap-2 whitespace-nowrap">
        <span className={cx("size-2 shrink-0 rounded-full", live ? "bg-emerald-500" : state === "paused" ? "bg-amber-500" : "bg-slate-400")} aria-hidden />
        {label}
      </div>
      {(when || (container.restarts ?? 0) > 0) && (
        <div className="text-xs text-slate-500 dark:text-slate-400">
          {[when, (container.restarts ?? 0) > 0 ? `${container.restarts} restarts` : ""].filter(Boolean).join(" · ")}
        </div>
      )}
    </div>
  );
}

function runsAs(container: ContainerResult) {
  if (container.runs_as) return container.runs_as;
  if (container.state === undefined) return "";
  return container.user ? `user ${container.user}` : "root";
}

function SeverityChips({ counts }: { counts: Partial<Record<string, number>> }) {
  const shown = severityOrder.map((severity) => [severity, counts[severity] ?? 0] as const).filter(([, count]) => count > 0);
  if (shown.length === 0) return null;
  return (
    <span className="inline-flex flex-wrap gap-1">
      {shown.map(([severity, count]) => (
        <span
          key={severity}
          title={`${count} ${severityStyle[severity].label.toLowerCase()}`}
          className={cx("inline-flex min-w-6 justify-center rounded-md px-1.5 py-0.5 text-xs font-semibold tabular-nums ring-1 ring-inset", severityStyle[severity].badge)}
        >
          {count}
        </span>
      ))}
    </span>
  );
}

function Exploited({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <span className="inline-flex items-center gap-1 rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium whitespace-nowrap text-red-700 ring-1 ring-red-600/20 ring-inset dark:bg-red-500/15 dark:text-red-300">
      <Flame className="size-3" aria-hidden /> {count} exploited
    </span>
  );
}

function ContainerRow({ container, open }: { container: ContainerResult; open: () => void }) {
  const isScanned = scanned(container);
  const counts: Partial<Record<string, number>> = {};
  for (const [severity, count] of Object.entries(container.severity ?? {})) counts[normalizeSeverity(severity)] = count;
  return (
    <tr
      className={cx("cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50", !isScanned && "text-slate-500 dark:text-slate-400")}
      onClick={open}
      onKeyDown={(event) => event.key === "Enter" && open()}
      tabIndex={0}
      aria-label={`Open ${container.name}`}
    >
      <Td>
        <div className="flex items-start gap-2">
          <ChevronRight className="mt-0.5 size-4 shrink-0 text-slate-400" aria-hidden />
          <div className="min-w-0">
            <div className={cx("font-medium break-all", isScanned && "text-slate-900 dark:text-slate-100")}>{container.name}</div>
            <div className="text-xs text-slate-500 dark:text-slate-400">
              {runtimeName[container.runtime] ?? container.runtime}
              {container.id && <span className="font-mono"> · {shortID(container.id)}</span>}
            </div>
          </div>
        </div>
      </Td>
      <Td>
        <StateLine container={container} />
      </Td>
      <Td>
        <div className="font-mono text-xs break-all">{container.image}</div>
        {container.image_id && <div className="font-mono text-xs text-slate-500 dark:text-slate-400">{shortID(container.image_id)}</div>}
        {container.os && (
          <div className="mt-1 flex flex-wrap items-center gap-1 text-xs">
            {container.os} <ReleaseBadge lifecycle={container.lifecycle} onlyProblems />
          </div>
        )}
      </Td>
      <Td className="text-xs">
        {isScanned ? (
          <>
            {container.os ? (
              <div className="whitespace-nowrap">
                {container.packages} packages
                {endOfLife(container) && <span className="text-amber-700 dark:text-amber-400"> (not checked)</span>}
              </div>
            ) : container.error ? (
              <div className="text-amber-700 dark:text-amber-400" title={container.error}>
                OS packages not checked
              </div>
            ) : (
              <div className="whitespace-nowrap">No OS packages</div>
            )}
            <div className="whitespace-nowrap">{container.libraries} libraries</div>
          </>
        ) : (
          "—"
        )}
      </Td>
      <Td>
        {isScanned ? (
          <div className="flex flex-col items-start gap-1">
            {total(container) > 0 ? (
              <SeverityChips counts={counts} />
            ) : (
              <span className="text-sm text-slate-500 dark:text-slate-400">{container.error ? "None in its libraries" : "None found"}</span>
            )}
            <Exploited count={container.exploited ?? 0} />
          </div>
        ) : (
          <span className="text-xs">Not scanned: it isn't running. Scan its image on the Images page.</span>
        )}
      </Td>
      <Td className="text-xs">
        {runsAs(container) || "—"}
        {container.privileged && (
          <div>
            <span className="rounded-full bg-red-50 px-2 py-0.5 font-medium text-red-700 ring-1 ring-red-600/20 ring-inset dark:bg-red-500/15 dark:text-red-300">privileged</span>
          </div>
        )}
      </Td>
    </tr>
  );
}

function Detail({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <div className="text-xs text-slate-500 dark:text-slate-400">{label}</div>
      <div className="text-sm break-words">{children}</div>
    </div>
  );
}

/** One container: what it is and how it runs, then every vulnerability in it as a tree. */
function ContainerDetail({ container, back }: { container: ContainerResult; back: () => void }) {
  const isScanned = scanned(container);
  const hasDetails = container.state !== undefined;
  return (
    <Card>
      <div className="flex flex-wrap items-center gap-2 border-b border-slate-200 px-5 py-3 text-sm dark:border-slate-800">
        <button type="button" onClick={back} className="inline-flex items-center gap-1 text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100">
          <ArrowLeft className="size-4" aria-hidden /> All containers
        </button>
        <span className="text-slate-400">/</span>
        <span className="font-semibold break-all">{container.name}</span>
      </div>
      <div className="grid gap-x-8 gap-y-4 px-5 py-4 sm:grid-cols-2 lg:grid-cols-4">
        <Detail label="State">
          <StateLine container={container} />
        </Detail>
        <Detail label="Image">
          <div className="font-mono text-xs break-all">{container.image}</div>
          {container.image_id && (
            <div className="font-mono text-xs text-slate-500 dark:text-slate-400" title={container.image_id}>
              {shortID(container.image_id)}
            </div>
          )}
        </Detail>
        <Detail label="Operating system">
          {container.os ? (
            <span className="inline-flex flex-wrap items-center gap-1">
              {container.os} <ReleaseBadge lifecycle={container.lifecycle} onlyProblems />
            </span>
          ) : isScanned ? (
            container.error ? "Not checked" : "No OS packages found"
          ) : (
            "—"
          )}
        </Detail>
        <Detail label="Runtime">
          {runtimeName[container.runtime] ?? container.runtime}
          {container.id && <span className="font-mono text-xs"> · {shortID(container.id)}</span>}
        </Detail>
        {hasDetails && (
          <>
            <Detail label="Command">{container.command ? <span className="font-mono text-xs">{container.command}</span> : "—"}</Detail>
            <Detail label="Runs as">
              {runsAs(container) || "—"}
              {container.privileged ? (
                <span className="ml-1 rounded-full bg-red-50 px-2 py-0.5 text-xs font-medium text-red-700 ring-1 ring-red-600/20 ring-inset dark:bg-red-500/15 dark:text-red-300">privileged</span>
              ) : (
                <span className="ml-1 text-xs text-slate-500 dark:text-slate-400">not privileged</span>
              )}
            </Detail>
            <Detail label="Network · published ports">
              {container.network || "—"}
              {" · "}
              {(container.ports ?? []).length > 0 ? <span className="font-mono text-xs">{(container.ports ?? []).join(", ")}</span> : "none"}
            </Detail>
            <Detail label="Created · started">
              {dateTime(container.created)} · {dateTime(container.started_at)}
            </Detail>
          </>
        )}
      </div>
      <div className="space-y-3 border-t border-slate-200 px-5 py-4 dark:border-slate-800">
        {isScanned ? (
          <ContainerFindings container={container} />
        ) : (
          <p className="flex gap-2 text-sm text-slate-600 dark:text-slate-300">
            <Info className="mt-0.5 size-4 shrink-0 text-slate-400" aria-hidden /> This container isn't running, so its files couldn't be read. Scan its image, {container.image}, on the
            Images page.
          </p>
        )}
      </div>
    </Card>
  );
}

/**
 * What is vulnerable in a container's or an image's packages and libraries: notes, then every vulnerability
 * as a tree (OS packages and library locations, then packages, then vulnerabilities). Results from servers
 * before 1.8.0 have only the findings to fix, listed flat.
 */
export function ContainerFindings({ container, emptyText = "Nothing in this container has a fix or is known to be exploited." }: { container: ContainerResult; emptyText?: string }) {
  return (
    <div className="space-y-3">
      {container.error && <ErrorMessage error={container.error} />}
      {(container.notes ?? []).map((note) => (
        <p key={note} className="flex gap-2 text-sm text-slate-600 dark:text-slate-300">
          <Info className="mt-0.5 size-4 shrink-0 text-slate-400" aria-hidden /> {note}
        </p>
      ))}
      {container.vulnerabilities ? (
        <VulnerabilityTree vulnerabilities={container.vulnerabilities} os={container.os} packages={container.packages} libraries={container.libraries} />
      ) : (
        <FlatFindings container={container} emptyText={emptyText} />
      )}
    </div>
  );
}

function FlatFindings({ container, emptyText }: { container: ContainerResult; emptyText: string }) {
  if ((container.findings ?? []).length === 0) return <p className="text-sm text-slate-600 dark:text-slate-300">{emptyText}</p>;
  return (
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
  );
}

/** The folder or file a library was found in: a Python site-packages folder, a global node_modules, or the lock file or program itself. */
export function locationOf(path: string | undefined): string {
  if (!path) return "Unknown location";
  const parts = path.split("/");
  const name = parts[parts.length - 1];
  if ((name === "METADATA" || name === "PKG-INFO") && parts.length > 3) return parts.slice(0, -2).join("/");
  const global = path.indexOf("/lib/node_modules/");
  if (name === "package.json" && global >= 0) return path.slice(0, global + "/lib/node_modules".length);
  return path;
}

type Filter = "all" | "fixable" | "exploited";
type Grouping = "where" | "severity";

interface PackageNode {
  key: string;
  name: string;
  version: string;
  ecosystem?: string;
  fixed: string[];
  vulnerabilities: CheckFinding[];
}

interface Group {
  key: string;
  title: ReactNode;
  vulnerabilities: CheckFinding[];
  children?: Group[];
  packages?: PackageNode[];
}

function countsOf(vulnerabilities: CheckFinding[]) {
  const counts: Partial<Record<Severity, number>> = {};
  for (const vulnerability of vulnerabilities) {
    const severity = normalizeSeverity(vulnerability.severity);
    counts[severity] = (counts[severity] ?? 0) + 1;
  }
  return counts;
}

function packagesOf(vulnerabilities: CheckFinding[]): PackageNode[] {
  const byKey = new Map<string, PackageNode>();
  for (const vulnerability of vulnerabilities) {
    const name = vulnerability.package || vulnerability.rule;
    const key = `${name}@${vulnerability.version ?? ""}`;
    let node = byKey.get(key);
    if (!node) {
      node = { key, name, version: vulnerability.version ?? "", ecosystem: vulnerability.ecosystem, fixed: [], vulnerabilities: [] };
      byKey.set(key, node);
    }
    node.vulnerabilities.push(vulnerability);
    if (vulnerability.fixed && !node.fixed.includes(vulnerability.fixed)) node.fixed.push(vulnerability.fixed);
  }
  return [...byKey.values()].sort((a, b) => rank(a.vulnerabilities) - rank(b.vulnerabilities) || a.name.localeCompare(b.name));
}

/** Lower is more urgent: the most severe vulnerability first, then how many. */
function rank(vulnerabilities: CheckFinding[]) {
  const worst = Math.min(...vulnerabilities.map((vulnerability) => severityOrder.indexOf(normalizeSeverity(vulnerability.severity))));
  const exploited = vulnerabilities.some((vulnerability) => vulnerability.exploited) ? -10 : 0;
  return exploited + worst * 1000 - vulnerabilities.length;
}

/** Every vulnerability in a container or image, filtered and grouped by where it was found or by severity. */
export function VulnerabilityTree({ vulnerabilities, os, packages, libraries }: { vulnerabilities: CheckFinding[]; os?: string; packages: number; libraries: number }) {
  const [filter, setFilter] = useState<Filter>("all");
  const [grouping, setGrouping] = useState<Grouping>("where");
  const fixable = vulnerabilities.filter((vulnerability) => vulnerability.fixable).length;
  const exploited = vulnerabilities.filter((vulnerability) => vulnerability.exploited).length;
  const shown = vulnerabilities.filter((vulnerability) => filter === "all" || (filter === "fixable" ? vulnerability.fixable : vulnerability.exploited));

  const groups = useMemo<Group[]>(() => {
    if (grouping === "severity") {
      return severityOrder
        .map((severity) => {
          const matching = shown.filter((vulnerability) => normalizeSeverity(vulnerability.severity) === severity);
          return { key: severity, title: severityStyle[severity].label, vulnerabilities: matching, packages: packagesOf(matching) };
        })
        .filter((group) => group.vulnerabilities.length > 0);
    }
    const result: Group[] = [];
    const osVulnerabilities = shown.filter((vulnerability) => vulnerability.source === "os");
    if (osVulnerabilities.length > 0) {
      result.push({
        key: "os",
        title: (
          <>
            OS packages <span className="font-normal text-slate-500 dark:text-slate-400">· {os || "operating system"} · {packages} packages</span>
          </>
        ),
        vulnerabilities: osVulnerabilities,
        packages: packagesOf(osVulnerabilities),
      });
    }
    const libraryVulnerabilities = shown.filter((vulnerability) => vulnerability.source !== "os");
    if (libraryVulnerabilities.length > 0) {
      const byLocation = new Map<string, CheckFinding[]>();
      for (const vulnerability of libraryVulnerabilities) {
        const location = locationOf(vulnerability.paths?.[0]);
        byLocation.set(location, [...(byLocation.get(location) ?? []), vulnerability]);
      }
      const children = [...byLocation.entries()]
        .map(([location, items]) => ({
          key: `library:${location}`,
          title: (
            <>
              {items[0].ecosystem && <span className="mr-2 text-xs font-normal text-slate-500 dark:text-slate-400">{items[0].ecosystem}</span>}
              <span className="font-mono text-xs font-medium break-all">{location}</span>
            </>
          ),
          vulnerabilities: items,
          packages: packagesOf(items),
        }))
        .sort((a, b) => rank(a.vulnerabilities) - rank(b.vulnerabilities));
      result.push({
        key: "library",
        title: (
          <>
            Application libraries{" "}
            <span className="font-normal text-slate-500 dark:text-slate-400">
              · {children.length} {children.length === 1 ? "location" : "locations"} · {libraries} libraries
            </span>
          </>
        ),
        vulnerabilities: libraryVulnerabilities,
        children,
      });
    }
    return result;
  }, [shown, grouping, os, packages, libraries]);

  // Groups start open and packages closed; toggled holds the ones changed.
  const [toggled, setToggled] = useState<Set<string>>(() => new Set());
  const toggle = (key: string) =>
    setToggled((current) => {
      const next = new Set(current);
      if (next.has(key)) next.delete(key);
      else next.add(key);
      return next;
    });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <Segmented
          label="Show"
          value={filter}
          onChange={setFilter}
          options={[
            ["all", `All ${vulnerabilities.length}`],
            ["fixable", `Fix available ${fixable}`],
            ["exploited", `Known exploited ${exploited}`],
          ]}
        />
        <Segmented
          label="Group by"
          value={grouping}
          onChange={setGrouping}
          options={[
            ["where", "Where found"],
            ["severity", "Severity"],
          ]}
        />
      </div>
      {shown.length === 0 ? (
        <p className="text-sm text-slate-600 dark:text-slate-300">
          {vulnerabilities.length === 0 ? "No known vulnerabilities in its packages and libraries." : "None match this filter."}
        </p>
      ) : (
        <div className="overflow-hidden rounded-lg bg-white ring-1 ring-slate-200 dark:bg-slate-900 dark:ring-slate-800">
          {groups.map((group) => (
            <GroupNode key={group.key} group={group} depth={0} toggled={toggled} toggle={toggle} />
          ))}
        </div>
      )}
    </div>
  );
}

function Segmented<T extends string>({ label, value, onChange, options }: { label: string; value: T; onChange: (value: T) => void; options: [T, string][] }) {
  return (
    <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400" role="group" aria-label={label}>
      {label}
      <div className="flex gap-1 rounded-lg bg-slate-100 p-1 ring-1 ring-slate-200 dark:bg-slate-950/60 dark:ring-slate-800">
        {options.map(([option, text]) => (
          <button
            key={option}
            type="button"
            aria-pressed={value === option}
            onClick={() => onChange(option)}
            className={cx(
              "rounded-md px-2.5 py-1 font-medium whitespace-nowrap",
              value === option ? "bg-white text-slate-900 shadow-sm dark:bg-slate-700 dark:text-slate-100" : "hover:text-slate-900 dark:hover:text-slate-100",
            )}
          >
            {text}
          </button>
        ))}
      </div>
    </div>
  );
}

const indent = ["pl-3", "pl-9", "pl-15", "pl-21", "pl-27"];
const packagesShown = 50;

function Row({ depth, onClick, expanded, children, counts, strong }: { depth: number; onClick?: () => void; expanded?: boolean; children: ReactNode; counts?: Partial<Record<string, number>>; strong?: boolean }) {
  const Chevron = expanded ? ChevronDown : ChevronRight;
  return (
    <div
      className={cx(
        "flex items-center gap-2 border-b border-slate-200 py-2 pr-4 text-sm last:border-b-0 dark:border-slate-800",
        indent[Math.min(depth, indent.length - 1)],
        strong && "bg-slate-50 dark:bg-slate-950/40",
        onClick && "cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-800/50",
      )}
      onClick={onClick}
      onKeyDown={(event) => onClick && event.key === "Enter" && onClick()}
      role={onClick ? "button" : undefined}
      aria-expanded={onClick ? expanded : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      {onClick && <Chevron className="size-4 shrink-0 text-slate-400" aria-hidden />}
      <div className="min-w-0 flex-1">{children}</div>
      {counts && <SeverityChips counts={counts} />}
    </div>
  );
}

function GroupNode({ group, depth, toggled, toggle }: { group: Group; depth: number; toggled: Set<string>; toggle: (key: string) => void }) {
  const [all, setAll] = useState(false);
  const expanded = !toggled.has(group.key);
  const packages = group.packages ?? [];
  const visible = all ? packages : packages.slice(0, packagesShown);
  return (
    <>
      <Row depth={depth} onClick={() => toggle(group.key)} expanded={expanded} counts={countsOf(group.vulnerabilities)} strong={depth === 0}>
        <span className={cx(depth === 0 && "font-semibold")}>{group.title}</span>
      </Row>
      {expanded && (
        <>
          {(group.children ?? []).map((child) => (
            <GroupNode key={child.key} group={child} depth={depth + 1} toggled={toggled} toggle={toggle} />
          ))}
          {visible.map((node) => (
            <PackageRow key={node.key} node={node} depth={depth + 1} expanded={toggled.has(`${group.key}/${node.key}`)} toggle={() => toggle(`${group.key}/${node.key}`)} />
          ))}
          {packages.length > visible.length && (
            <div className={cx("border-b border-slate-200 py-2 text-xs dark:border-slate-800", indent[Math.min(depth + 1, indent.length - 1)])}>
              <button type="button" className="font-medium text-indigo-600 hover:underline dark:text-indigo-400" onClick={() => setAll(true)}>
                Show {packages.length - visible.length} more packages
              </button>
            </div>
          )}
        </>
      )}
    </>
  );
}

function PackageRow({ node, depth, expanded, toggle }: { node: PackageNode; depth: number; expanded: boolean; toggle: () => void }) {
  const exploited = node.vulnerabilities.filter((vulnerability) => vulnerability.exploited).length;
  return (
    <>
      <Row depth={depth} onClick={toggle} expanded={expanded} counts={countsOf(node.vulnerabilities)}>
        <span className="inline-flex flex-wrap items-center gap-x-2 gap-y-0.5">
          <span className="font-mono text-[13px] font-medium break-all">{node.name}</span>
          <span className="font-mono text-xs text-slate-500 dark:text-slate-400">{node.version}</span>
          {node.fixed.length > 0 ? (
            <span className="text-xs text-emerald-700 dark:text-emerald-400">fix: {upgradeTo(node.version, node.fixed)}</span>
          ) : (
            <span className="text-xs text-slate-500 dark:text-slate-400">no fix yet</span>
          )}
          <Exploited count={exploited} />
        </span>
      </Row>
      {expanded &&
        node.vulnerabilities.map((vulnerability, index) => (
          <div
            key={`${vulnerability.rule}-${index}`}
            className={cx("flex gap-3 border-b border-slate-200 py-2 pr-4 dark:border-slate-800", indent[Math.min(depth + 1, indent.length - 1)])}
          >
            <SeverityBadge severity={normalizeSeverity(vulnerability.severity)} />
            <div className="min-w-0 text-sm">
              <div className="break-words">
                <span className="font-mono text-xs">{vulnerability.rule}</span>
                {vulnerability.summary && <> · {vulnerability.summary}</>}
              </div>
              <div className="text-xs break-words text-slate-500 dark:text-slate-400">{vulnerability.detail}</div>
              {vulnerability.source !== "os" && (vulnerability.paths ?? []).length > 1 && (
                <div className="font-mono text-xs break-all text-slate-500 dark:text-slate-400">Also in {(vulnerability.paths ?? []).slice(1).join(", ")}</div>
              )}
            </div>
          </div>
        ))}
    </>
  );
}

const compare = (a: string, b: string) => a.localeCompare(b, undefined, { numeric: true });

/**
 * The version to update to: for each vulnerability, the lowest version that fixes it above the installed one
 * (advisories list a fix per release line, such as "3.2.14, 4.0.6"), and the highest of those.
 */
export function upgradeTo(installed: string, fixed: string[]) {
  let target = "";
  for (const list of fixed) {
    const versions = list.split(",").map((version) => version.trim()).filter(Boolean).sort(compare);
    const next = versions.find((version) => compare(version, installed) > 0) ?? versions.at(-1) ?? "";
    if (next && (!target || compare(next, target) > 0)) target = next;
  }
  return target;
}
