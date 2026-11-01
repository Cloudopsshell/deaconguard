import { ArrowUpCircle } from "lucide-react";
import type { AgentUpgrade, CheckId, HostSummary } from "../api";
import { checkMeta } from "../lib/checks";
import { CopyBlock } from "./CopyBlock";

const upgradeDocs = "https://docs.deaconguard.io/installation/upgrade";

/** Marks an agent older than the server. */
export function UpgradeBadge({ upgrade }: { upgrade: AgentUpgrade }) {
  return (
    <span
      className="inline-flex shrink-0 items-center rounded-full bg-amber-50 px-2 py-0.5 text-xs font-medium whitespace-nowrap text-amber-800 ring-1 ring-amber-600/20 ring-inset dark:bg-amber-500/15 dark:text-amber-200 dark:ring-amber-400/30"
      title={`The server runs ${upgrade.to}. Upgrade this agent to ${upgrade.to}.`}
    >
      Upgrade to {upgrade.to}
    </span>
  );
}

function checkList(ids: CheckId[]) {
  const names = ids.map((id) => checkMeta[id]?.label ?? id);
  if (names.length <= 1) return names.join("");
  return `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
}

function inKubernetes(host: HostSummary) {
  return !host.agent?.upgrade?.command;
}

/**
 * Lists the agents older than the server on the Agents page, with how to
 * upgrade them and the checks they can't run until then.
 */
export function UpgradeNotice({ agents }: { agents: HostSummary[] }) {
  const outdated = agents.filter((host) => host.agent?.upgrade);
  if (outdated.length === 0) return null;
  const to = outdated[0].agent!.upgrade!.to;
  const machines = outdated.filter((host) => !inKubernetes(host));
  const kubernetes = outdated.filter(inKubernetes);
  const missing = [...new Set(outdated.flatMap((host) => host.agent!.upgrade!.checks ?? []))];
  return (
    <div className="mx-5 mt-4 rounded-lg bg-amber-50 px-4 py-3 text-sm text-amber-900 ring-1 ring-amber-600/20 ring-inset dark:bg-amber-500/10 dark:text-amber-100">
      <p className="flex items-center gap-2 font-medium">
        <ArrowUpCircle className="size-4 shrink-0 text-amber-600 dark:text-amber-400" aria-hidden />
        {outdated.length} of {agents.length} {agents.length === 1 ? "agent is" : "agents are"} older than this server, DeaconGuard {to}.
      </p>
      <p className="mt-1">
        They keep working, but get fixes and new checks only once upgraded
        {missing.length > 0 ? `; until then they can't run ${checkList(missing)}` : ""}.
      </p>
      {machines.length > 0 && (
        <div className="mt-3 space-y-2">
          <p>
            On {machines.length === 1 ? "the machine" : `each of the ${machines.length} machines`} ({machines.map((host) => host.address).join(", ")}),
            run as a user with sudo rights. It keeps the agent's enrollment:
          </p>
          <CopyBlock text={machines[0].agent!.upgrade!.command!} label="Copy the upgrade command" />
        </div>
      )}
      {kubernetes.length > 0 && (
        <p className="mt-3">
          In Kubernetes ({kubernetes.map((host) => host.address).join(", ")}): upgrade the agent's Helm release, or the image tag in its Kustomize
          overlay, to {to}.
        </p>
      )}
      <p className="mt-3 text-xs">
        Installed with packages or Docker Compose instead? See{" "}
        <a className="underline" href={upgradeDocs} target="_blank" rel="noreferrer">
          Upgrade
        </a>
        .
      </p>
    </div>
  );
}

/** Says on a host's page that its agent is older than the server. */
export function HostUpgradeNotice({ host }: { host: HostSummary }) {
  const upgrade = host.agent?.upgrade;
  if (!upgrade) return null;
  const checks = upgrade.checks ?? [];
  return (
    <div className="space-y-2 text-sm">
      <h2 className="font-semibold">Its agent is older than this server</h2>
      <p className="text-slate-600 dark:text-slate-300">
        The agent runs {host.agent!.version} and the server {upgrade.to}.
        {checks.length > 0 ? ` Upgrade it to run ${checkList(checks)} here.` : " Upgrading it brings the fixes made since."}
      </p>
      {upgrade.command ? (
        <>
          <p className="text-slate-600 dark:text-slate-300">On the machine, as a user with sudo rights:</p>
          <CopyBlock text={upgrade.command} label="Copy the upgrade command" />
        </>
      ) : (
        <p className="text-slate-600 dark:text-slate-300">Upgrade the agent's Helm release, or the image tag in its Kustomize overlay, to {upgrade.to}.</p>
      )}
      <p className="text-xs text-slate-500 dark:text-slate-400">
        Installed another way? See{" "}
        <a className="underline" href={upgradeDocs} target="_blank" rel="noreferrer">
          Upgrade
        </a>
        .
      </p>
    </div>
  );
}
