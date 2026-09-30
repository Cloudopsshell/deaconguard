import { useState } from "react";
import { useMutation, useQuery } from "@tanstack/react-query";
import { AlertTriangle, Play, ShieldCheck } from "lucide-react";
import { api, type CheckId, type Host } from "../api";
import { checkMeta, rememberChecks, rememberedChecks } from "../lib/checks";
import { useRefreshAll, useStartScan } from "../lib/hooks";
import { Button, Dialog, ErrorMessage, Loading, cx } from "./ui";

/** Lets the user choose which checks to run, and whether sudo may be used, before a scan. */
export function ScanDialog({
  host,
  open,
  onClose,
  initial,
}: {
  host: Host;
  open: boolean;
  onClose: () => void;
  initial?: CheckId[];
}) {
  if (!open) return null;
  return <ScanDialogBody host={host} onClose={onClose} initial={initial} />;
}

function ScanDialogBody({ host, onClose, initial }: { host: Host; onClose: () => void; initial?: CheckId[] }) {
  const refresh = useRefreshAll();
  const definitions = useQuery({ queryKey: ["checks"], queryFn: api.checks, staleTime: Infinity });
  const [selected, setSelected] = useState<CheckId[] | null>(initial ?? rememberedChecks());
  const [allowSudo, setAllowSudo] = useState(host.allow_sudo);
  const startScan = useStartScan();
  const saveSudo = useMutation({ mutationFn: (allow: boolean) => api.setAllowSudo(host.id, allow), onSuccess: refresh });

  const chosen = selected ?? definitions.data?.filter((check) => check.default).map((check) => check.id) ?? [];
  const chosenDefinitions = definitions.data?.filter((check) => chosen.includes(check.id)) ?? [];
  const wantsSudo = chosenDefinitions.some((check) => check.sudo === "recommended");

  function toggle(id: CheckId) {
    setSelected(chosen.includes(id) ? chosen.filter((value) => value !== id) : [...chosen, id]);
  }

  async function start() {
    if (allowSudo !== host.allow_sudo) await saveSudo.mutateAsync(allowSudo);
    rememberChecks(chosen);
    await startScan.mutateAsync({ hostId: host.id, checks: chosen });
    onClose();
  }

  return (
    <Dialog open onClose={onClose} title={`Scan ${host.address}`}>
      {definitions.isPending ? (
        <Loading />
      ) : definitions.error ? (
        <ErrorMessage error={definitions.error} />
      ) : (
        <div className="space-y-4">
          <fieldset className="space-y-2">
            <legend className="mb-2 text-sm font-medium">Choose what to check</legend>
            {definitions.data.map((check) => {
              const Icon = checkMeta[check.id].icon;
              const checked = chosen.includes(check.id);
              return (
                <label
                  key={check.id}
                  className={cx(
                    "flex cursor-pointer gap-3 rounded-lg p-3 ring-1 ring-inset transition-colors",
                    checked
                      ? "bg-indigo-50/60 ring-indigo-600/40 dark:bg-indigo-500/10 dark:ring-indigo-400/40"
                      : "ring-slate-200 hover:bg-slate-50 dark:ring-slate-800 dark:hover:bg-slate-800/50",
                  )}
                >
                  <input
                    type="checkbox"
                    checked={checked}
                    onChange={() => toggle(check.id)}
                    className="mt-1 size-4 shrink-0 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
                  />
                  <span className="min-w-0">
                    <span className="flex flex-wrap items-center gap-x-2 gap-y-1 text-sm font-semibold">
                      <Icon className="size-4 text-slate-500 dark:text-slate-400" />
                      {check.name}
                      {check.sudo === "recommended" && (
                        <span className="rounded bg-slate-100 px-1.5 py-0.5 text-[11px] font-medium text-slate-600 dark:bg-slate-800 dark:text-slate-300">
                          better with sudo
                        </span>
                      )}
                    </span>
                    <span className="mt-0.5 block text-xs leading-relaxed text-slate-500 dark:text-slate-400">{check.description}</span>
                    {checked && check.warning && (
                      <span className="mt-1.5 flex gap-1 text-xs text-amber-700 dark:text-amber-400">
                        <AlertTriangle className="mt-px size-3.5 shrink-0" /> {check.warning}
                      </span>
                    )}
                  </span>
                </label>
              );
            })}
          </fieldset>

          {wantsSudo && (
            <label
              className={cx(
                "flex cursor-pointer gap-3 rounded-lg p-3 text-sm ring-1 ring-inset",
                allowSudo
                  ? "bg-emerald-50 ring-emerald-600/30 dark:bg-emerald-500/10 dark:ring-emerald-400/30"
                  : "bg-amber-50 ring-amber-600/40 dark:bg-amber-500/10 dark:ring-amber-400/40",
              )}
            >
              <input
                type="checkbox"
                checked={allowSudo}
                onChange={(event) => setAllowSudo(event.target.checked)}
                className="mt-0.5 size-4 shrink-0 rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
              />
              <span>
                <span className="flex items-center gap-1.5 font-semibold">
                  <ShieldCheck className="size-4 text-slate-500" /> Let DeaconGuard use sudo on this host
                </span>
                <span className="mt-0.5 block text-xs leading-relaxed text-slate-600 dark:text-slate-300">
                  {allowSudo
                    ? "Checks will read other users' processes, protected files, and firewall rules with DeaconGuard's fixed read-only commands. If sudo needs a password you will be asked for it. Saved for this host."
                    : "Off: the checks you picked will only see what the user running DeaconGuard can read, and results will show partial coverage. Tick this to use sudo. Saved for this host."}
                </span>
              </span>
            </label>
          )}

          <ErrorMessage error={startScan.error ?? saveSudo.error} />
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="secondary" onClick={onClose}>
              Cancel
            </Button>
            <Button disabled={chosen.length === 0} loading={startScan.isPending || saveSudo.isPending} onClick={start}>
              <Play className="size-4" /> {wantsSudo && !allowSudo ? "Start scan without sudo" : "Start scan"}
            </Button>
          </div>
        </div>
      )}
    </Dialog>
  );
}
