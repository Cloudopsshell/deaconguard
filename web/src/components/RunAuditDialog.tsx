import { useState } from "react";
import { useNavigate } from "react-router";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { ClipboardCheck } from "lucide-react";
import { api, type Host } from "../api";
import { Button, Dialog, ErrorMessage } from "./ui";

const parts = [
  "Package vulnerabilities against the distribution's advisories",
  "System file integrity against the package manager",
  "Malware and compromise indicators",
  "Security configuration",
  "The hardening baseline: about 60 controls, from SSH and passwords to the firewall and logging",
  "Antivirus scan with ClamAV",
  "The machine's inventory: OS, hardware, disks, network, users and listening services",
];

/** Starts a handover audit of a host and opens its page. */
export function RunAuditDialog({ host, open, onClose }: { host: Host; open: boolean; onClose: () => void }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [advanced, setAdvanced] = useState(false);
  const start = useMutation({
    mutationFn: () => api.startAudit(host.id, advanced),
    onSuccess: (scan) => {
      queryClient.invalidateQueries();
      navigate(`/audits/${scan.id}`);
    },
  });
  return (
    <Dialog open={open} onClose={onClose} title={`Audit ${host.address}`}>
      <div className="space-y-4 text-sm">
        <p className="text-slate-600 dark:text-slate-300">
          A full check of the machine, graded A to F, for handing a new server over or checking an existing one. It runs:
        </p>
        <ul className="list-disc space-y-1 pl-5 text-slate-600 dark:text-slate-300">
          {parts.map((part) => (
            <li key={part}>{part}</li>
          ))}
        </ul>
        <label className="flex items-start gap-2">
          <input type="checkbox" className="mt-0.5 accent-indigo-600" checked={advanced} onChange={(event) => setAdvanced(event.target.checked)} />
          <span>
            <span className="font-medium">Add the advanced antivirus scan (YARA)</span>
            <span className="block text-xs text-slate-500 dark:text-slate-400">Better at webshells and attacker tools; takes a few more minutes.</span>
          </span>
        </label>
        <p className="text-xs text-slate-500 dark:text-slate-400">
          It takes a few minutes, mostly for the antivirus scan, and changes nothing on the machine. You can leave the page while it runs.
        </p>
        <ErrorMessage error={start.error} />
        <div className="flex justify-end gap-2">
          <Button variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button loading={start.isPending} onClick={() => start.mutate()}>
            <ClipboardCheck className="size-4" /> Start audit
          </Button>
        </div>
      </div>
    </Dialog>
  );
}
