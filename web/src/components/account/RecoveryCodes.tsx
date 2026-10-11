import { useState } from "react";
import { Check, Copy, Download } from "lucide-react";
import { Button } from "../ui";

/** Recovery codes, shown once: copy or download them, then confirm they are saved. */
export function RecoveryCodes({ codes, username, onDone }: { codes: string[]; username: string; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const [copied, setCopied] = useState(false);
  const text = `DeaconGuard recovery codes for ${username}\nEach code works once, in place of the code from your authenticator app.\n\n${codes.join("\n")}\n`;

  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
    } catch {
      setCopied(false);
    }
  }

  function download() {
    const link = document.createElement("a");
    link.href = URL.createObjectURL(new Blob([text], { type: "text/plain" }));
    link.download = `deaconguard-recovery-codes-${username}.txt`;
    link.click();
    URL.revokeObjectURL(link.href);
  }

  return (
    <div className="space-y-4">
      <div className="rounded-lg bg-amber-50 p-3 text-sm text-amber-900 ring-1 ring-amber-600/20 ring-inset dark:bg-amber-500/10 dark:text-amber-200">
        <p className="font-semibold">Save these recovery codes now. They are shown only once.</p>
        <p className="mt-1">
          If you lose your phone, each code signs you in once instead of the authenticator app. Keep them in your password manager, or
          print them.
        </p>
      </div>
      <ol className="grid grid-cols-2 gap-x-6 gap-y-1.5 rounded-lg bg-slate-50 p-4 font-mono text-sm dark:bg-slate-950">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ol>
      <div className="flex flex-wrap gap-2">
        <Button type="button" variant="secondary" onClick={copy}>
          {copied ? <Check className="size-4" /> : <Copy className="size-4" />} {copied ? "Copied" : "Copy"}
        </Button>
        <Button type="button" variant="secondary" onClick={download}>
          <Download className="size-4" /> Download
        </Button>
      </div>
      <label className="flex items-center gap-2 text-sm">
        <input
          type="checkbox"
          checked={saved}
          onChange={(event) => setSaved(event.target.checked)}
          className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-600"
        />
        I have saved my recovery codes
      </label>
      <Button type="button" disabled={!saved} onClick={onDone}>
        Done
      </Button>
    </div>
  );
}
