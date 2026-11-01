import { useState } from "react";
import { Check, Copy } from "lucide-react";

/** A command to copy, such as an enroll or upgrade command. */
export function CopyBlock({ text, label }: { text: string; label: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      // Clipboard access can be denied; the text stays selectable.
    }
  }
  return (
    <div className="relative">
      <pre className="overflow-x-auto rounded-lg bg-slate-950 p-3 pr-12 font-mono text-xs leading-relaxed break-all whitespace-pre-wrap text-slate-100">
        {text}
      </pre>
      <button
        type="button"
        onClick={copy}
        className="absolute top-2 right-2 rounded-md p-1.5 text-slate-400 hover:bg-slate-800 hover:text-slate-100"
        aria-label={label}
        title="Copy"
      >
        {copied ? <Check className="size-4 text-emerald-400" /> : <Copy className="size-4" />}
      </button>
    </div>
  );
}
