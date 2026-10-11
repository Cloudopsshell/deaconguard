import { useEffect, useRef, useState, type FormEvent } from "react";
import { useMutation } from "@tanstack/react-query";
import QRCode from "qrcode";
import { api } from "../../api";
import { Button, ErrorMessage, Field } from "../ui";
import { RecoveryCodes } from "./RecoveryCodes";

/**
 * Sets up two-step sign-in: scan a QR code (or type the key) into any
 * authenticator app, confirm with a code, then save the recovery codes.
 * replacing asks for the password first, since an authenticator exists.
 */
export function MFASetup({ username, replacing, onDone }: { username: string; replacing: boolean; onDone: () => void }) {
  const [password, setPassword] = useState("");
  const [code, setCode] = useState("");
  const [qr, setQr] = useState("");
  const start = useMutation({ mutationFn: () => api.startMFA(password) });
  const confirm = useMutation({ mutationFn: () => api.confirmMFA(code), onError: () => setCode("") });

  // Once only: each start makes a new key, and React may run effects twice.
  const started = useRef(false);
  useEffect(() => {
    if (replacing || started.current) return;
    started.current = true;
    start.mutate();
  }, [replacing, start]);

  useEffect(() => {
    if (!start.data) return;
    QRCode.toDataURL(start.data.uri, { margin: 1, width: 200, errorCorrectionLevel: "M" }).then(setQr, () => setQr(""));
  }, [start.data]);

  if (confirm.data) {
    return <RecoveryCodes codes={confirm.data.recovery_codes} username={username} onDone={onDone} />;
  }

  if (replacing && !start.data) {
    return (
      <form
        className="space-y-4"
        onSubmit={(event: FormEvent) => {
          event.preventDefault();
          start.mutate();
        }}
      >
        <p className="text-sm text-slate-600 dark:text-slate-300">
          Confirm your password to move two-step sign-in to a new phone or app. The current one keeps working until the new one is confirmed.
        </p>
        <Field label="Password" type="password" autoComplete="current-password" required value={password} onChange={(event) => setPassword(event.target.value)} />
        <ErrorMessage error={start.error} />
        <Button type="submit" loading={start.isPending}>
          Continue
        </Button>
      </form>
    );
  }

  const key = start.data?.secret.replace(/(.{4})/g, "$1 ").trim();
  return (
    <form
      className="space-y-5"
      onSubmit={(event: FormEvent) => {
        event.preventDefault();
        confirm.mutate();
      }}
    >
      <ol className="space-y-5 text-sm">
        <li>
          <p className="font-semibold">1. Scan this QR code with your authenticator app</p>
          <p className="mt-1 text-slate-500 dark:text-slate-400">
            Any app that supports TOTP works: Google or Microsoft Authenticator, Bitwarden, 1Password, Proton Pass, Apple Passwords, Ente Auth,
            2FAS, Aegis, and others.
          </p>
          <div className="mt-3 flex flex-wrap items-center gap-5">
            <div className="flex size-[212px] items-center justify-center rounded-lg bg-white p-1.5 ring-1 ring-slate-200">
              {qr ? <img src={qr} alt="QR code to add DeaconGuard to an authenticator app" width={200} height={200} /> : <span className="text-xs text-slate-400">…</span>}
            </div>
            <div className="min-w-0">
              <p className="text-slate-500 dark:text-slate-400">Can't scan it? Enter this key instead:</p>
              <code className="mt-1 block font-mono text-sm break-all select-all">{key ?? "…"}</code>
              <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Account: {username} · Time-based · 6 digits</p>
            </div>
          </div>
        </li>
        <li>
          <p className="font-semibold">2. Enter the 6-digit code the app shows</p>
          <div className="mt-2 max-w-48">
            <Field
              label="Code"
              autoComplete="one-time-code"
              inputMode="numeric"
              placeholder="123 456"
              required
              value={code}
              onChange={(event) => setCode(event.target.value)}
              className="font-mono tracking-widest"
            />
          </div>
        </li>
      </ol>
      <ErrorMessage error={start.error ?? confirm.error} />
      <Button type="submit" loading={confirm.isPending} disabled={!start.data}>
        Turn on two-step sign-in
      </Button>
    </form>
  );
}
