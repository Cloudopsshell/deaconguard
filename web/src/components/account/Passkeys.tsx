import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, Pencil, Plus, Trash2 } from "lucide-react";
import { api, type Passkey } from "../../api";
import { passkeysSupported, createPasskey } from "../../lib/passkey";
import { dateTime, timeAgo } from "../../lib/format";
import { Button, Card, CardHeader, Dialog, ErrorMessage, Field } from "../ui";

/** A name for a new passkey, from the browser it is made in. */
function suggestedName() {
  const agent = navigator.userAgent;
  if (/iPhone/.test(agent)) return "iPhone";
  if (/iPad/.test(agent)) return "iPad";
  if (/Android/.test(agent)) return "Android phone";
  if (/Mac OS X/.test(agent)) return "Mac";
  if (/Windows/.test(agent)) return "Windows PC";
  return "Passkey";
}

/** The account's passkeys: add, rename and remove them. */
export function Passkeys({ onChange }: { onChange: () => void }) {
  const queryClient = useQueryClient();
  const passkeys = useQuery({ queryKey: ["passkeys"], queryFn: api.passkeys });
  const refresh = () => {
    queryClient.invalidateQueries({ queryKey: ["passkeys"] });
    onChange();
  };
  const [adding, setAdding] = useState(false);
  const [renaming, setRenaming] = useState<Passkey | null>(null);
  const [removing, setRemoving] = useState<Passkey | null>(null);
  const supported = passkeysSupported();

  return (
    <Card>
      <CardHeader
        title="Passkeys"
        description="Sign in with your fingerprint, face or device PIN instead of a password and code. A passkey counts as two-step sign-in, and can't be phished: it only works on this dashboard."
        action={
          supported && (
            <Button variant="secondary" onClick={() => setAdding(true)}>
              <Plus className="size-4" /> Add a passkey
            </Button>
          )
        }
      />
      {!supported && (
        <p className="px-5 pb-4 text-sm text-amber-700 dark:text-amber-400">
          This browser can't use passkeys on this address. Passkeys need the dashboard on a name, such as dg.example.com, with a certificate the browser trusts.
        </p>
      )}
      <ErrorMessage error={passkeys.error} />
      {passkeys.data && passkeys.data.length === 0 && supported && (
        <p className="px-5 pb-5 text-sm text-slate-500 dark:text-slate-400">No passkeys yet.</p>
      )}
      {passkeys.data && passkeys.data.length > 0 && (
        <ul className="divide-y divide-slate-200 border-t border-slate-200 dark:divide-slate-800 dark:border-slate-800">
          {passkeys.data.map((key) => (
            <li key={key.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 px-5 py-3.5">
              <KeyRound className="size-5 shrink-0 text-slate-400" aria-hidden />
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium break-words">{key.name}</p>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  added {dateTime(key.created_at)} · {key.last_used_at ? `last used ${timeAgo(key.last_used_at)}` : "not used yet"}
                </p>
              </div>
              <Button variant="ghost" onClick={() => setRenaming(key)} aria-label={`Rename ${key.name}`}>
                <Pencil className="size-4" />
              </Button>
              <Button variant="ghost" onClick={() => setRemoving(key)} aria-label={`Remove ${key.name}`}>
                <Trash2 className="size-4" />
              </Button>
            </li>
          ))}
        </ul>
      )}
      {adding && <AddPasskey onClose={() => setAdding(false)} onDone={refresh} />}
      {renaming && <RenamePasskey passkey={renaming} onClose={() => setRenaming(null)} onDone={refresh} />}
      {removing && <RemovePasskey passkey={removing} onClose={() => setRemoving(null)} onDone={refresh} />}
    </Card>
  );
}

/** Sets up two-step sign-in with a passkey instead of an authenticator app. */
export function PasskeyInstead({ onDone }: { onDone: () => void }) {
  const [adding, setAdding] = useState(false);
  if (!passkeysSupported()) return null;
  return (
    <div className="mt-6 border-t border-slate-200 pt-5 dark:border-slate-800">
      <p className="text-sm text-slate-600 dark:text-slate-300">Or use a passkey: your fingerprint, face or device PIN, with no codes to type.</p>
      <Button className="mt-3" variant="secondary" onClick={() => setAdding(true)}>
        <KeyRound className="size-4" /> Add a passkey instead
      </Button>
      {adding && <AddPasskey onClose={() => setAdding(false)} onDone={onDone} />}
    </div>
  );
}

function AddPasskey({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(suggestedName);
  const [password, setPassword] = useState("");
  const add = useMutation({
    mutationFn: async () => api.addPasskey(name, password, await createPasskey(await api.passkeyOptions())),
    onSuccess: () => {
      onDone();
      onClose();
    },
    onError: () => setPassword(""),
  });
  return (
    <Dialog open onClose={onClose} title="Add a passkey">
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          add.mutate();
        }}
      >
        <p className="text-sm text-slate-600 dark:text-slate-300">
          Your browser asks where to save it: this device, your phone, or a password manager. Saved in a password manager or iCloud Keychain, it works on
          your other devices too.
        </p>
        <Field label="Name" value={name} onChange={(event) => setName(event.target.value)} maxLength={64} required hint="So you can tell your passkeys apart." />
        <Field
          label="Your password"
          type="password"
          autoComplete="current-password"
          required
          value={password}
          onChange={(event) => setPassword(event.target.value)}
          data-autofocus
        />
        <ErrorMessage error={add.error} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={add.isPending}>
            <KeyRound className="size-4" /> Create passkey
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function RenamePasskey({ passkey, onClose, onDone }: { passkey: Passkey; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(passkey.name);
  const rename = useMutation({
    mutationFn: () => api.renamePasskey(passkey.id, name),
    onSuccess: () => {
      onDone();
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title="Rename passkey">
      <form
        className="space-y-4"
        onSubmit={(event) => {
          event.preventDefault();
          rename.mutate();
        }}
      >
        <Field label="Name" value={name} onChange={(event) => setName(event.target.value)} maxLength={64} required data-autofocus />
        <ErrorMessage error={rename.error} />
        <div className="flex justify-end gap-2">
          <Button type="button" variant="secondary" onClick={onClose}>
            Cancel
          </Button>
          <Button type="submit" loading={rename.isPending}>
            Save
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

function RemovePasskey({ passkey, onClose, onDone }: { passkey: Passkey; onClose: () => void; onDone: () => void }) {
  const remove = useMutation({
    mutationFn: () => api.removePasskey(passkey.id),
    onSuccess: () => {
      onDone();
      onClose();
    },
  });
  return (
    <Dialog open onClose={onClose} title={`Remove ${passkey.name}?`}>
      <p className="text-sm text-slate-600 dark:text-slate-300">
        It no longer signs you in. Also delete it from the device or password manager that keeps it, which DeaconGuard can't do.
      </p>
      <ErrorMessage error={remove.error} />
      <div className="mt-5 flex justify-end gap-2">
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="danger" loading={remove.isPending} onClick={() => remove.mutate()}>
          <Trash2 className="size-4" /> Remove
        </Button>
      </div>
    </Dialog>
  );
}
