import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ImageUp, Trash2 } from "lucide-react";
import { api } from "../api";
import { Button, Card, CardHeader, ErrorMessage, Field, Loading, PageHeader } from "../components/ui";

/** Admin settings: how reports are branded. */
export function Settings() {
  const queryClient = useQueryClient();
  const branding = useQuery({ queryKey: ["branding"], queryFn: api.branding });
  const [company, setCompany] = useState("");
  const [contact, setContact] = useState("");
  const [saved, setSaved] = useState(false);
  const [logoVersion, setLogoVersion] = useState(0);
  const file = useRef<HTMLInputElement>(null);
  useEffect(() => {
    if (branding.data) {
      setCompany(branding.data.company);
      setContact(branding.data.contact);
    }
  }, [branding.data]);
  const refresh = (data: unknown) => {
    queryClient.setQueryData(["branding"], data);
    setLogoVersion((version) => version + 1);
  };
  const save = useMutation({ mutationFn: () => api.saveBranding(company, contact), onSuccess: (data) => (refresh(data), setSaved(true)) });
  const upload = useMutation({ mutationFn: api.uploadLogo, onSuccess: refresh });
  const remove = useMutation({ mutationFn: api.removeLogo, onSuccess: refresh });

  if (branding.isPending) return <Loading />;
  if (branding.error) return <ErrorMessage error={branding.error} />;

  function submit(event: FormEvent) {
    event.preventDefault();
    setSaved(false);
    save.mutate();
  }
  return (
    <>
      <PageHeader title="Settings" description="Settings for everyone using this server." />
      <Card className="mb-6">
        <CardHeader
          title="Notifications"
          description="Email, Slack, Teams or webhooks for newly exploited vulnerabilities, malware, failed scans, offline agents, and daily or weekly digests."
          action={
            <Link to="/notifications" className="text-sm font-medium text-indigo-600 hover:underline dark:text-indigo-400">
              Manage notifications
            </Link>
          }
        />
      </Card>
      <Card className="mb-6">
        <CardHeader
          title="Policies"
          description="Your organisation's own controls, tested in every audit next to the baseline."
          action={
            <Link to="/policies" className="text-sm font-medium text-indigo-600 hover:underline dark:text-indigo-400">
              Manage policies
            </Link>
          }
        />
      </Card>
      <Card>
        <CardHeader
          title="Reports"
          description="Every report you create shows your company's name, contact line and logo on its cover and in its footer. Reports made earlier keep what they had."
        />
        <form className="grid gap-6 px-5 py-5 lg:grid-cols-2" onSubmit={submit}>
          <div className="space-y-4">
            <Field label="Company name" maxLength={120} value={company} onChange={(event) => setCompany(event.target.value)} placeholder="CloudOpsShell Ltd" />
            <Field
              label="Contact line"
              hint="For example an email address and phone number."
              maxLength={200}
              value={contact}
              onChange={(event) => setContact(event.target.value)}
              placeholder="security@example.com · +44 20 0000 0000"
            />
            <div className="flex items-center gap-3">
              <Button type="submit" loading={save.isPending}>
                Save
              </Button>
              {saved && <span className="text-sm text-emerald-700 dark:text-emerald-400">Saved.</span>}
            </div>
            <ErrorMessage error={save.error} />
          </div>
          <div>
            <p className="text-sm font-medium">Logo</p>
            <div className="mt-2 flex h-28 items-center justify-center rounded-lg bg-white p-3 ring-1 ring-slate-200 dark:ring-slate-700">
              {branding.data.has_logo ? (
                <img src={`/api/settings/reports/logo?v=${logoVersion}`} alt="Report logo" className="max-h-full max-w-full object-contain" />
              ) : (
                <span className="text-sm text-slate-400">No logo</span>
              )}
            </div>
            <p className="mt-2 text-xs text-slate-500 dark:text-slate-400">A PNG or JPEG of at most 256 KB. A wide logo on a white or transparent background works best.</p>
            <input
              ref={file}
              type="file"
              accept="image/png,image/jpeg"
              className="sr-only"
              aria-label="Choose a logo"
              onChange={(event) => {
                const chosen = event.target.files?.[0];
                if (chosen) upload.mutate(chosen);
                event.target.value = "";
              }}
            />
            <div className="mt-3 flex gap-2">
              <Button type="button" variant="secondary" loading={upload.isPending} onClick={() => file.current?.click()}>
                <ImageUp className="size-4" /> {branding.data.has_logo ? "Replace logo" : "Upload logo"}
              </Button>
              {branding.data.has_logo && (
                <Button type="button" variant="ghost" loading={remove.isPending} onClick={() => remove.mutate()}>
                  <Trash2 className="size-4" /> Remove
                </Button>
              )}
            </div>
            <ErrorMessage error={upload.error ?? remove.error} />
          </div>
        </form>
      </Card>
    </>
  );
}
