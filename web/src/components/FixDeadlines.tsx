import { useEffect, useState, type FormEvent } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, type SLA } from "../api";
import { Button, Card, CardHeader, ErrorMessage, Field } from "./ui";

const fields: { key: keyof Omit<SLA, "enabled">; label: string }[] = [
  { key: "exploited", label: "Known exploited" },
  { key: "critical", label: "Critical" },
  { key: "high", label: "High" },
  { key: "medium", label: "Medium" },
  { key: "low", label: "Low" },
];

/** Settings: how long a vulnerability may stay unfixed. */
export function FixDeadlines() {
  const queryClient = useQueryClient();
  const { data, error } = useQuery({ queryKey: ["sla"], queryFn: api.sla });
  const [sla, setSLA] = useState<SLA | null>(null);
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    if (data) setSLA(data);
  }, [data]);
  const save = useMutation({
    mutationFn: () => api.setSLA(sla!),
    onSuccess: () => {
      setSaved(true);
      queryClient.invalidateQueries();
    },
  });
  function submit(event: FormEvent) {
    event.preventDefault();
    setSaved(false);
    save.mutate();
  }
  if (!sla) return error ? <ErrorMessage error={error} /> : null;
  return (
    <Card className="mb-6">
      <CardHeader
        title="Fix deadlines"
        description="How many days a vulnerability may stay unfixed on a host, counted from the scan that first found it there. Known exploited ones get whichever deadline is sooner. Only those an update or a restart fixes can be overdue."
      />
      <form onSubmit={submit} className="space-y-4 px-5 py-5">
        <label className="flex items-center gap-2 text-sm font-medium">
          <input type="checkbox" className="accent-indigo-600" checked={sla.enabled} onChange={(event) => setSLA({ ...sla, enabled: event.target.checked })} />
          Track fix deadlines
        </label>
        {sla.enabled && (
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
            {fields.map((field) => (
              <Field
                key={field.key}
                label={`${field.label} (days)`}
                type="number"
                min={1}
                max={730}
                required
                value={sla[field.key]}
                onChange={(event) => setSLA({ ...sla, [field.key]: Number(event.target.value) })}
              />
            ))}
          </div>
        )}
        <ErrorMessage error={save.error} />
        <div className="flex items-center gap-3">
          <Button type="submit" variant="secondary" loading={save.isPending}>
            Save deadlines
          </Button>
          {saved && <span className="text-sm text-emerald-700 dark:text-emerald-400">Saved.</span>}
        </div>
      </form>
    </Card>
  );
}
