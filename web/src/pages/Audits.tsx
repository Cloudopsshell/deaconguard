import { Link } from "react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { ClipboardCheck } from "lucide-react";
import { api } from "../api";
import { Card, CardHeader, EmptyState, ErrorMessage, Loading, PageHeader, StatusBadge, Table, Td, Th } from "../components/ui";
import { GradeBadge } from "../lib/audit";
import { dateTime, isActive, timeAgo } from "../lib/format";
import { useCan } from "../lib/role";

/** Every audit, newest first, with the setting to audit machines as they enroll. */
export function Audits() {
  const { data, error, isPending } = useQuery({
    queryKey: ["audits"],
    queryFn: () => api.auditList(),
    refetchInterval: (query) => (query.state.data?.some((item) => isActive(item.status)) ? 3000 : 30_000),
  });
  return (
    <>
      <PageHeader
        title="Server audits"
        description="Full checks of a machine, graded A to F: for handing a new server over, or checking an existing one. Start one from a host's page."
      />
      <div className="space-y-6">
        <AuditOnEnroll />
        <Card>
          {isPending ? (
            <Loading />
          ) : error ? (
            <div className="p-5">
              <ErrorMessage error={error} />
            </div>
          ) : data.length === 0 ? (
            <EmptyState
              icon={<ClipboardCheck className="size-6" />}
              title="No audits yet"
              description="Open a host and choose Run audit. Audits are kept until someone deletes them."
            />
          ) : (
            <Table>
              <thead>
                <tr>
                  <Th>Grade</Th>
                  <Th>Host</Th>
                  <Th>Result</Th>
                  <Th>Audited</Th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
                {data.map((item) => (
                  <tr key={item.id} className="hover:bg-slate-50 dark:hover:bg-slate-800/50">
                    <Td>
                      <Link to={`/audits/${item.id}`} aria-label={`Audit of ${item.address}`}>
                        <GradeBadge grade={item.grade} />
                      </Link>
                    </Td>
                    <Td>
                      <Link to={`/audits/${item.id}`} className="font-medium text-indigo-600 hover:underline dark:text-indigo-400">
                        {item.address}
                      </Link>
                      <p className="text-xs text-slate-500 dark:text-slate-400">{item.os || "—"}</p>
                    </Td>
                    <Td>
                      {item.grade ? (
                        <span className="text-sm text-slate-600 dark:text-slate-300">
                          Score {item.score} · {item.failed} {item.failed === 1 ? "control" : "controls"} failed
                        </span>
                      ) : (
                        <StatusBadge status={item.status} />
                      )}
                    </Td>
                    <Td className="text-sm whitespace-nowrap text-slate-500 dark:text-slate-400">
                      <span title={dateTime(item.started_at)}>{timeAgo(item.started_at)}</span>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          )}
        </Card>
      </div>
    </>
  );
}

function AuditOnEnroll() {
  const canChange = useCan("admin");
  const queryClient = useQueryClient();
  const settings = useQuery({ queryKey: ["audit-settings"], queryFn: api.auditSettings });
  const toggle = useMutation({
    mutationFn: (on: boolean) => api.setAuditOnEnroll(on),
    onSettled: () => queryClient.invalidateQueries({ queryKey: ["audit-settings"] }),
  });
  const on = settings.data?.audit_on_enroll ?? false;
  return (
    <Card>
      <CardHeader
        title="Audit new machines when they enroll"
        description={
          on
            ? "On. Each machine is audited as soon as its agent enrolls, so a newly built server has an audit ready for its handover."
            : "Off. Turn it on to audit each machine as soon as its agent enrolls."
        }
        action={
          canChange && (
            <button
              type="button"
              role="switch"
              aria-checked={on}
              aria-label="Audit new machines when they enroll"
              disabled={settings.isPending || toggle.isPending}
              onClick={() => toggle.mutate(!on)}
              className={`relative inline-flex h-6 w-11 shrink-0 items-center rounded-full transition-colors disabled:opacity-60 ${on ? "bg-indigo-600" : "bg-slate-300 dark:bg-slate-700"}`}
            >
              <span className={`inline-block size-5 rounded-full bg-white shadow transition-transform ${on ? "translate-x-5.5" : "translate-x-0.5"}`} />
            </button>
          )
        }
      />
      {toggle.error && (
        <div className="px-5 pb-4">
          <ErrorMessage error={toggle.error} />
        </div>
      )}
    </Card>
  );
}
