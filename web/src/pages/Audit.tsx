import { useQuery } from "@tanstack/react-query";
import { ScrollText } from "lucide-react";
import { api } from "../api";
import { Card, EmptyState, ErrorMessage, Loading, PageHeader, Table, Td, Th, cx } from "../components/ui";
import { dateTime } from "../lib/format";

const actionLabels: Record<string, string> = {
  "user.login": "Signed in",
  "user.login_failed": "Failed sign-in",
  "user.logout": "Signed out",
  "user.add": "Added account",
  "user.passwd": "Changed password",
  "user.remove": "Removed account",
  "user.enable": "Enabled account",
  "user.disable": "Disabled account",
  "user.mfa_enable": "Turned on two-step sign-in",
  "user.mfa_disable": "Turned off two-step sign-in",
  "user.mfa_reset": "Reset two-step sign-in",
  "user.recovery_codes": "Created new recovery codes",
  "user.passkey_add": "Added a passkey",
  "user.passkey_rename": "Renamed a passkey",
  "user.passkey_remove": "Removed a passkey",
  "user.sessions_end": "Signed out sessions",
  "settings.require_mfa": "Require two-step sign-in",
  "settings.sso": "Changed single sign-on",
  "audit.start": "Started audit",
  "report.create": "Created report",
  "report.download": "Downloaded report",
  "report.delete": "Deleted report",
  "report.share": "Shared report link",
  "report.unshare": "Revoked report link",
  "report.share_view": "Opened shared report",
  "report.share_download": "Downloaded shared report",
  "settings.reports": "Changed report branding",
  "policy.add": "Added policy",
  "policy.update": "Changed policy",
  "policy.enable": "Turned on policy",
  "policy.disable": "Turned off policy",
  "policy.delete": "Deleted policy",
  "audit.accept": "Accepted a risk",
  "audit.unaccept": "Withdrew an accepted risk",
  "settings.audit_on_enroll": "Audit new machines on enrollment",
  "user.role": "Changed role",
  "token.create": "Created enrollment token",
  "token.revoke": "Revoked enrollment token",
  "agent.enroll": "Agent enrolled",
  "agent.enroll_failed": "Agent enrollment refused",
  "host.add": "Added host",
  "host.remove": "Removed host",
  "host.sudo": "Changed sudo setting",
  "scan.start": "Started scan",
  "scan.cancel": "Cancelled queued scan",
  "scan.delete": "Deleted scan",
  "schedule.create": "Created schedule",
  "schedule.update": "Changed schedule",
  "schedule.delete": "Deleted schedule",
  "schedule.run": "Ran schedule now",
  "logs.view": "Viewed the log",
  "logs.download": "Downloaded the log",
};

export function Audit() {
  const { data, error, isPending } = useQuery({ queryKey: ["audit"], queryFn: api.audit, refetchInterval: 30_000 });
  return (
    <>
      <PageHeader title="Audit log" description="Who signed in, enrolled agents, and started or removed what. Newest first." />
      <Card>
        {isPending ? (
          <Loading />
        ) : error ? (
          <div className="p-5">
            <ErrorMessage error={error} />
          </div>
        ) : data.length === 0 ? (
          <EmptyState icon={<ScrollText className="size-6" />} title="Nothing recorded yet" description="Actions appear here as they happen." />
        ) : (
          <Table>
            <thead>
              <tr>
                <Th>When</Th>
                <Th>Who</Th>
                <Th>Action</Th>
                <Th>Details</Th>
                <Th>From</Th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-200 dark:divide-slate-800">
              {data.map((entry) => (
                <tr key={entry.id}>
                  <Td className="text-sm whitespace-nowrap text-slate-600 dark:text-slate-300">{dateTime(entry.at)}</Td>
                  <Td className="text-sm font-medium">{entry.actor}</Td>
                  <Td>
                    <span
                      className={cx(
                        "text-sm",
                        entry.action.endsWith("_failed") && "font-medium text-red-700 dark:text-red-400",
                      )}
                    >
                      {actionLabels[entry.action] ?? entry.action}
                    </span>
                  </Td>
                  <Td className="text-sm text-slate-600 dark:text-slate-300">
                    {entry.target && <span className="font-medium">{entry.target}</span>}
                    {entry.target && entry.detail && " · "}
                    {entry.detail}
                  </Td>
                  <Td className="font-mono text-xs text-slate-500 dark:text-slate-400">{entry.remote || "—"}</Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Card>
    </>
  );
}
