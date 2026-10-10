import { Link } from "react-router";
import { useQuery } from "@tanstack/react-query";
import { Logs } from "lucide-react";
import { api, type HostDetail } from "../api";
import { LogTable } from "./LogTable";
import { Card, CardHeader, EmptyState, ErrorMessage, Loading } from "./ui";

/** Agents send their own log from this version on. */
function sendsLogs(version: string | undefined) {
  const match = /^(\d+)\.(\d+)/.exec(version ?? "");
  if (!match) return version !== undefined && version !== "";
  const [major, minor] = [Number(match[1]), Number(match[2])];
  return major > 0 || minor >= 6;
}

/** The newest log entries about one machine: the server's and its agent's. */
export function HostLog({ host }: { host: HostDetail }) {
  const logs = useQuery({
    queryKey: ["logs", { host: host.id, limit: 25 }],
    queryFn: () => api.logs({ host: host.id, limit: 25 }),
    refetchInterval: 10_000,
  });
  const agent = host.transport === "agent";
  return (
    <Card className="mt-6">
      <CardHeader
        title="Log"
        description={
          agent
            ? "What the server and this machine's agent did, newest first."
            : "What the server did for this machine, newest first."
        }
        action={
          <Link to={`/logs?host=${host.id}`} className="text-sm font-medium text-indigo-600 hover:underline dark:text-indigo-400">
            Open in Logs
          </Link>
        }
      />
      {agent && !sendsLogs(host.agent?.version) && (
        <p className="border-b border-slate-200 px-5 py-2.5 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
          The agent here runs {host.agent?.version ?? "an older version"}, which keeps its log in the machine's journal only. Upgrade it to
          0.6.0 or later to see its log here: <code className="font-mono">curl -fsSL https://get.deaconguard.io | sudo sh -</code>
        </p>
      )}
      {logs.isPending ? (
        <Loading />
      ) : logs.error ? (
        <div className="p-5">
          <ErrorMessage error={logs.error} />
        </div>
      ) : logs.data.entries.length === 0 ? (
        <EmptyState icon={<Logs className="size-6" />} title="Nothing logged yet" description="Entries appear as scans run and the agent connects." />
      ) : (
        <LogTable entries={logs.data.entries} showHost={false} />
      )}
    </Card>
  );
}
