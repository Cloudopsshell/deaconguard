import { useMutation, useQueryClient } from "@tanstack/react-query";
import { api, type CheckId } from "../api";

/** Invalidates every query so dashboards, host lists, and details refresh together. */
export function useRefreshAll() {
  const client = useQueryClient();
  return () => client.invalidateQueries();
}

export function useStartScan() {
  const refresh = useRefreshAll();
  return useMutation({
    mutationFn: ({ hostId, checks }: { hostId: string; checks: CheckId[] }) => api.startScan(hostId, checks),
    onSettled: refresh,
  });
}
