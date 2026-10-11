import { useQuery } from "@tanstack/react-query";
import { api, type Role } from "../api";

const rank: Record<Role, number> = { viewer: 1, operator: 2, admin: 3 };

/**
 * The signed-in account's role. The local dashboard has no accounts, so it
 * can do everything. The server checks the role on every request; this only
 * decides what the dashboard offers.
 */
export function useRole(): Role {
  const { data } = useQuery({ queryKey: ["session"], queryFn: api.session, staleTime: 60_000 });
  if (data && !data.login_required) return "admin";
  return data?.role ?? "viewer";
}

/** Whether the signed-in account may do what needs at least the role needed. */
export function useCan(needed: Role) {
  return rank[useRole()] >= rank[needed];
}
