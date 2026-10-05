/** Role names as the server reports them, and the convenience checks built on them. */
import { useSession } from "../security/SessionProvider";

export const role = {
  observer: "observer",
  investigator: "investigator",
  reader: "sensitive_evidence_reader",
  approver: "sensitive_evidence_approver",
  audit: "audit_administrator",
  policyApprover: "policy_approver",
} as const;

/**
 * `null` roles is the explicit local machine-login mode, where everything is offered. Hiding a
 * control is a courtesy; the server authorizes every call and its refusal is always shown.
 */
export function hasRole(roles: readonly string[] | null, name: string): boolean {
  return roles === null || roles.includes(name);
}

export type Roles = Readonly<{
  roles: readonly string[] | null;
  has: (name: string) => boolean;
  /** The signed-in subject; `null` for a machine credential, whose identity is unknown here. */
  subject: string | null;
  machine: boolean;
}>;

export function useRoles(): Roles {
  const { state } = useSession();
  const roles = state.roles;
  return {
    roles,
    has: (name) => hasRole(roles, name),
    subject: state.session?.subject ?? null,
    machine: state.session === null,
  };
}
