/**
 * Role hints for the investigation pages. They only decide what the page offers or explains;
 * the server authorizes every request on its own. `null` is the local machine-login mode, where
 * the console cannot know the roles, so every action stays offered and the server answers.
 */
export type RoleSet = readonly string[] | null;

export function hasRole(roles: RoleSet, role: string): boolean {
  return roles === null || roles.includes(role);
}

/** Structured search, causality and "add to case" need Investigator. */
export const canSearch = (roles: RoleSet) => hasRole(roles, "investigator");

/** Request, model, agent and artifact detail reads need Observer. */
export const canObserve = (roles: RoleSet) => hasRole(roles, "observer");

/** Calibration report reads need AuditAdministrator. */
export const canAuditAdminister = (roles: RoleSet) => hasRole(roles, "audit_administrator");

export const ROLE_SEARCH_TEXT = "检索与因果查询需要 Investigator 角色，由服务端独立校验。";
export const ROLE_OBSERVER_TEXT = "详情读取需要 Observer 角色，由服务端独立校验。";
