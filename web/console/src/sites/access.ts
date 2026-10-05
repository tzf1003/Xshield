/**
 * What the signed-in roles may attempt on a site. This only decides what is *offered*; the
 * server authorizes every call independently (and answers 403 for anything else), exactly as
 * the previous pages did:
 *
 *  - SystemAdmin edits configuration and reads it;
 *  - Observer reads status, health and revisions;
 *  - PolicyAuthor validates, PolicyApprover approves, ReleaseOperator applies and rolls back.
 *
 * `roles === null` is the explicit local machine-login mode, which offers every action.
 */
export type SiteAccess = Readonly<{
  machine: boolean;
  canConfigure: boolean;
  canObserve: boolean;
  canValidate: boolean;
  canApprove: boolean;
  canApply: boolean;
  /** Any of validate, approve, apply or roll back. */
  canRelease: boolean;
}>;

export function siteAccess(roles: readonly string[] | null): SiteAccess {
  const has = (role: string) => roles === null || roles.includes(role);
  const canValidate = has("policy_author");
  const canApprove = has("policy_approver");
  const canApply = has("release_operator");
  return {
    machine: roles === null,
    canConfigure: has("system_admin"),
    canObserve: has("observer"),
    canValidate,
    canApprove,
    canApply,
    canRelease: canValidate || canApprove || canApply,
  };
}
