import type { OperationSnapshot } from "../../security/pending-operations.ts";

const sitePath = (siteId: string) => `/control/v1/sites/${siteId}`;

export type WriteKind =
  | "create"
  | "save"
  | "validate"
  | "apply"
  | "approve"
  | "rollback"
  | "delete";

/** What a registered operation was, from the frozen method and path (labels are for people). */
export function operationKind(
  operation: Pick<OperationSnapshot, "method" | "path">,
): WriteKind | null {
  const { method, path } = operation;
  if (method === "POST" && path === "/control/v1/sites") return "create";
  const match = /^\/control\/v1\/sites\/[A-Za-z0-9_.-]{1,128}(?:\/([a-z]+))?$/.exec(path);
  if (!match) return null;
  const tail = match[1];
  if (method === "DELETE" && tail === undefined) return "delete";
  if (method === "PUT" && tail === "config") return "save";
  if (
    method === "POST" &&
    (tail === "validate" || tail === "apply" || tail === "approve" || tail === "rollback")
  ) {
    return tail;
  }
  return null;
}

/** Unresolved writes that belong to one site (or to the site being created). */
export function operationsOfSite(
  operations: readonly OperationSnapshot[],
  siteId: string | null,
  creating: boolean,
): OperationSnapshot[] {
  return operations.filter((operation) => {
    if (creating) return operation.method === "POST" && operation.path === "/control/v1/sites";
    return (
      siteId !== null &&
      (operation.path === sitePath(siteId) || operation.path.startsWith(`${sitePath(siteId)}/`))
    );
  });
}

export const writeKindLabel: Record<WriteKind, string> = {
  create: "创建站点",
  save: "保存配置",
  validate: "验证配置",
  apply: "应用配置",
  approve: "批准并应用",
  rollback: "回滚配置",
  delete: "删除站点",
};
