/**
 * The page that owns a frozen write, so the workbench can send the operator there. Only fixed
 * path shapes with canonical IDs are recognised; anything else has no home and gets no link
 * (the exact retry still works from the workbench). Pure and unit-tested.
 */
import { uuid } from "../api-contract.ts";
import type { OperationSnapshot } from "../security/pending-operations.ts";

export type OperationHome = Readonly<{
  to: string;
  search?: Readonly<Record<string, string>>;
  label: string;
}>;

const site = "[A-Za-z0-9_.-]{1,128}";
const caseId = `case_${uuid}`;
const exact = (pattern: string) => new RegExp(`^/control/v1/${pattern}(?![\\s\\S])`);

const patterns = {
  siteCreate: exact("sites"),
  siteConfig: exact(`sites/(${site})/config`),
  siteRelease: exact(`sites/(${site})/(?:validate|apply|approve|rollback)`),
  site: exact(`sites/(${site})`),
  legacySiteConfig: exact("site-config"),
  caseCreate: exact("cases"),
  caseWrite: exact(`cases/(${caseId})/(items|close|analyze|holds)`),
  accessRequest: exact(`artifacts/artifact_${uuid}/access`),
  accessDecision: exact(`evidence-access-requests/(access_${uuid})/(?:approve|deny)`),
  exportRequest: exact("exports"),
  exportDecision: exact(`exports/(export_${uuid})/(?:approve|deny)`),
  holdRelease: exact(`evidence-holds/ev_${uuid}/release`),
  apiKeys: exact(`agent-api-keys(?:/key_${uuid}/(?:revoke|rotate))?`),
};

const caseTabs: Record<string, string> = {
  items: "evidence",
  close: "",
  analyze: "analysis",
  holds: "holds",
};

/** The `case_id` of a frozen JSON body, when it has a canonical one. */
function bodyCase(body: string | null): string | null {
  if (body === null) return null;
  try {
    const value: unknown = JSON.parse(body);
    if (typeof value !== "object" || value === null) return null;
    const id = (value as Record<string, unknown>).case_id;
    return typeof id === "string" && new RegExp(`^${caseId}$`).test(id) ? id : null;
  } catch {
    return null;
  }
}

export function operationHome(
  operation: Pick<OperationSnapshot, "method" | "path" | "body">,
): OperationHome | null {
  const { path } = operation;
  let match: RegExpExecArray | null = patterns.siteConfig.exec(path);
  if (match) return { to: `/sites/${match[1]}/overview`, label: "站点配置" };
  match = patterns.siteRelease.exec(path);
  if (match) return { to: `/sites/${match[1]}/releases`, label: "站点发布" };
  match = patterns.site.exec(path);
  if (match) {
    // A deleted site has no page left; its list is where the outcome shows.
    return operation.method === "DELETE"
      ? { to: "/sites", label: "受保护站点" }
      : { to: `/sites/${match[1]}/overview`, label: "站点配置" };
  }
  if (patterns.siteCreate.test(path) || patterns.legacySiteConfig.test(path)) {
    return { to: "/sites", label: "受保护站点" };
  }
  if (patterns.caseCreate.test(path)) return { to: "/cases", label: "案件工作台" };
  match = patterns.caseWrite.exec(path);
  if (match) {
    const tab = caseTabs[match[2] ?? ""] ?? "";
    return { to: `/cases/${match[1]}${tab ? `/${tab}` : ""}`, label: "案件详情" };
  }
  if (patterns.accessRequest.test(path)) {
    const owner = bodyCase(operation.body);
    return owner
      ? { to: `/cases/${owner}/access`, label: "案件访问申请" }
      : { to: "/cases", label: "案件工作台" };
  }
  match = patterns.accessDecision.exec(path) ?? patterns.exportDecision.exec(path);
  if (match?.[1]) return { to: "/approvals", search: { item: match[1] }, label: "审批中心" };
  if (patterns.exportRequest.test(path)) {
    const owner = bodyCase(operation.body);
    return owner
      ? { to: `/cases/${owner}/exports`, label: "案件导出" }
      : { to: "/cases", label: "案件工作台" };
  }
  if (patterns.holdRelease.test(path)) return { to: "/cases", label: "案件工作台" };
  if (patterns.apiKeys.test(path)) return { to: "/admin/api-keys", label: "API Key" };
  return null;
}
