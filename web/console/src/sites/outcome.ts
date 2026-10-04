import type {
  SiteApplyResponse,
  SiteConfigResponse,
  SiteDeleteResponse,
  SiteValidationResponse,
} from "../api.ts";
import { reasonText } from "../ui/reason-codes.ts";
import type { WriteKind } from "./state/write-kinds.ts";

/** What the page tells the operator after a write the server confirmed. */
export type Outcome = Readonly<{
  tone: "success" | "info" | "warning";
  title: string;
  detail: string | null;
}>;

type StateFacts = Readonly<{
  apply_state: "active" | "pending" | "failed" | "paused" | null;
  requires_approval: boolean | null;
  desired_revision: number | null;
  active_revision: number | null;
  reason_code: string | null;
}>;

/** One honest sentence about where the change stands: staged, awaiting approval, live, failed. */
export function standing(facts: StateFacts, status: "draft" | "active" | "paused" | null): string {
  const served =
    facts.active_revision === null
      ? "edge 目前没有服务该站点"
      : `edge 仍在服务 r${facts.active_revision}`;
  if (facts.apply_state === "failed") {
    return `应用失败：${reasonText(facts.reason_code).text}${served}。`;
  }
  if (facts.requires_approval === true) {
    return `这次变更需要独立审批后才会应用；${served}。`;
  }
  if (status === "draft") return "草稿不会发布到 edge。";
  if (facts.apply_state === "active")
    return `edge 已确认 r${facts.active_revision ?? facts.desired_revision}。`;
  if (facts.apply_state === "paused") return "站点已暂停，edge 不对外服务。";
  if (facts.apply_state === "pending") return `等待 edge 确认；${served}。`;
  return "";
}

export function describeSave(response: SiteConfigResponse, created: boolean): Outcome {
  const facts: StateFacts = {
    apply_state: response.apply_state,
    requires_approval: response.requires_approval,
    desired_revision: response.desired_revision,
    active_revision: response.active_revision,
    reason_code: response.reason_code,
  };
  const failed = response.apply_state === "failed";
  return {
    tone: failed ? "warning" : response.requires_approval ? "info" : "success",
    title: `${created ? "站点已创建，" : ""}已保存为 r${response.desired_revision ?? "?"}。`,
    detail: standing(facts, response.config?.status ?? null) || null,
  };
}

export function describeValidation(response: SiteValidationResponse): Outcome {
  return response.valid
    ? {
        tone: "success",
        title: `配置验证通过：已保存的 r${response.revision} 通过服务端校验。`,
        detail: null,
      }
    : {
        tone: "warning",
        title: `配置验证未通过：${reasonText(response.reason_code).text}`,
        detail: reasonText(response.reason_code).action,
      };
}

export function describeApply(
  kind: "apply" | "approve" | "rollback",
  response: SiteApplyResponse,
): Outcome {
  const facts: StateFacts = response;
  const verb =
    kind === "approve" ? "已批准" : kind === "rollback" ? "已回滚（创建了新修订）" : "已提交应用";
  const failed = response.apply_state === "failed";
  return {
    tone: failed ? "warning" : response.apply_state === "active" ? "success" : "info",
    title: `${verb}：当前暂存 r${response.desired_revision}。`,
    detail: standing(facts, response.apply_state === "paused" ? "paused" : null) || null,
  };
}

export function describeDelete(response: SiteDeleteResponse): Outcome {
  const title = "站点已删除，监听端口已释放。";
  const detail = reasonText(response.reason_code).text;
  return { tone: "success", title, detail: detail === title ? null : detail };
}

export const writeFailureTitle: Record<WriteKind, string> = {
  create: "创建站点没有成功",
  save: "保存没有成功",
  validate: "验证没有完成",
  apply: "应用没有成功",
  approve: "批准没有成功",
  rollback: "回滚没有成功",
  delete: "删除没有成功",
};
