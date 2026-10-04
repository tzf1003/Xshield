/** One vocabulary for the state pills of cases, evidence, access requests, exports and holds. */
import type { CaseItem } from "../cases.ts";
import type { AccessStatus } from "../evidence-access.ts";
import type { ExportStatus } from "../exports.ts";
import type { JobView } from "../jobs.ts";

export type Tone = "success" | "warning" | "error" | "processing" | "default";
export type Pill = Readonly<{ label: string; tone: Tone; hint: string }>;

export const casePill: Record<"open" | "closed", Pill> = {
  open: { label: "开放", tone: "success", hint: "案件开放：可以关联证据、申请原文访问和导出。" },
  closed: {
    label: "已关闭",
    tone: "default",
    hint: "案件已关闭：历史引用仍可浏览，不能新增关联或申请原文访问；仍可申请导出。",
  },
};

export const accessPill: Record<AccessStatus, Pill> = {
  pending: { label: "待审批", tone: "warning", hint: "等待另一位具备审批权限的主体决定。" },
  approved: {
    label: "已批准",
    tone: "success",
    hint: "已批准。每次下载仍由服务端重新校验期限、案件与证据状态，并要求 MFA 再认证。",
  },
  denied: { label: "已拒绝", tone: "error", hint: "申请已被拒绝，不产生读取资格。" },
  expired: { label: "已过期", tone: "default", hint: "读取资格已过期。" },
  revoked: { label: "已撤销", tone: "default", hint: "读取资格已被撤销。" },
};

const exportPills: Record<ExportStatus, Pill> = {
  pending_approval: {
    label: "待审批",
    tone: "warning",
    hint: "等待另一位具备审批权限的主体决定。",
  },
  approved: {
    label: "已批准·生成中",
    tone: "processing",
    hint: "已批准，元数据包尚未完成；原批准人可用原请求确认结果。",
  },
  ready: { label: "可下载", tone: "success", hint: "元数据包已就绪，期限内最多可领取 2 次。" },
  rejected: { label: "已拒绝", tone: "error", hint: "导出申请已被拒绝。" },
  expired: { label: "已过期", tone: "default", hint: "导出包期限已过。" },
  failed: { label: "生成失败", tone: "error", hint: "导出包生成失败。" },
};

/** An approved or ready export past its expiry (judged at the database observation time). */
export function exportLapsed(
  item: { status: ExportStatus; expires_at: string | null },
  asOfMs: number,
): boolean {
  if (item.status !== "approved" && item.status !== "ready") return false;
  if (item.expires_at === null || !Number.isFinite(asOfMs)) return false;
  return Date.parse(item.expires_at) <= asOfMs;
}

export function exportPill(status: ExportStatus, lapsed = false): Pill {
  if (lapsed) {
    return {
      label: "已过期",
      tone: "default",
      hint: "导出包期限已过（按观察时间判断），不能再下载。",
    };
  }
  return exportPills[status];
}

export const catalogPill: Record<CaseItem["catalog_status"], Pill> = {
  active: {
    label: "目录有效",
    tone: "success",
    hint: "证据目录有效且未到期。目录状态不证明读取权。",
  },
  expired: {
    label: "已到期",
    tone: "warning",
    hint: "证据按期限已到期，引用仍保留；不能再新建原文访问申请。",
  },
  deleted: { label: "已删除", tone: "error", hint: "证据已被物理删除，仅保留引用与历史。" },
  unavailable: {
    label: "目录不可用",
    tone: "default",
    hint: "服务端未返回该证据的目录状态，不能据此判断内容是否存在。",
  },
};

export type HoldState = "active" | "expired" | "released";
export const holdPill: Record<HoldState, Pill> = {
  active: { label: "保留生效中", tone: "success", hint: "保留锁生效，推迟证据的物理删除。" },
  expired: {
    label: "保留期限已过",
    tone: "warning",
    hint: "保留期限已过但尚未释放，证据可能按原期限被清理。",
  },
  released: { label: "已释放", tone: "default", hint: "保留锁已被管理员释放。" },
};

export const jobPill: Record<JobView["status"], Pill> = {
  queued: { label: "排队中", tone: "default", hint: "任务已受理，等待执行。" },
  running: { label: "运行中", tone: "processing", hint: "任务正在执行。" },
  succeeded: { label: "已完成", tone: "success", hint: "任务已完成。" },
  failed: { label: "失败", tone: "error", hint: "任务失败，见原因码。" },
  cancelled: { label: "已取消", tone: "default", hint: "任务已取消。" },
};
