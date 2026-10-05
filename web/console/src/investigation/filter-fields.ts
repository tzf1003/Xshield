import { sharePattern } from "../api-contract.ts";
import { normalizePaste, recognise } from "../shell/palette-classifier.ts";
import { filterAccepted, type SearchPresetKind } from "./search-preset.ts";

/**
 * The allowlisted conditions of structured event search, as the form presents them. The server
 * accepts exactly these kinds (docs/29 §29.14); this table only adds the words and the input
 * style, and `filterAccepted` (the validator) still decides what is valid.
 */
export type FieldInput = "id" | "text" | "subject" | "outcome" | "basis_points";

export type FieldDef = Readonly<{
  id: FilterField;
  label: string;
  input: FieldInput;
  placeholder: string;
  /** What the condition matches, shown under the input. */
  hint: string;
  /** Extra role the server demands for this condition, shown as a caution. */
  needs?: string;
}>;

export const textFields = [
  "event_type",
  "stage",
  "reason_code",
  "operation_id",
  "model_revision",
] as const;

export type FilterField =
  | SearchPresetKind
  | "subject_ref"
  | (typeof textFields)[number]
  | "outcome"
  | "confidence_at_most";

const id = (
  field: FilterField,
  label: string,
  placeholder: string,
  hint: string,
  needs?: string,
): FieldDef => ({ id: field, label, input: "id", placeholder, hint, needs });

export const filterFields: readonly FieldDef[] = [
  id("request_id", "请求 ID", "req_…", "该请求的全部事件。"),
  id("event_id", "事件 ID", "ev_…", "精确定位一个已发布事件。"),
  id("trace_id", "Trace ID", "32 位小写十六进制", "同一 Trace 的事件，不据此推断身份或资格。"),
  id("caused_by_event_id", "前驱事件 ID", "ev_…", "把该事件记录为直接前驱的事件（只查直接关联）。"),
  id("grant_id", "资格 ID", "grant_…", "资格签发、分享签发与账本读取历史。"),
  id("auth_binding_id", "身份绑定 ID", "auth_…", "绑定创建、刷新、撤销与账本读取历史。"),
  {
    id: "subject_ref",
    label: "主体引用",
    input: "subject",
    placeholder: "1–256 字节，不含控制字符",
    hint: "仅用于精确筛选；结果与已提交计划都不会回显该值。",
  },
  id("case_id", "案件 ID", "case_…", "引用该案件的固定事件。"),
  id("artifact_id", "证据 ID", "artifact_…", "evidence_refs 含该证据的事件。"),
  id(
    "calibration_report_id",
    "校准报告 ID",
    "calr_…",
    "报告发布、保留维护与读取历史。",
    "AuditAdministrator",
  ),
  id("evidence_access_request_id", "访问申请 ID", "access_…", "申请与决策历史。"),
  id("evidence_hold_id", "保留锁 ID", "ev_…", "保留锁创建、释放与管理历史。", "AuditAdministrator"),
  id("model_call_id", "模型调用 ID", "mdl_…", "模型生命周期与详情读取历史。"),
  id("agent_run_id", "Agent 运行 ID", "agt_…", "Agent 固定生命周期事件。"),
  id("job_id", "任务 ID", "job_…", "任务读取的管理历史。"),
  id("share_grant_id", "分享资格 ID", "share_…", "分享资格签发事件，不含分享凭证。"),
  {
    id: "event_type",
    label: "事件类型",
    input: "text",
    placeholder: "例如 request.completed",
    hint: "精确文本，字母、数字与 _ . : - 。",
  },
  {
    id: "stage",
    label: "阶段",
    input: "text",
    placeholder: "例如 operation_admission",
    hint: "精确文本，字母、数字与 _ . : - 。",
  },
  {
    id: "reason_code",
    label: "原因码",
    input: "text",
    placeholder: "例如 UI_ACTION_NOT_AVAILABLE",
    hint: "精确文本，字母、数字与 _ . : - 。",
  },
  {
    id: "operation_id",
    label: "操作 ID",
    input: "text",
    placeholder: "例如 orders.read",
    hint: "精确文本，字母、数字与 _ . : - 。",
  },
  {
    id: "model_revision",
    label: "模型版本",
    input: "text",
    placeholder: "例如 jev-1.13.0",
    hint: "精确文本，字母、数字与 _ . : - 。",
  },
  {
    id: "outcome",
    label: "结果",
    input: "outcome",
    placeholder: "",
    hint: "PASS / ALLOW / DENY / UNKNOWN / ERROR / SKIPPED / CANCELLED。",
  },
  {
    id: "confidence_at_most",
    label: "置信度上限（基点）",
    input: "basis_points",
    placeholder: "0–10000 的整数",
    hint: "仅匹配有数值置信度的事件；规则事件的空置信度不会匹配。",
  },
];

const byId: ReadonlyMap<FilterField, FieldDef> = new Map(
  filterFields.map((field) => [field.id, field]),
);

export function fieldDef(field: FilterField): FieldDef {
  return byId.get(field) ?? (filterFields[0] as FieldDef);
}

export const outcomeValues = [
  "PASS",
  "ALLOW",
  "DENY",
  "UNKNOWN",
  "ERROR",
  "SKIPPED",
  "CANCELLED",
] as const;

/** The conditions of one form: AND-combined on the same event, at most this many. */
export const MAX_CONDITIONS = 8;

export type Condition = { id: number; field: FilterField; value: string };

/** The wire filter for a draft condition. Validation happens in `validateSearchPlan`. */
export function conditionToFilter(condition: Pick<Condition, "field" | "value">): unknown {
  const { field, value } = condition;
  if (field === "confidence_at_most") {
    return { kind: field, basis_points: value.trim() === "" ? Number.NaN : Number(value) };
  }
  if ((textFields as readonly string[]).includes(field)) return { kind: "text", field, value };
  return { kind: field, value };
}

/** Why a draft condition cannot be added, or null when the validator accepts it. */
export function conditionProblem(condition: Pick<Condition, "field" | "value">): string | null {
  if (condition.value.trim() === "") return "请填写条件的值。";
  if (filterAccepted(conditionToFilter(condition))) return null;
  const def = fieldDef(condition.field);
  switch (def.input) {
    case "id":
      return `${def.label}格式无效：须为小写规范 ID（${def.placeholder}）。`;
    case "text":
      return "只允许字母、数字与 _ . : - ，且不超过 128 个字符。";
    case "subject":
      return "主体引用须为 1–256 个 UTF-8 字节，且不含控制字符。";
    case "basis_points":
      return "请输入 0–10000 的整数。";
    case "outcome":
      return "请选择有效的结果。";
  }
}

export type Detection = Readonly<{
  /** The field to use; the first of `alternatives`. */
  field: FilterField;
  /** Fields that share this ID shape (an `ev_` ID is an event and a retention lock). */
  alternatives: readonly FilterField[];
  noun: string;
}>;

const byPrefix: Readonly<Record<string, readonly FilterField[]>> = {
  req: ["request_id"],
  mdl: ["model_call_id"],
  agt: ["agent_run_id"],
  grant: ["grant_id"],
  auth: ["auth_binding_id"],
  calr: ["calibration_report_id"],
  case: ["case_id"],
  access: ["evidence_access_request_id"],
  job: ["job_id"],
  artifact: ["artifact_id"],
  share: ["share_grant_id"],
  ev: ["event_id", "evidence_hold_id"],
};

/**
 * Picks the condition field for a pasted value. The shell's classifier decides whether the text
 * is a canonical ID (exact prefix, lowercase UUIDv7 or a 32-hex Trace ID); this only maps the
 * recognised kind to the search field. Anything else, including a malformed ID, is not detected.
 */
export function detectField(raw: string): Detection | null {
  const value = normalizePaste(raw);
  if (value === "") return null;
  if (sharePattern.test(value)) {
    return { field: "share_grant_id", alternatives: ["share_grant_id"], noun: "分享资格 ID" };
  }
  const recognised = recognise(value);
  if (!recognised) return null;
  if (recognised.noun === "Trace ID") {
    return { field: "trace_id", alternatives: ["trace_id"], noun: recognised.noun };
  }
  const prefix = value.slice(0, value.indexOf("_"));
  const fields = byPrefix[prefix];
  if (!fields?.[0]) return null;
  return { field: fields[0], alternatives: fields, noun: recognised.noun };
}
