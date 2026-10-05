/**
 * Plain-language names for the closed vocabularies that appear on request and event DTOs. A value
 * the table does not know is shown as received, never guessed.
 */

export type Named = Readonly<{ label: string; known: boolean }>;

function lookup(table: Readonly<Record<string, string>>, value: string | null | undefined): Named {
  if (value === null || value === undefined || value === "") {
    return { label: "未记录", known: false };
  }
  const label = Object.hasOwn(table, value) ? table[value] : undefined;
  return label === undefined ? { label: value, known: false } : { label, known: true };
}

/**
 * Pipeline stages. The first group is what the gateway writes today; the second is the
 * historical vocabulary of older records and fixtures; the third are lifecycle families that show
 * up in search results.
 */
const stages: Readonly<Record<string, string>> = {
  operation_admission: "操作准入",
  crypto_decode: "请求解密",
  crypto_encode: "响应加密",
  evidence_capture: "证据采集",
  sensor_html_inject: "传感器注入",
  ui_semantic_match: "界面语义匹配",
  grant: "资格签发",
  response_grant: "响应资格签发",
  share_grant: "分享资格签发",
  model_eval: "模型判别",
  site_config: "站点配置",
  identity_bind: "身份绑定",
  ui_provenance: "界面来源",
  capability: "资源资格",
  baseline_inspection: "基础 WAF 检查",
  origin_forward: "源站转发",
  admission: "准入检查",
  auth_binding: "认证绑定",
  ui_action: "界面来源",
  terminal: "请求终态",
  origin: "源站交互",
  identity_lifecycle: "身份生命周期",
  control_access: "管理访问",
  case_management: "案件管理",
  evidence_access: "证据访问申请",
  evidence_access_decision: "证据访问决策",
  evidence_catalog: "证据目录",
  evidence_hold: "证据保留锁",
  evidence_retention: "证据保留清理",
  calibration_report: "校准报告",
  calibration_evidence_read: "校准证据读取",
};

export function stageName(stage: string | null | undefined): Named {
  return lookup(stages, stage);
}

const eventTypes: Readonly<Record<string, string>> = {
  "request.accepted": "请求受理",
  "stage.completed": "阶段完成",
  "stage.skipped": "阶段跳过",
  "decision.composed": "判定合成",
  "origin.forward_intent": "转发意图",
  "origin.response": "源站响应",
  "origin.unknown": "源站结果未知",
  "request.completed": "请求完成",
  "request.aborted": "请求中止",
  "audit.recovered": "审计恢复",
  "sensor.observation": "传感器观察",
  "model.started": "模型调用开始",
  "model.requested": "模型请求已发出",
  "model.cache_hit": "模型缓存命中",
  "model.responded": "模型已响应",
  "model.failed": "模型调用失败",
  "model.timeout": "模型调用超时",
  "model.cancelled": "模型调用取消",
  "grant.issued": "资格签发",
  "response_grant.issued": "响应资格签发",
  "share.issued": "分享资格签发",
  "agent.started": "Agent 启动",
  "agent.tool_called": "Agent 调用工具",
  "agent.tool_result": "Agent 工具返回",
  "agent.artifact_created": "Agent 产出证据",
  "agent.finished": "Agent 结束",
  "evidence.deleted": "证据删除",
};

export function eventTypeName(eventType: string | null | undefined): Named {
  return lookup(eventTypes, eventType);
}

const proofKinds: Readonly<Record<string, string>> = {
  deterministic: "确定性规则",
  model: "模型判别",
  observation: "观察记录",
  none: "无证明",
};

export function proofKindName(kind: string | null | undefined): Named {
  return lookup(proofKinds, kind);
}

const confidenceStates: Readonly<Record<string, string>> = {
  provided: "已提供",
  not_applicable: "不适用",
  not_provided: "未提供",
  unavailable: "不可用",
};

export function confidenceStateName(state: string | null | undefined): Named {
  return lookup(confidenceStates, state);
}

/**
 * The confidence cell: a number only when the server provided one, otherwise the availability
 * state in words. A deterministic rule or a Noul question never shows a number.
 */
export function confidenceText(
  confidence: number | null | undefined,
  state: string | null | undefined,
): string {
  if (typeof confidence === "number") return String(confidence);
  if (state === "not_applicable") return "无置信度（不适用）";
  if (state === "unavailable") return "置信度不可用";
  if (state === "not_provided") return "置信度未提供";
  return "未记录";
}

const sensitivities: Readonly<Record<string, string>> = {
  PUBLIC: "公开",
  INTERNAL: "内部",
  SENSITIVE: "敏感",
  RESTRICTED: "受限",
};

export function sensitivityName(value: string | null | undefined): Named {
  return lookup(sensitivities, value);
}

const captureStates: Readonly<Record<string, string>> = {
  complete: "已采集",
  entity_exact: "实体精确",
  semantic: "语义保真",
  redacted: "已脱敏",
  INTERNAL: "内部",
  SENSITIVE: "敏感",
  RESTRICTED: "受限",
};

/** Evidence capture status, fidelity and classification share one small vocabulary. */
export function captureName(value: string | null | undefined): Named {
  return lookup(captureStates, value);
}

const originStates: Readonly<Record<string, string>> = {
  not_sent: "未转发到源站",
  unknown: "源站结果未知",
  response_received: "已收到源站响应",
};

export function originStateName(value: string | null | undefined): Named {
  return lookup(originStates, value);
}

const modelStatuses: Readonly<Record<string, string>> = {
  started: "已开始",
  requested: "已请求",
  success: "已响应",
  error: "失败",
  timeout: "超时",
  cancelled: "已取消",
};

export function modelStatusName(value: string | null | undefined): Named {
  return lookup(modelStatuses, value);
}

const questionTypes: Readonly<Record<string, string>> = {
  choice: "选择题（choice）",
  score: "评分（score）",
  noul: "Noul（无置信度）",
};

export function questionTypeName(value: string | null | undefined): Named {
  return lookup(questionTypes, value);
}

/** Agent lifecycle events and request events both use these outcome words. */
const outcomes: Readonly<Record<string, string>> = {
  PASS: "通过",
  ALLOW: "放行",
  DENY: "拒绝",
  UNKNOWN: "未知",
  ERROR: "错误",
  SKIPPED: "已跳过",
  CANCELLED: "已取消",
  not_sent: "未转发",
  unknown: "结果未知",
  response_received: "已收到响应",
};

export function outcomeName(value: string | null | undefined): Named {
  return lookup(outcomes, value);
}
