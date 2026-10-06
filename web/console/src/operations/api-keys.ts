/**
 * Agent API keys as the console presents them: the capability catalogue in plain words, the
 * issuer rules, and the checks a create or rotate request must pass before it is frozen and sent.
 * The checks mirror the server's 400 rules (`management_api_key.rs`) so an operator learns about
 * a malformed request here, not from an audited refusal; the issuer rule (403
 * CONTROL_API_KEY_SCOPE_FORBIDDEN) is only a warning, because the server knows the session's
 * exact scopes and the console does not. Pure and unit-tested (tests/api-keys-model.test.ts).
 */
import type { ManagementApiKeyRecord } from "../api.ts";

/** Reserved site ID of the tenant-wide row; it carries `site.create` and nothing else. */
export const TENANT_WIDE = "__tenant__";
export const SCOPES_MAX = 32;
/** The server accepts expiries up to 90 days ahead of its own clock. */
export const EXPIRY_MAX_MS = 90 * 24 * 60 * 60 * 1000;
/**
 * Room for the browser clock to run ahead of the server's: a preset or custom expiry stays this
 * far inside the 90-day limit, and at least this far in the future.
 */
export const EXPIRY_MARGIN_MS = 10 * 60 * 1000;

export type Capability =
  | "site.read"
  | "site.health.read"
  | "site.config.write"
  | "site.config.validate"
  | "site.config.apply_direct"
  | "site.rollback"
  | "site.create";

export type CapabilityInfo = Readonly<{
  name: Capability;
  label: string;
  /** What a key with it can do, in plain words. */
  description: string;
  /** Roles the issuing session must hold on the site (or tenant) to grant it. */
  issuerRoles: readonly string[];
  /** `site.create` is granted on the tenant-wide row only. */
  tenantWide: boolean;
}>;

export const capabilityCatalog: readonly CapabilityInfo[] = [
  {
    name: "site.read",
    label: "读取站点",
    description: "列出站点，读取配置、状态、修订和工作台快照（只含持有该能力的站点）。",
    issuerRoles: ["system_admin", "observer"],
    tenantWide: false,
  },
  {
    name: "site.health.read",
    label: "读取健康",
    description: "读取站点健康观察；每次读取都会在服务端写入一条审计与观察记录。",
    issuerRoles: ["observer"],
    tenantWide: false,
  },
  {
    name: "site.config.write",
    label: "修改配置",
    description: "为已存在的站点保存新的配置修订；不能创建站点，是否需要审批照常由服务端判断。",
    issuerRoles: ["system_admin"],
    tenantWide: false,
  },
  {
    name: "site.config.validate",
    label: "校验配置",
    description: "对已保存的配置执行服务端校验，不改变任何东西。",
    issuerRoles: ["policy_author"],
    tenantWide: false,
  },
  {
    name: "site.config.apply_direct",
    label: "直接应用",
    description:
      "不经另一位审批人，直接把待审批的修订发布到 edge；改变浏览器来源流程（认证入口、SENSOR_HTML 页面、页面签发动作、资源资格）的修订除外，它们只能由独立审批人批准。",
    issuerRoles: ["release_operator", "policy_approver"],
    tenantWide: false,
  },
  {
    name: "site.rollback",
    label: "回滚",
    description: "以先前生效的修订创建新修订；新修订仍按审批规则评估。",
    issuerRoles: ["release_operator"],
    tenantWide: false,
  },
  {
    name: "site.create",
    label: "创建站点",
    description: "在租户内新建站点；不能读取、改写或覆盖已存在的站点。",
    issuerRoles: ["system_admin"],
    tenantWide: true,
  },
];

const byName = new Map(capabilityCatalog.map((info) => [info.name, info]));

export function capabilityInfo(name: string): CapabilityInfo | null {
  return byName.get(name as Capability) ?? null;
}

/** What `site.config.apply_direct` means for approvals, shown next to its checkbox. */
export const applyDirectWarning =
  "勾选后，这把 Key 可以跳过“另一位审批人批准”，把需要审批的高风险修订直接发布到 edge。每次直接应用都会以 Key ID 与 Agent 主体写入审批记录和审计（EDGE_DIRECT_APPLY_CONFIRMED），但不会再有第二个人看过这次变更。改变浏览器来源流程（认证入口、SENSOR_HTML 页面、页面签发动作、资源资格）的修订不在此列：服务端以 CONTROL_SITE_INDEPENDENT_APPROVAL_REQUIRED 拒绝，什么也不发布，只能由独立审批人批准。只在确有自动化发布需求时授予。";

export type ScopeRow = Readonly<{
  /** Local row identity for the editor; never sent. */
  id: string;
  target: "site" | "tenant";
  siteId: string;
  capabilities: readonly Capability[];
}>;

export type ExpiryChoice =
  | Readonly<{ kind: "preset"; days: 7 | 30 | 90 }>
  /** A `datetime-local` value, read in the browser's zone. */
  | Readonly<{ kind: "custom"; local: string }>;

export type KeyDraft = Readonly<{
  displayName: string;
  subject: string;
  expiry: ExpiryChoice;
  scopes: readonly ScopeRow[];
}>;

/** The request body of `POST /agent-api-keys` and `/rotate`, exactly as the server takes it. */
export type KeyRequest = Readonly<{
  subject: string;
  display_name: string;
  expires_at: string;
  scopes: readonly Readonly<{ tenant_id: string; site_id: string; capabilities: string[] }>[];
}>;

const subjectPattern = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/;
const sitePattern = /^[A-Za-z0-9_.-]{1,128}$/;
// Control characters, zero-width and bidirectional overrides: the server refuses all of them.
const hiddenCharacter = /[\p{Cc}​-‏‪-‮⁠-⁤⁦-⁩﻿]/u;
const edgeSpace = /^\s|\s$/u;

export function subjectProblem(value: string): string | null {
  if (value.length === 0) return "请填写 Agent 主体";
  if (value.length > 128) return "Agent 主体最多 128 个字符";
  if (!/^[A-Za-z0-9]/.test(value)) return "Agent 主体须以字母或数字开头";
  if (!subjectPattern.test(value)) return "Agent 主体只能使用 ASCII 字母、数字和 . _ : @ / -";
  return null;
}

export function displayNameProblem(value: string): string | null {
  if (value.length === 0) return "请填写名称";
  if ([...value].length > 128) return "名称最多 128 个字符";
  if (hiddenCharacter.test(value)) return "名称不能包含控制、零宽或双向覆盖字符";
  if (edgeSpace.test(value)) return "名称首尾不能有空白";
  return null;
}

/** The instant a choice stands for, or why it cannot be used. */
export function expiryInstant(
  choice: ExpiryChoice,
  nowMs: number,
): { ms: number; problem: null } | { ms: null; problem: string } {
  const latest = nowMs + EXPIRY_MAX_MS - EXPIRY_MARGIN_MS;
  if (choice.kind === "preset") {
    return { ms: Math.min(nowMs + choice.days * 24 * 60 * 60 * 1000, latest), problem: null };
  }
  if (choice.local === "") return { ms: null, problem: "请选择到期时间" };
  const ms = Date.parse(choice.local);
  if (!Number.isFinite(ms)) return { ms: null, problem: "到期时间无法识别" };
  if (ms < nowMs + EXPIRY_MARGIN_MS) return { ms: null, problem: "到期时间至少要在 10 分钟之后" };
  if (ms > latest) return { ms: null, problem: "到期时间不能超过 90 天（服务端上限）" };
  return { ms, problem: null };
}

/** Why each scope row cannot be sent (row ID → problems), plus problems of the whole set. */
export function scopeProblems(rows: readonly ScopeRow[]): {
  rows: ReadonlyMap<string, readonly string[]>;
  overall: readonly string[];
} {
  const overall: string[] = [];
  if (rows.length === 0) overall.push("至少添加一行范围");
  if (rows.length > SCOPES_MAX) overall.push(`最多 ${SCOPES_MAX} 行范围`);
  const result = new Map<string, string[]>();
  const seen = new Map<string, number>();
  for (const row of rows) {
    const key = row.target === "tenant" ? TENANT_WIDE : row.siteId;
    seen.set(key, (seen.get(key) ?? 0) + 1);
  }
  for (const row of rows) {
    const problems: string[] = [];
    if (row.target === "tenant") {
      if (row.capabilities.length === 0) problems.push("“整个租户”行要勾选“创建站点”");
      if (row.capabilities.some((name) => name !== "site.create")) {
        problems.push("“整个租户”只能授予“创建站点”");
      }
      if ((seen.get(TENANT_WIDE) ?? 0) > 1) problems.push("“整个租户”只需要一行");
    } else {
      if (row.siteId === "") problems.push("请选择或输入站点");
      else if (row.siteId === TENANT_WIDE) problems.push("__tenant__ 是保留标记，不是站点");
      else if (!sitePattern.test(row.siteId)) {
        problems.push("站点 ID 只能是 1–128 个字母、数字或 _ . -");
      }
      if (row.capabilities.length === 0) problems.push("至少勾选一项能力");
      if (row.capabilities.includes("site.create")) {
        problems.push("“创建站点”只能授予“整个租户”");
      }
      if (row.siteId !== "" && (seen.get(row.siteId) ?? 0) > 1) {
        problems.push("同一站点只需要一行");
      }
    }
    if (problems.length > 0) result.set(row.id, problems);
  }
  return { rows: result, overall };
}

/**
 * Capabilities the session cannot grant because it lacks a role entirely. A session with the
 * role may still be refused for a site outside its scope; the server decides.
 */
export function issuerGaps(
  rows: readonly ScopeRow[],
  roles: readonly string[] | null,
): readonly { capability: Capability; missing: readonly string[] }[] {
  if (roles === null) return [];
  const gaps = new Map<Capability, readonly string[]>();
  for (const row of rows) {
    for (const name of row.capabilities) {
      const info = byName.get(name);
      if (!info || gaps.has(name)) continue;
      const missing = info.issuerRoles.filter((role) => !roles.includes(role));
      if (missing.length > 0) gaps.set(name, missing);
    }
  }
  return [...gaps].map(([capability, missing]) => ({ capability, missing }));
}

/** Every role that grants at least one capability. Without one, a session can only revoke and rotate. */
export function canIssueAnything(roles: readonly string[] | null): boolean {
  if (roles === null) return true;
  return capabilityCatalog.some((info) => info.issuerRoles.every((role) => roles.includes(role)));
}

export type BuildResult =
  | Readonly<{ ok: true; request: KeyRequest; expiresAtMs: number }>
  | Readonly<{
      ok: false;
      subject: string | null;
      displayName: string | null;
      expiry: string | null;
      scopes: ReturnType<typeof scopeProblems>;
    }>;

/** The exact body to freeze, built once at submit time; `capabilities` in catalogue order. */
export function buildKeyRequest(draft: KeyDraft, tenantId: string, nowMs: number): BuildResult {
  const subject = subjectProblem(draft.subject);
  const displayName = displayNameProblem(draft.displayName);
  const expiry = expiryInstant(draft.expiry, nowMs);
  const scopes = scopeProblems(draft.scopes);
  if (
    subject ||
    displayName ||
    expiry.problem ||
    scopes.rows.size > 0 ||
    scopes.overall.length > 0 ||
    expiry.ms === null
  ) {
    return { ok: false, subject, displayName, expiry: expiry.problem, scopes };
  }
  const order = capabilityCatalog.map((info) => info.name);
  return {
    ok: true,
    expiresAtMs: expiry.ms,
    request: {
      subject: draft.subject,
      display_name: draft.displayName,
      expires_at: new Date(expiry.ms).toISOString(),
      scopes: draft.scopes.map((row) => ({
        tenant_id: tenantId,
        site_id: row.target === "tenant" ? TENANT_WIDE : row.siteId,
        capabilities: order.filter((name) => row.capabilities.includes(name)),
      })),
    },
  };
}

export type KeyStatus = "active" | "expired" | "revoked";

/**
 * The list has no observation time, so expiry is judged on the browser clock and labelled as
 * such; the server rejects an expired key on its own clock whatever this says.
 */
export function keyStatus(
  key: Pick<ManagementApiKeyRecord, "status" | "expires_at">,
  nowMs: number,
): KeyStatus {
  if (key.status === "revoked") return "revoked";
  return Date.parse(key.expires_at) <= nowMs ? "expired" : "active";
}

/** The scope rows a key was issued with, as a short summary for the table. */
export function scopeSummary(
  scopes: readonly Readonly<{ site_id: string; capabilities: readonly string[] }>[],
): readonly string[] {
  return scopes.map((scope) => {
    const where = scope.site_id === TENANT_WIDE ? "整个租户" : scope.site_id;
    const what = scope.capabilities.map((name) => capabilityInfo(name)?.label ?? name).join("、");
    return `${where}：${what}`;
  });
}
