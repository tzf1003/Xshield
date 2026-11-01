// Local checks that mirror the server's SITE_CONFIG_* rules (docs/07 7.6.2, 7.9.12) so the form
// can point at the field that is wrong. The server remains the authority: its error codes are
// still shown when a save is refused. Messages here never echo more than the field name.

import type { Advanced, SiteSpec } from "../api/types.ts";
import { parsePattern } from "./patterns.ts";
import { isSiteName } from "./ids.ts";

export type FieldGroup = "basics" | "session" | "entries" | "bypass" | "mode" | "advanced";

export type FieldIssue = { group: FieldGroup; field: string; message: string };

export const BUILTIN_SECRET_WORDS = [
  "password",
  "passwd",
  "pwd",
  "secret",
  "token",
  "otp",
  "credential",
  "authorization",
  "cvv",
] as const;

export const BUILTIN_SYNONYMS: ReadonlyArray<readonly [string, string]> = [["payment", "card"]];

/** Words that name an object in many field names; a secret word that matches them hides ids. */
const OBJECT_WORDS = [
  "id",
  "card",
  "user",
  "owner",
  "account",
  "order",
  "file",
  "basket",
  "address",
  "coupon",
  "product",
  "record",
  "item",
  "no",
  "code",
];

const HOST_MAX = 253;

export function validHost(host: string): boolean {
  return (
    host.length > 0 &&
    host.length <= HOST_MAX &&
    !/^[.-]/.test(host) &&
    !/[.-]$/.test(host) &&
    !host.includes("..") &&
    /^[A-Za-z0-9.-]+$/.test(host)
  );
}

/** `http(s)://host[:port]` with no path, query or credentials (docs/07 7.9.1, config.rs). */
export function validOrigin(origin: string): boolean {
  const match = /^https?:\/\/(.+)$/.exec(origin);
  if (!match) return false;
  const rest = match[1] ?? "";
  const colon = rest.lastIndexOf(":");
  const host = colon >= 0 ? rest.slice(0, colon) : rest;
  const port = colon >= 0 ? rest.slice(colon + 1) : null;
  if (!validHost(host)) return false;
  return port === null || (/^[0-9]{1,5}$/.test(port) && Number(port) <= 65535);
}

/** Cookie names and header names: RFC 7230 token characters. */
export function validToken(name: string): boolean {
  return name.length > 0 && name.length <= 64 && /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/.test(name);
}

function intIn(value: number, min: number, max: number): boolean {
  return Number.isInteger(value) && value >= min && value <= max;
}

function validateAdvanced(advanced: Advanced | undefined): FieldIssue[] {
  const issues: FieldIssue[] = [];
  const add = (field: string, message: string) => {
    issues.push({ group: "advanced", field, message });
  };
  if (!advanced) return issues;
  if (advanced.jev_timeout_ms !== undefined && !intIn(advanced.jev_timeout_ms, 100, 30000)) {
    add("jev_timeout_ms", "Jev 超时需在 100–30000 ms 之间");
  }
  if (
    advanced.session_calls_per_minute !== undefined &&
    !intIn(advanced.session_calls_per_minute, 1, 600)
  ) {
    add("session_calls_per_minute", "会话调用上限需在 1–600 次之间");
  }
  if (
    advanced.address_calls_per_minute !== undefined &&
    !intIn(advanced.address_calls_per_minute, 1, 600)
  ) {
    add("address_calls_per_minute", "地址调用上限需在 1–600 次之间");
  }
  if (advanced.allow_cache_minutes !== undefined && !intIn(advanced.allow_cache_minutes, 0, 60)) {
    add("allow_cache_minutes", "放行缓存时长需在 0–60 分钟之间");
  }
  const words = advanced.secret_fields ?? [];
  if (words.length > 32) add("secret_fields", "追加脱敏词最多 32 个");
  const seenWords = new Set<string>();
  for (const word of words) {
    if (!/^[a-z0-9_-]{3,32}$/.test(word)) {
      add("secret_fields", `脱敏词 “${word}” 需为 3–32 个小写字母、数字、_ 或 -`);
    } else if ((BUILTIN_SECRET_WORDS as readonly string[]).includes(word) || seenWords.has(word)) {
      add("secret_fields", `脱敏词 “${word}” 与内置词或已有词重复`);
    }
    seenWords.add(word);
  }
  const groups = advanced.synonyms ?? [];
  if (groups.length > 32) add("synonyms", "同义词最多 32 组");
  const seenGroups = new Set<string>();
  for (const [a, b] of groups) {
    const ok = /^[a-z]{3,24}$/.test(a) && /^[a-z]{3,24}$/.test(b);
    if (!ok) {
      add("synonyms", `同义词 “${a} ↔ ${b}” 每个词需为 3–24 个小写字母`);
      continue;
    }
    if (a === b) add("synonyms", `同义词 “${a} ↔ ${b}” 两个词不能相同`);
    const key = [a, b].sort().join("|");
    if (seenGroups.has(key)) add("synonyms", `同义词 “${a} ↔ ${b}” 重复`);
    seenGroups.add(key);
  }
  return issues;
}

/** Errors block saving; warnings are shown beside the field and do not block. */
export function validateSpec(spec: SiteSpec): { errors: FieldIssue[]; warnings: FieldIssue[] } {
  const errors: FieldIssue[] = [];
  const warnings: FieldIssue[] = [];
  if (!isSiteName(spec.name)) {
    errors.push({
      group: "basics",
      field: "name",
      message: "站点名只能用小写字母、数字、-、_，最长 64 个字符",
    });
  }
  if (spec.hosts.length === 0 || spec.hosts.length > 16 || !spec.hosts.every(validHost)) {
    errors.push({
      group: "basics",
      field: "hosts",
      message: "Host 不能为空，最多 16 个，每个必须是有效的主机名",
    });
  }
  if (!validOrigin(spec.origin)) {
    errors.push({
      group: "basics",
      field: "origin",
      message: "源站地址必须是 http://主机[:端口] 或 https://主机[:端口]，不带路径",
    });
  }
  const credential = spec.session.cookie ?? spec.session.header ?? "";
  const credentialOk =
    Number(spec.session.cookie !== undefined) + Number(spec.session.header !== undefined) === 1 &&
    validToken(credential);
  if (!credentialOk) {
    errors.push({
      group: "session",
      field: "session",
      message: "会话凭证需要一个有效的 Cookie 名或请求头名",
    });
  }
  errors.push(...validateRules("entries", spec.entries, 1));
  errors.push(...validateRules("bypass", spec.bypass ?? [], 0));
  for (const raw of spec.entries) {
    const parsed = parsePattern(raw);
    if (
      parsed.ok &&
      parsed.value.prefix &&
      parsed.value.literal.split("/").filter(Boolean).length <= 1
    ) {
      warnings.push({
        group: "entries",
        field: raw,
        message: "前缀入口会放大无会话可达的范围",
      });
    }
  }
  for (const word of spec.advanced?.secret_fields ?? []) {
    if (OBJECT_WORDS.includes(word)) {
      warnings.push({
        group: "advanced",
        field: "secret_fields",
        message: `“${word}” 会让 ${word}Id 这类对象引用也被脱敏，Jev 无法判断越权`,
      });
    }
  }
  errors.push(...validateAdvanced(spec.advanced));
  return { errors, warnings };
}

function validateRules(
  group: "entries" | "bypass",
  rules: string[],
  minimum: number,
): FieldIssue[] {
  const issues: FieldIssue[] = [];
  if (rules.length < minimum) {
    issues.push({
      group,
      field: group,
      message: group === "entries" ? "入口至少一条" : "绕过规则不能为空",
    });
  }
  if (rules.length > 64) {
    issues.push({ group, field: group, message: "最多 64 条" });
  }
  rules.forEach((raw, index) => {
    const parsed = parsePattern(raw);
    if (!parsed.ok) {
      issues.push({ group, field: `${group}[${index}]`, message: parsed.reason });
    }
  });
  return issues;
}
