// TypeScript port of the gateway's path rules (crates/xshield-core/src/context/config.rs,
// `PathPattern` and `is_plain_path`). The console uses it only to explain a draft in the rule
// tester and in the rule editor; the gateway's answer is the one that counts. The test cases in
// tests/patterns.test.ts are copied from the Rust tests.

export const PATTERN_MAX = 256;

export type ParsedPattern = { raw: string; prefix: boolean; literal: string };

export type PatternParse = { ok: true; value: ParsedPattern } | { ok: false; reason: string };

/** `.` and `..` segments, in either a configured pattern or a request path. */
export function hasDotSegment(path: string): boolean {
  return path.split("/").some((segment) => segment === "." || segment === "..");
}

/** True for C0 control characters and DEL, which neither a pattern nor a path may contain. */
function hasControl(text: string): boolean {
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    if (code <= 0x1f || code === 0x7f) return true;
  }
  return false;
}

/** Parses an entry or bypass rule: an absolute path, no query, `*` only as the last byte. */
export function parsePattern(raw: string): PatternParse {
  if (raw.length === 0) return { ok: false, reason: "不能为空" };
  // The gateway counts bytes (`raw.len()`), so a pattern with CJK characters reaches the limit sooner.
  if (new TextEncoder().encode(raw).length > PATTERN_MAX)
    return { ok: false, reason: `不能超过 ${PATTERN_MAX} 字节` };
  if (!raw.startsWith("/")) return { ok: false, reason: "必须以 / 开头" };
  const prefix = raw.endsWith("*");
  const literal = prefix ? raw.slice(0, -1) : raw;
  if (/[*?#\\]/.test(literal)) return { ok: false, reason: "* 只能写在末尾，不能含 ? # 或反斜杠" };
  if (literal.includes(" ") || hasControl(literal))
    return { ok: false, reason: "不能含空格或控制字符" };
  if (hasDotSegment(literal)) return { ok: false, reason: "不能含 . 或 .. 段" };
  return { ok: true, value: { raw, prefix, literal } };
}

/** True when a request path has exactly one spelling the origin would also resolve. */
export function isPlainPath(path: string): boolean {
  if (!path.startsWith("/")) return false;
  if (path.includes("//")) return false;
  if (/[\\?#;]/.test(path)) return false;
  if (hasControl(path)) return false;
  if (hasDotSegment(path)) return false;
  const lower = path.toLowerCase();
  return !["%2e", "%2f", "%5c", "%00"].some((bad) => lower.includes(bad));
}

/** Whether a request path (without query) is covered by a parsed rule. */
export function matchesPattern(pattern: ParsedPattern, path: string): boolean {
  if (!isPlainPath(path)) return false;
  return pattern.prefix ? path.startsWith(pattern.literal) : path === pattern.raw;
}

export type PathVerdict =
  | { kind: "bypass"; rule: string }
  | { kind: "entry"; rule: string }
  | { kind: "needs_session" }
  | { kind: "invalid_spelling" };

/**
 * What the gateway would do with a path under a draft: bypass is checked first (docs/06 6.4.9
 * rule tester), then entries. Rules that do not parse never match.
 */
export function judgePath(path: string, entries: string[], bypass: string[]): PathVerdict {
  if (!isPlainPath(path)) return { kind: "invalid_spelling" };
  for (const raw of bypass) {
    const parsed = parsePattern(raw);
    if (parsed.ok && matchesPattern(parsed.value, path)) return { kind: "bypass", rule: raw };
  }
  for (const raw of entries) {
    const parsed = parsePattern(raw);
    if (parsed.ok && matchesPattern(parsed.value, path)) return { kind: "entry", rule: raw };
  }
  return { kind: "needs_session" };
}
