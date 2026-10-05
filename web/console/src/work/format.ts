/** Display and validation helpers shared by the case and approval pages. Pure; no DOM. */
import { validCaseText } from "../cases.ts";

const encoder = new TextEncoder();

export function utf8Length(value: string): number {
  return encoder.encode(value).byteLength;
}

/**
 * Why a free-text field (purpose, reason, justification) is not acceptable, in the operator's
 * words, or `null` when it is. The rule is the server's: 1-512 UTF-8 bytes, no control
 * characters, no leading or trailing white space.
 */
export function textProblem(value: string, label: string): string | null {
  if (value.length === 0) return `${label}不能为空`;
  if (/\p{Cc}/u.test(value)) return `${label}不能包含控制字符`;
  if (/^\p{White_Space}|\p{White_Space}$/u.test(value)) return `${label}首尾不能有空白`;
  const bytes = utf8Length(value);
  if (bytes > 512) return `${label}最多 512 字节（当前 ${bytes} 字节）`;
  return validCaseText(value) ? null : `${label}含有无法编码的字符`;
}

/** `2026-09-20 08:10:30 UTC`. Unparseable input is shown as it came, never thrown on. */
export function formatUtc(value: string | null | undefined): string {
  if (!value) return "—";
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return value;
  return `${new Date(ms).toISOString().slice(0, 19).replace("T", " ")} UTC`;
}

/** Elapsed time between two instants, rounded down to one unit. Never negative. */
export function formatAge(deltaMs: number): string {
  const ms = Number.isFinite(deltaMs) ? Math.max(0, deltaMs) : 0;
  const minutes = Math.floor(ms / 60_000);
  if (minutes < 1) return "刚刚";
  if (minutes < 60) return `${minutes} 分钟`;
  const hours = Math.floor(minutes / 60);
  if (hours < 48) return `${hours} 小时`;
  return `${Math.floor(hours / 24)} 天`;
}

/** Milliseconds since the epoch for an RFC 3339 instant; `NaN` when it is not one. */
export function parseMs(value: string | null | undefined): number {
  return value ? Date.parse(value) : Number.NaN;
}

/** `case_018f2a3b-…-000000000031` -> `case_018f2a3b…0031`, for tight spaces only. */
export function shortId(value: string): string {
  const at = value.indexOf("_");
  if (at < 0 || value.length <= 18) return value;
  return `${value.slice(0, at + 9)}…${value.slice(-4)}`;
}
