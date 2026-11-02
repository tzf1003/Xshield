// The interface name of a request and its logical path (header-routes-design 2 and 3). A route rule names
// the request from a header, a query parameter or a body field; the gateway joins the names to the URL path.
// Pure functions: no React and no network. The same cases (tests/fixtures/logical-path-cases.json) are run
// against the gateway's implementation, so a change here needs a case there.

import type { ApiInfo, ApiUnknown, RouteRule, UnknownApiReason } from "../api/types.ts";
import { matchesPattern, parsePattern } from "./patterns.ts";

/** The logical path of a request whose name could not be read. Rule paths start with `/`, so no rule matches it. */
export const UNKNOWN_LOGICAL_PATH = "unknown-api";

/** The most body bytes read to name a request (REQUEST_BODY_MAX, crates/xshield-edge/src/proxy.rs). */
export const BODY_PARSE_LIMIT = 48 * 1024;

/** The eight reasons a name can be unknown, in the order the rules check them. */
export const UNKNOWN_REASONS: readonly UnknownApiReason[] = [
  "missing",
  "repeated",
  "conflict",
  "invalid_name",
  "body_unsupported",
  "body_not_json",
  "body_too_large",
  "route_subpath",
];

/** A name value: letters, digits, `.`, `_`, `-`, at most 64 characters (header-routes-design 3). */
const NAME_VALUE = /^[A-Za-z0-9._-]{1,64}$/;

/** What the gateway sees of a request: enough to name it. Header names match case-insensitively. */
export type LogicalRequest = {
  /** URL path without the query string. */
  path: string;
  /** Query string without the leading `?`. */
  query: string | null;
  content_type: string | null;
  /** Header name and value, duplicates allowed. */
  headers: Array<[string, string]>;
  body: string | null;
};

export type LogicalResult = { logical_path: string; api: ApiInfo | null };

type Pair = [string, string];

type Read =
  | { state: "none" }
  | { state: "one"; text: string }
  | { state: "other" }
  | { state: "fail"; reason: UnknownApiReason };

const NONE: Read = { state: "none" };

type BodyInfo =
  | { kind: "none" }
  | { kind: "fail"; reason: UnknownApiReason }
  | { kind: "form"; pairs: Pair[] }
  | { kind: "json"; root: JsonNode };

/** The first rule whose path covers the request path, in the order of the rules. */
export function ruleFor(routes: readonly RouteRule[], path: string): RouteRule | null {
  for (const rule of routes) {
    const parsed = parsePattern(rule.path);
    if (parsed.ok && matchesPattern(parsed.value, path)) return rule;
  }
  return null;
}

/** Computes the logical path of a request under the route rules. Without a covering rule it is the URL path. */
export function logicalPath(routes: readonly RouteRule[], request: LogicalRequest): LogicalResult {
  const rule = ruleFor(routes, request.path);
  if (rule === null) return { logical_path: request.path, api: null };
  // A prefix rule's sub-path that ends in `/` would join to `//` with the name, which is not one logical path.
  if (request.path.endsWith("/")) return unknown({ unknown: "route_subpath" });
  if (rule.name_from.length === 0) return unknown({ unknown: "missing" });

  const context = contextOf(request);
  const names: string[] = [];
  const from: string[] = [];
  for (const group of rule.name_from) {
    const segment = readSegment(group, context);
    if (!segment.ok) {
      return unknown(
        segment.source === undefined
          ? { unknown: segment.reason }
          : { unknown: segment.reason, source: segment.source },
      );
    }
    names.push(segment.value);
    from.push(segment.from);
  }
  const name = names.join("/");
  return { logical_path: `${request.path}/${name}`, api: { name, from } };
}

function unknown(api: ApiUnknown): LogicalResult {
  return { logical_path: UNKNOWN_LOGICAL_PATH, api };
}

type Segment =
  | { ok: true; value: string; from: string }
  | { ok: false; reason: UnknownApiReason; source?: string };

/**
 * One segment of the name. Every location of the group is read in order; a location that fails (repeated, or a
 * body that cannot be read) decides the reason. Then the segment needs exactly one value: none is `missing`,
 * different values are a `conflict`, and a value outside the name set is `invalid_name`.
 */
function readSegment(group: readonly string[], context: Context): Segment {
  if (group.length === 0) return { ok: false, reason: "missing" };
  const values: Array<{ source: string; text: string }> = [];
  let other: string | null = null;
  for (const source of group) {
    const read = readLocation(source, context);
    if (read.state === "fail") return { ok: false, reason: read.reason, source };
    if (read.state === "one") values.push({ source, text: read.text });
    if (read.state === "other" && other === null) other = source;
  }
  if (other !== null) return { ok: false, reason: "invalid_name", source: other };
  const first = values[0];
  if (first === undefined) return { ok: false, reason: "missing", source: group[0] };
  const differing = values.find((item) => item.text !== first.text);
  if (differing !== undefined) return { ok: false, reason: "conflict", source: differing.source };
  if (!NAME_VALUE.test(first.text) || first.text === "." || first.text === "..") {
    return { ok: false, reason: "invalid_name", source: first.source };
  }
  return { ok: true, value: first.text, from: first.source };
}

type Context = {
  headers: Array<[string, string]>;
  query: () => Pair[];
  body: () => BodyInfo;
};

/** Reads the query and the body only when a rule names a request from them. */
function contextOf(request: LogicalRequest): Context {
  let query: Pair[] | null = null;
  let body: BodyInfo | null = null;
  return {
    headers: request.headers,
    query: () => {
      query ??= parseForm(request.query ?? "");
      return query;
    },
    body: () => {
      body ??= readBody(request.body, request.content_type);
      return body;
    },
  };
}

/** `header.X-Id`, `query.action`, `body.a.b.c`: the kind and the name after the first dot. */
export function splitSource(source: string): { kind: string; name: string } {
  const dot = source.indexOf(".");
  return dot < 0
    ? { kind: source, name: "" }
    : { kind: source.slice(0, dot), name: source.slice(dot + 1) };
}

function readLocation(source: string, context: Context): Read {
  const { kind, name } = splitSource(source);
  if (kind === "header") return headerRead(context.headers, name);
  if (kind === "query") return pairRead(context.query(), name);
  if (kind === "body") return bodyRead(context.body(), name);
  return { state: "fail", reason: "invalid_name" };
}

function headerRead(headers: readonly Pair[], name: string): Read {
  const wanted = name.toLowerCase();
  const hits = headers.filter(([key]) => key.toLowerCase() === wanted);
  if (hits.length > 1) return { state: "fail", reason: "repeated" };
  const hit = hits[0];
  return hit === undefined ? NONE : { state: "one", text: hit[1].trim() };
}

function pairRead(pairs: readonly Pair[], name: string): Read {
  const hits = pairs.filter(([key]) => key === name);
  if (hits.length > 1) return { state: "fail", reason: "repeated" };
  const hit = hits[0];
  return hit === undefined ? NONE : { state: "one", text: hit[1] };
}

function bodyRead(info: BodyInfo, name: string): Read {
  switch (info.kind) {
    case "none":
      return NONE;
    case "fail":
      return { state: "fail", reason: info.reason };
    case "form":
      return pairRead(info.pairs, name);
    case "json":
      return jsonRead(info.root, name);
  }
}

/** Media type without parameters, lower case: `application/json; charset=utf-8` reads as `application/json`. */
function mediaType(contentType: string | null): string {
  return (contentType ?? "").split(";")[0]?.trim().toLowerCase() ?? "";
}

/** Whether the body can be read for names, and how. A body that is absent or empty has no fields. */
function readBody(body: string | null, contentType: string | null): BodyInfo {
  if (body === null || body.length === 0) return { kind: "none" };
  const media = mediaType(contentType);
  if (media !== "application/json" && media !== "application/x-www-form-urlencoded") {
    return { kind: "fail", reason: "body_unsupported" };
  }
  if (new TextEncoder().encode(body).length > BODY_PARSE_LIMIT) {
    return { kind: "fail", reason: "body_too_large" };
  }
  if (media === "application/x-www-form-urlencoded")
    return { kind: "form", pairs: parseForm(body) };
  // JSON.parse is the reference for what counts as JSON; the tree keeps duplicate keys, which it does not.
  try {
    JSON.parse(body);
  } catch {
    return { kind: "fail", reason: "body_not_json" };
  }
  const root = parseJsonTree(body);
  return root === null ? { kind: "fail", reason: "body_not_json" } : { kind: "json", root };
}

/** Form and query text: `&`-separated pairs, `+` is a space, percent escapes decoded when they are valid. */
export function parseForm(text: string): Pair[] {
  const pairs: Pair[] = [];
  for (const part of text.split("&")) {
    if (part.length === 0) continue;
    const equals = part.indexOf("=");
    const key = equals < 0 ? part : part.slice(0, equals);
    const value = equals < 0 ? "" : part.slice(equals + 1);
    pairs.push([decodeForm(key), decodeForm(value)]);
  }
  return pairs;
}

function decodeForm(text: string): string {
  const spaced = text.replace(/\+/g, " ");
  try {
    return decodeURIComponent(spaced);
  } catch {
    return spaced;
  }
}

/** A JSON value with its object keys kept in order, duplicates included. Arrays are not walked into. */
type JsonNode =
  | { kind: "string"; value: string }
  | { kind: "scalar" }
  | { kind: "null" }
  | { kind: "array" }
  | { kind: "object"; entries: Array<[string, JsonNode]> };

/** Reads a field path (`a.b.c`) through objects. A duplicate key, an array on the path and a missing key are read
 * as the rules say: duplicates and arrays are not names, a missing key is no value. */
function jsonRead(root: JsonNode, name: string): Read {
  let node: JsonNode = root;
  for (const key of name.split(".")) {
    if (node.kind === "array") return { state: "fail", reason: "body_unsupported" };
    if (node.kind !== "object") return NONE;
    const hits = node.entries.filter(([entry]) => entry === key);
    if (hits.length > 1) return { state: "fail", reason: "repeated" };
    const hit = hits[0];
    if (hit === undefined) return NONE;
    node = hit[1];
  }
  switch (node.kind) {
    case "string":
      return { state: "one", text: node.value };
    case "null":
      return NONE;
    case "array":
      return { state: "fail", reason: "body_unsupported" };
    default:
      return { state: "other" };
  }
}

const JSON_SPACE = " \t\r\n";
const JSON_NUMBER = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/y;
const JSON_ESCAPES: Record<string, string> = {
  '"': '"',
  "\\": "\\",
  "/": "/",
  b: "\b",
  f: "\f",
  n: "\n",
  r: "\r",
  t: "\t",
};

/** Parses JSON text into a tree that keeps duplicate keys. Null when the text is not JSON. */
function parseJsonTree(text: string): JsonNode | null {
  let at = 0;
  const skip = (): void => {
    while (at < text.length && JSON_SPACE.includes(text.charAt(at))) at += 1;
  };
  const expect = (char: string): void => {
    if (text.charAt(at) !== char) throw new SyntaxError("json");
    at += 1;
  };
  const string = (): string => {
    expect('"');
    let out = "";
    while (at < text.length) {
      const char = text.charAt(at);
      at += 1;
      if (char === '"') return out;
      if (char.charCodeAt(0) < 0x20) throw new SyntaxError("json");
      if (char !== "\\") {
        out += char;
        continue;
      }
      const code = text.charAt(at);
      at += 1;
      if (code === "u") {
        const hex = text.slice(at, at + 4);
        if (!/^[0-9a-fA-F]{4}$/.test(hex)) throw new SyntaxError("json");
        out += String.fromCharCode(Number.parseInt(hex, 16));
        at += 4;
        continue;
      }
      const decoded = JSON_ESCAPES[code];
      if (decoded === undefined) throw new SyntaxError("json");
      out += decoded;
    }
    throw new SyntaxError("json");
  };
  const value = (): JsonNode => {
    skip();
    const char = text.charAt(at);
    if (char === "{") return object();
    if (char === "[") return array();
    if (char === '"') return { kind: "string", value: string() };
    if (text.startsWith("true", at)) {
      at += 4;
      return { kind: "scalar" };
    }
    if (text.startsWith("false", at)) {
      at += 5;
      return { kind: "scalar" };
    }
    if (text.startsWith("null", at)) {
      at += 4;
      return { kind: "null" };
    }
    JSON_NUMBER.lastIndex = at;
    const number = JSON_NUMBER.exec(text);
    if (number === null) throw new SyntaxError("json");
    at += number[0].length;
    return { kind: "scalar" };
  };
  const object = (): JsonNode => {
    expect("{");
    const entries: Array<[string, JsonNode]> = [];
    skip();
    if (text.charAt(at) === "}") {
      at += 1;
      return { kind: "object", entries };
    }
    for (;;) {
      skip();
      const key = string();
      skip();
      expect(":");
      entries.push([key, value()]);
      skip();
      const separator = text.charAt(at);
      at += 1;
      if (separator === "}") return { kind: "object", entries };
      if (separator !== ",") throw new SyntaxError("json");
    }
  };
  const array = (): JsonNode => {
    expect("[");
    skip();
    if (text.charAt(at) === "]") {
      at += 1;
      return { kind: "array" };
    }
    for (;;) {
      value();
      skip();
      const separator = text.charAt(at);
      at += 1;
      if (separator === "]") return { kind: "array" };
      if (separator !== ",") throw new SyntaxError("json");
    }
  };
  try {
    const root = value();
    skip();
    return at === text.length ? root : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------------ credentials in pasted requests

/** Shown in place of a credential value; the name stays so the request still reads as a request. */
export const MASK = "••••••";

/** Cookie, Authorization and any header whose name contains `token`, in any letter case. */
export function isSensitiveHeader(name: string): boolean {
  return /cookie|authorization|token/i.test(name);
}

export type Hidden = { count: number; names: string[] };

/**
 * Replaces the value of each credential header in a pasted request with the mask, before the text is shown or
 * parsed. Counts the values hidden (an empty value hides nothing). The request line and the body are unchanged.
 */
export function maskRequestText(text: string): { text: string; hidden: Hidden } {
  const lines = text.split("\n");
  const hidden: Hidden = { count: 0, names: [] };
  const out: string[] = [];
  let inHeaders = false;
  let masking = false;
  for (const [index, line] of lines.entries()) {
    const cr = line.endsWith("\r") ? "\r" : "";
    const bare = cr === "" ? line : line.slice(0, -1);
    if (index === 0) {
      inHeaders = true;
      out.push(line);
      continue;
    }
    if (!inHeaders) {
      out.push(line);
      continue;
    }
    if (bare.trim() === "") {
      inHeaders = false;
      masking = false;
      out.push(line);
      continue;
    }
    if (/^[ \t]/.test(bare)) {
      // A folded line continues the value of the header above it.
      out.push(masking ? `\t${MASK}${cr}` : line);
      continue;
    }
    const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):(.*)$/.exec(bare);
    if (match === null) {
      masking = false;
      out.push(line);
      continue;
    }
    const name = match[1] ?? "";
    const value = (match[2] ?? "").trim();
    masking = isSensitiveHeader(name) && value.length > 0;
    if (!masking) {
      out.push(line);
      continue;
    }
    hidden.count += 1;
    if (!hidden.names.includes(name)) hidden.names.push(name);
    out.push(`${name}: ${MASK}${cr}`);
  }
  return { text: out.join("\n"), hidden };
}

// ------------------------------------------------------------------ pasted requests

export type RawRequest = LogicalRequest & { method: string };

export type ParseFailure = "request_line" | "target" | "header_line";

/** Reads a pasted HTTP request: a request line, header lines, a blank line, then the body. */
export function parseRawRequest(
  text: string,
): { ok: true; request: RawRequest } | { ok: false; reason: ParseFailure } {
  const start = text.replace(/^(?:[ \t]*\r?\n)+/, "");
  const separator = /\r?\n\r?\n/.exec(start);
  const head = separator === null ? start : start.slice(0, separator.index);
  const rawBody = separator === null ? null : start.slice(separator.index + separator[0].length);
  const lines = head.split(/\r?\n/);
  const line = /^([A-Za-z]+)[ \t]+(\S+)(?:[ \t]+HTTP\/[0-9.]+)?[ \t]*$/.exec(lines[0] ?? "");
  if (line === null) return { ok: false, reason: "request_line" };
  const target = splitTarget(line[2] ?? "");
  if (target === null) return { ok: false, reason: "target" };

  const headers: Pair[] = [];
  for (const raw of lines.slice(1)) {
    if (raw.trim() === "") continue;
    const last = headers[headers.length - 1];
    if (/^[ \t]/.test(raw) && last !== undefined) {
      last[1] = `${last[1]} ${raw.trim()}`;
      continue;
    }
    const match = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+):(.*)$/.exec(raw);
    if (match === null) return { ok: false, reason: "header_line" };
    headers.push([match[1] ?? "", (match[2] ?? "").trim()]);
  }

  // Two different Content-Type values leave the body's type unknown: the request is read as having none.
  const types = new Set(
    headers.filter(([key]) => key.toLowerCase() === "content-type").map(([, value]) => value),
  );
  const body = rawBody === null ? null : rawBody.replace(/(?:\r?\n)+$/, "");
  return {
    ok: true,
    request: {
      method: (line[1] ?? "").toUpperCase(),
      path: target.path,
      query: target.query,
      headers,
      content_type: types.size === 1 ? ([...types][0] ?? null) : null,
      body: body === null || body.length === 0 ? null : body,
    },
  };
}

/** The path and query of a request target; an absolute form (`http://host/x`) keeps only its path. */
function splitTarget(raw: string): { path: string; query: string | null } | null {
  let rest = raw;
  if (/^https?:\/\//i.test(rest)) rest = rest.replace(/^https?:\/\/[^/?#]*/i, "") || "/";
  if (rest.startsWith("?")) rest = `/${rest}`;
  const hash = rest.indexOf("#");
  if (hash >= 0) rest = rest.slice(0, hash);
  const question = rest.indexOf("?");
  const path = question < 0 ? rest : rest.slice(0, question);
  if (!path.startsWith("/")) return null;
  const query = question < 0 ? "" : rest.slice(question + 1);
  return { path, query: query.length === 0 ? null : query };
}

/** What the rule tester shows for what was typed: nothing, a path, or a pasted request, after hiding credentials. */
export type TestOutcome =
  | { kind: "empty" }
  | { kind: "invalid"; reason: ParseFailure }
  | {
      kind: "ok";
      /** Null when only a path was typed. */
      method: string | null;
      request: LogicalRequest;
      logical: LogicalResult;
      hidden: Hidden;
    };

/**
 * Resolves what the tester was given. A single line that starts with `/` is a path (its query is kept, no
 * headers); anything else is a pasted request, read after its credentials are hidden.
 */
export function testRequest(input: string, routes: readonly RouteRule[]): TestOutcome {
  const text = input.trim();
  if (text.length === 0) return { kind: "empty" };
  if (!text.includes("\n") && text.startsWith("/")) {
    const question = text.indexOf("?");
    const path = question < 0 ? text : text.slice(0, question);
    const request: LogicalRequest = {
      path,
      query: question < 0 ? null : text.slice(question + 1) || null,
      content_type: null,
      headers: [],
      body: null,
    };
    return {
      kind: "ok",
      method: null,
      request,
      logical: logicalPath(routes, request),
      hidden: { count: 0, names: [] },
    };
  }
  const masked = maskRequestText(text);
  const parsed = parseRawRequest(masked.text);
  if (!parsed.ok) return { kind: "invalid", reason: parsed.reason };
  const { method, ...request } = parsed.request;
  return {
    kind: "ok",
    method,
    request,
    logical: logicalPath(routes, request),
    hidden: masked.hidden,
  };
}

// ------------------------------------------------------------------ recent records

/** The fields of a request row the completions and the examples read. */
export type RecentRow = {
  path: string;
  logical_path: string;
  api: ApiInfo | null;
};

export type RecentPath = { logical_path: string; count: number };

/** Whether a rule's path covers a URL path (exact or prefix, plain spelling only). */
export function ruleCovers(rule: RouteRule, path: string): boolean {
  const parsed = parsePattern(rule.path);
  return parsed.ok && matchesPattern(parsed.value, path);
}

/** The literal part of a rule: its path without a trailing `*`. Null when the rule does not parse. */
export function ruleBase(rule: RouteRule): string | null {
  const parsed = parsePattern(rule.path);
  return parsed.ok ? parsed.value.literal : null;
}

/** Whether what was typed is under the rule: it extends the rule's path past a `/` (`/x/…` under `/x`). */
export function typedUnderRule(typed: string, rule: RouteRule): boolean {
  const base = ruleBase(rule);
  if (base === null || typed.length <= base.length || !typed.startsWith(base)) return false;
  return base.endsWith("/") || typed.charAt(base.length) === "/";
}

/** The part of a logical path after the rule's base, without its leading `/`, for showing in a list. */
export function nameAfter(logical: string, base: string): string {
  const rest = logical.slice(base.length);
  return rest.startsWith("/") ? rest.slice(1) : rest;
}

/**
 * Groups recent rows of one rule by logical path, most frequent first. Rows the rule does not cover, rows
 * without a name, and rows whose name is unknown are left out.
 */
export function recentPaths(rows: readonly RecentRow[], rule: RouteRule): RecentPath[] {
  const counts = new Map<string, number>();
  for (const row of rows) {
    if (!ruleCovers(rule, row.path) || !isNamed(row)) continue;
    counts.set(row.logical_path, (counts.get(row.logical_path) ?? 0) + 1);
  }
  return [...counts]
    .map(([logical_path, count]) => ({ logical_path, count }))
    .sort((a, b) => b.count - a.count || a.logical_path.localeCompare(b.logical_path));
}

/** Rows of one rule whose name could not be read. */
export function unknownCount(rows: readonly RecentRow[], rule: RouteRule): number {
  return rows.filter((row) => ruleCovers(rule, row.path) && isUnknownApi(row.api)).length;
}

/** The logical path of the newest row of the rule that has a name, or null. Rows come newest first. */
export function latestNamed(rows: readonly RecentRow[], rule: RouteRule): string | null {
  const row = rows.find((item) => ruleCovers(rule, item.path) && isNamed(item));
  return row === undefined ? null : row.logical_path;
}

/** Whether an interface field records a name that could not be read. */
export function isUnknownApi(api: ApiInfo | null | undefined): api is ApiUnknown {
  return api !== null && api !== undefined && "unknown" in api;
}

/** A row with a name: a logical path is present and the name was read. Older rows may lack the fields. */
function isNamed(row: RecentRow): boolean {
  return typeof row.logical_path === "string" && row.api !== null && !isUnknownApi(row.api);
}
