/**
 * The two numbers a `SENSOR_HTML` page build pins, computed from the exact bytes the origin
 * serves: the lowercase-hex SHA-256 of those bytes and the BYTE offset of the first `</head>`.
 *
 * Why it exists: the edge releases a static page only when the SHA-256 of the complete origin
 * entity equals an approved build, and injects the sensor at that build's offset, which must
 * hold the exact bytes `</head>` (crates/xshield-gateway/src/sensor_html.rs). An operator cannot
 * be expected to compute either by hand, and a JavaScript string index is not a byte offset as
 * soon as a multi-byte character comes before `</head>`.
 *
 * Invariants:
 * - Bytes are hashed as given. A chosen file is read as raw bytes and never decoded and
 *   re-encoded; pasted text is encoded once as UTF-8 (the only encoding the edge injects into).
 * - The offset is a byte index into those same bytes; the edge compares `</head>` byte for byte,
 *   so an uppercase `</HEAD>` is reported, not silently matched.
 * - Everything happens in the browser with WebCrypto: the page bytes are never sent anywhere and
 *   never stored; callers keep them only for the duration of one computation.
 *
 * Errors are values (`PageDigestResult`), each with an operator-readable message. Work and memory
 * are bounded by `MAX_PAGE_BYTES`, checked before a file is read or text is encoded.
 */

/** Gateway `MAX_BUFFERED_JSON_BYTES`: no route may release a larger response. */
export const MAX_PAGE_BYTES = 16 * 1024 * 1024;

/** `</head>` in ASCII. */
const HEAD_CLOSE = [0x3c, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x3e] as const;

export type PageDigest = Readonly<{
  /** SHA-256 of the exact bytes, 64 lowercase hexadecimal digits. */
  sha256: string;
  /** Byte offset of the first `</head>`. */
  injectionOffset: number;
  /** Length of the page in bytes, to compare with the route's response limit. */
  byteLength: number;
}>;

export type PageDigestFailure =
  | "EMPTY"
  | "TOO_LARGE"
  | "NOT_UTF8"
  | "HEAD_CLOSE_MISSING"
  | "HEAD_CLOSE_NOT_LOWERCASE"
  | "CRYPTO_UNAVAILABLE";

export type PageDigestResult =
  | Readonly<{ ok: true; digest: PageDigest }>
  | Readonly<{ ok: false; failure: PageDigestFailure; message: string }>;

export const pageDigestMessages: Readonly<Record<PageDigestFailure, string>> = {
  EMPTY: "页面内容为空：请粘贴页面源码，或选择源站返回的页面文件。",
  TOO_LARGE: "页面超过 16 MiB：edge 不会放行这么大的 SENSOR_HTML 页面，控制台也不计算它的摘要。",
  NOT_UTF8:
    "页面字节不是有效的 UTF-8：edge 只向 UTF-8 页面注入探针，会拒绝这份页面。请确认源站返回的编码。",
  HEAD_CLOSE_MISSING:
    "页面里没有 </head>：edge 只在 </head> 处注入探针，没有它就无法放行这份页面。请确认这是完整的 HTML 页面。",
  HEAD_CLOSE_NOT_LOWERCASE:
    "页面里只有大写或大小写混合的 </HEAD>：edge 按字节精确匹配小写的 </head>，无法向这份页面注入；需要源站改用小写标签。",
  CRYPTO_UNAVAILABLE:
    "浏览器当前不能使用 WebCrypto（需要 HTTPS 或 localhost 安全上下文），无法在本地计算摘要。",
};

/** What the computation assumes, said once next to the control (and in the docs). */
export const pageDigestAssumptions = [
  "必须是源站返回的原始字节，空白或换行不同就是另一份页面。",
  "粘贴的源码按 UTF-8 编码计算，而浏览器文本框会把换行统一为 LF；源站返回 CRLF 换行、BOM 或非 UTF-8 编码时，请选择保存下来的原始文件（文件按原始字节计算，不重新编码）。",
  "注入偏移是第一个 </head> 在页面字节中的位置（字节，不是字符）。",
  "源站对不同用户或每次请求返回不同内容（例如内嵌令牌或时间）时，摘要每次都会不同，edge 会拒绝放行。",
  "页面内容只在本页内存中计算，不会上传，也不会保存。",
] as const;

const fail = (failure: PageDigestFailure): PageDigestResult => ({
  ok: false,
  failure,
  message: pageDigestMessages[failure],
});

/** Index of the first occurrence of `pattern` in `bytes` (with `fold`, ASCII case-insensitive). */
function indexOf(bytes: Uint8Array, pattern: readonly number[], fold: boolean): number {
  const lower = (byte: number) => (fold && byte >= 0x41 && byte <= 0x5a ? byte + 0x20 : byte);
  const last = bytes.length - pattern.length;
  outer: for (let at = 0; at <= last; at += 1) {
    for (let index = 0; index < pattern.length; index += 1) {
      if (lower(bytes[at + index] ?? -1) !== pattern[index]) continue outer;
    }
    return at;
  }
  return -1;
}

/** Byte offset of the first exact `</head>`, or -1. */
export function findHeadClose(bytes: Uint8Array): number {
  return indexOf(bytes, HEAD_CLOSE, false);
}

/** Whether the bytes are well-formed UTF-8 (`std::str::from_utf8` on the edge). */
export function isUtf8(bytes: Uint8Array): boolean {
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return true;
  } catch {
    return false;
  }
}

/**
 * The page's WebCrypto, or `null` outside a secure context (HTTPS or localhost), where browsers
 * hide `crypto.subtle`. Callers may pass `null` to exercise that path.
 */
const browserSubtle = (): SubtleCrypto | null => globalThis.crypto?.subtle ?? null;

const hex = (buffer: ArrayBuffer) =>
  Array.from(new Uint8Array(buffer), (byte) => byte.toString(16).padStart(2, "0")).join("");

/**
 * Digest and `</head>` offset of `bytes`, exactly as given. `subtle` is the WebCrypto
 * implementation (injectable for tests); with `null` the result is `CRYPTO_UNAVAILABLE`.
 */
export async function digestPageBytes(
  bytes: Uint8Array,
  subtle: SubtleCrypto | null = browserSubtle(),
): Promise<PageDigestResult> {
  if (bytes.length === 0) return fail("EMPTY");
  if (bytes.length > MAX_PAGE_BYTES) return fail("TOO_LARGE");
  if (!isUtf8(bytes)) return fail("NOT_UTF8");
  const offset = findHeadClose(bytes);
  if (offset < 0) {
    return fail(
      indexOf(bytes, HEAD_CLOSE, true) >= 0 ? "HEAD_CLOSE_NOT_LOWERCASE" : "HEAD_CLOSE_MISSING",
    );
  }
  if (!subtle) return fail("CRYPTO_UNAVAILABLE");
  // Copy into a fresh ArrayBuffer-backed view: the digest must see exactly these bytes, and the
  // WebCrypto typings refuse views over a possibly shared buffer.
  const digest = await subtle.digest("SHA-256", new Uint8Array(bytes));
  return {
    ok: true,
    digest: { sha256: hex(digest), injectionOffset: offset, byteLength: bytes.length },
  };
}

/**
 * Digest of pasted page text, encoded once as UTF-8. A string is never shorter in UTF-8 bytes
 * than in UTF-16 code units, so an oversized paste is refused before it is encoded.
 */
export async function digestPastedPage(
  text: string,
  subtle: SubtleCrypto | null = browserSubtle(),
): Promise<PageDigestResult> {
  if (text.length === 0) return fail("EMPTY");
  if (text.length > MAX_PAGE_BYTES) return fail("TOO_LARGE");
  return digestPageBytes(new TextEncoder().encode(text), subtle);
}

/** Digest of a chosen file's raw bytes; its size is checked before anything is read. */
export async function digestPageFile(
  file: Blob,
  subtle: SubtleCrypto | null = browserSubtle(),
): Promise<PageDigestResult> {
  if (file.size === 0) return fail("EMPTY");
  if (file.size > MAX_PAGE_BYTES) return fail("TOO_LARGE");
  return digestPageBytes(new Uint8Array(await file.arrayBuffer()), subtle);
}
