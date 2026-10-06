import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import {
  digestPageBytes,
  digestPageFile,
  digestPastedPage,
  findHeadClose,
  isUtf8,
  MAX_PAGE_BYTES,
  type PageDigestResult,
  pageDigestAssumptions,
  pageDigestMessages,
} from "../src/sites/model/page-digest.ts";

const utf8 = (text: string) => new TextEncoder().encode(text);
const ok = (result: PageDigestResult) => {
  assert.ok(result.ok, result.ok ? "" : result.message);
  return result.digest;
};
const failure = (result: PageDigestResult) => (result.ok ? null : result.failure);

test("known SHA-256 vectors, as lowercase hex over the exact bytes", async () => {
  // FIPS 180-2 vectors, wrapped in the smallest page that has a </head>: the digest is checked
  // against Node's own SHA-256 of the same bytes, and the vectors themselves directly.
  assert.equal(
    createHash("sha256").update("abc").digest("hex"),
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
  );
  for (const text of ["</head>", "<html><head></head><body>abc</body></html>"]) {
    const digest = ok(await digestPastedPage(text));
    assert.equal(digest.sha256, createHash("sha256").update(text, "utf8").digest("hex"));
    assert.match(digest.sha256, /^[0-9a-f]{64}$/);
  }
  const abc = ok(await digestPageBytes(utf8("abc</head>")));
  assert.equal(abc.sha256, createHash("sha256").update("abc</head>").digest("hex"));
});

test("the browser loop's page gives the digest and offset its script pins", async () => {
  const page = new Uint8Array(
    readFileSync(new URL("../../../tests/browser-loop/app.html", import.meta.url)),
  );
  const digest = ok(await digestPageFile(new Blob([page])));
  // scripts/test_browser_loop.sh: hashlib.sha256(body).hexdigest(), body.index(b"</head>")
  assert.deepEqual(digest, {
    sha256: "f5eb29b7c7fbac05248d0d1d9b4e693b913bc1fbe2aaf3fd878e8384209b43ea",
    injectionOffset: 293,
    byteLength: 2110,
  });
});

test("the offset counts bytes, not characters, when multi-byte text comes first", async () => {
  const text = "<html><head><title>订单 · 我的账户 😀</title></head><body></body></html>";
  const digest = ok(await digestPastedPage(text));
  const characters = text.indexOf("</head>");
  // 订 单 我 的 账 户 are three bytes each, · is two, and the emoji (two UTF-16 units) is four.
  assert.equal(digest.injectionOffset, characters + 6 * 2 + 1 + 2);
  assert.equal(digest.injectionOffset, Buffer.from(text, "utf8").indexOf("</head>"));
  assert.equal(digest.byteLength, Buffer.byteLength(text, "utf8"));
  // The first </head> wins, as in the loop script.
  assert.equal(findHeadClose(utf8("a</head>b</head>")), 1);
});

test("a chosen file is hashed as its raw bytes, never re-encoded", async () => {
  // CRLF line ends and a BOM are bytes of the page; a text box would have changed both.
  const raw = utf8("﻿<html>\r\n<head></head>\r\n</html>");
  const fromFile = ok(await digestPageFile(new Blob([raw])));
  assert.equal(fromFile.sha256, createHash("sha256").update(raw).digest("hex"));
  assert.equal(fromFile.injectionOffset, 3 + 6 + 2 + 6);
  const fromText = ok(await digestPastedPage("<html>\n<head></head>\n</html>"));
  assert.notEqual(fromText.sha256, fromFile.sha256);
});

test("a page without </head> is refused with a message that says why", async () => {
  const missing = await digestPastedPage("<html><body>no head</body></html>");
  assert.equal(failure(missing), "HEAD_CLOSE_MISSING");
  assert.ok(!missing.ok && missing.message.includes("</head>"));
  // The edge matches the lowercase bytes exactly: an uppercase tag cannot be injected into.
  const upper = await digestPastedPage("<HTML><HEAD></HEAD><BODY></BODY></HTML>");
  assert.equal(failure(upper), "HEAD_CLOSE_NOT_LOWERCASE");
  assert.equal(findHeadClose(utf8("</HEAD>")), -1);
});

test("empty, oversized, non-UTF-8 and crypto-less inputs are refused before any digest", async () => {
  assert.equal(failure(await digestPastedPage("")), "EMPTY");
  assert.equal(failure(await digestPageFile(new Blob([]))), "EMPTY");
  assert.equal(failure(await digestPageBytes(new Uint8Array())), "EMPTY");
  // Invalid UTF-8 (a lone continuation byte): the edge refuses such a page.
  const latin1 = new Uint8Array([0x3c, 0x2f, 0x68, 0x65, 0x61, 0x64, 0x3e, 0xe9]);
  assert.equal(isUtf8(latin1), false);
  assert.equal(failure(await digestPageBytes(latin1)), "NOT_UTF8");
  assert.equal(failure(await digestPastedPage("</head>", null)), "CRYPTO_UNAVAILABLE");
  assert.equal(failure(await digestPageBytes(utf8("</head>"), null)), "CRYPTO_UNAVAILABLE");
});

test("the input is bounded by the largest response the edge releases", async () => {
  assert.equal(MAX_PAGE_BYTES, 16 * 1024 * 1024);
  // A file is refused by its size, before it is read: a stub whose arrayBuffer() would throw.
  const huge = {
    size: MAX_PAGE_BYTES + 1,
    arrayBuffer: () => Promise.reject(new Error("must not be read")),
  } as unknown as Blob;
  assert.equal(failure(await digestPageFile(huge)), "TOO_LARGE");
  // Pasted text is refused by its length before it is encoded.
  assert.equal(failure(await digestPastedPage("a".repeat(MAX_PAGE_BYTES + 1))), "TOO_LARGE");
  // Short in UTF-16 units but over the bound once encoded (three bytes per character).
  const wide = "订".repeat(Math.floor(MAX_PAGE_BYTES / 3) + 1);
  assert.equal(failure(await digestPastedPage(wide)), "TOO_LARGE");
  // Exactly at the bound is accepted.
  const page = new Uint8Array(MAX_PAGE_BYTES).fill(0x20);
  page.set(utf8("</head>"), 100);
  const digest = ok(await digestPageBytes(page));
  assert.equal(digest.byteLength, MAX_PAGE_BYTES);
  assert.equal(digest.injectionOffset, 100);
});

test("every refusal and every assumption is worded for the operator", () => {
  for (const message of Object.values(pageDigestMessages)) assert.match(message, /[一-鿿]/);
  assert.ok(pageDigestAssumptions.some((line) => line.includes("原始字节")));
  assert.ok(pageDigestAssumptions.some((line) => line.includes("空白或换行不同就是另一份页面")));
  assert.ok(pageDigestAssumptions.some((line) => line.includes("不会上传")));
});
