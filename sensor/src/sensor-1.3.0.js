/*
 * Xshield browser sensor 1.3.0, served at /__xshield/v1/sensor/1.3.0.js.
 *
 * Responsibilities: page observations (as 1.0.0), presenting server-issued,
 * opaque action references on the page's own same-origin
 * fetch/XMLHttpRequest calls (as 1.1.0), reporting those observations over
 * the same-origin probe WSS channel the bootstrap advertises (as 1.2.0), and
 * encrypting the JSON body of same-origin fetch/XMLHttpRequest calls the
 * bootstrap names as ENVELOPE_HOOK operations (docs/08 section 8.1). The
 * sensor never creates, derives or guesses an action reference or an
 * encryption key: action references only repeat a value the edge delivered
 * through the no-store bootstrap or an approved JSON list response, and the
 * encryption key is the exact session-bound key the bootstrap issued. The
 * edge re-validates every presented reference and every envelope against the
 * full credential set, so a wrong, missing, or unencrypted entry is denied,
 * never silently allowed.
 *
 * ENVELOPE_HOOK only replaces a call's body when it is a plain string (the
 * common `body: JSON.stringify(...)` shape) and the page has not already set
 * its own Content-Type (fetch always replaces; XHR never does, since its
 * native setRequestHeader combines repeated values instead of replacing
 * them, and a combined Content-Type would simply be denied at the edge).
 * Anything else — a Request-carried body, FormData, an already-set XHR
 * Content-Type, no WebCrypto, no delivered key — passes through unmodified
 * and is denied at the edge rather than silently sent in the clear: the edge
 * is the enforcement point, never this script.
 *
 * Coverage (see docs/07 section 7.4): window.fetch and XMLHttpRequest of this
 * document only. Workers, iframes, service workers and references to fetch
 * saved before this script ran are not hooked; their requests carry no
 * reference or encryption and gated operations stay denied.
 *
 * Every hook failure falls back to the unmodified native call, so the sensor
 * can never break the page. The bytes of this file are pinned by SRI once
 * released: ship a new version path instead of editing it.
 */
(() => {
  "use strict";

  const SENSOR_VERSION = "1.3.0";
  const RESERVED_PREFIX = "/__xshield/";
  const BOOTSTRAP_PATH = "/__xshield/v1/bootstrap";
  const ACTION_HEADER = "X-Xshield-Action-Ref";
  const MAX_VALUE_LENGTH = 256;
  const MAX_ACTIONS = 16;
  const MAX_RULES = 64;
  const MAX_HARVESTED_REFS = 1024;
  const MAX_HARVEST_BYTES = 1024 * 1024;
  const BOOTSTRAP_WAIT_MS = 5000;
  const HARVEST_WAIT_MS = 2000;
  // Heartbeat jitter keeps many pages from reconnecting or beating in lockstep.
  const HEARTBEAT_JITTER_RATIO = 0.2;
  const WS_RECONNECT_MIN_MS = 1000;
  const WS_RECONNECT_MAX_MS = 60000;
  const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
  const REF = /^[A-Za-z0-9_.-]{1,128}$/;
  const NAME = /^[A-Za-z0-9_.-]{1,128}$/;
  const PAGE_HANDLE =
    /^pgh_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const JSON_TYPE = /^application\/(?:[A-Za-z0-9.+-]+\+)?json(?:\s*;|$)/i;
  const ENVELOPE_CONTENT_TYPE = "application/vnd.xshield.encrypted+json";
  const ENVELOPE_PROTOCOL_LABEL = "xshield.request.envelope-hook.v1";
  const ENVELOPE_KEY_HEX = /^[0-9a-f]{64}$/;
  const ENVELOPE_KEY_ID = /^ehk\.(?:0|[1-9][0-9]*)$/;
  // The server's own max_message_age_seconds (docs/08 §8.1, site-configured,
  // 1..3600) must be at least this, or every envelope this sensor builds
  // expires before the edge can ever see it as "not yet expired".
  const ENVELOPE_MESSAGE_AGE_SECONDS = 30;

  // Captured before any later page script can replace them.
  const nativeFetch = typeof globalThis.fetch === "function" ? globalThis.fetch : null;
  const NativeXHR =
    typeof globalThis.XMLHttpRequest === "function" ? globalThis.XMLHttpRequest : null;
  const NativeRequest = typeof globalThis.Request === "function" ? globalThis.Request : null;
  const NativeHeaders = typeof globalThis.Headers === "function" ? globalThis.Headers : null;
  const NativeWebSocket =
    typeof globalThis.WebSocket === "function" ? globalThis.WebSocket : null;
  const nativeCrypto =
    typeof globalThis.crypto === "object" && globalThis.crypto !== null ? globalThis.crypto : null;
  const nativeSubtle =
    nativeCrypto !== null && typeof nativeCrypto.subtle === "object" ? nativeCrypto.subtle : null;
  const setTimer = globalThis.setTimeout.bind(globalThis);

  const state = {
    ready: false,
    booted: false,
    started: false,
    actions: new Map(),
    rules: [],
    invalidate: new Set(),
    refs: new Map(),
    pending: new Set(),
    envelopeOps: new Map(),
    tenantId: null,
    siteId: null,
    envelopeKeyId: null,
    envelopeKey: Promise.resolve(null),
  };
  let markReady = () => undefined;
  const ready = new Promise((resolve) => {
    markReady = resolve;
  });
  const finish = () => {
    state.ready = true;
    markReady();
  };
  // A blocked or missing loader must not hold page requests indefinitely.
  setTimer(finish, BOOTSTRAP_WAIT_MS);

  const bounded = (value) =>
    typeof value === "string" && value.length > 0 && value.length <= MAX_VALUE_LENGTH;
  const path = (value) =>
    typeof value === "string" &&
    value.length <= 512 &&
    value.startsWith("/") &&
    !/[?#{}\s]/.test(value);
  const integer = (value, min, max) =>
    Number.isInteger(value) && value >= min && value <= max;
  const pointer = (value) =>
    typeof value === "string" && value.length <= 512 && (value === "" || value.startsWith("/"));

  const bytesToHex = (bytes) => {
    let out = "";
    for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
    return out;
  };
  const hexToBytes = (hex) => {
    const bytes = new Uint8Array(hex.length / 2);
    for (let index = 0; index < bytes.length; index += 1) {
      bytes[index] = Number.parseInt(hex.slice(index * 2, index * 2 + 2), 16);
    }
    return bytes;
  };

  // A random, lowercase, hyphenated UUIDv7: a 48-bit big-endian millisecond
  // timestamp, then version and variant nibbles, then random bits — the same
  // layout the edge's own `Uuid::now_v7()` produces and parses.
  const uuidv7 = () => {
    const bytes = new Uint8Array(16);
    nativeCrypto.getRandomValues(bytes);
    let time = Date.now();
    for (let index = 5; index >= 0; index -= 1) {
      bytes[index] = time % 256;
      time = Math.floor(time / 256);
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    const hex = bytesToHex(bytes);
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  };

  // The exact length-prefixed AAD layout the edge's own `aad()` builds:
  // each field as a big-endian u32 byte length followed by its UTF-8 bytes,
  // concatenated in this fixed order. Any mismatch — order, a missing
  // field, or a different encoding — authenticates against different bytes
  // than the edge computes, so decryption fails rather than succeeding
  // against the wrong binding.
  const buildAad = (fields) => {
    const encoder = new TextEncoder();
    const parts = fields.map((field) => encoder.encode(field));
    const total = parts.reduce((sum, part) => sum + 4 + part.byteLength, 0);
    const out = new Uint8Array(total);
    const view = new DataView(out.buffer);
    let offset = 0;
    for (const part of parts) {
      view.setUint32(offset, part.byteLength, false);
      offset += 4;
      out.set(part, offset);
      offset += part.byteLength;
    }
    return out;
  };

  // Encrypts one same-origin call's JSON body into an ENVELOPE_HOOK envelope
  // (docs/08 §8.1) under the session key the bootstrap issued. Rejects if
  // WebCrypto, the key, or the plaintext shape is unavailable, so the caller
  // always falls back to the unmodified native call rather than ever
  // sending a malformed envelope.
  const buildEnvelope = async (op, method, url, plaintext) => {
    const key = await state.envelopeKey;
    if (key === null || nativeSubtle === null) throw new Error("envelope key unavailable");
    const issuedAt = Math.floor(Date.now() / 1000);
    const expiresAt = issuedAt + ENVELOPE_MESSAGE_AGE_SECONDS;
    const nonce = nativeCrypto.getRandomValues(new Uint8Array(12));
    const messageId = `msg_${uuidv7()}`;
    const aad = buildAad([
      ENVELOPE_PROTOCOL_LABEL,
      state.tenantId,
      state.siteId,
      op.operationId,
      method,
      url.pathname,
      op.adapterRevision,
      state.envelopeKeyId,
      messageId,
      String(issuedAt),
      String(expiresAt),
      "application/json",
    ]);
    const sealed = new Uint8Array(
      await nativeSubtle.encrypt(
        { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
        key,
        new TextEncoder().encode(plaintext),
      ),
    );
    const ciphertext = sealed.slice(0, sealed.length - 16);
    const tag = sealed.slice(sealed.length - 16);
    return JSON.stringify({
      schema_version: 1,
      adapter_revision: op.adapterRevision,
      key_id: state.envelopeKeyId,
      message_id: messageId,
      issued_at: issuedAt,
      expires_at: expiresAt,
      nonce: bytesToHex(nonce),
      ciphertext: bytesToHex(ciphertext),
      tag: bytesToHex(tag),
    });
  };

  // The configured ENVELOPE_HOOK operation for one exact same-origin
  // method and path, like `referenceFor` for action references: no query,
  // no prefix matching.
  const envelopeOpFor = (method, url) =>
    url.search === "" ? state.envelopeOps.get(`${method} ${url.pathname}`) ?? null : null;

  const sameOriginUrl = (value) => {
    if (!bounded(value)) return null;
    try {
      const url = new URL(value, globalThis.location.href);
      return url.origin === globalThis.location.origin ? url : null;
    } catch {
      return null;
    }
  };

  // The bootstrap names the WSS channel by same-origin path, exactly like
  // prepare_url; this derives the ws(s): URL from the page's own scheme so
  // the probe never dials a cross-origin or scheme-downgraded endpoint.
  const sameOriginWsUrl = (value) => {
    const http = sameOriginUrl(value);
    if (http === null) return null;
    const scheme = globalThis.location.protocol === "https:" ? "wss:" : "ws:";
    try {
      const url = new URL(http.href);
      url.protocol = scheme;
      return url;
    } catch {
      return null;
    }
  };

  const isRequest = (value) => NativeRequest !== null && value instanceof NativeRequest;

  // Resolves the effective method and same-origin URL of one call, or null.
  const describe = (input, method) => {
    const href = isRequest(input) ? input.url : String(input);
    const url = new URL(href, globalThis.location.href);
    if (url.origin !== globalThis.location.origin) return null;
    const verb = String(method ?? (isRequest(input) ? input.method : "GET")).toUpperCase();
    return { method: verb, url };
  };

  const resolvePointer = (document, token) => {
    if (token === "") return document;
    let value = document;
    for (const raw of token.slice(1).split("/")) {
      const key = raw.replace(/~1/g, "/").replace(/~0/g, "~");
      if (Array.isArray(value)) {
        if (!/^(?:0|[1-9][0-9]*)$/.test(key)) return undefined;
        value = value[Number(key)];
      } else if (value !== null && typeof value === "object" && Object.hasOwn(value, key)) {
        value = value[key];
      } else {
        return undefined;
      }
    }
    return value;
  };

  // Targets and page actions never carry a query (the edge rejects one);
  // a list source may (the edge still injects its references).
  const routeMatches = (route, url, queryAllowed = false) =>
    (queryAllowed || url.search === "") &&
    (route.path !== undefined
      ? url.pathname === route.path
      : url.pathname.startsWith(route.prefix) &&
        url.pathname.length > route.prefix.length &&
        !url.pathname.slice(route.prefix.length).includes("/"));

  // The resource value a target request names, decoded once like the edge.
  const targetResource = (rule, url) => {
    if (rule.target.prefix !== undefined) {
      if (!routeMatches(rule.target, url)) return null;
      try {
        return decodeURIComponent(url.pathname.slice(rule.target.prefix.length));
      } catch {
        return null;
      }
    }
    if (url.pathname !== rule.target.path) return null;
    const query = new URLSearchParams(url.search);
    const values = query.getAll(rule.target.parameter);
    return values.length === 1 && [...query.keys()].length === 1 ? values[0] : null;
  };

  const referenceFor = (method, url) => {
    const now = Date.now();
    if (url.search === "") {
      const action = state.actions.get(`${method} ${url.pathname}`);
      if (action !== undefined && action.expiresAt > now) return action.ref;
    }
    for (let index = 0; index < state.rules.length; index += 1) {
      const rule = state.rules[index];
      if (rule.target.method !== method) continue;
      const resource = targetResource(rule, url);
      if (resource === null) continue;
      const entry = state.refs.get(`${index}\u0000${resource}`);
      if (entry !== undefined && entry.expiresAt > now) return entry.ref;
    }
    return null;
  };

  const couldBeHarvested = (method, url) =>
    state.rules.some(
      (rule) => rule.target.method === method && targetResource(rule, url) !== null,
    );

  const remember = (key, ref, expiresAt) => {
    state.refs.delete(key);
    if (state.refs.size >= MAX_HARVESTED_REFS) {
      state.refs.delete(state.refs.keys().next().value);
    }
    state.refs.set(key, { ref, expiresAt });
  };

  const clearReferences = () => {
    state.actions.clear();
    state.refs.clear();
  };

  const harvest = (index, document) => {
    const rule = state.rules[index];
    const items = resolvePointer(document, rule.itemsPointer);
    if (!Array.isArray(items) || items.length > rule.maxItems) return;
    const expiresAt = Date.now() + rule.ttlSeconds * 1000;
    for (const item of items) {
      if (item === null || typeof item !== "object" || Array.isArray(item)) continue;
      const ref = Object.hasOwn(item, rule.refField) ? item[rule.refField] : undefined;
      const resource = resolvePointer(item, rule.resourcePointer);
      if (typeof ref !== "string" || !REF.test(ref)) continue;
      if (typeof resource !== "string" || resource.length === 0 || resource.length > 512) {
        continue;
      }
      remember(`${index}\u0000${resource}`, ref, expiresAt);
    }
  };

  const harvestRule = (method, url) =>
    state.rules.findIndex(
      (rule) => rule.source.method === method && routeMatches(rule.source, url, true),
    );

  const track = (work) => {
    state.pending.add(work);
    work.finally(() => state.pending.delete(work)).catch(() => undefined);
  };

  // Reads the sensor's own clone. Cancelling one branch of a teed body only
  // settles once the page's branch is done too, so cancellation is never
  // awaited: the page keeps its response and the harvest ends now.
  const readBounded = async (response) => {
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_HARVEST_BYTES) {
      response.body?.cancel().catch(() => undefined);
      return null;
    }
    const reader = response.body?.getReader();
    if (reader === undefined) return null;
    const chunks = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_HARVEST_BYTES) {
        reader.cancel().catch(() => undefined);
        return null;
      }
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.byteLength;
    }
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  };

  // Observes a same-origin fetch response without consuming the page's body.
  const observeFetch = (responsePromise, target) => {
    const index = harvestRule(target.method, target.url);
    const invalidates = state.invalidate.has(`${target.method} ${target.url.pathname}`);
    if (index < 0 && !invalidates) return;
    const work = responsePromise
      .then((response) => {
        if (!response.ok) return undefined;
        if (invalidates) {
          clearReferences();
          return undefined;
        }
        if (!JSON_TYPE.test(response.headers.get("content-type") ?? "")) return undefined;
        // Cloned synchronously, before the page can read its own body.
        return readBounded(response.clone()).then((text) => {
          if (text !== null) harvest(index, JSON.parse(text));
        });
      })
      .catch(() => undefined);
    track(work);
  };

  // Returns a cancel function for a send that throws before dispatch, so a
  // request that never runs cannot hold the pending-harvest set.
  const observeXhr = (xhr, target) => {
    const index = harvestRule(target.method, target.url);
    const invalidates = state.invalidate.has(`${target.method} ${target.url.pathname}`);
    if (index < 0 && !invalidates) return null;
    let settle = () => undefined;
    track(
      new Promise((resolve) => {
        settle = resolve;
      }),
    );
    const done = () => {
      try {
        if (xhr.status < 200 || xhr.status > 299) return;
        if (invalidates) {
          clearReferences();
          return;
        }
        if (!JSON_TYPE.test(xhr.getResponseHeader("content-type") ?? "")) return;
        if (xhr.responseType === "json") {
          if (xhr.response !== null) harvest(index, xhr.response);
        } else if (xhr.responseType === "" || xhr.responseType === "text") {
          const text = xhr.responseText;
          if (text.length <= MAX_HARVEST_BYTES) harvest(index, JSON.parse(text));
        }
      } catch {
        // Observation is best effort; the page keeps its own response.
      } finally {
        settle();
      }
    };
    xhr.addEventListener("loadend", done, { once: true });
    return () => {
      xhr.removeEventListener("loadend", done);
      settle();
    };
  };

  // Waits for the bootstrap and, for a possible harvest target without a
  // known reference, for in-flight list responses (both bounded).
  const settleFor = (target) =>
    ready.then(() => {
      if (
        state.pending.size === 0 ||
        referenceFor(target.method, target.url) !== null ||
        !couldBeHarvested(target.method, target.url)
      ) {
        return undefined;
      }
      return Promise.race([
        Promise.allSettled([...state.pending]),
        new Promise((resolve) => setTimer(resolve, HARVEST_WAIT_MS)),
      ]);
    });

  const mustWait = (target) =>
    !state.ready ||
    (state.pending.size > 0 &&
      referenceFor(target.method, target.url) === null &&
      couldBeHarvested(target.method, target.url));

  // Adds the reference to a copy of the call's headers; a value the page set
  // itself is never replaced, and Request-carried referrer data is preserved.
  const withReference = (input, init, ref) => {
    const own = init !== undefined && init !== null && init.headers !== undefined;
    const headers = new NativeHeaders(
      own ? init.headers : isRequest(input) ? input.headers : undefined,
    );
    if (headers.has(ACTION_HEADER)) return null;
    headers.set(ACTION_HEADER, ref);
    const next = Object.create(init !== null && typeof init === "object" ? init : null);
    Object.defineProperty(next, "headers", { value: headers, enumerable: true });
    if (isRequest(input)) {
      for (const field of ["referrer", "referrerPolicy"]) {
        if (init === undefined || init === null || init[field] === undefined) {
          Object.defineProperty(next, field, { value: input[field], enumerable: true });
        }
      }
    }
    return next;
  };

  // Replaces a fetch call's body with its ENVELOPE_HOOK envelope when the
  // target names a configured operation and the call carries a plain string
  // body (the common `body: JSON.stringify(...)` shape); `null` otherwise,
  // so the caller dispatches the call unmodified — a `Request`-carried body,
  // FormData, or any other shape is left for the edge to deny.
  const encryptedCall = (method, url, call) => {
    const op = envelopeOpFor(method, url);
    if (op === null) return null;
    const [input, init] = call;
    const plaintext = init !== null && typeof init === "object" ? init.body : undefined;
    if (typeof plaintext !== "string") return null;
    return buildEnvelope(op, method, url, plaintext).then((envelope) => {
      const headers = new NativeHeaders(init.headers);
      headers.set("Content-Type", ENVELOPE_CONTENT_TYPE);
      const next = Object.create(init);
      Object.defineProperty(next, "headers", { value: headers, enumerable: true });
      Object.defineProperty(next, "body", { value: envelope, enumerable: true });
      return [input, next];
    });
  };

  const installFetchHook = () => {
    if (nativeFetch === null || NativeHeaders === null) return;
    const hooked = function fetch(input, init) {
      let target = null;
      try {
        target = describe(input, init?.method);
      } catch {
        target = null;
      }
      if (target === null || target.url.pathname.startsWith(RESERVED_PREFIX)) {
        return Reflect.apply(nativeFetch, this, arguments);
      }
      const self = this;
      const original = arguments;
      const finish = (call) => {
        const response = Reflect.apply(nativeFetch, self, call);
        try {
          observeFetch(response, target);
        } catch {
          // Never let observation affect the page's promise.
        }
        return response;
      };
      const dispatch = () => {
        let call = original;
        try {
          const ref = referenceFor(target.method, target.url);
          const next = ref === null ? null : withReference(input, init, ref);
          if (next !== null) call = [input, next];
        } catch {
          call = original;
        }
        const encrypted = encryptedCall(target.method, target.url, call);
        return encrypted === null ? finish(call) : encrypted.then(finish, () => finish(call));
      };
      return mustWait(target) ? settleFor(target).then(dispatch) : dispatch();
    };
    Object.defineProperty(hooked, "length", { value: nativeFetch.length });
    globalThis.fetch = hooked;
  };

  const installXhrHook = () => {
    if (NativeXHR === null) return;
    const prototype = NativeXHR.prototype;
    const nativeOpen = prototype.open;
    const nativeSend = prototype.send;
    const nativeSetHeader = prototype.setRequestHeader;
    const calls = new WeakMap();
    prototype.open = function open(method, url) {
      try {
        const target = describe(url, method);
        calls.set(this, {
          target,
          async: arguments.length < 3 || Boolean(arguments[2]),
          pageReference: false,
          contentTypeSet: false,
        });
      } catch {
        calls.delete(this);
      }
      return Reflect.apply(nativeOpen, this, arguments);
    };
    prototype.setRequestHeader = function setRequestHeader(name, _value) {
      try {
        const call = calls.get(this);
        if (call !== undefined) {
          const lower = String(name).toLowerCase();
          if (lower === ACTION_HEADER.toLowerCase()) call.pageReference = true;
          // XHR's native setRequestHeader combines repeated values instead
          // of replacing them, unlike Headers#set: a page that already set
          // its own Content-Type must not also receive the encrypted one.
          if (lower === "content-type") call.contentTypeSet = true;
        }
      } catch {
        // Header tracking is advisory; the native call decides.
      }
      return Reflect.apply(nativeSetHeader, this, arguments);
    };
    prototype.send = function send(body) {
      const call = calls.get(this);
      if (
        call === undefined ||
        call.target === null ||
        call.target.url.pathname.startsWith(RESERVED_PREFIX)
      ) {
        return Reflect.apply(nativeSend, this, arguments);
      }
      const xhr = this;
      const original = arguments;
      const dispatch = () => {
        // A later open() replaces this call; never send on its behalf.
        if (calls.get(xhr) !== call) return undefined;
        let cancel = null;
        const finish = (sendArgs) => {
          try {
            const ref = call.pageReference ? null : referenceFor(call.target.method, call.target.url);
            if (ref !== null) Reflect.apply(nativeSetHeader, xhr, [ACTION_HEADER, ref]);
            cancel = observeXhr(xhr, call.target);
          } catch {
            // Fall through to the unmodified native send.
          }
          try {
            return Reflect.apply(nativeSend, xhr, sendArgs);
          } catch (error) {
            cancel?.();
            throw error;
          }
        };
        const op = call.contentTypeSet ? null : envelopeOpFor(call.target.method, call.target.url);
        if (op === null || typeof body !== "string") return finish(original);
        buildEnvelope(op, call.target.method, call.target.url, body)
          .then((envelope) => {
            if (calls.get(xhr) !== call) return;
            Reflect.apply(nativeSetHeader, xhr, ["Content-Type", ENVELOPE_CONTENT_TYPE]);
            finish([envelope]);
          })
          .catch(() => finish(original));
        return undefined;
      };
      if (!call.async || !mustWait(call.target)) return dispatch();
      settleFor(call.target)
        .then(dispatch)
        .catch(() => undefined);
      return undefined;
    };
  };

  const validActions = (actions) => {
    if (!Array.isArray(actions) || actions.length > MAX_ACTIONS) return null;
    const valid = new Map();
    const now = Date.now();
    for (const action of actions) {
      if (
        action === null ||
        typeof action !== "object" ||
        typeof action.action_ref !== "string" ||
        !REF.test(action.action_ref) ||
        !METHODS.has(action.method) ||
        !path(action.path_template) ||
        !integer(action.expires_in_seconds, 1, 86400)
      ) {
        return null;
      }
      valid.set(`${action.method} ${action.path_template}`, {
        ref: action.action_ref,
        expiresAt: now + action.expires_in_seconds * 1000,
      });
    }
    return valid;
  };

  const validRoute = (route, allowQuery) => {
    if (route === null || typeof route !== "object" || !METHODS.has(route.method)) return null;
    if (route.prefix !== undefined) {
      return path(route.prefix) && route.prefix.endsWith("/") && route.path === undefined
        ? { method: route.method, prefix: route.prefix }
        : null;
    }
    if (!path(route.path)) return null;
    if (route.parameter === undefined) return { method: route.method, path: route.path };
    return allowQuery && typeof route.parameter === "string" && NAME.test(route.parameter)
      ? { method: route.method, path: route.path, parameter: route.parameter }
      : null;
  };

  const validRules = (rules) => {
    if (!Array.isArray(rules) || rules.length > MAX_RULES) return null;
    const valid = [];
    for (const rule of rules) {
      if (rule === null || typeof rule !== "object") return null;
      const source = validRoute(rule.source, false);
      const target = validRoute(rule.target, true);
      if (
        source === null ||
        target === null ||
        (target.prefix === undefined && target.parameter === undefined) ||
        !pointer(rule.items_pointer) ||
        !pointer(rule.resource_pointer) ||
        typeof rule.ref_field !== "string" ||
        !NAME.test(rule.ref_field) ||
        !integer(rule.ttl_seconds, 1, 86400) ||
        !integer(rule.max_items, 1, 1000)
      ) {
        return null;
      }
      valid.push({
        source,
        target,
        itemsPointer: rule.items_pointer,
        resourcePointer: rule.resource_pointer,
        refField: rule.ref_field,
        ttlSeconds: rule.ttl_seconds,
        maxItems: rule.max_items,
      });
    }
    return valid;
  };

  const validInvalidations = (routes) => {
    if (!Array.isArray(routes) || routes.length > MAX_RULES) return null;
    const valid = new Set();
    for (const route of routes) {
      const checked = validRoute(route, false);
      if (checked === null || checked.path === undefined) return null;
      valid.add(`${checked.method} ${checked.path}`);
    }
    return valid;
  };

  // The site's ENVELOPE_HOOK operations (docs/08 §8.1): each one an exact
  // method and path, like an invalidation route, plus the operation and
  // adapter identifiers the AAD binds. An absent list means the site
  // configured none; an invalid one rejects the whole bootstrap, same as
  // every other malformed field.
  const validEnvelopeOperations = (operations) => {
    if (operations === undefined) return new Map();
    if (!Array.isArray(operations) || operations.length > MAX_RULES) return null;
    const valid = new Map();
    for (const operation of operations) {
      const route = validRoute(operation, false);
      if (
        route === null ||
        route.path === undefined ||
        !bounded(operation.operation_id) ||
        !bounded(operation.adapter_revision)
      ) {
        return null;
      }
      valid.set(`${route.method} ${route.path}`, {
        operationId: operation.operation_id,
        adapterRevision: operation.adapter_revision,
      });
    }
    return valid;
  };

  // A same-origin WSS channel for heartbeat and event reporting, with the
  // 1.1.0 HTTPS batch POST as its fallback transport (docs/07 7.3). The
  // socket is best-effort: every send still has a working HTTPS path, so a
  // blocked or failing upgrade never holds up or loses an observation.
  const openWsChannel = (wsUrl) => {
    if (NativeWebSocket === null) return null;
    const channel = { socket: null, attempt: 0, closed: false };
    const reconnectDelay = () => {
      const base = Math.min(
        WS_RECONNECT_MIN_MS * 2 ** channel.attempt,
        WS_RECONNECT_MAX_MS,
      );
      return base / 2 + Math.random() * (base / 2);
    };
    const connect = () => {
      if (channel.closed) return;
      let socket;
      try {
        socket = new NativeWebSocket(wsUrl.href);
      } catch {
        setTimer(connect, reconnectDelay());
        channel.attempt += 1;
        return;
      }
      channel.socket = socket;
      socket.addEventListener("open", () => {
        channel.attempt = 0;
      });
      const retry = () => {
        if (channel.socket === socket) channel.socket = null;
        if (channel.closed) return;
        setTimer(connect, reconnectDelay());
        channel.attempt += 1;
      };
      socket.addEventListener("close", retry);
      socket.addEventListener("error", () => undefined);
    };
    connect();
    return channel;
  };

  const startObservations = (bootstrap, prepareUrl, wsUrl) => {
    let sequence = 0;
    const channel = openWsChannel(wsUrl);
    const sendHttps = (event) => {
      void Reflect.apply(nativeFetch, globalThis, [
        prepareUrl,
        {
          method: "POST",
          credentials: "same-origin",
          keepalive: true,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ events: [event] }),
        },
      ]).catch(() => undefined);
    };
    const emit = (eventType) => {
      sequence += 1;
      const event = {
        sensor_version: SENSOR_VERSION,
        build_ref: bootstrap.build_ref,
        page_handle: bootstrap.page_handle,
        navigation_id: bootstrap.navigation_id,
        action_hint: null,
        client_request_id: null,
        client_event_seq: sequence,
        visibility: globalThis.document.visibilityState,
        event_type: eventType,
        callsite_fingerprint: null,
      };
      const body = JSON.stringify({ events: [event] });
      if (
        channel !== null &&
        channel.socket !== null &&
        channel.socket.readyState === NativeWebSocket.OPEN
      ) {
        try {
          channel.socket.send(body);
          return;
        } catch {
          // Falls through to the HTTPS transport below.
        }
      }
      sendHttps(event);
    };
    emit("PAGE_READY");
    const heartbeat = () => {
      emit("HEARTBEAT");
      const jittered =
        bootstrap.heartbeat_seconds *
        1000 *
        (1 + (Math.random() * 2 - 1) * HEARTBEAT_JITTER_RATIO);
      setTimer(heartbeat, jittered);
    };
    setTimer(heartbeat, bootstrap.heartbeat_seconds * 1000);
    globalThis.document.addEventListener("visibilitychange", () => emit("VISIBILITY"));
  };

  // Applies one validated bootstrap document. Any invalid field rejects the
  // whole document: the page then holds no references (default deny).
  const start = (bootstrap, pageHandle) => {
    // A bootstrap that arrives after the wait bound still applies to later calls.
    if (state.started || bootstrap === null || typeof bootstrap !== "object") return false;
    const prepareUrl = sameOriginUrl(bootstrap.prepare_url);
    const wsUrl = sameOriginWsUrl(bootstrap.ws_url);
    const actions = validActions(bootstrap.actions);
    const rules = validRules(bootstrap.harvest);
    const invalidate = validInvalidations(bootstrap.invalidate);
    const envelopeOps = validEnvelopeOperations(bootstrap.envelope_operations);
    // The key and its identifier are only required once at least one
    // operation needs them; a site with none configured sends neither.
    const envelopeHookReady =
      envelopeOps !== null &&
      (envelopeOps.size === 0 ||
        (bounded(bootstrap.tenant_id) &&
          bounded(bootstrap.site_id) &&
          ENVELOPE_KEY_HEX.test(bootstrap.envelope_key ?? "") &&
          ENVELOPE_KEY_ID.test(bootstrap.envelope_key_id ?? "")));
    if (
      bootstrap.sensor_version !== SENSOR_VERSION ||
      bootstrap.page_handle !== pageHandle ||
      prepareUrl === null ||
      wsUrl === null ||
      actions === null ||
      rules === null ||
      invalidate === null ||
      !envelopeHookReady ||
      !bounded(bootstrap.build_ref) ||
      !bounded(bootstrap.navigation_id) ||
      !integer(bootstrap.heartbeat_seconds, 5, 300)
    ) {
      return false;
    }
    state.started = true;
    state.actions = actions;
    state.rules = rules;
    state.invalidate = invalidate;
    state.envelopeOps = envelopeOps;
    if (envelopeOps.size > 0) {
      state.tenantId = bootstrap.tenant_id;
      state.siteId = bootstrap.site_id;
      state.envelopeKeyId = bootstrap.envelope_key_id;
      state.envelopeKey =
        nativeSubtle === null
          ? Promise.resolve(null)
          : nativeSubtle
              .importKey("raw", hexToBytes(bootstrap.envelope_key), "AES-GCM", false, ["encrypt"])
              .catch(() => null);
    }
    finish();
    startObservations(bootstrap, prepareUrl, wsUrl);
    return true;
  };

  // Fetches the no-store bootstrap for exactly the page handle the edge
  // embedded in this document's loader tag. Runs at most once.
  const boot = (pageHandle) => {
    if (state.booted) return Promise.resolve(false);
    state.booted = true;
    if (nativeFetch === null || typeof pageHandle !== "string" || !PAGE_HANDLE.test(pageHandle)) {
      finish();
      return Promise.resolve(false);
    }
    return Reflect.apply(nativeFetch, globalThis, [
      `${BOOTSTRAP_PATH}?page=${pageHandle}&sensor_version=${SENSOR_VERSION}`,
      { credentials: "same-origin", cache: "no-store", headers: { Accept: "application/json" } },
    ])
      .then((response) => (response.ok ? response.json() : null))
      .then((bootstrap) => start(bootstrap, pageHandle))
      .catch(() => false)
      .then((started) => {
        finish();
        return started;
      });
  };

  try {
    installFetchHook();
    installXhrHook();
  } catch {
    // A partially hooked page still reaches the edge, which denies by default.
  }
  const api = Object.freeze({
    version: SENSOR_VERSION,
    boot,
    coverage: Object.freeze({
      fetch: nativeFetch !== null,
      xhr: NativeXHR !== null,
      workers: false,
      iframes: false,
      serviceWorkers: false,
      savedFetchReferences: false,
      envelopeHook: nativeSubtle !== null,
    }),
  });
  try {
    Object.defineProperty(globalThis, "XshieldSensor", {
      value: api,
      configurable: false,
      enumerable: false,
      writable: false,
    });
  } catch {
    // Another sensor already owns the name; the hooks above still apply.
  }
})();
