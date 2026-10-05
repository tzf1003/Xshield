/*
 * Xshield browser sensor 1.1.0, served at /__xshield/v1/sensor/1.1.0.js.
 *
 * Responsibilities: page observations (as 1.0.0) and presenting
 * server-issued, opaque action references on the page's own same-origin
 * fetch/XMLHttpRequest calls. The sensor never creates, derives or guesses a
 * reference: it only repeats a value the edge delivered through the no-store
 * bootstrap (page actions) or injected into an approved JSON list response
 * (harvested references). The edge re-validates every presented reference
 * against the full credential set, so a wrong or missing reference is denied,
 * never silently allowed.
 *
 * Coverage (see docs/07 section 7.4): window.fetch and XMLHttpRequest of this
 * document only. Workers, iframes, service workers and references to fetch
 * saved before this script ran are not hooked; their requests carry no
 * reference and gated operations stay denied.
 *
 * Every hook failure falls back to the unmodified native call, so the sensor
 * can never break the page. The bytes of this file are pinned by SRI once
 * released: ship a new version path instead of editing it.
 */
(() => {
  "use strict";

  const SENSOR_VERSION = "1.1.0";
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
  const METHODS = new Set(["GET", "POST", "PUT", "PATCH", "DELETE"]);
  const REF = /^[A-Za-z0-9_.-]{1,128}$/;
  const NAME = /^[A-Za-z0-9_.-]{1,128}$/;
  const PAGE_HANDLE =
    /^pgh_[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
  const JSON_TYPE = /^application\/(?:[A-Za-z0-9.+-]+\+)?json(?:\s*;|$)/i;

  // Captured before any later page script can replace them.
  const nativeFetch = typeof globalThis.fetch === "function" ? globalThis.fetch : null;
  const NativeXHR =
    typeof globalThis.XMLHttpRequest === "function" ? globalThis.XMLHttpRequest : null;
  const NativeRequest = typeof globalThis.Request === "function" ? globalThis.Request : null;
  const NativeHeaders = typeof globalThis.Headers === "function" ? globalThis.Headers : null;
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

  const sameOriginUrl = (value) => {
    if (!bounded(value)) return null;
    try {
      const url = new URL(value, globalThis.location.href);
      return url.origin === globalThis.location.origin ? url : null;
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

  const routeMatches = (route, url) =>
    route.path !== undefined
      ? url.pathname === route.path && url.search === ""
      : url.search === "" &&
        url.pathname.startsWith(route.prefix) &&
        url.pathname.length > route.prefix.length &&
        !url.pathname.slice(route.prefix.length).includes("/");

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
    state.rules.findIndex((rule) => rule.source.method === method && routeMatches(rule.source, url));

  const track = (work) => {
    state.pending.add(work);
    work.finally(() => state.pending.delete(work)).catch(() => undefined);
  };

  const readBounded = async (response) => {
    const declared = Number(response.headers.get("content-length"));
    if (Number.isFinite(declared) && declared > MAX_HARVEST_BYTES) {
      await response.body?.cancel();
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
        await reader.cancel();
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
      const dispatch = () => {
        let call = original;
        try {
          const ref = referenceFor(target.method, target.url);
          const next = ref === null ? null : withReference(input, init, ref);
          if (next !== null) call = [input, next];
        } catch {
          call = original;
        }
        const response = Reflect.apply(nativeFetch, self, call);
        try {
          observeFetch(response, target);
        } catch {
          // Never let observation affect the page's promise.
        }
        return response;
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
        });
      } catch {
        calls.delete(this);
      }
      return Reflect.apply(nativeOpen, this, arguments);
    };
    prototype.setRequestHeader = function setRequestHeader(name) {
      try {
        const call = calls.get(this);
        if (call !== undefined && String(name).toLowerCase() === ACTION_HEADER.toLowerCase()) {
          call.pageReference = true;
        }
      } catch {
        // Header tracking is advisory; the native call decides.
      }
      return Reflect.apply(nativeSetHeader, this, arguments);
    };
    prototype.send = function send() {
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
        try {
          const ref = call.pageReference ? null : referenceFor(call.target.method, call.target.url);
          if (ref !== null) Reflect.apply(nativeSetHeader, xhr, [ACTION_HEADER, ref]);
          cancel = observeXhr(xhr, call.target);
        } catch {
          // Fall through to the unmodified native send.
        }
        try {
          return Reflect.apply(nativeSend, xhr, original);
        } catch (error) {
          cancel?.();
          throw error;
        }
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

  const startObservations = (bootstrap, prepareUrl) => {
    let sequence = 0;
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
    emit("PAGE_READY");
    const heartbeat = () => {
      emit("HEARTBEAT");
      setTimer(heartbeat, bootstrap.heartbeat_seconds * 1000);
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
    const actions = validActions(bootstrap.actions);
    const rules = validRules(bootstrap.harvest);
    const invalidate = validInvalidations(bootstrap.invalidate);
    if (
      bootstrap.sensor_version !== SENSOR_VERSION ||
      bootstrap.page_handle !== pageHandle ||
      prepareUrl === null ||
      actions === null ||
      rules === null ||
      invalidate === null ||
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
    finish();
    startObservations(bootstrap, prepareUrl);
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
      `${BOOTSTRAP_PATH}?page=${pageHandle}`,
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
