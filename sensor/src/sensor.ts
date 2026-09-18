(() => {
  "use strict";

  const SENSOR_VERSION = "1.0.0";
  const MAX_VALUE_LENGTH = 256;
  let started = false;

  const bounded = (value) =>
    typeof value === "string" && value.length > 0 && value.length <= MAX_VALUE_LENGTH;

  const sameOriginUrl = (value) => {
    if (!bounded(value)) return null;
    try {
      const url = new URL(value, globalThis.location.href);
      return url.origin === globalThis.location.origin ? url : null;
    } catch {
      return null;
    }
  };

  const start = (bootstrap) => {
    if (started || !bootstrap || typeof bootstrap !== "object") return false;
    const prepareUrl = sameOriginUrl(bootstrap.prepare_url);
    if (
      bootstrap.sensor_version !== SENSOR_VERSION ||
      !prepareUrl ||
      !bounded(bootstrap.build_ref) ||
      !bounded(bootstrap.page_handle) ||
      !bounded(bootstrap.navigation_id) ||
      !Number.isInteger(bootstrap.heartbeat_seconds) ||
      bootstrap.heartbeat_seconds < 5 ||
      bootstrap.heartbeat_seconds > 300
    ) {
      return false;
    }
    started = true;
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
      void globalThis
        .fetch(prepareUrl, {
          method: "POST",
          credentials: "same-origin",
          keepalive: true,
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ events: [event] }),
        })
        .catch(() => undefined);
    };
    emit("PAGE_READY");
    const heartbeat = () => {
      emit("HEARTBEAT");
      globalThis.setTimeout(heartbeat, bootstrap.heartbeat_seconds * 1000);
    };
    globalThis.setTimeout(heartbeat, bootstrap.heartbeat_seconds * 1000);
    globalThis.document.addEventListener("visibilitychange", () => emit("VISIBILITY"));
    return true;
  };

  const api = Object.freeze({ version: SENSOR_VERSION, start });
  Object.defineProperty(globalThis, "XshieldSensor", {
    value: api,
    configurable: false,
    enumerable: false,
    writable: false,
  });
  if (globalThis.__XSHIELD_BOOTSTRAP__) start(globalThis.__XSHIELD_BOOTSTRAP__);
})();
