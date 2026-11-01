/*
 * Xshield sensor loader 1.1.0, served at /__xshield/v1/sensor/1.1.0-loader.js.
 * Reads the per-delivery page handle from its own script tag (written by the
 * edge into the no-store HTML; it is not a credential) and asks the sensor to
 * fetch the session-bound bootstrap for exactly that page instance.
 */
(() => {
  "use strict";

  const script = globalThis.document?.currentScript;
  const page = typeof script?.getAttribute === "function"
    ? script.getAttribute("data-xshield-page")
    : null;
  const sensor = globalThis.XshieldSensor;
  if (sensor !== undefined && typeof sensor.boot === "function") {
    void sensor.boot(page).catch(() => undefined);
  }
})();
