(() => {
  "use strict";

  void globalThis
    .fetch("/__xshield/v1/bootstrap", {
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    })
    .then((response) => {
      if (!response.ok) throw new Error("bootstrap unavailable");
      return response.json();
    })
    .then((bootstrap) => globalThis.XshieldSensor?.start(bootstrap))
    .catch(() => undefined);
})();
