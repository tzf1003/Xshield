import { defineConfig } from "vite";

// The operator's credential may only reach this deployment-owned destination.
const target = new URL(
  process.env.XSHIELD_CONTROL_PROXY ?? "http://127.0.0.1:9443",
);
if (
  target.username ||
  target.password ||
  target.pathname !== "/" ||
  target.search ||
  target.hash ||
  !(
    target.protocol === "https:" ||
    (target.protocol === "http:" &&
      ["127.0.0.1", "[::1]", "localhost"].includes(target.hostname))
  )
) {
  throw new Error(
    "XSHIELD_CONTROL_PROXY requires an HTTPS origin or loopback HTTP origin",
  );
}
const readPath =
  /^\/control\/v1\/(?:requests\/req_[a-f0-9-]+(?:\/(?:events|evidence))?|artifacts\/artifact_[a-f0-9-]+|model-calls\/mdl_[a-f0-9-]+|grants\/grant_[a-f0-9-]+|auth-bindings\/auth_[a-f0-9-]+)$/;

export default defineConfig({
  server: {
    port: 5173,
    strictPort: true,
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
    },
    proxy: {
      "/control/": {
        target: target.origin,
        changeOrigin: true,
        followRedirects: false,
        configure(proxy) {
          proxy.on("proxyReq", (request) => {
            request.removeHeader("cookie");
          });
          proxy.on("proxyRes", (response) => {
            delete response.headers["set-cookie"];
          });
        },
        bypass(request, response) {
          const path = (request.url ?? "").split("?")[0] ?? "";
          const allowed =
            (request.method === "GET" && readPath.test(path)) ||
            (request.method === "POST" && request.url === "/control/v1/search");
          if (!allowed) {
            if (response) {
              response.statusCode = 404;
              response.end();
            }
            return false;
          }
        },
      },
    },
  },
  build: { sourcemap: false },
});
