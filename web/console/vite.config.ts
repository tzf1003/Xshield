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
  /^\/control\/v1\/(?:requests\/req_[a-f0-9-]+(?:\/(?:events|evidence))?|artifacts\/artifact_[a-f0-9-]+|model-calls\/mdl_[a-f0-9-]+|grants\/grant_[a-f0-9-]+|auth-bindings\/auth_[a-f0-9-]+|evidence-access-requests|cases(?:\/case_[a-f0-9-]+\/(?:items|holds))?)$/;
const writePath =
  /^\/control\/v1\/(?:cases|cases\/case_[a-f0-9-]+\/(?:items|close|holds)|evidence-holds\/ev_[a-f0-9-]+\/release|artifacts\/artifact_[a-f0-9-]+\/access|evidence-access-requests\/access_[a-f0-9-]+\/(?:approve|deny))$/;
const accessReadPath =
  /^\/control\/v1\/(?:evidence-access-requests\/access_[a-f0-9-]+|artifacts\/artifact_[a-f0-9-]+\/content)$/;

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
            (request.method === "GET" &&
              (readPath.test(path) ||
                (request.url === path && accessReadPath.test(path)))) ||
            (request.method === "POST" &&
              (request.url === "/control/v1/search" ||
                (request.url === path && writePath.test(path))));
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
