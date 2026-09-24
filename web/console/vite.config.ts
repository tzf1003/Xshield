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
  /^\/control\/v1\/(?:requests\/req_[a-f0-9-]+(?:\/(?:events|evidence))?|artifacts\/artifact_[a-f0-9-]+|model-calls(?:\/mdl_[a-f0-9-]+)?|grants\/grant_[a-f0-9-]+|auth-bindings\/auth_[a-f0-9-]+|evidence-access-requests|cases(?:\/case_[a-f0-9-]+\/(?:items|holds))?)$/;
const jobPath = /^\/control\/v1\/jobs\/job_[a-f0-9-]+$/;
const calibrationReportPath =
  /^\/control\/v1\/calibration-reports\/calr_[a-f0-9-]+$/;
const writePath =
  /^\/control\/v1\/(?:cases|cases\/case_[a-f0-9-]+\/(?:items|close|holds|analyze)|evidence-holds\/ev_[a-f0-9-]+\/release|artifacts\/artifact_[a-f0-9-]+\/access|evidence-access-requests\/access_[a-f0-9-]+\/(?:approve|deny))$/;
const accessReadPath =
  /^\/control\/v1\/(?:evidence-access-requests\/access_[a-f0-9-]+|artifacts\/artifact_[a-f0-9-]+\/content)$/;
const modelCallListPath = "/control/v1/model-calls";
const auditHealthPath = "/control/v1/audit/health";
const causalityPath = "/control/v1/causality";
const oidcLoginPath = "/control/v1/auth/oidc/start";
const oidcCallbackPath = "/control/v1/auth/oidc/callback";
const oidcReauthStartPath = "/control/v1/auth/oidc/reauth/start";
const sessionPath = "/control/v1/session";
const sessionLogoutPath = "/control/v1/session/logout";

function validModelCallListQuery(url: string): boolean {
  const [path, query] = url.split("?", 2);
  if (path !== modelCallListPath || query === undefined) return false;
  const parameters = new URLSearchParams(query);
  const start = parameters.get("start");
  const end = parameters.get("end");
  const limit = parameters.get("limit");
  const cursor = parameters.get("cursor");
  return (
    (parameters.size === 3 || parameters.size === 4) &&
    start !== null &&
    end !== null &&
    limit !== null &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(start) &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(end) &&
    /^(?:[1-9]|[1-9][0-9]|100)$/.test(limit) &&
    (parameters.size === 3
      ? cursor === null
      : cursor !== null && /^[A-Za-z0-9_.-]{1,160}$/.test(cursor))
  );
}

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
        bypass(request, response) {
          const path = (request.url ?? "").split("?")[0] ?? "";
          const allowed =
            (request.method === "GET" &&
              ((path === oidcLoginPath && request.url === path) ||
                path === oidcCallbackPath ||
                (path === sessionPath && request.url === path) ||
                (path === modelCallListPath
                ? validModelCallListQuery(request.url ?? "")
                : path === auditHealthPath
                  ? request.url === auditHealthPath
                  : readPath.test(path)) ||
                (request.url === path && calibrationReportPath.test(path)) ||
                (request.url === path && accessReadPath.test(path)) ||
                (request.url === path && jobPath.test(path)))) ||
            (request.method === "POST" &&
              (((path === sessionLogoutPath || path === oidcReauthStartPath) &&
                request.url === path) ||
                request.url === "/control/v1/search" ||
                request.url === causalityPath ||
                (request.url === path && writePath.test(path))));
          if (!allowed) {
            if (response) {
              response.statusCode = 404;
              response.end();
            }
            return false;
          }
        },
        configure(proxy) {
          proxy.on("proxyReq", (proxyRequest, request) => {
            const path = (request.url ?? "").split("?", 2)[0] ?? "";
            const allowedCookieNames =
              path === oidcCallbackPath
                ? ["__Host-xshield-oidc-state"]
                : path === oidcLoginPath
                  ? []
                  : ["__Host-xshield-session"];
            const rawCookie = request.headers.cookie;
            const cookies = (Array.isArray(rawCookie) ? rawCookie : [rawCookie])
              .filter((value): value is string => typeof value === "string")
              .flatMap((value) => value.split(";"))
              .map((value) => value.trim())
              .filter((value) =>
                allowedCookieNames.some((name) => value.startsWith(`${name}=`)),
              );
            if (cookies.length === 0) proxyRequest.removeHeader("cookie");
            else proxyRequest.setHeader("cookie", cookies.join("; "));
          });
          proxy.on("proxyRes", (proxyResponse, request) => {
            const path = (request.url ?? "").split("?", 2)[0] ?? "";
            if (
              path !== oidcLoginPath &&
              path !== oidcCallbackPath &&
              path !== sessionLogoutPath &&
              path !== oidcReauthStartPath
            ) {
              delete proxyResponse.headers["set-cookie"];
            }
          });
        },
      },
    },
  },
  build: { sourcemap: false },
});
