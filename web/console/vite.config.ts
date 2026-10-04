import { defineConfig } from "vite";

// The operator's credential may only reach this deployment-owned destination.
const target = new URL(process.env.XSHIELD_CONTROL_PROXY ?? "http://127.0.0.1:9443");
if (
  target.username ||
  target.password ||
  target.pathname !== "/" ||
  target.search ||
  target.hash ||
  !(
    target.protocol === "https:" ||
    (target.protocol === "http:" && ["127.0.0.1", "[::1]", "localhost"].includes(target.hostname))
  )
) {
  throw new Error("XSHIELD_CONTROL_PROXY requires an HTTPS origin or loopback HTTP origin");
}
const readPath =
  /^\/control\/v1\/(?:requests\/req_[a-f0-9-]+(?:\/(?:events|evidence))?|artifacts\/artifact_[a-f0-9-]+|model-calls(?:\/mdl_[a-f0-9-]+)?|grants\/grant_[a-f0-9-]+|auth-bindings\/auth_[a-f0-9-]+|evidence-access-requests|cases(?:\/case_[a-f0-9-]+\/(?:items|holds))?|exports\/export_[a-f0-9-]+)$/;
const jobPath = /^\/control\/v1\/jobs\/job_[a-f0-9-]+$/;
const calibrationReportPath = /^\/control\/v1\/calibration-reports\/calr_[a-f0-9-]+$/;
const writePath =
  /^\/control\/v1\/(?:cases|cases\/case_[a-f0-9-]+\/(?:items|close|holds|analyze)|evidence-holds\/ev_[a-f0-9-]+\/release|artifacts\/artifact_[a-f0-9-]+\/access|evidence-access-requests\/access_[a-f0-9-]+\/(?:approve|deny)|exports|exports\/export_[a-f0-9-]+\/(?:approve|deny))$/;
const accessReadPath =
  /^\/control\/v1\/(?:evidence-access-requests\/access_[a-f0-9-]+|artifacts\/artifact_[a-f0-9-]+\/content|exports\/export_[a-f0-9-]+\/download)$/;
const modelCallListPath = "/control/v1/model-calls";
const auditHealthPath = "/control/v1/audit/health";
const workbenchOverviewPath = "/control/v1/workbench/overview";
const causalityPath = "/control/v1/causality";
const oidcLoginPath = "/control/v1/auth/oidc/start";
const oidcCallbackPath = "/control/v1/auth/oidc/callback";
const oidcReauthStartPath = "/control/v1/auth/oidc/reauth/start";
const sessionPath = "/control/v1/session";
const sessionLogoutPath = "/control/v1/session/logout";
const siteConfigPath = "/control/v1/site-config";
const sitesPath = "/control/v1/sites";
const sitePath = /^\/control\/v1\/sites\/[A-Za-z0-9_.-]{1,128}$/;
const siteConfigCollectionPath = /^\/control\/v1\/sites\/[A-Za-z0-9_.-]{1,128}\/config$/;
const siteOperationPath =
  /^\/control\/v1\/sites\/[A-Za-z0-9_.-]{1,128}\/(?:revisions|status|health)$/;
const siteMutationPath =
  /^\/control\/v1\/sites\/[A-Za-z0-9_.-]{1,128}\/(?:validate|apply|approve|rollback)$/;

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

function validSiteListQuery(url: string): boolean {
  const [path, query] = url.split("?", 2);
  if (path !== sitesPath || query === undefined) return false;
  const parameters = new URLSearchParams(query);
  const limit = parameters.get("limit");
  const cursor = parameters.get("cursor");
  return (
    (parameters.size === 1 || parameters.size === 2) &&
    limit !== null &&
    /^(?:[1-9]|[1-9][0-9]|100)$/.test(limit) &&
    (parameters.size === 1
      ? cursor === null
      : cursor !== null && /^[A-Za-z0-9_.-]{1,160}$/.test(cursor))
  );
}

export default defineConfig({
  server: {
    port: 55173,
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
                    : path === workbenchOverviewPath
                      ? request.url === workbenchOverviewPath
                      : readPath.test(path)) ||
                (request.url === path && calibrationReportPath.test(path)) ||
                (request.url === path && accessReadPath.test(path)) ||
                (request.url === path && jobPath.test(path)))) ||
            request.url === siteConfigPath ||
            request.url === sitesPath ||
            validSiteListQuery(request.url ?? "") ||
            (request.url === path && sitePath.test(path)) ||
            (request.url === path && siteConfigCollectionPath.test(path)) ||
            (request.url === path && siteOperationPath.test(path)) ||
            (request.method === "PATCH" && request.url === path && sitePath.test(path)) ||
            (request.method === "DELETE" && request.url === path && sitePath.test(path)) ||
            (request.method === "POST" && request.url === path && siteMutationPath.test(path)) ||
            (request.method === "PUT" &&
              (request.url === siteConfigPath ||
                (request.url === path && siteConfigCollectionPath.test(path)))) ||
            (request.method === "POST" && request.url === sitesPath) ||
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
              .filter((value) => allowedCookieNames.some((name) => value.startsWith(`${name}=`)));
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
  build: {
    sourcemap: false,
    // The CSP is `font-src 'self'`: fonts must stay separate hashed files, never data: URIs.
    assetsInlineLimit: 0,
  },
});
