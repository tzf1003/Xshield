import { defineConfig } from "vite";

// In dev, requests to /api are forwarded to the control plane (same cookie-based session). The
// production build is served by the control plane itself on the same origin (docs/07 7.2.3).
// XSHIELD_CONTROL_PROXY lets each developer or CI worktree point at its own backend instance.
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

export default defineConfig({
  server: {
    port: 55173,
    strictPort: true,
    // Routes are lazily loaded chunks that the dev server compiles on first use. Transforming the
    // app at start-up keeps the first visit as fast as the hundredth, which matters on a cold CI
    // runner where a slow first load would make a spec's waits time out.
    warmup: { clientFiles: ["./index.html", "./src/main.tsx", "./src/**/*.{ts,tsx}"] },
    headers: {
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
    },
    proxy: {
      "/api": {
        target: target.origin,
        changeOrigin: true,
        followRedirects: false,
      },
    },
  },
  build: {
    sourcemap: false,
    chunkSizeWarningLimit: 700,
  },
});
