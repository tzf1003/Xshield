import { defineConfig } from "vite";

// In dev, requests to /api are forwarded to the control backend (same cookie-based session).
// XSHIELD_CONTROL_PROXY lets each developer/CI worktree point at its own backend instance.
const target = process.env.XSHIELD_CONTROL_PROXY ?? "http://127.0.0.1:9443";

export default defineConfig({
  server: {
    port: 55173,
    strictPort: true,
    proxy: {
      "/api": {
        target,
        changeOrigin: true,
        followRedirects: false,
      },
    },
  },
  build: {
    sourcemap: false,
  },
});
