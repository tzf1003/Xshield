import { defineConfig, devices } from "@playwright/test";

// Parallel worktrees pick a distinct port via XSHIELD_E2E_PORT.
const port = Number(process.env.XSHIELD_E2E_PORT ?? 5175);
const baseURL = `http://127.0.0.1:${port}`;

// Every spec runs against fixed JSON served by page.route (tests/helpers/mock-api.ts), so no
// backend is needed. The same files in tests/fixtures are the contract the Rust side round-trips.
export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.ts",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 2 : 0,
  reporter: "list",
  timeout: 30_000,
  expect: { timeout: 8_000 },
  use: {
    baseURL,
    trace: "off",
    screenshot: "off",
    locale: "zh-CN",
    timezoneId: "Asia/Shanghai",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: `npx vite --host 127.0.0.1 --port ${port} --strictPort`,
    url: baseURL,
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
