import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.ts",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  workers: 2,
  reporter: "list",
  use: { baseURL: "http://127.0.0.1:5175", trace: "off", screenshot: "off" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "pnpm exec vite --host 127.0.0.1 --port 5175 --strictPort",
    url: "http://127.0.0.1:5175",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  },
});
