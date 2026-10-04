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
  projects: [
    { name: "chromium", testIgnore: "**/browser-session.spec.ts", use: { ...devices["Desktop Chrome"] } },
    { name: "browser-session", testMatch: "**/browser-session.spec.ts", use: { ...devices["Desktop Chrome"], baseURL: "http://127.0.0.1:5176" } },
  ],
  webServer: [{
    command:
      "VITE_XSHIELD_E2E_MACHINE_LOGIN=1 npx vite --host 127.0.0.1 --port 5175 --strictPort",
    url: "http://127.0.0.1:5175",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  }, {
    command: "VITE_XSHIELD_E2E_MACHINE_LOGIN=0 npx vite --host 127.0.0.1 --port 5176 --strictPort",
    url: "http://127.0.0.1:5176",
    reuseExistingServer: !process.env.CI,
    timeout: 30_000,
  }],
});
