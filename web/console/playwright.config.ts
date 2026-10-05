import { defineConfig, devices } from "@playwright/test";

// Parallel worktrees pick distinct port pairs: XSHIELD_E2E_PORT and the next port.
const machinePort = Number(process.env.XSHIELD_E2E_PORT ?? 5175);
const sessionPort = machinePort + 1;
const machineOrigin = `http://127.0.0.1:${machinePort}`;
const sessionOrigin = `http://127.0.0.1:${sessionPort}`;

export default defineConfig({
  testDir: "./tests",
  testMatch: "**/*.spec.ts",
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  // The mocked control API tells a StrictMode duplicate read from a real one by a short abort
  // window (tests/control-mock.ts), which a slow shared runner can miss. One CI retry absorbs
  // that; a deterministic failure still fails both attempts and a passed retry is reported flaky.
  retries: process.env.CI ? 1 : 0,
  workers: 2,
  reporter: "list",
  use: { baseURL: machineOrigin, trace: "off", screenshot: "off" },
  projects: [
    {
      name: "chromium",
      testIgnore: [
        "**/browser-session.spec.ts",
        "**/shell-session.spec.ts",
        "**/work-session.spec.ts",
        "**/site-roles.spec.ts",
        "**/site-release-session.spec.ts",
        "**/operations-session.spec.ts",
        "**/api-keys-session.spec.ts",
      ],
      use: { ...devices["Desktop Chrome"] },
    },
    {
      name: "browser-session",
      testMatch: [
        "**/browser-session.spec.ts",
        "**/shell-session.spec.ts",
        "**/work-session.spec.ts",
        "**/site-roles.spec.ts",
        "**/site-release-session.spec.ts",
        "**/operations-session.spec.ts",
        "**/api-keys-session.spec.ts",
      ],
      use: { ...devices["Desktop Chrome"], baseURL: sessionOrigin },
    },
  ],
  webServer: [
    {
      command: `VITE_XSHIELD_E2E_MACHINE_LOGIN=1 npx vite --host 127.0.0.1 --port ${machinePort} --strictPort`,
      url: machineOrigin,
      reuseExistingServer: !process.env.CI,
      timeout: 30_000,
    },
    {
      command: `VITE_XSHIELD_E2E_MACHINE_LOGIN=0 npx vite --host 127.0.0.1 --port ${sessionPort} --strictPort`,
      url: sessionOrigin,
      reuseExistingServer: !process.env.CI,
      timeout: 30_000,
    },
  ],
});
