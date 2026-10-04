import { App as AntdApp } from "antd";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { AppRouter } from "./router/AppRouter";
import { runFrozenWrite } from "./security/guarded.ts";
import { createSessionRuntime } from "./security/runtime.ts";
import { machineLoginEnabled, SessionProvider } from "./security/SessionProvider";
import { applyStoredThemeAttributes, ThemeProvider } from "./theme/ThemeProvider";
import "./theme/fonts";
import "./theme/tokens.generated.css";
import "./style.css";
import "./shell/shell.css";

// One runtime for the page: the session, its query cache and its pending writes live and die together.
const runtime = createSessionRuntime();
// Test-only seam of the explicitly enabled local Playwright build (the same gate as the Bearer
// form). `import.meta.env.DEV` is false in production builds, so none of this ships.
if (machineLoginEnabled) {
  Object.defineProperty(window, "__xshieldE2E", {
    value: Object.freeze({ runtime, runFrozenWrite }),
  });
}
const root = document.getElementById("root");
const cspNonce =
  document.querySelector('meta[name="xshield-csp-nonce"]')?.getAttribute("content") || undefined;
// An explicit light/dark choice must be on <html> before the first React paint.
applyStoredThemeAttributes();
if (root)
  createRoot(root).render(
    <StrictMode>
      <ThemeProvider cspNonce={cspNonce}>
        <SessionProvider runtime={runtime}>
          <AntdApp>
            <AppRouter runtime={runtime} />
          </AntdApp>
        </SessionProvider>
      </ThemeProvider>
    </StrictMode>,
  );
