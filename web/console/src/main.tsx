import { App as AntdApp } from "antd";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { applyStoredThemeAttributes, ThemeProvider } from "./theme/ThemeProvider";
import "./theme/fonts";
import "./theme/tokens.generated.css";
import "./style.css";

const root = document.getElementById("root");
const cspNonce =
  document.querySelector('meta[name="xshield-csp-nonce"]')?.getAttribute("content") || undefined;
// An explicit light/dark choice must be on <html> before the first React paint.
applyStoredThemeAttributes();
if (root)
  createRoot(root).render(
    <StrictMode>
      <ThemeProvider cspNonce={cspNonce}>
        <AntdApp>
          <App />
        </AntdApp>
      </ThemeProvider>
    </StrictMode>,
  );
