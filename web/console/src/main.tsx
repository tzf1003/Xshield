import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App as AntdApp, ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import { App } from "./App";
import "./style.css";

const root = document.getElementById("root");
const cspNonce = document.querySelector('meta[name="xshield-csp-nonce"]')?.getAttribute("content") ?? undefined;
if (root)
  createRoot(root).render(
    <StrictMode>
      <ConfigProvider
        locale={zhCN}
        componentSize="middle"
        csp={cspNonce ? { nonce: cspNonce } : undefined}
        getPopupContainer={(trigger) => trigger?.parentElement ?? document.body}
        theme={{
          token: {
            colorPrimary: "#2563eb",
            colorInfo: "#2563eb",
            colorSuccess: "#16a34a",
            colorWarning: "#d97706",
            colorError: "#dc2626",
            colorText: "#0f172a",
            colorTextSecondary: "#475569",
            colorBorder: "#dbe3ec",
            colorBgLayout: "#f5f7fa",
            borderRadius: 8,
            controlHeight: 40,
            fontFamily: "Inter, -apple-system, BlinkMacSystemFont, Segoe UI, PingFang SC, Microsoft YaHei, sans-serif",
          },
        }}
      >
        <AntdApp>
          <App />
        </AntdApp>
      </ConfigProvider>
    </StrictMode>,
  );
