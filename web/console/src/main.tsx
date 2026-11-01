import "@fontsource/ibm-plex-sans/400.css";
import "@fontsource/ibm-plex-sans/600.css";
import "@fontsource/jetbrains-mono/400.css";
import "./style.css";

import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { ConfigProvider } from "antd";
import zhCN from "antd/locale/zh_CN";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { onUnauthorized } from "./api.ts";
import { createAppRouter } from "./router.tsx";

const queryClient = new QueryClient({
  defaultOptions: { queries: { retry: false, refetchOnWindowFocus: false } },
});

const router = createAppRouter({ queryClient });

// A 401 from any API call (session expired mid-use) sends the operator back to /login, no
// matter which page or query triggered it.
onUnauthorized(() => {
  if (router.state.location.pathname !== "/login") {
    router.navigate({ to: "/login" });
  }
});

const root = document.getElementById("root");
if (root) {
  createRoot(root).render(
    <StrictMode>
      <QueryClientProvider client={queryClient}>
        <ConfigProvider
          locale={zhCN}
          button={{ autoInsertSpace: false }}
          theme={{ token: { colorPrimary: "#0958d9" } }}
        >
          <RouterProvider router={router} />
        </ConfigProvider>
      </QueryClientProvider>
    </StrictMode>,
  );
}
