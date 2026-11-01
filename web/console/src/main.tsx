import "./styles/global.css";
import { QueryClientProvider } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { App as AntdApp } from "antd";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { queryClient } from "./api/query-client.ts";
import { router } from "./app/router.tsx";
import { ThemeProvider, applyStoredAttributes } from "./theme/ThemeProvider.tsx";

// Density and theme are written to the root before the first paint, so a stored choice never flashes.
applyStoredAttributes();

const container = document.getElementById("root");
if (!container) throw new Error("#root is missing from index.html");

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <ThemeProvider>
        <AntdApp>
          <RouterProvider router={router} />
        </AntdApp>
      </ThemeProvider>
    </QueryClientProvider>
  </StrictMode>,
);
