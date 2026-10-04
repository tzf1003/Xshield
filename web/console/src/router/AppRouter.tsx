import { RouterProvider } from "@tanstack/react-router";
import { NotFoundPage } from "../pages/NotFoundPage";
import { RootGate } from "../pages/RootGate";
import { RouteFailure, RoutePending } from "../pages/RouteStatus";
import type { SessionRuntime } from "../security/runtime.ts";
import { ShellLayout } from "../shell/ShellLayout";
import { createAppRouter } from "./create-router.ts";

// Created once per page load, outside React; the session runtime arrives through router context.
const { router } = createAppRouter({
  Root: RootGate,
  Shell: ShellLayout,
  NotFound: NotFoundPage,
  Pending: RoutePending,
  Failure: RouteFailure,
});

export function AppRouter({ runtime }: { runtime: SessionRuntime }) {
  return <RouterProvider router={router} context={{ runtime }} />;
}
