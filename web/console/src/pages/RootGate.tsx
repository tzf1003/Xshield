import { Outlet } from "@tanstack/react-router";
import { useSession } from "../security/SessionProvider";
import { LoginScreen } from "./LoginScreen";

/**
 * Hidden navigation is not authorization, and a missing session is not a route: until the server
 * has confirmed a session the sign-in screen replaces whatever address was requested, without
 * redirecting, and the matched route renders once the session exists.
 */
export function RootGate() {
  const { state } = useSession();
  if (state.status !== "connected") return <LoginScreen />;
  return <Outlet />;
}
