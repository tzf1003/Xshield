import { QueryClientProvider } from "@tanstack/react-query";
import {
  createContext,
  type ReactNode,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useSyncExternalStore,
} from "react";
import { ApiError, bootstrapBrowserSession, ControlClient } from "../api";
import { installBeforeUnloadGuard } from "./pending-operations.ts";
import type { SessionRuntime } from "./runtime.ts";
import type { SessionState } from "./session-store.ts";

/**
 * The synthetic Bearer form exists only in the explicitly enabled local Playwright build; the
 * production console authenticates with the HttpOnly OIDC cookie alone.
 */
export const machineLoginEnabled =
  import.meta.env.DEV && import.meta.env.VITE_XSHIELD_E2E_MACHINE_LOGIN === "1";

export type SessionContextValue = {
  runtime: SessionRuntime;
  /** Reactive snapshot of the session store. */
  state: SessionState;
  /** False until the cookie-session probe answered; always true for machine login. */
  authReady: boolean;
  machineLoginEnabled: boolean;
  /** Returns false when the credential is not a well-formed Bearer token. */
  connectWithToken: (token: string) => boolean;
  /** Ends the server session, then clears local state whether or not the server answered. */
  logout: () => Promise<void>;
  /** Starts the OIDC step-up. Resolves to a message on failure, or null while redirecting. */
  reauthenticate: () => Promise<string | null>;
  disconnect: (notice?: string | null) => void;
};

const SessionContext = createContext<SessionContextValue | null>(null);

export function SessionProvider({
  runtime,
  children,
}: {
  runtime: SessionRuntime;
  children: ReactNode;
}) {
  const { store } = runtime;
  const state = useSyncExternalStore(store.subscribe, store.getState);
  const [authReady, setAuthReady] = useState(machineLoginEnabled);

  // Browser sessions: ask the server who the HttpOnly cookie belongs to.
  useEffect(() => {
    if (machineLoginEnabled) return;
    const controller = new AbortController();
    void bootstrapBrowserSession(controller.signal)
      .then((session) => {
        if (controller.signal.aborted) return;
        store.connect({
          client: new ControlClient(undefined, session.csrf_token),
          scope: { tenant_id: session.tenant_id, site_id: session.site_id },
          roles: session.roles,
          session,
        });
      })
      .catch((error: unknown) => {
        if (controller.signal.aborted) return;
        if (!(error instanceof ApiError && error.status === 401)) {
          store.setNotice(
            error instanceof ApiError ? error.message : "无法恢复管理会话，请检查服务后重试。",
          );
        }
      })
      .finally(() => {
        if (!controller.signal.aborted) setAuthReady(true);
      });
    return () => controller.abort();
  }, [store]);

  // Activity restarts the idle countdown; hiding or leaving the page ends the session.
  const connected = state.status === "connected";
  useEffect(() => {
    if (!connected) return;
    const touch = () => store.touch();
    const leave = () => store.disconnect(null);
    window.addEventListener("pointerdown", touch);
    window.addEventListener("keydown", touch);
    window.addEventListener("pagehide", leave);
    return () => {
      window.removeEventListener("pointerdown", touch);
      window.removeEventListener("keydown", touch);
      window.removeEventListener("pagehide", leave);
    };
  }, [connected, store]);

  useEffect(() => installBeforeUnloadGuard(runtime.pending, window), [runtime.pending]);

  const connectWithToken = useCallback(
    (token: string) => {
      try {
        store.connect({
          client: new ControlClient(token),
          scope: null,
          roles: null,
          session: null,
        });
        return true;
      } catch {
        return false;
      }
    },
    [store],
  );

  const logout = useCallback(async () => {
    const client = store.getState().client;
    if (!client) return;
    try {
      await client.logoutBrowserSession();
      store.disconnect("已安全退出管理会话。");
    } catch (error) {
      // The server may have revoked the session before an audit or network failure prevented
      // a success reply. Never keep sensitive UI state.
      store.disconnect(
        error instanceof ApiError
          ? `${error.message} 页面状态已清理，请重新登录确认会话状态。`
          : "退出状态未确认；页面状态已清理，请重新登录确认会话状态。",
      );
    }
  }, [store]);

  const reauthenticate = useCallback(async () => {
    const client = store.getState().client;
    if (!client) return null;
    try {
      const authorizationUrl = await client.startReauthentication(store.signal);
      window.location.assign(authorizationUrl);
      return null;
    } catch (error) {
      return error instanceof ApiError
        ? `${error.message} 页面状态保持不变。`
        : "无法启动身份再认证，请稍后重试。";
    }
  }, [store]);

  const disconnect = useCallback(
    (notice: string | null = null) => store.disconnect(notice),
    [store],
  );

  const value = useMemo<SessionContextValue>(
    () => ({
      runtime,
      state,
      authReady,
      machineLoginEnabled,
      connectWithToken,
      logout,
      reauthenticate,
      disconnect,
    }),
    [runtime, state, authReady, connectWithToken, logout, reauthenticate, disconnect],
  );

  return (
    <QueryClientProvider client={runtime.queryClient}>
      <SessionContext.Provider value={value}>{children}</SessionContext.Provider>
    </QueryClientProvider>
  );
}

export function useSession(): SessionContextValue {
  const value = useContext(SessionContext);
  if (!value) throw new Error("useSession requires SessionProvider");
  return value;
}
