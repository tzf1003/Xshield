// Sign-out shared by the navigation and the user menu. The cached data of the signed-in visitor is
// dropped, so the next person to sign in on this browser tab never sees it.

import { useNavigate } from "@tanstack/react-router";
import { useCallback } from "react";
import { api } from "../api/client.ts";
import { keys } from "../api/queries.ts";
import { queryClient } from "../api/query-client.ts";

export function useLogoutAction(): () => Promise<void> {
  const navigate = useNavigate();
  return useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // The session cookie is cleared by the server on success; a failed call still ends the session
      // in this tab, because the login page is shown next.
    }
    queryClient.setQueryData(keys.session, { authenticated: false });
    await navigate({ to: "/login", replace: true });
    queryClient.clear();
  }, [navigate]);
}
