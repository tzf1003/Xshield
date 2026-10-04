import { useCallback, useSyncExternalStore } from "react";

/** Mobile layout breakpoint: below this width navigation becomes an off-canvas drawer. */
export const MOBILE_QUERY = "(max-width: 760px)";

export function useMediaQuery(query: string): boolean {
  const subscribe = useCallback(
    (notify: () => void) => {
      const list = window.matchMedia(query);
      list.addEventListener("change", notify);
      return () => list.removeEventListener("change", notify);
    },
    [query],
  );
  return useSyncExternalStore(
    subscribe,
    () => window.matchMedia(query).matches,
    () => false,
  );
}
