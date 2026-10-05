import { createContext, useContext, useEffect } from "react";

/**
 * The heading belongs to the shell so a title appears exactly once. A page that knows more than
 * its route does (a site's display name) contributes it through this slot; the override is
 * dropped when the page unmounts, so it can never outlive the page that set it.
 */
export const PageTitleSetter = createContext<((title: string | null) => void) | null>(null);

export function usePageTitle(title: string | null) {
  const set = useContext(PageTitleSetter);
  useEffect(() => {
    set?.(title);
    return () => set?.(null);
  }, [set, title]);
}
