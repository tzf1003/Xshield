import { createContext, type ReactNode, useContext } from "react";
import { createPortal } from "react-dom";

/**
 * The page heading belongs to the shell so a title appears exactly once. A page contributes its
 * own actions (refresh, export, ...) to the heading row through this slot.
 */
export const PageActionsTarget = createContext<HTMLElement | null>(null);

export function PageActions({ children }: { children: ReactNode }) {
  const target = useContext(PageActionsTarget);
  return target ? createPortal(children, target) : null;
}
