import { createContext, useContext } from "react";
import type { PaletteAction } from "./palette-classifier.ts";

/**
 * What a routed page may ask of the shell. It is the command palette's action vocabulary, so a
 * page that offers "准备历史检索" does exactly what pasting that ID into the palette would do:
 * open the structured search with one prefilled, unsubmitted condition.
 */
export type ShellActions = Readonly<{ run: (action: PaletteAction) => void }>;

export const ShellActionsContext = createContext<ShellActions | null>(null);

/** `null` outside the shell (unit-rendered pages): callers hide the affordance then. */
export function useShellActions(): ShellActions | null {
  return useContext(ShellActionsContext);
}
