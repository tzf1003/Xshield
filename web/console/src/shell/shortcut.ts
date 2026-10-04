type KeyEventLike = Pick<KeyboardEvent, "key" | "metaKey" | "ctrlKey" | "altKey" | "shiftKey">;

/**
 * Command/Ctrl+K, without Alt or Shift. Kept apart from the classifier so the shell can listen
 * for it without loading the (lazily fetched) palette code.
 */
export function isPaletteShortcut(event: KeyEventLike): boolean {
  return (
    (event.metaKey || event.ctrlKey) &&
    !event.altKey &&
    !event.shiftKey &&
    event.key.toLowerCase() === "k"
  );
}
