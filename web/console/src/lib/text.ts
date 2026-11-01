// Untrusted text from request records is only ever rendered as text nodes. Invisible and
// direction-changing characters are shown as visible escapes so a reader cannot be misled by
// them (docs/06 6.5.5). The source file itself contains no such characters: they are written as
// escapes in the pattern.

export type TextSegment = { kind: "text"; text: string } | { kind: "hidden"; code: string };

// biome-ignore lint/suspicious/noControlCharactersInRegex: the C0 range is the point; these characters must be shown, not hidden
const HIDDEN = /[\u0000-\u001f\u007f​-‏⁠﻿‪-‮⁦-⁩]/g;

/** Splits text into visible runs and escaped control characters, e.g. `‮`. */
export function splitHidden(text: string): TextSegment[] {
  const segments: TextSegment[] = [];
  let last = 0;
  for (const match of text.matchAll(HIDDEN)) {
    const index = match.index ?? 0;
    if (index > last) segments.push({ kind: "text", text: text.slice(last, index) });
    const code = match[0].charCodeAt(0).toString(16).padStart(4, "0");
    segments.push({ kind: "hidden", code: `\\u${code}` });
    last = index + match[0].length;
  }
  if (last < text.length) segments.push({ kind: "text", text: text.slice(last) });
  return segments;
}

/** True when the text contains anything `splitHidden` would escape. */
export function hasHidden(text: string): boolean {
  return new RegExp(HIDDEN.source).test(text);
}
