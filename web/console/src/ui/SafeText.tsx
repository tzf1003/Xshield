// Text that came from a request record: rendered as text nodes only, with invisible and
// direction-changing characters shown as escapes and the search term highlighted (docs/06 6.5.5).

import { Fragment, type ReactNode } from "react";
import { splitHighlight } from "../lib/highlight.ts";
import { splitHidden } from "../lib/text.ts";

type Piece = { at: number; node: ReactNode };

export function SafeText({ text, query = "" }: { text: string; query?: string }) {
  const pieces: Piece[] = [];
  let at = 0;
  const push = (node: ReactNode, width: number) => {
    pieces.push({ at, node });
    at += width;
  };
  for (const segment of splitHidden(text)) {
    if (segment.kind === "hidden") {
      push(
        <span className="hidden-char" title="不可见或方向控制字符">
          {segment.code}
        </span>,
        1,
      );
      continue;
    }
    for (const part of splitHighlight(segment.text, query)) {
      push(part.hit ? <mark className="hit">{part.text}</mark> : part.text, part.text.length);
    }
  }
  return (
    <>
      {pieces.map((piece) => (
        <Fragment key={piece.at}>{piece.node}</Fragment>
      ))}
    </>
  );
}
