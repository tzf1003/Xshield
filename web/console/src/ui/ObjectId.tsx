import type { ReactNode } from "react";
import { CopyButton } from "./CopyButton";
import { abbreviateId } from "./ids.ts";
import "./kit.css";

type Props = {
  value: string;
  /** Makes the ID a real link (middle-click and copy-link work); `onOpen` handles a plain click. */
  href?: string;
  onOpen?: () => void;
  /** Abbreviate the middle in dense tables. The full ID stays in the accessible name. */
  short?: boolean;
  /** Let a long ID wrap instead of truncating (detail panes). */
  wrap?: boolean;
  copyable?: boolean;
  /** Keep the copy button out of the tab order (dense tables). */
  quietCopy?: boolean;
};

function isModifiedClick(event: {
  button: number;
  metaKey: boolean;
  ctrlKey: boolean;
  shiftKey: boolean;
  altKey: boolean;
}) {
  return event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey;
}

/**
 * One object ID as a compact chip: monospace, optionally a link or button that opens the object,
 * and a copy control. The visible text may be abbreviated; the accessible name never is.
 */
export function ObjectId({
  value,
  href,
  onOpen,
  short = false,
  wrap = false,
  copyable = true,
  quietCopy = false,
}: Props) {
  const text = short ? abbreviateId(value) : value;
  const labelled = short ? { "aria-label": value } : {};
  let main: ReactNode;
  if (href) {
    main = (
      <a
        href={href}
        title={value}
        {...labelled}
        onClick={(event) => {
          if (!onOpen || isModifiedClick(event)) return;
          event.preventDefault();
          onOpen();
        }}
      >
        {text}
      </a>
    );
  } else if (onOpen) {
    main = (
      <button type="button" className="xs-id-open" title={value} {...labelled} onClick={onOpen}>
        {text}
      </button>
    );
  } else {
    main = (
      <span className="xs-id-text" title={value}>
        {text}
      </span>
    );
  }
  return (
    <span className={wrap ? "xs-id xs-id--wrap" : "xs-id"}>
      {main}
      {copyable ? <CopyButton value={value} tabbable={!quietCopy} /> : null}
    </span>
  );
}
