import { CheckOutlined, CopyOutlined } from "@ant-design/icons";
import { useEffect, useRef, useState } from "react";
import "./kit.css";

type Props = {
  /** The text placed on the clipboard. */
  value: string;
  /** What is being copied, for the accessible name. Defaults to the value itself. */
  label?: string;
  /** Dense tables keep the control out of the tab order; the detail pages do not. */
  tabbable?: boolean;
};

/** Copy-to-clipboard icon button. A blocked clipboard (insecure context) degrades to a notice. */
export function CopyButton({ value, label, tabbable = true }: Props) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<number | null>(null);
  useEffect(
    () => () => {
      if (timer.current !== null) window.clearTimeout(timer.current);
    },
    [],
  );
  async function copy() {
    try {
      await navigator.clipboard.writeText(value);
      setState("copied");
    } catch {
      setState("failed");
    }
    if (timer.current !== null) window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState("idle"), 1500);
  }
  const name = label ?? value;
  const text =
    state === "copied"
      ? `已复制 ${name}`
      : state === "failed"
        ? "复制失败，请手动选择"
        : `复制 ${name}`;
  return (
    <button
      type="button"
      className="xs-copy"
      aria-label={text}
      title={text}
      tabIndex={tabbable ? 0 : -1}
      onClick={() => void copy()}
    >
      {state === "copied" ? (
        <CheckOutlined aria-hidden="true" />
      ) : (
        <CopyOutlined aria-hidden="true" />
      )}
    </button>
  );
}
