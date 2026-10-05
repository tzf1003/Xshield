import { CheckOutlined, CopyOutlined } from "@ant-design/icons";
import { useEffect, useRef, useState } from "react";
import "./ui.css";

type Props = {
  value: string;
  /** What the value is, for the copy button's accessible name (for example "站点 ID"). */
  label: string;
  /** Show only the start and the end of long values (the full value stays in the title). */
  maxLength?: number;
};

function shorten(value: string, maxLength: number | undefined): string {
  if (maxLength === undefined || value.length <= maxLength) return value;
  const head = Math.ceil((maxLength - 1) * 0.6);
  const tail = maxLength - 1 - head;
  return `${value.slice(0, head)}…${value.slice(value.length - tail)}`;
}

/** An identifier in the monospace face with a copy button; copying never leaves the page. */
export function IdChip({ value, label, maxLength }: Props) {
  const [copied, setCopied] = useState(false);
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
      setCopied(true);
      if (timer.current !== null) window.clearTimeout(timer.current);
      timer.current = window.setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard access can be denied (insecure context, permissions); the value is on screen.
      setCopied(false);
    }
  }
  return (
    <span className="xs-idchip">
      <code className="mono" title={value}>
        {shorten(value, maxLength)}
      </code>
      <button
        type="button"
        className="xs-idchip-copy"
        aria-label={copied ? `${label}已复制` : `复制${label}`}
        onClick={() => void copy()}
      >
        {copied ? <CheckOutlined /> : <CopyOutlined />}
      </button>
    </span>
  );
}
