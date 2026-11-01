// A collapsible view of a parsed JSON value. Every key and value is a text node (docs/07 7.10.6).
// Nodes past `openDepth` start collapsed, so a large record stays readable.

import { useState } from "react";
import { SafeText } from "./SafeText.tsx";

type Props = {
  value: unknown;
  openDepth?: number;
  query?: string;
};

export function JsonTree({ value, openDepth = 2, query = "" }: Props) {
  return (
    <div className="json-tree">
      <Node name={null} value={value} depth={0} openDepth={openDepth} query={query} />
    </div>
  );
}

function Leaf({ value, query }: { value: unknown; query: string }) {
  if (typeof value === "string") {
    return (
      <span className="str">
        {`"`}
        <SafeText text={value} query={query} />
        {`"`}
      </span>
    );
  }
  if (typeof value === "number") return <span className="num">{String(value)}</span>;
  if (typeof value === "boolean" || value === null) return <span className="lit">{String(value)}</span>;
  return <span className="lit">{String(value)}</span>;
}

function Node({
  name,
  value,
  depth,
  openDepth,
  query,
}: {
  name: string | null;
  value: unknown;
  depth: number;
  openDepth: number;
  query: string;
}) {
  const [open, setOpen] = useState(depth < openDepth);
  const label = name === null ? null : <span className="k">{`${name}: `}</span>;

  if (value === null || typeof value !== "object") {
    return (
      <div>
        {label}
        <Leaf value={value} query={query} />
      </div>
    );
  }

  const entries: Array<[string, unknown]> = Array.isArray(value)
    ? value.map((item, index) => [String(index), item])
    : Object.entries(value);
  const open_ = open ? "▾" : "▸";
  const brackets = Array.isArray(value) ? ["[", "]"] : ["{", "}"];

  return (
    <div>
      <button type="button" aria-expanded={open} onClick={() => setOpen((current) => !current)}>
        {open_}
      </button>{" "}
      {label}
      <span>{brackets[0]}</span>
      {open ? null : <span className="dim">{` … ${entries.length} 项 `}</span>}
      {open ? (
        <div className="indent">
          {entries.map(([key, item]) => (
            <Node
              key={key}
              name={key}
              value={item}
              depth={depth + 1}
              openDepth={openDepth}
              query={query}
            />
          ))}
        </div>
      ) : null}
      <span>{brackets[1]}</span>
    </div>
  );
}
