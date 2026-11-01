// Page furniture shared by every page: heading, cards, empty and error states, key-value lists,
// loading placeholders and metric tiles (docs/06 6.3.1, 6.7).

import { Link } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { ApiError } from "../api/client.ts";
import { errorText } from "../lib/vocab.ts";

export function PageHead({
  title,
  sub,
  actions,
  crumbs,
}: {
  title: string;
  sub?: ReactNode;
  actions?: ReactNode;
  crumbs?: ReactNode;
}) {
  return (
    <>
      {crumbs ? <div className="crumbs">{crumbs}</div> : null}
      <div className="pagehead">
        <div className="grow">
          <h1>{title}</h1>
          {sub ? <div className="sub">{sub}</div> : null}
        </div>
        {actions ? <div className="actions">{actions}</div> : null}
      </div>
    </>
  );
}

export function Card({
  title,
  aside,
  children,
  className,
}: {
  title?: ReactNode;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
}) {
  return (
    <section className={className ? `card ${className}` : "card"}>
      {title || aside ? (
        <div className="card-h">
          <span>{title}</span>
          {aside ? <span className="aside">{aside}</span> : null}
        </div>
      ) : null}
      {children}
    </section>
  );
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="empty">
      <div className="empty-title">{title}</div>
      {children}
    </div>
  );
}

/** The message for a failed request. Codes become text; the code itself is shown small for support. */
export function ErrorBar({ error, onRetry }: { error: unknown; onRetry?: () => void }) {
  const code = error instanceof ApiError ? error.code : undefined;
  const text = error instanceof ApiError ? errorText(code) : "无法读取数据，请稍后重试";
  return (
    <div className="errbar" role="alert">
      <span>{text}</span>
      {code ? <span className="mono small dim">{code}</span> : null}
      {onRetry ? (
        <button type="button" className="btn" onClick={onRetry}>
          重试
        </button>
      ) : null}
    </div>
  );
}

export function Kv({ items }: { items: Array<[string, ReactNode]> }) {
  return (
    <dl className="kv">
      {items.map(([term, value]) => (
        <div key={term} style={{ display: "contents" }}>
          <dt>{term}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Loading({ height = 14 }: { height?: number }) {
  return <div className="skeleton" style={{ height }} aria-label="正在加载" role="status" />;
}

export function Notice({
  tone = "warn",
  children,
}: {
  tone?: "warn" | "info" | "bad";
  children: ReactNode;
}) {
  const cls = tone === "warn" ? "notice" : `notice ${tone}`;
  return <div className={cls}>{children}</div>;
}

/** A metric card. With `to`, the whole card links to a filtered list. */
export function Tile({
  label,
  value,
  sub,
  children,
  to,
  search,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  children?: ReactNode;
  to?: "/requests" | "/jev" | "/sessions";
  search?: Record<string, string>;
}) {
  const body = (
    <>
      <div className="tile-l">{label}</div>
      <div className="tile-v">{value}</div>
      {sub ? <div className="tile-s">{sub}</div> : null}
      {children}
    </>
  );
  if (!to) return <div className="tile">{body}</div>;
  return (
    <Link to={to} search={(previous) => ({ ...previous, ...search })} className="tile">
      {body}
    </Link>
  );
}
