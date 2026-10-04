import { CheckOutlined, CopyOutlined } from "@ant-design/icons";
import { Alert, Button, Skeleton, Space, Tag } from "antd";
import { type HTMLAttributes, type ReactNode, useEffect, useState } from "react";
import { StaleSessionError } from "../security/errors.ts";
import { type ErrorView, errorView } from "./errors.ts";
import { formatUtc, shortId } from "./format.ts";
import type { Pill } from "./status.ts";

/** A stable code, status and request ID next to the safe message; never server-written text. */
export function ErrorNotice({
  error,
  title,
  action,
}: {
  error: unknown;
  title?: string;
  action?: ReactNode;
}) {
  if (error instanceof StaleSessionError) return null;
  const view: ErrorView = errorView(error);
  return (
    <Alert
      type="error"
      showIcon
      title={title ?? view.message}
      action={action}
      description={
        <>
          {title && <div>{view.message}</div>}
          {view.hint && <div>{view.hint}</div>}
          <small className="mono xs-w-code">
            {view.code}
            {view.status ? ` · HTTP ${view.status}` : ""}
            {view.requestId ? ` · ${view.requestId}` : ""}
          </small>
        </>
      }
    />
  );
}

/** A monospace ID with a copy button. The full ID stays in the page text unless `short`. */
export function IdChip({
  id,
  short = false,
  label = "ID",
}: {
  id: string;
  short?: boolean;
  label?: string;
}) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = window.setTimeout(() => setCopied(false), 1500);
    return () => window.clearTimeout(timer);
  }, [copied]);
  async function copy() {
    try {
      await navigator.clipboard.writeText(id);
      setCopied(true);
    } catch {
      // No clipboard in this context: the ID is selectable text.
    }
  }
  return (
    <span className="xs-w-id">
      <code className="mono" title={id}>
        {short ? shortId(id) : id}
      </code>
      <Button
        type="text"
        size="small"
        aria-label={`复制${label} ${id}`}
        icon={copied ? <CheckOutlined aria-hidden="true" /> : <CopyOutlined aria-hidden="true" />}
        onClick={() => void copy()}
      />
    </span>
  );
}

/** One state vocabulary everywhere: the same word, colour and explanation for the same state. */
export function StatePill({ pill }: { pill: Pill }) {
  return (
    <Tag color={pill.tone} title={pill.hint} className="xs-w-pill">
      {pill.label}
    </Tag>
  );
}

/**
 * `onCell` helper: on narrow screens the table turns into stacked cards and each cell shows its
 * column name from this attribute (see work.css).
 */
export const labelled = (label: string) => () =>
  ({ "data-label": label }) as HTMLAttributes<HTMLElement>;

/** A UTC time with the exact instant on hover. */
export function Time({ value }: { value: string | null | undefined }) {
  if (!value) return <span>—</span>;
  return (
    <time dateTime={value} title={value}>
      {formatUtc(value)}
    </time>
  );
}

/**
 * Skeleton while the first read runs, the error with a retry once it failed, the content
 * otherwise. A session that ended renders nothing: the login screen replaces the page anyway.
 */
export function LoadState({
  pending,
  error,
  onRetry,
  children,
}: {
  pending: boolean;
  error: unknown;
  onRetry: () => void;
  children: ReactNode;
}) {
  if (pending) {
    return (
      <div aria-busy="true">
        <Skeleton active paragraph={{ rows: 3 }} />
      </div>
    );
  }
  if (error) {
    return (
      <ErrorNotice
        error={error}
        action={
          <Button size="small" onClick={onRetry}>
            重试
          </Button>
        }
      />
    );
  }
  return <>{children}</>;
}

/**
 * A labelled form control with one line of help or error text. The label is bound to the control
 * through `id`; the help is announced as its description.
 */
export function Field({
  id,
  label,
  help,
  error,
  children,
}: {
  id: string;
  label: string;
  help?: ReactNode;
  error?: string | null;
  children: ReactNode;
}) {
  return (
    <div className="xs-w-field">
      <label htmlFor={id}>{label}</label>
      {children}
      <small id={`${id}-help`} className={error ? "xs-w-error" : "xs-w-muted"}>
        {error ?? help}
      </small>
    </div>
  );
}

/** Label/value rows for detail panes. */
export function Facts({ rows }: { rows: readonly (readonly [string, ReactNode])[] }) {
  return (
    <dl className="xs-w-facts">
      {rows.map(([name, value]) => (
        <div key={name}>
          <dt>{name}</dt>
          <dd>{value}</dd>
        </div>
      ))}
    </dl>
  );
}

export function Observed({ asOf, requestId }: { asOf: string; requestId?: string }) {
  return (
    <span className="xs-w-muted xs-w-observed">
      观察于 <Time value={asOf} />
      {requestId ? (
        <>
          {" "}
          · 管理请求 <span className="mono">{requestId}</span>
        </>
      ) : null}
    </span>
  );
}

/** Cursor stack: pages replace each other and each is a fresh, independently audited read. */
export type PagerState = Readonly<{
  cursor: string | undefined;
  index: number;
  next: (cursor: string) => void;
  prev: () => void;
  first: () => void;
}>;

/**
 * `scope` is everything the cursor is bound to (view, case, filter ...). When it changes the
 * stack starts over, so a cursor can never be replayed against a query it was not issued for.
 */
export function usePager(scope: string): PagerState {
  const [state, setState] = useState<{ scope: string; stack: readonly (string | undefined)[] }>({
    scope,
    stack: [undefined],
  });
  const stack = state.scope === scope ? state.stack : [undefined];
  return {
    cursor: stack[stack.length - 1],
    index: stack.length - 1,
    next: (cursor) => setState({ scope, stack: [...stack, cursor] }),
    prev: () => setState({ scope, stack: stack.length > 1 ? stack.slice(0, -1) : stack }),
    first: () => setState({ scope, stack: [undefined] }),
  };
}

export function Pager({
  pager,
  count,
  nextCursor,
  busy,
  noun = "条",
}: {
  pager: PagerState;
  count: number;
  nextCursor: string | null;
  busy: boolean;
  noun?: string;
}) {
  return (
    <Space className="xs-w-pager" wrap>
      <Button size="small" disabled={busy || pager.index === 0} onClick={pager.first}>
        回到首页
      </Button>
      <Button size="small" disabled={busy || pager.index === 0} onClick={pager.prev}>
        上一页
      </Button>
      <span className="xs-w-muted">
        第 {pager.index + 1} 页 · 本页 {count} {noun}
      </span>
      <Button
        size="small"
        disabled={busy || nextCursor === null}
        onClick={() => {
          if (nextCursor !== null) pager.next(nextCursor);
        }}
      >
        下一页
      </Button>
    </Space>
  );
}
