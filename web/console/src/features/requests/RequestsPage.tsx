// The request trace (docs/06 6.4.3): the main page of the console. Quick chips with counts, the
// condition line, the list, the preview beside it, batch lookup, export, and live mode.

import { Link, useNavigate, useSearch } from "@tanstack/react-router";
import { Button, Popover, Checkbox } from "antd";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useRequestCounts, useRequestPages, useSystem } from "../../api/queries.ts";
import type { RequestRow } from "../../api/types.ts";
import type { ChipId } from "../../app/search-schema.ts";
import { keepScope, type Scope, useScope, useSetSearch } from "../../app/scope.ts";
import { useKeys } from "../../app/keys.ts";
import { fmtClock, fmtInt } from "../../lib/format.ts";
import { isStaticAsset } from "../../lib/quick-rules.ts";
import { readJson, writeJson } from "../../lib/storage.ts";
import { RANGE_LABEL } from "../../lib/vocab.ts";
import { ErrorBar, Loading, PageHead, Notice } from "../../ui/Page.tsx";
import { QuickRuleDialog, type QuickTarget } from "../sites/QuickRuleDialog.tsx";
import { BatchLookupDialog } from "./BatchLookupDialog.tsx";
import { ExportDialog } from "./ExportDialog.tsx";
import { FilterBar } from "./FilterBar.tsx";
import { PeekPanel } from "./PeekPanel.tsx";
import { RequestTable, EXTRA_COLUMNS, type ExtraColumn, type RowAction } from "./RequestTable.tsx";
import { CHIPS, chipCount, planCounts, planList, unknownSiteCount } from "./query.ts";
import { LIVE_LIMIT, useLivePoll } from "./live.ts";

const LIVE_WINDOW_MS = 10 * 60 * 1000;
const ROW_CAP = 2000;
const FRESH_MS = 2000;
const COLUMNS_KEY = "xshield.console.columns";

function isExtraColumn(value: unknown): value is ExtraColumn {
  return EXTRA_COLUMNS.some((column) => column.id === value);
}

function readExtras(): ExtraColumn[] {
  return readJson<ExtraColumn[]>(
    COLUMNS_KEY,
    [],
    (value): value is ExtraColumn[] => Array.isArray(value) && value.every(isExtraColumn),
  );
}

function appendTerm(q: string, term: string): string {
  return [q.trim(), term].filter((part) => part.length > 0).join(" ");
}

function merge(incoming: RequestRow[], existing: RequestRow[]): RequestRow[] {
  const seen = new Set(incoming.map((row) => row.request_id));
  return [...incoming, ...existing.filter((row) => !seen.has(row.request_id))];
}

export function RequestsPage() {
  const search = useSearch({ from: "/requests" });
  const setSearch = useSetSearch();
  const navigate = useNavigate();
  const scope = useScope();
  const system = useSystem();

  const q = search.q ?? "";
  const chip: ChipId = search.chip ?? "judged";
  const allOn = search.scope === "all";
  const live = search.live === "1";
  const peek = search.peek ?? null;
  const batchOpen = search.batch === "1";

  const [exportOpen, setExportOpen] = useState(false);
  const [quick, setQuick] = useState<QuickTarget | null>(null);
  const [extras, setExtras] = useState<ExtraColumn[]>(readExtras);
  const [liveRows, setLiveRows] = useState<RequestRow[]>([]);
  const [pending, setPending] = useState<RequestRow[]>([]);
  const [fresh, setFresh] = useState<Set<string>>(() => new Set());
  const [overflow, setOverflow] = useState(false);
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const sentinel = useRef<HTMLDivElement | null>(null);
  const peekRef = useRef<string | null>(peek);

  useEffect(() => {
    peekRef.current = peek;
  });

  const listScope: Scope = useMemo(
    () =>
      live ? { ...scope, since: scope.until - LIVE_WINDOW_MS, until: scope.until + 60_000 } : scope,
    [live, scope],
  );
  const plan = useMemo(
    () => planList({ q, chip, all: allOn, scope: listScope }),
    [q, chip, allOn, listScope],
  );
  const countsQuery = useMemo(() => planCounts(q, scope), [q, scope]);
  const counts = useRequestCounts(countsQuery);
  const pages = useRequestPages(plan.query);
  const { hasNextPage, isFetchingNextPage, fetchNextPage, isPending, isError, error, refetch } =
    pages;

  // A new filter or window starts the live list again.
  // biome-ignore lint/correctness/useExhaustiveDependencies: the reset is keyed on the query itself
  useEffect(() => {
    setLiveRows([]);
    setPending([]);
    setOverflow(false);
  }, [plan.query]);

  const pageRows = useMemo(
    () => pages.data?.pages.flatMap((page) => page.rows) ?? [],
    [pages.data],
  );

  const displayRows = useMemo(() => {
    const seen = new Set<string>();
    const out: RequestRow[] = [];
    for (const row of [...liveRows, ...pageRows]) {
      if (seen.has(row.request_id)) continue;
      seen.add(row.request_id);
      out.push(row);
    }
    return out;
  }, [liveRows, pageRows]);
  const capped = displayRows.length >= ROW_CAP;

  const newestMillis = useMemo(() => {
    let newest = 0;
    for (const row of displayRows) newest = Math.max(newest, row.at_millis);
    return newest > 0 ? newest : null;
  }, [displayRows]);

  const onLiveRows = useCallback((rows: RequestRow[], overflowed: boolean) => {
    setOverflow(overflowed);
    if (rows.length === 0) return;
    const atTop = (scrollerRef.current?.scrollTop ?? 0) < 4 && peekRef.current === null;
    if (atTop) {
      setLiveRows((previous) => merge(rows, previous));
      setFresh(new Set(rows.map((row) => row.request_id)));
      window.setTimeout(() => setFresh(new Set()), FRESH_MS);
    } else {
      setPending((previous) => merge(rows, previous));
    }
  }, []);

  const poll = useLivePoll({ enabled: live, query: plan.query, newestMillis, onRows: onLiveRows });

  // Infinite list: the next page loads when the end of the table scrolls into view.
  useEffect(() => {
    const node = sentinel.current;
    if (!node || !hasNextPage || isFetchingNextPage || capped) return undefined;
    const observer = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) void fetchNextPage();
      },
      { root: scrollerRef.current, rootMargin: "200px" },
    );
    observer.observe(node);
    return () => observer.disconnect();
  }, [hasNextPage, isFetchingNextPage, capped, fetchNextPage]);

  const selectedIndex = peek ? displayRows.findIndex((row) => row.request_id === peek) : -1;

  const select = (id: string) => setSearch({ peek: id }, true);
  const openDetail = (id: string) => {
    void navigate({ to: "/requests/$requestId", params: { requestId: id }, search: keepScope });
  };
  const step = (delta: number) => {
    if (displayRows.length === 0) return;
    const base = selectedIndex < 0 ? (delta > 0 ? -1 : displayRows.length) : selectedIndex;
    const next = Math.min(displayRows.length - 1, Math.max(0, base + delta));
    const row = displayRows[next];
    if (!row) return;
    select(row.request_id);
    document.getElementById(`row-${row.request_id}`)?.scrollIntoView({ block: "nearest" });
  };

  const modalOpen = batchOpen || exportOpen || quick !== null;
  useKeys(
    {
      j: () => step(1),
      k: () => step(-1),
      Enter: (event) => {
        // Enter on a focused button or link keeps its own meaning.
        const tag = (event.target as HTMLElement | null)?.tagName;
        if (peek && tag !== "BUTTON" && tag !== "A") openDetail(peek);
      },
      Escape: () => {
        if (peek) setSearch({ peek: undefined }, true);
      },
      c: () => {
        if (peek) void navigator.clipboard?.writeText(peek);
      },
      l: () => setSearch({ live: live ? undefined : "1" }),
    },
    !modalOpen,
  );

  const setChip = (id: ChipId) =>
    setSearch({ chip: id === "judged" ? undefined : id, peek: undefined });

  const updateExtras = (next: ExtraColumn[]) => {
    setExtras(next);
    writeJson(COLUMNS_KEY, next);
  };

  const rowActions = (row: RequestRow): RowAction[] => {
    const items: RowAction[] = [
      {
        key: "copy",
        label: "复制请求 ID",
        onSelect: () => void navigator.clipboard?.writeText(row.request_id),
      },
      {
        key: "timeline",
        label: "打开会话时间线",
        disabled: row.session === "",
        onSelect: () =>
          void navigate({
            to: "/sessions/$label",
            params: { label: row.session },
            search: keepScope,
          }),
      },
      {
        key: "only-session",
        label: "只看这个会话",
        disabled: row.session === "",
        onSelect: () => setSearch({ q: appendTerm(q, `session:${row.session}`), peek: undefined }),
      },
      {
        key: "only-path",
        label: "只看这个路径",
        onSelect: () => setSearch({ q: appendTerm(q, `path:${row.path}`), peek: undefined }),
      },
    ];
    if (row.site !== null && row.decision_path === "no_session") {
      items.push({
        key: "entry",
        label: "登记为入口…",
        onSelect: () =>
          setQuick({
            kind: "entry",
            site: row.site ?? "",
            path: row.path,
            requestId: row.request_id,
          }),
      });
    }
    if (
      row.site !== null &&
      (isStaticAsset(row.path) || row.decision_path === "body_not_inspectable")
    ) {
      items.push({
        key: "bypass",
        label: "加入绕过…",
        onSelect: () =>
          setQuick({
            kind: "bypass",
            site: row.site ?? "",
            path: row.path,
            requestId: row.request_id,
          }),
      });
    }
    return items;
  };

  const gaps = (system.data?.storage.gaps ?? []).filter(
    (gap) => gap.to_millis >= scope.since && gap.from_millis <= scope.until,
  );
  const rangeLabel =
    scope.range === "custom" ? "自定义时间范围" : `最近 ${RANGE_LABEL[scope.range]}`;
  const showDate = scope.until - scope.since > 24 * 60 * 60 * 1000;
  const emptyOverall =
    !isPending && displayRows.length === 0 && q.length === 0 && chip === "judged";
  const emptyTitle =
    scope.range === "custom"
      ? "所选时间范围内没有请求"
      : `最近 ${RANGE_LABEL[scope.range]}没有请求`;

  const estimate = chipCount(chip, counts.data);
  const hiddenUnknown = unknownSiteCount(counts.data);

  return (
    <>
      <PageHead
        title="请求追溯"
        sub={`${scope.site ?? "全部站点"} · ${rangeLabel}`}
        actions={
          <>
            <Popover
              trigger="click"
              placement="bottomRight"
              title="显示的列"
              content={
                <Checkbox.Group
                  value={extras}
                  onChange={(value) => updateExtras(value.filter(isExtraColumn))}
                  options={EXTRA_COLUMNS.map((column) => ({
                    label: column.label,
                    value: column.id,
                  }))}
                  style={{ display: "flex", flexDirection: "column", gap: 6 }}
                />
              }
            >
              <Button>列…</Button>
            </Popover>
            <Button onClick={() => setSearch({ batch: "1" })}>批量对照</Button>
            <Button onClick={() => setExportOpen(true)}>导出</Button>
          </>
        }
      />

      <fieldset
        className="chips"
        aria-label="快捷筛选"
        style={{ border: 0, margin: 0, padding: 0, minWidth: 0 }}
      >
        {CHIPS.map((item) => {
          const count = chipCount(item.id, counts.data);
          return (
            <button
              type="button"
              key={item.id}
              className="chip"
              aria-pressed={chip === item.id}
              onClick={() => setChip(item.id)}
            >
              {item.label}
              <span className="count">{count === null ? "…" : fmtInt(count)}</span>
            </button>
          );
        })}
        {counts.data && !counts.data.complete ? (
          <span className="toolbar-note">按前 {fmtInt(counts.data.scanned)} 条记录计算</span>
        ) : null}
        {!allOn && hiddenUnknown > 0 ? (
          <span className="toolbar-note">
            另有 {fmtInt(hiddenUnknown)} 条未知站点请求 ·{" "}
            <button type="button" className="linkbtn" onClick={() => setSearch({ scope: "all" })}>
              显示
            </button>
          </span>
        ) : null}
      </fieldset>

      <FilterBar
        value={q}
        onCommit={(text) => setSearch({ q: text.length > 0 ? text : undefined, peek: undefined })}
        allOn={allOn}
        onAll={(on) => setSearch({ scope: on ? "all" : undefined })}
        includesAll={plan.includesAll}
        live={live}
        onLive={(on) => setSearch({ live: on ? "1" : undefined })}
        liveDisabled={false}
      />

      {gaps.length > 0 ? (
        <Notice tone="warn">
          {fmtClock(gaps[0]?.from_millis ?? 0)}–{fmtClock(gaps[0]?.to_millis ?? 0)} {gaps[0]?.edge}{" "}
          有 {gaps[0]?.rows} 条记录未写入（
          {gaps[0]?.reason === "queue_full" ? "队列满" : "写入出错"}
          ），这段时间的请求可能查不到 · <Link to="/system">查看系统</Link>
        </Notice>
      ) : null}
      {live && poll.paused ? (
        <Notice tone="info">
          实时模式已暂停（10 分钟无操作）·{" "}
          <button type="button" className="linkbtn" onClick={poll.resume}>
            继续
          </button>
        </Notice>
      ) : null}
      {live && overflow ? (
        <Notice tone="warn">
          新请求太多，实时模式只显示最新 {fmtInt(LIVE_LIMIT)} 条，请增加筛选条件。
        </Notice>
      ) : null}
      {pending.length > 0 ? (
        <div className="row" style={{ marginBottom: 8 }}>
          <button
            type="button"
            className="btn"
            onClick={() => {
              setLiveRows((previous) => merge(pending, previous));
              setPending([]);
              scrollerRef.current?.scrollTo({ top: 0 });
            }}
          >
            ↑ {pending.length} 条新请求
          </button>
        </div>
      ) : null}
      <div className="sr-only" aria-live="polite">
        {pending.length > 0 ? `有 ${pending.length} 条新请求` : ""}
      </div>

      {isError ? <ErrorBar error={error} onRetry={() => void refetch()} /> : null}

      <div className={peek ? "split" : undefined}>
        <div style={{ minWidth: 0 }}>
          {isPending && displayRows.length === 0 ? (
            <Loading height={220} />
          ) : plan.impossible ? (
            <div className="empty">
              <div className="empty-title">条件互相排斥，没有结果</div>
              两个条件要求的结论没有交集（例如 outcome:blocked 与 outcome:allowed 同时出现）。
            </div>
          ) : displayRows.length === 0 ? (
            <div className="empty">
              {emptyOverall ? (
                <>
                  <div className="empty-title">{emptyTitle}</div>
                  <div className="row" style={{ justifyContent: "center" }}>
                    <Link to="/system" search={keepScope}>
                      查看网关状态
                    </Link>
                    <button
                      type="button"
                      className="linkbtn"
                      onClick={() => setSearch({ range: "7d", since: undefined, until: undefined })}
                    >
                      扩大到 7 天
                    </button>
                  </div>
                </>
              ) : (
                <>
                  <div className="empty-title">没有符合条件的请求</div>
                  <div className="row" style={{ justifyContent: "center" }}>
                    {q.length > 0 ? (
                      <button
                        type="button"
                        className="linkbtn"
                        onClick={() => setSearch({ q: undefined })}
                      >
                        清除条件
                      </button>
                    ) : null}
                    {chip !== "judged" ? (
                      <button type="button" className="linkbtn" onClick={() => setChip("judged")}>
                        清除快捷筛选
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className="linkbtn"
                      onClick={() => setSearch({ range: "7d", since: undefined, until: undefined })}
                    >
                      扩大到 7 天
                    </button>
                    {!allOn ? (
                      <button
                        type="button"
                        className="linkbtn"
                        onClick={() => setSearch({ scope: "all" })}
                      >
                        包含绕过和未知站点
                      </button>
                    ) : null}
                  </div>
                </>
              )}
            </div>
          ) : (
            <RequestTable
              rows={displayRows}
              selectedId={peek}
              showSite={scope.site === undefined}
              showDate={showDate}
              extras={extras}
              fresh={fresh}
              scrollerRef={scrollerRef}
              onSelect={select}
              onOpen={openDetail}
              actionsFor={rowActions}
            />
          )}
          <div className="tbl-foot">
            <span>
              已显示 {fmtInt(displayRows.length)} 条
              {capped ? "（已达 2,000 条上限，请缩小时间范围或增加条件）" : ""}
            </span>
            {hasNextPage && !capped ? (
              <button
                type="button"
                className="linkbtn"
                onClick={() => void fetchNextPage()}
                disabled={isFetchingNextPage}
              >
                {isFetchingNextPage ? "正在加载…" : "加载更多"}
              </button>
            ) : null}
            <span ref={sentinel} aria-hidden="true" />
          </div>
        </div>
        {peek ? (
          <PeekPanel
            requestId={peek}
            onClose={() => setSearch({ peek: undefined }, true)}
            onOpen={() => openDetail(peek)}
          />
        ) : null}
      </div>

      <BatchLookupDialog open={batchOpen} onClose={() => setSearch({ batch: undefined }, true)} />
      <ExportDialog
        open={exportOpen}
        onClose={() => setExportOpen(false)}
        query={plan.query}
        estimate={estimate}
        complete={counts.data?.complete ?? true}
      />
      <QuickRuleDialog target={quick} onClose={() => setQuick(null)} />
    </>
  );
}
