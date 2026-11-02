// The interface-name rules of a configuration (header-routes-design 2; console-design-objects-routes 2): one card
// per rule with its path and up to four segments, each read from one or more locations. A card shows what the
// last day's records name under its path, and a hint when every segment reads one location only.
//
// The rows carry their own ids, so a row keeps its focus while the rows around it change. The rows follow the
// draft when it changes from outside (a discard, a link that adds a rule); the editor's own edits are not read
// back as outside changes.

import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { useRequestCounts, useRequests } from "../../api/queries.ts";
import type { RouteRule } from "../../api/types.ts";
import { useGlobalSearch, useNowBucket } from "../../app/scope.ts";
import { latestNamed, ruleBase, splitSource, unknownCount } from "../../lib/logical-path.ts";
import type { FieldIssue } from "../../lib/site-validate.ts";
import { readJson, writeJson } from "../../lib/storage.ts";
import {
  ROUTE_ACK_LABEL,
  ROUTE_ADD_LOCATION,
  ROUTE_ADD_RULE,
  ROUTE_ADD_SEGMENT,
  ROUTE_DELETE_RULE,
  ROUTE_DELETE_SEGMENT,
  ROUTE_HEADER_NOTE,
  ROUTE_LOCATION_HELP,
  ROUTE_SINGLE_HINT,
  ROUTE_SOURCE_LABEL,
  ROUTE_UNKNOWN_LINK,
  UNKNOWN_API_LABEL,
} from "../../lib/vocab.ts";
import { SafeText } from "../../ui/SafeText.tsx";
import { namedCountQuery, namedRowsQuery, unknownRowsQuery, windowText } from "./route-records.ts";

const MAX_SEGMENTS = 4;
const KINDS = ["header", "query", "body"] as const;

/** Example text for each place: a header name, a query parameter name, a body field path. */
const PLACEHOLDER: Record<string, string> = {
  header: "例如 X-Service-Id",
  query: "例如 action",
  body: "例如 method 或 op.name",
};

type LocationRow = { id: number; kind: string; name: string };
type SegmentRow = { id: number; locations: LocationRow[] };
type RuleRow = { id: number; path: string; segments: SegmentRow[] };

let rowSeq = 0;
function nextId(): number {
  rowSeq += 1;
  return rowSeq;
}

function newLocation(): LocationRow {
  return { id: nextId(), kind: "header", name: "" };
}

function newSegment(): SegmentRow {
  return { id: nextId(), locations: [newLocation()] };
}

function newRule(): RuleRow {
  return { id: nextId(), path: "", segments: [newSegment()] };
}

/** The editable rows of the rules. A location string is `kind.name`, split at its first dot. */
function rowsOf(routes: readonly RouteRule[]): RuleRow[] {
  return routes.map((rule) => ({
    id: nextId(),
    path: rule.path,
    segments: rule.name_from.map((group) => ({
      id: nextId(),
      locations: group.map((source) => {
        const { kind, name } = splitSource(source);
        return { id: nextId(), kind, name };
      }),
    })),
  }));
}

function rulesOf(rows: readonly RuleRow[]): RouteRule[] {
  return rows.map((row) => ({
    path: row.path,
    name_from: row.segments.map((segment) =>
      segment.locations.map((location) => `${location.kind}.${location.name}`),
    ),
  }));
}

/** The rules whose path was acknowledged as "the source reads this location only", kept for this session. */
function ackKey(site: string): string {
  return `xshield.console.route-ack.${site}`;
}

function isStringList(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string");
}

function readAcks(site: string | null): string[] {
  if (site === null) return [];
  return readJson<string[]>(ackKey(site), [], isStringList, "session");
}

/** The messages of one field of the rules, e.g. `routes[0].path`. */
function messagesAt(issues: FieldIssue[], field: string): string[] {
  return issues
    .filter((issue) => issue.group === "routes" && issue.field === field)
    .map((issue) => issue.message);
}

function Errors({ messages }: { messages: string[] }) {
  return (
    <>
      {messages.map((message) => (
        <div key={message} className="field-error" role="alert">
          {message}
        </div>
      ))}
    </>
  );
}

function singleLocation(row: RuleRow): boolean {
  return row.segments.length > 0 && row.segments.every((segment) => segment.locations.length === 1);
}

function readsHeader(row: RuleRow): boolean {
  return row.segments.some((segment) =>
    segment.locations.some((location) => location.kind === "header"),
  );
}

export function RoutesEditor({
  site,
  routes,
  issues,
  onChange,
}: {
  /** The site's name; null while the site is being created (no records to read yet). */
  site: string | null;
  routes: RouteRule[];
  issues: FieldIssue[];
  onChange: (routes: RouteRule[]) => void;
}) {
  const json = JSON.stringify(routes);
  const [seen, setSeen] = useState(json);
  const [rows, setRows] = useState(() => rowsOf(routes));
  const [acks, setAcks] = useState(() => readAcks(site));
  // The draft changed outside this editor: the rows are read again from it.
  if (json !== seen) {
    setSeen(json);
    setRows(rowsOf(routes));
  }

  const commit = (next: RuleRow[]) => {
    const rules = rulesOf(next);
    setRows(next);
    setSeen(JSON.stringify(rules));
    onChange(rules);
  };

  const acknowledge = (path: string) => {
    const next = [...acks, path];
    setAcks(next);
    if (site !== null) writeJson(ackKey(site), next, "session");
  };

  return (
    <div className="stack-tight">
      {rows.length === 0 ? (
        <div className="small muted">还没有接口名规则：接口名就是 URL 路径。</div>
      ) : null}
      {rows.map((row, index) => (
        <RuleCard
          key={row.id}
          row={row}
          index={index}
          site={site}
          issues={issues}
          acknowledged={acks.includes(row.path)}
          onChange={(next) => commit(rows.map((item) => (item.id === next.id ? next : item)))}
          onRemove={() => commit(rows.filter((item) => item.id !== row.id))}
          onAcknowledge={() => acknowledge(row.path)}
        />
      ))}
      <div>
        <button type="button" className="btn" onClick={() => commit([...rows, newRule()])}>
          {ROUTE_ADD_RULE}
        </button>
      </div>
    </div>
  );
}

function RuleCard({
  row,
  index,
  site,
  issues,
  acknowledged,
  onChange,
  onRemove,
  onAcknowledge,
}: {
  row: RuleRow;
  index: number;
  site: string | null;
  issues: FieldIssue[];
  acknowledged: boolean;
  onChange: (row: RuleRow) => void;
  onRemove: () => void;
  onAcknowledge: () => void;
}) {
  const at = `routes[${index}]`;
  const pathId = `site-field-route-${index}`;
  const base = ruleBase({ path: row.path, name_from: [] });
  const pathErrors = messagesAt(issues, `${at}.path`);
  const ruleErrors = [...messagesAt(issues, at), ...messagesAt(issues, `${at}.name_from`)];
  const single = singleLocation(row) && !acknowledged;

  const setSegments = (segments: SegmentRow[]) => onChange({ ...row, segments });

  return (
    <section className="route-card" aria-label={`接口名规则 ${index + 1}`}>
      <div className="route-head">
        <label className="field-label" htmlFor={pathId}>
          路径
        </label>
        <input
          id={pathId}
          className="native-input mono"
          value={row.path}
          placeholder="例如 /weixin/wx/mp/wx361163d21a65f679/gateway"
          aria-invalid={pathErrors.length > 0 ? true : undefined}
          onChange={(event) => onChange({ ...row, path: event.target.value })}
        />
        <button type="button" className="btn" onClick={onRemove}>
          {ROUTE_DELETE_RULE}
        </button>
      </div>
      <Errors messages={pathErrors} />
      {site !== null && base !== null ? (
        <RuleStats site={site} path={row.path} base={base} />
      ) : null}

      <div className="stack-tight">
        {row.segments.map((segment, position) => (
          <SegmentEditor
            key={segment.id}
            segment={segment}
            number={position + 1}
            removable={row.segments.length > 1}
            errors={messagesAt(issues, `${at}.name_from[${position}]`)}
            onChange={(next) =>
              setSegments(row.segments.map((item) => (item.id === next.id ? next : item)))
            }
            onRemove={() => setSegments(row.segments.filter((item) => item.id !== segment.id))}
          />
        ))}
      </div>
      {row.segments.length < MAX_SEGMENTS ? (
        <div>
          <button
            type="button"
            className="linkbtn"
            onClick={() => setSegments([...row.segments, newSegment()])}
          >
            {ROUTE_ADD_SEGMENT}
          </button>
        </div>
      ) : null}
      <Errors messages={ruleErrors} />
      {single ? (
        <div className="field-warn">
          ! {ROUTE_SINGLE_HINT}{" "}
          <button type="button" className="linkbtn" onClick={onAcknowledge}>
            {ROUTE_ACK_LABEL}
          </button>
        </div>
      ) : null}
      {site !== null && readsHeader(row) ? (
        <div className="small muted">{ROUTE_HEADER_NOTE}</div>
      ) : null}
    </section>
  );
}

function SegmentEditor({
  segment,
  number,
  removable,
  errors,
  onChange,
  onRemove,
}: {
  segment: SegmentRow;
  number: number;
  removable: boolean;
  errors: string[];
  onChange: (segment: SegmentRow) => void;
  onRemove: () => void;
}) {
  const setLocations = (locations: LocationRow[]) => onChange({ ...segment, locations });
  return (
    <div className="route-seg">
      <div className="route-seg-head">
        <span className="small muted">接口名第 {number} 段</span>
        {removable ? (
          <button type="button" className="linkbtn" onClick={onRemove}>
            {ROUTE_DELETE_SEGMENT}
          </button>
        ) : null}
      </div>
      {segment.locations.map((location, position) => (
        <LocationEditor
          key={location.id}
          location={location}
          segment={number}
          number={position + 1}
          removable={position > 0}
          onChange={(next) =>
            setLocations(segment.locations.map((item) => (item.id === next.id ? next : item)))
          }
          onRemove={() => setLocations(segment.locations.filter((item) => item.id !== location.id))}
        />
      ))}
      <div>
        <button
          type="button"
          className="linkbtn"
          title={ROUTE_LOCATION_HELP}
          onClick={() => setLocations([...segment.locations, newLocation()])}
        >
          {ROUTE_ADD_LOCATION}
        </button>
      </div>
      <Errors messages={errors} />
    </div>
  );
}

function LocationEditor({
  location,
  segment,
  number,
  removable,
  onChange,
  onRemove,
}: {
  location: LocationRow;
  segment: number;
  number: number;
  removable: boolean;
  onChange: (location: LocationRow) => void;
  onRemove: () => void;
}) {
  const label = `接口名第 ${segment} 段的第 ${number} 个位置`;
  const known = Object.hasOwn(ROUTE_SOURCE_LABEL, location.kind);
  return (
    <div className="route-loc">
      <select
        className="native-input"
        aria-label={`${label}的来源`}
        value={location.kind}
        onChange={(event) => onChange({ ...location, kind: event.target.value })}
      >
        {KINDS.map((kind) => (
          <option key={kind} value={kind}>
            {ROUTE_SOURCE_LABEL[kind]}
          </option>
        ))}
        {known ? null : <option value={location.kind}>{location.kind}</option>}
      </select>
      <input
        className="native-input mono"
        aria-label={`${label}的名称`}
        value={location.name}
        placeholder={PLACEHOLDER[location.kind] ?? ""}
        onChange={(event) => onChange({ ...location, name: event.target.value })}
      />
      {removable ? (
        <button type="button" className="iconbtn" aria-label={`删除${label}`} onClick={onRemove}>
          ×
        </button>
      ) : (
        <span aria-hidden="true" />
      )}
    </div>
  );
}

/**
 * What a rule's path shows for the last day: the requests it covers (bypass included), the newest example, and
 * the requests under the same path whose name could not be read.
 */
function RuleStats({ site, path, base }: { site: string; path: string; base: string }) {
  const now = useNowBucket(60_000);
  const total = useRequestCounts(namedCountQuery(site, base, now));
  const named = useRequests(namedRowsQuery(site, base, now));
  const unknown = useRequests(unknownRowsQuery(site, now));
  const globalSearch = useGlobalSearch();
  const covering: RouteRule = { path, name_from: [] };
  const example = latestNamed(named.data?.rows ?? [], covering);
  const unknownShown = unknownCount(unknown.data?.rows ?? [], covering);
  const unknownPartial = unknown.data !== undefined && unknown.data.next_cursor !== null;
  const count = total.data;
  return (
    <div className="route-stats small">
      {count === undefined ? null : (
        <div className="tnum">
          {windowText(count.judged, false)}
          {count.complete ? null : "（扫描未完整，计数可能偏低）"}
        </div>
      )}
      {example === null ? null : (
        <div className="mono">
          示例 <SafeText text={example} />
        </div>
      )}
      {unknownShown === 0 ? null : (
        <div>
          取不到 {windowText(unknownShown, unknownPartial)}，按“{UNKNOWN_API_LABEL}”处理{" "}
          <Link
            to="/requests"
            search={{ ...globalSearch, q: `site:${site} api:unknown` }}
            className="linkbtn"
          >
            {ROUTE_UNKNOWN_LINK}
          </Link>
        </div>
      )}
    </div>
  );
}
