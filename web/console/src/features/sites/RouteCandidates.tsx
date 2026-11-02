// Completions of a rule's logical paths, from the newest records of the last day: the names the rule read most
// often, most frequent first. Shown under a path typed under a rule, and under an entry or bypass that a rule now
// hides (console-design-objects-routes 2). Picking one fills in the full logical path.

import { useRequests } from "../../api/queries.ts";
import type { RouteRule } from "../../api/types.ts";
import { useNowBucket } from "../../app/scope.ts";
import { nameAfter, recentPaths, ruleBase } from "../../lib/logical-path.ts";
import { ROUTE_CANDIDATE_TITLE } from "../../lib/vocab.ts";
import { SafeText } from "../../ui/SafeText.tsx";
import { namedRowsQuery, windowText } from "./route-records.ts";

const SHOWN = 5;

export function RouteCandidates({
  site,
  rule,
  prefix,
  onPick,
}: {
  site: string;
  rule: RouteRule;
  /** Only the candidates that start with this text are listed. */
  prefix: string;
  onPick: (logical: string) => void;
}) {
  const base = ruleBase(rule);
  if (base === null) return null;
  return <Candidates site={site} rule={rule} base={base} prefix={prefix} onPick={onPick} />;
}

function Candidates({
  site,
  rule,
  base,
  prefix,
  onPick,
}: {
  site: string;
  rule: RouteRule;
  base: string;
  prefix: string;
  onPick: (logical: string) => void;
}) {
  const now = useNowBucket(60_000);
  const rows = useRequests(namedRowsQuery(site, base, now));
  const list = recentPaths(rows.data?.rows ?? [], rule)
    .filter((item) => item.logical_path.startsWith(prefix))
    .slice(0, SHOWN);
  if (list.length === 0) return null;
  const partial = rows.data !== undefined && rows.data.next_cursor !== null;
  return (
    <div className="route-candidates">
      <div className="small muted">{ROUTE_CANDIDATE_TITLE}</div>
      <ul className="route-candidate-list">
        {list.map((item) => (
          <li key={item.logical_path}>
            <button
              type="button"
              className="route-candidate"
              onClick={() => onPick(item.logical_path)}
            >
              <span className="mono">
                <SafeText text={nameAfter(item.logical_path, base)} />
              </span>
              <span className="small muted tnum">{windowText(item.count, partial)}</span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}
