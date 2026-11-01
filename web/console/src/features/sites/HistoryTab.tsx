// The change history of a site (docs/06 6.4.9): every version with its kind, its note and what it changed against
// the version before. Two versions can be compared (the address keeps the pair as `diff=a..b`); a version can be
// read in full, rolled back to, or used to find the requests it judged.

import { Link } from "@tanstack/react-router";
import { useState } from "react";
import { useVersions } from "../../api/queries.ts";
import type { ChangeKind, SiteDetail, SiteSpec, SiteVersion } from "../../api/types.ts";
import { useSetSearch } from "../../app/scope.ts";
import { semanticChanges, yamlDiff } from "../../lib/diff.ts";
import { fmtInt, fmtLocalDateTime } from "../../lib/format.ts";
import { specToYaml } from "../../lib/yaml.ts";
import { ErrorBar, Loading } from "../../ui/Page.tsx";
import { DiffView } from "./DiffView.tsx";

const KIND_LABEL: Record<ChangeKind, string> = {
  create: "创建",
  update: "修改",
  rollback: "回滚",
  delete: "删除",
  import: "导入",
};

type Props = {
  site: SiteDetail;
  /** The compared pair from the address, written `a..b`. */
  diff: string | undefined;
  onRollback: (version: SiteVersion) => void;
};

function parsePair(text: string | undefined): [number, number] | null {
  const match = text === undefined ? null : /^(\d{1,6})\.\.(\d{1,6})$/.exec(text);
  if (match === null) return null;
  return [Number(match[1]), Number(match[2])];
}

/** What a version changed against the one before it, in a few words for the table. */
function summaryOf(item: SiteVersion, before: SiteSpec | null): string {
  if (item.spec === null) return "删除站点";
  if (before === null) return item.change === "create" ? "新建站点" : "首个版本";
  const changes = semanticChanges(before, item.spec);
  if (changes.length === 0) return "内容没有变化";
  const head = changes.slice(0, 3).join("、");
  return changes.length > 3 ? `${head} 等 ${fmtInt(changes.length)} 项` : head;
}

export function HistoryTab({ site, diff, onRollback }: Props) {
  const versions = useVersions(site.name);
  const setSearch = useSetSearch();
  const [open, setOpen] = useState<number | null>(null);

  if (versions.isPending) return <Loading height={160} />;
  if (versions.isError)
    return <ErrorBar error={versions.error} onRetry={() => void versions.refetch()} />;

  const list = [...(versions.data?.versions ?? [])].sort((a, b) => b.version - a.version);
  const specs = new Map(list.map((item): [number, SiteSpec | null] => [item.version, item.spec]));
  const specOf = (version: number): SiteSpec | null => specs.get(version) ?? null;
  const [newest, previous] = list;
  const defaultPair: [number, number] | null =
    newest && previous ? [previous.version, newest.version] : null;
  const requested = parsePair(diff);
  const pair =
    requested !== null && specs.has(requested[0]) && specs.has(requested[1])
      ? requested
      : defaultPair;

  const setPair = (from: number, to: number) => setSearch({ diff: `${from}..${to}` }, true);

  return (
    <div className="stack">
      <section className="stack-tight" aria-label="比较两个版本">
        <div className="compare-row small">
          {pair ? (
            <>
              <label>
                从{" "}
                <select
                  className="native-input"
                  value={pair[0]}
                  onChange={(event) => setPair(Number(event.target.value), pair[1])}
                >
                  {list.map((item) => (
                    <option key={item.version} value={item.version}>
                      v{item.version}
                    </option>
                  ))}
                </select>
              </label>
              <label>
                到{" "}
                <select
                  className="native-input"
                  value={pair[1]}
                  onChange={(event) => setPair(pair[0], Number(event.target.value))}
                >
                  {list.map((item) => (
                    <option key={item.version} value={item.version}>
                      v{item.version}
                    </option>
                  ))}
                </select>
              </label>
            </>
          ) : (
            <span className="muted">至少需要两个版本才能比较。</span>
          )}
        </div>
        {pair !== null && pair[0] === pair[1] ? (
          <div className="small muted">选择两个不同的版本。</div>
        ) : null}
        {pair !== null &&
        pair[0] !== pair[1] &&
        (specOf(pair[0]) === null || specOf(pair[1]) === null) ? (
          <div className="small muted">删除记录没有配置内容，无法比较。</div>
        ) : null}
        {pair !== null &&
        pair[0] !== pair[1] &&
        specOf(pair[0]) !== null &&
        specOf(pair[1]) !== null ? (
          <DiffView ops={yamlDiff(specOf(pair[0]), specOf(pair[1]))} mode="unified" />
        ) : null}
      </section>

      <div className="tbl-wrap">
        <table className="tbl" aria-label="版本历史">
          <thead>
            <tr>
              <th scope="col">版本</th>
              <th scope="col">时间</th>
              <th scope="col">类型</th>
              <th scope="col">备注与改动</th>
              <th scope="col">
                <span className="sr-only">操作</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {list.map((item) => {
              const before = specOf(item.version - 1);
              const expanded = open === item.version && item.spec !== null;
              return (
                <tr key={item.version}>
                  <td className="tnum">
                    v{item.version}
                    {item.version === site.version ? <span className="pill"> 当前</span> : null}
                  </td>
                  <td className="tnum">{fmtLocalDateTime(Date.parse(item.changed_at))}</td>
                  <td>
                    {KIND_LABEL[item.change]}
                    {item.rollback_of !== null ? `（回到 v${item.rollback_of}）` : ""}
                  </td>
                  <td>
                    {item.note ? <div>{item.note}</div> : null}
                    <div className="small muted">{summaryOf(item, before)}</div>
                  </td>
                  <td>
                    <div className="row" style={{ justifyContent: "flex-end", flexWrap: "wrap" }}>
                      {item.spec !== null ? (
                        <button
                          type="button"
                          className="linkbtn"
                          aria-expanded={expanded}
                          onClick={() => setOpen(expanded ? null : item.version)}
                        >
                          {expanded ? "收起全文" : "查看全文"}
                        </button>
                      ) : null}
                      {item.spec !== null && item.version !== site.version ? (
                        <button type="button" className="btn" onClick={() => onRollback(item)}>
                          以此版本回滚…
                        </button>
                      ) : null}
                      <Link
                        to="/requests"
                        search={{ site: site.name, q: `version:${item.version}` }}
                        className="linkbtn"
                      >
                        查看用此版本判定的请求
                      </Link>
                    </div>
                    {expanded && item.spec !== null ? (
                      <pre className="codeblock" style={{ marginTop: 8 }}>
                        {specToYaml(item.spec)}
                      </pre>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
