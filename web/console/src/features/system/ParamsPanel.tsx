// The "运行参数" tab (docs/06 6.4.11), read only. The matrix shows each site's overrides of the
// overridable judging parameters (a value where the site overrides it, linking to that site's advanced
// parameters) against the defaults; the fixed table lists the code defaults that no site can change,
// one sentence each (docs/07 7.8.2, 7.9.8).

import { Link } from "@tanstack/react-router";
import { useSite, useSites } from "../../api/queries.ts";
import type { Advanced, FixedParams, SystemInfo } from "../../api/types.ts";
import { fmtInt, fmtMs } from "../../lib/format.ts";
import { isSiteName } from "../../lib/ids.ts";
import { PARAM_INFO } from "../../lib/vocab.ts";
import { Card, ErrorBar, Loading, Notice } from "../../ui/Page.tsx";

type Defaults = SystemInfo["params"]["site_overridable"];

/** A byte size in the units docs/06 6.6.6 writes: `48 KiB`, `1 MiB`. */
function sizeText(bytes: number): string {
  return bytes % 1_048_576 === 0
    ? `${fmtInt(bytes / 1_048_576)} MiB`
    : `${fmtInt(bytes / 1024)} KiB`;
}

function minutesText(minutes: number): string {
  return minutes === 0 ? "0 分钟（不缓存）" : `${fmtInt(minutes)} 分钟`;
}

const FIXED: Array<{
  key: keyof FixedParams;
  label: string;
  value: (n: number) => string;
  note: string;
}> = [
  {
    key: "seen_max",
    label: "上下文容量",
    value: (n) => `${fmtInt(n)} 个值`,
    note: "每个会话最多记住的已见值数量",
  },
  {
    key: "sources_max",
    label: "来源数",
    value: (n) => `${fmtInt(n)} 个`,
    note: "每个值最多记录的来源请求数",
  },
  {
    key: "recent_max",
    label: "最近访问",
    value: (n) => `${fmtInt(n)} 条`,
    note: "会话里保存的最近访问条数；写进 Jev 记录时只取最近 10 条",
  },
  {
    key: "idle_hours",
    label: "会话过期",
    value: (n) => `${fmtInt(n)} 小时`,
    note: "会话无活动超过这个时长即过期；网关重启也会清空",
  },
  {
    key: "sessions_max",
    label: "会话数上限",
    value: (n) => `${fmtInt(n)} 个`,
    note: "网关内存中同时保存的会话数上限",
  },
  {
    key: "long_value_chars",
    label: "长值长度",
    value: (n) => `${fmtInt(n)} 个字符`,
    note: "短于这个长度的值，只有字段名和接口名属于同一类对象时才算已核验",
  },
  {
    key: "state_bytes_max",
    label: "state 上限",
    value: sizeText,
    note: "发给 Jev 的上下文上限；裁剪到这个大小仍超过时，不调用 Jev",
  },
  {
    key: "request_body_max",
    label: "请求体上限",
    value: sizeText,
    note: "超过的请求体不可判定，返回 413",
  },
  {
    key: "response_parse_max",
    label: "响应解析上限",
    value: sizeText,
    note: "超过的源站响应不解析，其中的值不会被学习",
  },
  {
    key: "request_values_max",
    label: "每请求值数",
    value: (n) => `${fmtInt(n)} 个`,
    note: "一个请求最多提取的值数；超出时追溯里标注截断",
  },
];

export function ParamsPanel({ system }: { system: SystemInfo }) {
  const sites = useSites();
  const defaults = system.params.site_overridable;
  const list = sites.data?.sites ?? [];

  return (
    <>
      <Card title="站点可覆盖的默认值" aside="覆盖处显示该站点的值，点击进入它的高级判定参数">
        {sites.isError ? (
          <ErrorBar error={sites.error} onRetry={() => void sites.refetch()} />
        ) : null}
        <div className="tbl-wrap">
          <table className="tbl sys-matrix">
            <caption className="sr-only">站点可覆盖的判定参数</caption>
            <thead>
              <tr>
                <th scope="col">站点</th>
                <th scope="col" className="num" title={PARAM_INFO.jev_timeout_ms.cost}>
                  {PARAM_INFO.jev_timeout_ms.label}
                </th>
                <th scope="col" className="num" title={PARAM_INFO.session_calls_per_minute.cost}>
                  {PARAM_INFO.session_calls_per_minute.label}
                </th>
                <th scope="col" className="num" title={PARAM_INFO.address_calls_per_minute.cost}>
                  {PARAM_INFO.address_calls_per_minute.label}
                </th>
                <th scope="col" className="num" title={PARAM_INFO.allow_cache_minutes.cost}>
                  {PARAM_INFO.allow_cache_minutes.label}
                </th>
                <th scope="col" className="num" title={PARAM_INFO.secret_fields.cost}>
                  {PARAM_INFO.secret_fields.label}
                </th>
                <th scope="col" className="num" title={PARAM_INFO.synonyms.cost}>
                  {PARAM_INFO.synonyms.label}
                </th>
              </tr>
            </thead>
            <tbody>
              <DefaultsRow defaults={defaults} />
              {list.map((site) => (
                <SiteRow key={site.name} name={site.name} />
              ))}
            </tbody>
          </table>
        </div>
        {sites.isPending ? <Loading height={14} /> : null}
        {!sites.isPending && !sites.isError && list.length === 0 ? (
          <Notice tone="info">还没有站点，所有站点都使用这里的默认值。</Notice>
        ) : null}
      </Card>

      <div className="sys-section">
        <Card title="固定参数" aside="代码默认值，只读">
          <div className="tbl-wrap">
            <table className="tbl">
              <caption className="sr-only">固定参数</caption>
              <thead>
                <tr>
                  <th scope="col">参数</th>
                  <th scope="col" className="num">
                    值
                  </th>
                  <th scope="col">说明</th>
                </tr>
              </thead>
              <tbody>
                {FIXED.map((item) => (
                  <tr key={item.key}>
                    <th scope="row" className="sys-rowhead">
                      {item.label}
                    </th>
                    <td className="num tnum">{item.value(system.params.fixed[item.key])}</td>
                    <td className="sys-note">{item.note}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      </div>
    </>
  );
}

function DefaultsRow({ defaults }: { defaults: Defaults }) {
  return (
    <tr className="sys-defaults-row">
      <th scope="row" className="sys-rowhead">
        默认值
      </th>
      <td className="num tnum">{fmtMs(defaults.jev_timeout_ms)}</td>
      <td className="num tnum">{fmtInt(defaults.session_calls_per_minute)} 次/分钟</td>
      <td className="num tnum">{fmtInt(defaults.address_calls_per_minute)} 次/分钟</td>
      <td className="num tnum">{minutesText(defaults.allow_cache_minutes)}</td>
      <td className="num">内置 {fmtInt(defaults.secret_fields.length)} 个</td>
      <td className="num">内置 {fmtInt(defaults.synonyms.length)} 组</td>
    </tr>
  );
}

/** One site's overrides. The spec is read per site: the list shows only what each site changes. */
function SiteRow({ name }: { name: string }) {
  const site = useSite(name);
  const linkable = isSiteName(name);

  if (site.isPending) {
    return (
      <tr>
        <th scope="row" className="sys-rowhead">
          {name}
        </th>
        <td colSpan={6}>
          <Loading height={12} />
        </td>
      </tr>
    );
  }
  if (!site.data) {
    return (
      <tr>
        <th scope="row" className="sys-rowhead">
          {name}
        </th>
        <td colSpan={6} className="hint-bad">
          无法读取这个站点的参数
        </td>
      </tr>
    );
  }

  const advanced: Advanced = site.data.spec.advanced ?? {};
  const cell = (text: string, title?: string) =>
    linkable ? (
      <Link
        to="/sites/$name"
        params={{ name }}
        search={{ tab: "config", group: "advanced" }}
        className="sys-override"
        title={title}
      >
        {text}
      </Link>
    ) : (
      <span className="sys-override">{text}</span>
    );
  const fallback = <span className="sys-default">默认</span>;
  const words = advanced.secret_fields ?? [];
  const pairs = advanced.synonyms ?? [];

  return (
    <tr>
      <th scope="row" className="sys-rowhead">
        {linkable ? (
          <Link to="/sites/$name" params={{ name }} search={{ tab: "config" }}>
            {name}
          </Link>
        ) : (
          name
        )}
      </th>
      <td className="num tnum">
        {advanced.jev_timeout_ms === undefined ? fallback : cell(fmtMs(advanced.jev_timeout_ms))}
      </td>
      <td className="num tnum">
        {advanced.session_calls_per_minute === undefined
          ? fallback
          : cell(`${fmtInt(advanced.session_calls_per_minute)} 次/分钟`)}
      </td>
      <td className="num tnum">
        {advanced.address_calls_per_minute === undefined
          ? fallback
          : cell(`${fmtInt(advanced.address_calls_per_minute)} 次/分钟`)}
      </td>
      <td className="num tnum">
        {advanced.allow_cache_minutes === undefined
          ? fallback
          : cell(minutesText(advanced.allow_cache_minutes))}
      </td>
      <td className="num">
        {words.length === 0 ? fallback : cell(`追加 ${fmtInt(words.length)} 个`, words.join("、"))}
      </td>
      <td className="num">
        {pairs.length === 0
          ? fallback
          : cell(
              `追加 ${fmtInt(pairs.length)} 组`,
              pairs.map(([a, b]) => `${a} ↔ ${b}`).join("、"),
            )}
      </td>
    </tr>
  );
}
