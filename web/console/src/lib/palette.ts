// What the command palette makes of pasted or typed text (docs/06 6.3.3). The first matching rule
// decides the list; the list is grouped for display. Pure: sites are passed in.

import { parseFilter } from "./filter-dsl.ts";
import { findRequestIds, isSessionLabel, requestIdMillis } from "./ids.ts";
import { fmtLocalDateTime } from "./format.ts";

export type PaletteAction =
  | { kind: "route"; to: string; search?: Record<string, string> }
  | { kind: "command"; command: "theme" | "copy-link" | "help" | "batch-text" };

export type PaletteItem = {
  id: string;
  label: string;
  sub?: string;
  disabled?: string;
  action: PaletteAction;
};

export type PaletteGroup = { title: string; items: PaletteItem[] };

const METHOD_PATH = /^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(\/\S*)$/i;

const COMMANDS: Array<{ label: string; action: PaletteAction; match: string[] }> = [
  {
    label: "新建站点",
    action: { kind: "route", to: "/sites/new" },
    match: ["新建", "站点", "site"],
  },
  {
    label: "导入判定日志",
    action: { kind: "route", to: "/system", search: { tab: "import" } },
    match: ["导入", "日志", "import"],
  },
  { label: "切换主题", action: { kind: "command", command: "theme" }, match: ["主题", "theme"] },
  {
    label: "复制当前页链接",
    action: { kind: "command", command: "copy-link" },
    match: ["复制", "链接", "link"],
  },
  {
    label: "查看快捷键",
    action: { kind: "command", command: "help" },
    match: ["快捷键", "键", "help"],
  },
];

export function classifyInput(input: string, sites: string[]): PaletteGroup[] {
  const text = input.trim();
  if (text.length === 0) return [];
  const groups: PaletteGroup[] = [];
  const ids = findRequestIds(text);
  if (ids.length === 1) {
    const id = ids[0] ?? "";
    const millis = requestIdMillis(id);
    groups.push({
      title: "请求",
      items: [
        {
          id: `req:${id}`,
          label: `打开请求 ${id}`,
          sub: millis === null ? undefined : fmtLocalDateTime(millis),
          action: { kind: "route", to: `/requests/${id}` },
        },
      ],
    });
  } else if (ids.length > 1) {
    groups.push({
      title: "批量",
      items: [
        {
          id: "batch",
          label: `批量对照 ${ids.length} 个请求 ID`,
          action: { kind: "route", to: "/requests", search: { batch: "1" } },
        },
      ],
    });
  }
  if (isSessionLabel(text)) {
    groups.push({
      title: "会话",
      items: [
        {
          id: `session:${text}`,
          label: `打开会话 ${text.slice(0, 8)}`,
          sub: "会话时间线",
          action: { kind: "route", to: `/sessions/${text}` },
        },
      ],
    });
  }
  const method = METHOD_PATH.exec(text);
  if (method) {
    const verb = (method[1] ?? "").toUpperCase();
    const path = method[2] ?? "";
    groups.push({
      title: "筛选",
      items: [
        {
          id: `method:${verb}:${path}`,
          label: `筛选 ${verb} ${path}`,
          action: { kind: "route", to: "/requests", search: { q: `method:${verb} path:${path}` } },
        },
      ],
    });
  } else if (text.startsWith("/")) {
    const items: PaletteItem[] = [
      {
        id: `path:${text}`,
        label: `筛选路径 ${text}`,
        action: { kind: "route", to: "/requests", search: { q: `path:${text}` } },
      },
    ];
    if (!text.endsWith("*")) {
      items.push({
        id: `prefix:${text}`,
        label: `筛选路径前缀 ${text}*`,
        action: { kind: "route", to: "/requests", search: { q: `path:${text}*` } },
      });
    }
    groups.push({ title: "路径", items });
  }
  const lower = text.toLowerCase();
  const siteHits = sites
    .filter((name) => name === lower || (lower.length >= 2 && name.includes(lower)))
    .slice(0, 5);
  if (siteHits.length > 0) {
    groups.push({
      title: "站点",
      items: siteHits.flatMap((name) => [
        {
          id: `site:${name}`,
          label: `打开站点 ${name}`,
          action: { kind: "route", to: `/sites/${name}` } as PaletteAction,
        },
        {
          id: `site-config:${name}`,
          label: `打开 ${name} 的站点配置`,
          action: {
            kind: "route",
            to: `/sites/${name}`,
            search: { tab: "config" },
          } as PaletteAction,
        },
        {
          id: `site-insights:${name}`,
          label: `打开 ${name} 的调优建议`,
          action: {
            kind: "route",
            to: `/sites/${name}`,
            search: { tab: "insights" },
          } as PaletteAction,
        },
      ]),
    });
  }
  if (text.includes(":") && ids.length === 0) {
    const parsed = parseFilter(text);
    if (parsed.errors.length === 0) {
      groups.push({
        title: "条件",
        items: [
          {
            id: `cond:${text}`,
            label: "按条件打开请求追溯",
            sub: text,
            action: { kind: "route", to: "/requests", search: { q: text } },
          },
        ],
      });
    } else {
      groups.push({
        title: "条件",
        items: [
          {
            id: "cond-error",
            label: "条件语法有误",
            disabled: parsed.errors[0]?.message ?? "语法有误",
            action: { kind: "route", to: "/requests" },
          },
        ],
      });
    }
  }
  if (ids.length === 0 && !isSessionLabel(text) && !text.startsWith("/") && !method) {
    const commands = COMMANDS.filter(
      (command) =>
        command.label.toLowerCase().includes(lower) ||
        command.match.some((word) => lower.includes(word)),
    );
    if (commands.length > 0) {
      groups.push({
        title: "命令",
        items: commands.map((command) => ({
          id: `cmd:${command.label}`,
          label: command.label,
          action: command.action,
        })),
      });
    }
  }
  return groups;
}
