// The top bar (docs/06 6.3.2): site scope, the search entry (⌘K), the time range, the two status
// lights, the bell of the "需要处理" rows and the user menu. Every control writes to the URL, so the scope
// survives navigation.

import { Select } from "antd";
import { useSites } from "../api/queries.ts";
import { AttentionBell } from "../features/overview/AttentionBell.tsx";
import { DEFAULT_RANGE, PRESETS, type RangeParam } from "../lib/time-range.ts";
import { RANGE_LABEL } from "../lib/vocab.ts";
import { Lights } from "./Lights.tsx";
import { useGlobalSearch, useSetSearch } from "./scope.ts";
import { UserMenu } from "./UserMenu.tsx";

const isMac = typeof navigator !== "undefined" && /Mac|iPhone|iPad/.test(navigator.userAgent);

type Props = {
  onOpenPalette: () => void;
  onCustomRange: () => void;
};

export function Topbar({ onOpenPalette, onCustomRange }: Props) {
  const global = useGlobalSearch();
  const setSearch = useSetSearch();
  const sites = useSites();
  const range: RangeParam = global.range ?? DEFAULT_RANGE;

  const siteOptions = [
    { value: "", label: "全部站点" },
    ...(sites.data?.sites ?? []).map((site) => ({
      value: site.name,
      label: `${site.name} · ${site.mode === "observe" ? "观察" : "拦截"}`,
    })),
  ];
  const rangeOptions = [
    ...PRESETS.map((preset) => ({ value: preset, label: RANGE_LABEL[preset] })),
    { value: "custom", label: "自定义…" },
  ];

  const onRange = (value: string) => {
    if (value === "custom") {
      onCustomRange();
      return;
    }
    setSearch({ range: value, since: undefined, until: undefined });
  };

  return (
    <header className="topbar">
      <Select
        aria-label="站点范围"
        value={global.site ?? ""}
        options={siteOptions}
        // The scope selector replaces the history entry, so Back returns to the scope of the page it
        // returns to (docs/06 6.2.2).
        onChange={(value: string) => setSearch({ site: value === "" ? undefined : value }, true)}
        style={{ width: 176 }}
      />
      <button
        type="button"
        className="search-trigger"
        onClick={onOpenPalette}
        aria-label="打开命令面板"
      >
        <span aria-hidden="true">⌕</span>
        <span>粘贴请求 ID、会话、路径或站点名…</span>
        <span className="kbd">{isMac ? "⌘K" : "Ctrl K"}</span>
      </button>
      <Select
        aria-label="时间范围"
        value={range}
        options={rangeOptions}
        onChange={onRange}
        style={{ width: 128 }}
      />
      <Lights />
      <AttentionBell />
      <UserMenu />
    </header>
  );
}
