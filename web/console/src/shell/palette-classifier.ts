import {
  agentRunPattern,
  artifactPattern,
  bindingPattern,
  calibrationReportPattern,
  eventPattern,
  grantPattern,
  jobPattern,
  modelCallPattern,
  requestPattern,
} from "../api-contract.ts";
import { casePattern } from "../cases.ts";
import { accessPattern } from "../evidence-access.ts";
import { exportPattern } from "../exports.ts";
import type { SearchPreset } from "../investigation/search-preset.ts";
import { flattenNav, isVisible, type NavGroup, type NavItem, visibleNav } from "./nav-model.ts";

export type PaletteAction =
  /** `search` is the URL query of the target, passed as an object (never spliced into `to`). */
  | { type: "navigate"; to: string; search?: Readonly<Record<string, string>> }
  /** Opens the structured search with one prefilled, unsubmitted condition. */
  | { type: "search"; preset: SearchPreset };

export type PaletteResult = Readonly<{
  /** Unique within one result list. */
  id: string;
  group: "object" | "page";
  label: string;
  hint: string;
  action: PaletteAction;
}>;

export type PaletteOutcome = Readonly<{
  results: readonly PaletteResult[];
  /** Shown when the input is recognisably an ID but not a valid one, or recognised but not allowed. */
  notice: string | null;
}>;

const traceIdPattern = /^[0-9a-f]{32}(?![\s\S])/;

type Recognised = {
  /** Human name of the object kind. */
  noun: string;
  candidates: readonly Candidate[];
};
type Candidate =
  | {
      type: "open";
      to: string;
      page: string;
      requires: readonly string[];
      search?: Readonly<Record<string, string>>;
    }
  | {
      type: "search";
      preset: SearchPreset["kind"];
      noun: string;
      requires: readonly string[];
      /** Any one of these roles; empty means no extra role beyond the pages in `requires`. */
      roles: readonly string[];
    };

const SEARCH = "/investigation/search";

/** Strips whitespace and the quotes a pasted value often arrives in. Nothing else is rewritten. */
export function normalizePaste(raw: string): string {
  return raw
    .trim()
    .replace(/^["'`“”‘’]+|["'`“”‘’]+$/g, "")
    .trim();
}

/** Recognises one ID by its prefix and exact canonical shape (version-7 UUID, lowercase). */
export function recognise(value: string): Recognised | null {
  const open = (
    to: string,
    page: string,
    requires: string,
    search?: Readonly<Record<string, string>>,
  ): Candidate => ({
    type: "open",
    to,
    page,
    requires: [requires],
    ...(search ? { search } : {}),
  });
  const search = (preset: SearchPreset["kind"], noun: string, ...roles: string[]): Candidate => ({
    type: "search",
    preset,
    noun,
    requires: [SEARCH],
    roles,
  });
  if (requestPattern.test(value)) {
    return {
      noun: "请求 ID",
      candidates: [open(`/investigation/requests/${value}`, "请求调查", "/investigation/requests")],
    };
  }
  if (modelCallPattern.test(value)) {
    return {
      noun: "模型调用 ID",
      candidates: [open(`/investigation/models/${value}`, "模型调用详情", "/investigation/models")],
    };
  }
  if (agentRunPattern.test(value)) {
    return {
      noun: "Agent 运行 ID",
      candidates: [open(`/investigation/agents/${value}`, "Agent 运行", "/investigation/agents")],
    };
  }
  if (grantPattern.test(value)) {
    return {
      noun: "资格 ID",
      candidates: [open(`/investigation/grants/${value}`, "身份与资格", "/investigation/grants")],
    };
  }
  if (bindingPattern.test(value)) {
    return {
      noun: "身份绑定 ID",
      candidates: [open(`/investigation/bindings/${value}`, "身份与资格", "/investigation/grants")],
    };
  }
  if (calibrationReportPattern.test(value)) {
    return {
      noun: "校准报告 ID",
      candidates: [
        open(`/investigation/calibration/${value}`, "校准报告", "/investigation/calibration"),
      ],
    };
  }
  if (casePattern.test(value)) {
    return { noun: "案件 ID", candidates: [open(`/cases/${value}`, "案件详情", "/cases")] };
  }
  if (accessPattern.test(value)) {
    return {
      noun: "访问申请 ID",
      candidates: [
        search("evidence_access_request_id", "访问申请 ID"),
        open("/approvals", "审批中心的该申请", "/approvals", { item: value }),
      ],
    };
  }
  if (exportPattern.test(value)) {
    return {
      noun: "导出 ID",
      candidates: [open("/approvals", "审批中心的该导出", "/approvals", { item: value })],
    };
  }
  if (jobPattern.test(value)) {
    return {
      noun: "任务 ID",
      candidates: [
        search("job_id", "任务 ID"),
        open(`/cases/jobs/${value}`, "案件分析任务", "/cases"),
      ],
    };
  }
  if (artifactPattern.test(value)) {
    // Evidence has no page of its own: it is reached through a case.
    return {
      noun: "证据 ID",
      candidates: [open("/cases", "案件工作台", "/cases")],
    };
  }
  if (eventPattern.test(value)) {
    // Event IDs and evidence-hold IDs share the `ev_` shape, so both interpretations are offered.
    // Hold history needs the audit role in addition to the structured search itself.
    return {
      noun: "事件 / 保留锁 ID",
      candidates: [
        search("event_id", "事件 ID"),
        search("evidence_hold_id", "保留锁 ID", "audit_administrator"),
      ],
    };
  }
  if (traceIdPattern.test(value)) {
    return { noun: "Trace ID", candidates: [search("trace_id", "Trace ID")] };
  }
  return null;
}

const idPrefixes = /^(req|mdl|agt|grant|auth|calr|case|access|export|job|artifact|ev)_/;

/** Subsequence-aware score: 0 means no match, higher is better. */
export function fuzzyScore(query: string, text: string): number {
  const needle = query.toLowerCase().replace(/\s+/g, "");
  const hay = text.toLowerCase().replace(/\s+/g, "");
  if (needle.length === 0) return 1;
  if (hay === needle) return 100;
  if (hay.startsWith(needle)) return 90;
  const at = hay.indexOf(needle);
  if (at >= 0) return 70 - Math.min(at, 20);
  let cursor = 0;
  let gaps = 0;
  for (const char of needle) {
    const found = hay.indexOf(char, cursor);
    if (found < 0) return 0;
    gaps += found - cursor;
    cursor = found + 1;
  }
  return Math.max(10, 40 - gaps);
}

function pageScore(query: string, entry: NavItem, group: NavGroup): number {
  const label = fuzzyScore(query, entry.label);
  const keyword = Math.max(0, ...entry.keywords.map((word) => fuzzyScore(query, word) * 0.8));
  const section = fuzzyScore(query, group.label) * 0.5;
  return Math.max(label, keyword, section);
}

/**
 * Everything the palette offers for the typed text, honouring role visibility: an object or
 * page the operator's roles do not show in the navigation is never offered. (Hiding is a view
 * aid only; the server still authorizes whatever is eventually requested.)
 */
export function paletteSearch(
  input: string,
  roles: readonly string[] | null,
  siteId: string | null,
): PaletteOutcome {
  const groups = visibleNav(roles, siteId);
  const visible = new Set(flattenNav(groups).map((entry) => entry.href));
  const query = normalizePaste(input);
  const results: PaletteResult[] = [];
  let notice: string | null = null;

  const recognised = recognise(query);
  if (recognised) {
    let blocked = 0;
    recognised.candidates.forEach((candidate, index) => {
      const roleAllowed = candidate.type === "open" || isVisible(roles, candidate.roles);
      if (!roleAllowed || !candidate.requires.every((href) => visible.has(href))) {
        blocked += 1;
        return;
      }
      if (candidate.type === "open") {
        results.push({
          id: `object:${index}:${candidate.to}`,
          group: "object",
          label: `打开${candidate.page}`,
          hint: `${recognised.noun} ${query}`,
          action: candidate.search
            ? { type: "navigate", to: candidate.to, search: candidate.search }
            : { type: "navigate", to: candidate.to },
        });
      } else {
        results.push({
          id: `object:${index}:search:${candidate.preset}`,
          group: "object",
          label: `在事件检索中查找 ${candidate.noun}`,
          hint: query,
          action: { type: "search", preset: { kind: candidate.preset, value: query } },
        });
      }
    });
    if (results.length === 0 && blocked > 0) {
      notice = `已识别为${recognised.noun}，但当前角色看不到对应页面。`;
    }
  } else if (idPrefixes.test(query)) {
    notice = "看起来是对象 ID，但格式不是规范的“前缀_UUIDv7”（小写）。";
  }
  // A half-typed or malformed ID still finds the page that owns its prefix ("req_12" -> "req").
  const pageQuery = !recognised && idPrefixes.test(query) ? (query.split("_")[0] ?? query) : query;

  const scored = groups.flatMap((group) =>
    group.items.map((entry, order) => ({
      entry,
      order,
      group,
      score: recognised ? 0 : pageScore(pageQuery, entry, group),
    })),
  );
  const matchedPages = recognised ? [] : scored.filter((candidate) => candidate.score > 0);
  matchedPages
    .sort((a, b) => b.score - a.score)
    .forEach(({ entry, group }) => {
      results.push({
        id: `page:${entry.href}`,
        group: "page",
        label: entry.label,
        hint: group.label,
        action: { type: "navigate", to: entry.href },
      });
    });
  return { results, notice };
}
