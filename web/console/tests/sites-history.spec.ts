// The change history of a site (docs/06 6.4.9): every version, the difference between two of them, and a rollback.
// A rollback saves a new version whose content is the target's, so the history keeps every step.

import { expect, type Page, test } from "@playwright/test";
import type { SiteSpec, SiteVersion } from "../src/api/types.ts";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { siteJuice } from "./helpers/fixtures.ts";
import { mockApi, reply } from "./helpers/mock-api.ts";
import {
  callsTo,
  expectDialogNoAxeViolations,
  freezeClock,
  impactWith,
} from "./helpers/sites-flow.ts";

/** Rolling back to v10 takes ssn out of the redaction words, so the redacted range changes for 17 requests. */
const ROLLBACK_PREVIEW = impactWith([
  { kind: "secret_fields", count: 17, top: [["POST", "/api/patients", 12]] },
]);

const ROLLBACK_ROW = "Jev 超时调到 3000 ms";

async function openHistory(
  page: Page,
  path: string,
  overrides: Record<string, unknown> = {},
): Promise<void> {
  await freezeClock(page);
  await mockApi(page, { overrides });
  await page.goto(path);
  await expect(page.getByRole("table", { name: "版本历史" })).toBeVisible();
}

test("the history compares the newest version with the one before it by default", async ({
  page,
}) => {
  await openHistory(page, "/sites/emr?tab=history");

  await expect(page.getByRole("combobox", { name: /^从/ })).toHaveValue("12");
  await expect(page.getByRole("combobox", { name: /^到/ })).toHaveValue("13");
  await expect(page.getByRole("region", { name: "差异" })).toContainText("ssn");
});

test("two chosen versions show their difference, and the address keeps the pair", async ({
  page,
}) => {
  await openHistory(page, "/sites/emr?tab=history&diff=6..7");

  const diff = page.getByRole("region", { name: "差异" });
  await expect(diff).toContainText("mode: observe");
  await expect(diff).toContainText("mode: enforce");

  await page.getByRole("combobox", { name: /^到/ }).selectOption({ label: "v8" });
  await expect(page).toHaveURL(/diff=6\.\.8/);
  await expect(page.getByRole("combobox", { name: /^到/ })).toHaveValue("8");
});

test("the same version on both sides asks for two different versions", async ({ page }) => {
  await openHistory(page, "/sites/emr?tab=history&diff=7..7");

  await expect(page.getByText("选择两个不同的版本。")).toBeVisible();
});

test("a version can be read in full, in a row across the table", async ({ page }) => {
  await openHistory(page, "/sites/emr?tab=history");

  const row = page.getByRole("row").filter({ hasText: "追加脱敏字段 ssn" });
  await row.getByRole("button", { name: "查看全文" }).click();
  await expect(row.getByRole("button", { name: "收起全文" })).toBeVisible();

  // The full text opens under the summary and keeps its lines: it fills the table's width and scrolls sideways.
  const full = page.getByRole("region", { name: /全文$/ });
  await expect(full).toContainText("mode: enforce");
  const code = full.locator("pre");
  await expect(code).toHaveCSS("white-space", "pre");
  const [table, text] = await Promise.all([
    page.getByRole("table", { name: "版本历史" }).boundingBox(),
    code.boundingBox(),
  ]);
  expect(text?.width ?? 0).toBeGreaterThan((table?.width ?? 0) - 40);

  await row.getByRole("button", { name: "收起全文" }).click();
  await expect(full).toBeHidden();
});

test("rolling back to v10 shows the change and the impact, then saves v14 with the note", async ({
  page,
}) => {
  await openHistory(page, "/sites/emr?tab=history", {
    "POST /api/sites/emr/preview": ROLLBACK_PREVIEW,
  });

  const history = page.getByRole("table", { name: "版本历史" });
  await history
    .getByRole("row")
    .filter({ hasText: ROLLBACK_ROW })
    .getByRole("button", { name: "以此版本回滚…" })
    .click();

  const dialog = page.getByRole("dialog", { name: "回滚 emr 到 v10" });
  await expect(dialog.getByRole("list", { name: "改动摘要" })).toContainText("追加脱敏词 －ssn");
  await expect(dialog.getByRole("region", { name: "差异" })).toContainText("ssn");
  await expect(dialog).toContainText("影响（最近 24 小时）");
  await expect(dialog).toContainText("脱敏范围变化");
  await dialog.getByLabel("备注（可选，最多 500 字）").fill("回到 v10，去掉 ssn");
  await dialog.getByRole("button", { name: "回滚，生成 v14（内容同 v10）" }).click();

  await expect(dialog).toBeHidden();
  await expect(page.getByText("● v14 已生效（2/2 个网关")).toBeVisible();
  const [rolled] = callsTo(page, "POST", "/api/sites/emr/rollback");
  expect(rolled?.body).toMatchObject({
    to_version: 10,
    expected_version: 13,
    note: "回到 v10，去掉 ssn",
  });

  // v12 is an older rollback to v10 as well, so the new row is the one with this note.
  const made = history.getByRole("row").filter({ hasText: "回到 v10，去掉 ssn" });
  await expect(made).toHaveCount(1);
  await expect(made).toContainText("回滚（回到 v10）");
  await expect(made).toContainText("v14");
  await expect(made).toContainText("当前");
});

test("a draft with unsaved changes holds the rollback until it is saved or dropped", async ({
  page,
}) => {
  await freezeClock(page);
  await mockApi(page);
  await page.goto("/sites/emr?tab=config&group=entries");
  await page.getByRole("textbox", { name: "添加入口规则" }).fill("/api/admin");
  await page.getByRole("button", { name: "添加", exact: true }).click();
  await expect(page.getByRole("region", { name: "未保存的改动" })).toContainText(
    "未保存的改动 1 处",
  );

  await page.getByRole("tab", { name: "变更历史" }).click();
  await page
    .getByRole("row")
    .filter({ hasText: ROLLBACK_ROW })
    .getByRole("button", { name: "以此版本回滚…" })
    .click();

  const dialog = page.getByRole("dialog", { name: "回滚 emr 到 v10" });
  await expect(dialog.getByRole("alert")).toContainText(
    "有未保存的改动。请先在配置页保存或放弃，再回滚。",
  );
  await expect(dialog.getByRole("button", { name: /^回滚，生成 v14/ })).toBeDisabled();
  expect(callsTo(page, "POST", "/api/sites/emr/rollback")).toHaveLength(0);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the rollback dialog passes axe in the ${theme} theme`, async ({ page }) => {
    await setTheme(page, theme);
    await openHistory(page, "/sites/emr?tab=history", {
      "POST /api/sites/emr/preview": ROLLBACK_PREVIEW,
    });
    await page
      .getByRole("row")
      .filter({ hasText: ROLLBACK_ROW })
      .getByRole("button", { name: "以此版本回滚…" })
      .click();

    await expect(page.getByRole("dialog", { name: "回滚 emr 到 v10" })).toContainText(
      "脱敏范围变化",
    );
    await expectDialogNoAxeViolations(page);
  });
}

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`a full text in the history passes axe in the ${theme} theme`, async ({ page }) => {
    await setTheme(page, theme);
    await openHistory(page, "/sites/emr?tab=history");
    await page
      .getByRole("row")
      .filter({ hasText: "追加脱敏字段 ssn" })
      .getByRole("button", { name: "查看全文" })
      .click();

    await expect(page.getByRole("region", { name: /全文$/ })).toContainText("mode: enforce");
    await expectNoAxeViolations(page);
  });
}

// ------------------------------------------------------------------ automatic versions (design 5)

const TIGHTEN_REASON = "同一个字段在 14 个会话里都是文档编号，已从医生收紧为文档。";
const PAUSE_REASON = "连续 3 次判定异常，已暂停这个字段的学习。";

/** Juice with one field class in its object map: the learning task is the one that moves it. */
function juiceSpec(kind: string): SiteSpec {
  const spec = structuredClone(siteJuice.spec);
  return {
    ...spec,
    advanced: {
      ...spec.advanced,
      field_kinds: [{ field: "attachments[].doc_id", kind, in: ["/api/records/{id}"] }],
    },
  };
}

/**
 * Three versions of juice: v5 and v7 by the administrator, v6 by the learning task. In `tightened` v6 moves the
 * field from doctor to document, so its summary names the change; in `same` v6 pauses learning and changes no route
 * or object setting, so its note stands in for the summary. The site itself is read at the current version (v7).
 */
function juiceHistory(variant: "tightened" | "same"): Record<string, unknown> {
  const tightened = variant === "tightened";
  const before = juiceSpec("doctor");
  const current = tightened ? juiceSpec("document") : before;
  const automatic: SiteVersion = tightened
    ? {
        version: 6,
        change: "auto_tighten",
        rollback_of: null,
        note: TIGHTEN_REASON,
        changed_at: "2026-11-01T12:00:00Z",
        spec: current,
      }
    : {
        version: 6,
        change: "auto_pause",
        rollback_of: null,
        note: PAUSE_REASON,
        changed_at: "2026-11-01T12:00:00Z",
        spec: before,
      };
  return {
    "GET /api/sites/juice": { ...siteJuice, spec: current },
    "GET /api/sites/juice/versions": {
      versions: [
        {
          version: 7,
          change: "update",
          rollback_of: null,
          note: null,
          changed_at: "2026-11-01T12:40:00Z",
          spec: current,
        },
        automatic,
        {
          version: 5,
          change: "update",
          rollback_of: null,
          note: "登记文档字段的类别",
          changed_at: "2026-11-01T09:00:00Z",
          spec: before,
        },
      ],
    },
    "POST /api/sites/juice/rollback": reply(200, { ...siteJuice, spec: before, version: 8 }),
  };
}

/** Runs in the page: one line for each cell that spills, each control that leaves its cell, and a too-wide table. */
function historyProblems(): string[] {
  const table = document.querySelector('table[aria-label="版本历史"]');
  if (table === null) return ["the version table is missing"];
  const problems: string[] = [];
  for (const cell of Array.from(table.querySelectorAll("td"))) {
    const box = cell.getBoundingClientRect();
    const text = (cell.textContent ?? "").trim().replace(/\s+/g, " ").slice(0, 24);
    if (cell.scrollWidth > cell.clientWidth + 1) problems.push(`"${text}" runs past its cell`);
    for (const control of Array.from(cell.querySelectorAll("button, a, .pill"))) {
      const rect = control.getBoundingClientRect();
      if (rect.width > 0 && (rect.left < box.left - 0.5 || rect.right > box.right + 0.5)) {
        problems.push(`"${text}": ${(control.textContent ?? "").trim()} leaves its cell`);
      }
    }
  }
  const frame = table.parentElement;
  if (frame !== null && table.getBoundingClientRect().width > frame.clientWidth + 1) {
    problems.push("the table is wider than its frame");
  }
  return problems;
}

async function openJuiceHistory(page: Page, variant: "tightened" | "same"): Promise<void> {
  await openHistory(page, "/sites/juice?tab=history", juiceHistory(variant));
}

test("自动收紧的版本用设计中的写法写出摘要，作者写作学习任务", async ({ page }) => {
  await openJuiceHistory(page, "tightened");

  const history = page.getByRole("table", { name: "版本历史" });
  const automatic = history.getByRole("row").filter({ hasText: "学习任务" });
  await expect(automatic).toHaveCount(1);
  await expect(automatic).toContainText(
    "自动收紧：响应 /api/records/{id} attachments[].doc_id 从医生改为文档",
  );
  await expect(automatic).toContainText(TIGHTEN_REASON);
  await expect(automatic.getByRole("cell", { name: "自动收紧", exact: true })).toBeVisible();
  await expect(automatic.getByRole("cell", { name: "学习任务", exact: true })).toBeVisible();

  const manual = history.getByRole("row").filter({ hasText: "登记文档字段的类别" });
  await expect(manual.getByRole("cell", { name: "管理员", exact: true })).toBeVisible();
  await expect(manual.getByRole("button", { name: "撤销…" })).toHaveCount(0);
});

test("自动版本没有可以列出的改动时，备注就是摘要，并且只写一次", async ({ page }) => {
  await openJuiceHistory(page, "same");

  const automatic = page
    .getByRole("table", { name: "版本历史" })
    .getByRole("row")
    .filter({ hasText: "学习任务" });
  await expect(automatic.getByRole("cell", { name: "自动暂停", exact: true })).toBeVisible();
  await expect(automatic.getByText(PAUSE_REASON, { exact: true })).toHaveCount(1);
});

test("撤销自动版本时打开回滚对话框，备注填入自动版本的原因，提交时带上它", async ({ page }) => {
  await openJuiceHistory(page, "tightened");

  const automatic = page
    .getByRole("table", { name: "版本历史" })
    .getByRole("row")
    .filter({ hasText: "学习任务" });
  await automatic.getByRole("button", { name: "撤销…" }).click();

  const dialog = page.getByRole("dialog", { name: "回滚 juice 到 v5" });
  await expect(dialog).toContainText("撤销 v6 的自动改动：回到 v5 的内容。");
  await expect(dialog.getByRole("list", { name: "改动摘要" })).toContainText(
    "响应 /api/records/{id} attachments[].doc_id 从文档改为医生",
  );
  await expect(dialog.getByLabel("备注（可选，最多 500 字）")).toHaveValue(TIGHTEN_REASON);
  await dialog.getByRole("button", { name: "回滚，生成 v8（内容同 v5）" }).click();

  await expect(dialog).toBeHidden();
  const [rolled] = callsTo(page, "POST", "/api/sites/juice/rollback");
  expect(rolled?.body).toMatchObject({
    to_version: 5,
    expected_version: 7,
    note: TIGHTEN_REASON,
  });
});

test("历史表格在 1024、1280 和 1920 px 下，单元格和其中的按钮都装得下", async ({ page }) => {
  await openJuiceHistory(page, "tightened");

  for (const width of [1024, 1280, 1920]) {
    await page.setViewportSize({ width, height: 900 });
    await page.goto("/sites/juice?tab=history");
    await expect(page.getByRole("table", { name: "版本历史" })).toBeVisible();
    const problems = await page.evaluate(historyProblems);
    expect(problems, `the history at ${width} px`).toEqual([]);
  }
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`自动版本的历史在 ${theme} 主题下通过 axe 检查`, async ({ page }) => {
    await setTheme(page, theme);
    await openJuiceHistory(page, "tightened");
    await expect(page.getByText(TIGHTEN_REASON)).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
