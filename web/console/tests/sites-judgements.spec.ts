// The judgements of the object map (console design W5, docs/07 7.9.16): a judged position names its judgement under its
// class, and a proposal the rules made is confirmed through a dialog that says what the site will be given, or dismissed
// with a notice. The mock records every call the page makes, so the writes are checked as the gateway receives them.

import { expect, type Page, test } from "@playwright/test";
import type { ObjectJudgement, ObjectsResponse } from "../src/api/types.ts";
import { type MockOptions, mockApi, reply } from "./helpers/mock-api.ts";
import { objectsEmr } from "./helpers/fixtures.ts";
import { callsTo, freezeClock, untilModalSettled } from "./helpers/sites-flow.ts";

const PROPOSAL_ID = "s4";
const CONFIRM = `/api/sites/emr/objects/slots/${PROPOSAL_ID}/judgement/confirm`;
const DISMISS = `/api/sites/emr/objects/slots/${PROPOSAL_ID}/judgement/dismiss`;

/** The object map of emr with one judged position (s1, a public response position) and one proposal the rules made
 *  for a request position: not accepting public sources, with 1234 votes from 56 sessions. */
function judgedObjects(): ObjectsResponse {
  const slots = objectsEmr.slots.map((row) =>
    row.id === "s1" ? { ...row, tier: "public" as const, reliability: "high" as const } : row,
  );
  const proposal: ObjectJudgement = {
    id: PROPOSAL_ID,
    key: "GET /doctor/{id} path[1]",
    reliability: "high",
    last_seen: null,
    accepts_public: false,
    votes: 1234,
    sessions: 56,
    public_per_mille: 4,
  };
  return { ...objectsEmr, slots, judgements: [proposal] };
}

async function openJudgedMap(page: Page, options: MockOptions = {}): Promise<void> {
  await freezeClock(page);
  await mockApi(page, {
    ...options,
    overrides: {
      "GET /api/sites/emr/objects": judgedObjects(),
      [`POST ${CONFIRM}`]: reply(204),
      [`POST ${DISMISS}`]: reply(204),
      ...options.overrides,
    },
  });
  await page.goto("/sites/emr?tab=objects");
  await expect(page.getByRole("tablist")).toBeVisible();
}

test("a judged position names its judgement, and the proposal is confirmed through its dialog", async ({
  page,
}) => {
  await openJudgedMap(page);

  await expect(page.getByRole("table", { name: "位置列表" })).toContainText(
    "归属 公共 · 可靠性 高",
  );

  const panel = page.locator(".obj-judgements");
  await expect(panel).toContainText("判断提议 1");
  await expect(panel).toContainText("不接受公共来源 · 可靠性 高");
  await expect(panel).toContainText("票 1234 · 会话 56 · 公共票 0.4%");

  await panel.getByRole("button", { name: "确认…" }).click();
  await untilModalSettled(page, "确认这条判断？");
  const dialog = page.getByRole("dialog", { name: "确认这条判断？" });
  await expect(dialog).toContainText(
    "位置 GET /doctor/{id} path[1] 将被判为：不接受公共来源 · 可靠性 高",
  );
  await dialog.getByRole("button", { name: "确认并保存版本" }).click();

  await expect(page.getByText("已确认。站点保存了一个新版本，判定开始使用它")).toBeVisible();
  expect(callsTo(page, "POST", CONFIRM)).toHaveLength(1);
});

test("a proposal is dismissed without a dialog, and the page says so", async ({ page }) => {
  await openJudgedMap(page);

  const panel = page.locator(".obj-judgements");
  await panel.getByRole("button", { name: "驳回" }).click();

  await expect(page.getByText("已驳回，同一判断不再提议，除非规则转到另一个判断")).toBeVisible();
  expect(callsTo(page, "POST", DISMISS)).toHaveLength(1);
  expect(callsTo(page, "POST", CONFIRM)).toHaveLength(0);
});
