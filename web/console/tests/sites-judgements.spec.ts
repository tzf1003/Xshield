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

/** One proposal the rules made for a request position: not accepting public sources at medium (a site without identity
 *  reaches no high), with 1234 votes from 56 sessions. */
const ACCEPTANCE: ObjectJudgement = {
  id: PROPOSAL_ID,
  key: "GET /doctor/{id} path[1]",
  reliability: "medium",
  last_seen: null,
  accepts_public: false,
  votes: 1234,
  sessions: 56,
  public_per_mille: 4,
};

/** An administrator's tier proposal for a response position: only administrators got its values (LQ-7). */
const ADMIN_TIER: ObjectJudgement = {
  id: "s10",
  key: "GET /api/admin/search results[].id",
  reliability: "high",
  last_seen: null,
  tier: "admin",
  units: 0,
  seen_values: 0,
  agreement_per_mille: 0,
};

/** The object map of emr with one judged position (s1, a public response position) and the proposals given. The site
 *  declares no user identity, as the emr fixture says. */
function judgedObjects(judgements: ObjectJudgement[] = [ACCEPTANCE]): ObjectsResponse {
  const slots = objectsEmr.slots.map((row) =>
    row.id === "s1" ? { ...row, tier: "public" as const, reliability: "high" as const } : row,
  );
  return { ...objectsEmr, identified: false, slots, judgements };
}

async function openJudgedMap(
  page: Page,
  options: MockOptions = {},
  objects: ObjectsResponse = judgedObjects(),
): Promise<void> {
  await freezeClock(page);
  await mockApi(page, {
    ...options,
    overrides: {
      "GET /api/sites/emr/objects": objects,
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
  await expect(panel).toContainText("不接受公共来源 · 可靠性 中");
  await expect(panel).toContainText("票 1234 · 会话 56 · 公共票 0.4%");

  await panel.getByRole("button", { name: "确认…" }).click();
  await untilModalSettled(page, "确认这条判断？");
  const dialog = page.getByRole("dialog", { name: "确认这条判断？" });
  await expect(dialog).toContainText(
    "位置 GET /doctor/{id} path[1] 将被判为：不接受公共来源 · 可靠性 中",
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

test("an administrator's tier proposal says who got the data, and an acceptance on a site without identity says so", async ({
  page,
}) => {
  await openJudgedMap(page, {}, judgedObjects([ACCEPTANCE, ADMIN_TIER]));

  const panel = page.locator(".obj-judgements");
  await expect(panel).toContainText("判断提议 2");
  await expect(panel).toContainText("归属 管理 · 可靠性 高");
  await expect(panel).toContainText("只有管理员拿到了数据，其他用户被拒绝");
  await expect(panel).not.toContainText("不同值");
  await expect(panel).toContainText("不接受公共来源 · 可靠性 中");
  await expect(panel).toContainText("本站点没有声明用户身份，这一条不会自动收紧");
});

test("a learned acceptance at medium reliability carries the same note in the object table", async ({
  page,
}) => {
  const objects = judgedObjects();
  const slots = objects.slots.map((row) =>
    row.id === "s9" ? { ...row, accepts_public: false, reliability: "medium" as const } : row,
  );
  await openJudgedMap(page, {}, { ...objects, slots });

  const table = page.getByRole("table", { name: "位置列表" });
  await expect(table).toContainText("不接受公共来源 · 可靠性 中");
  await expect(table).toContainText("本站点没有声明用户身份，这一条不会自动收紧");
});

test("a site that declares a user identity shows no such note", async ({ page }) => {
  await openJudgedMap(page, {}, { ...judgedObjects(), identified: true });

  await expect(page.locator(".obj-judgements")).toContainText("不接受公共来源 · 可靠性 中");
  await expect(page.locator(".obj-judgements")).not.toContainText("本站点没有声明用户身份");
});

test("a proposal that accepts public sources, or one at high reliability, carries no such note", async ({
  page,
}) => {
  const accepting: ObjectJudgement = {
    id: "p-accepting",
    key: "GET /doctor/{id} path[1]",
    reliability: "medium",
    last_seen: null,
    accepts_public: true,
    votes: 1234,
    sessions: 56,
    public_per_mille: 4,
  };
  const high: ObjectJudgement = {
    ...accepting,
    id: "p-high",
    reliability: "high",
    accepts_public: false,
  };
  await openJudgedMap(page, {}, judgedObjects([accepting, high]));

  const panel = page.locator(".obj-judgements");
  await expect(panel).toContainText("判断提议 2");
  await expect(panel).toContainText("接受公共来源 · 可靠性 中");
  await expect(panel).toContainText("不接受公共来源 · 可靠性 高");
  await expect(panel).not.toContainText("本站点没有声明用户身份");
});
