// The "模型" tab of the system page (design agent-model-ui 2, 3.6 and 5.1): the two cards and their status lines,
// the test and save flow with its gate, a stale save (409), the key that is write-only, the history and its restore,
// the environment fallback, the gateway's configuration row and the overview's warning, and axe in both themes.
// The shared mock keeps the configuration in memory, so a save shows in the next read.

import { expect, type Locator, type Page, test } from "@playwright/test";
import type { ModelsState, ModelTestResult } from "../src/api/types.ts";
import { MODEL_TEXT } from "../src/lib/vocab.ts";
import { expectNoAxeViolations, setTheme, type Theme } from "./helpers/axe.ts";
import { system, systemModels } from "./helpers/fixtures.ts";
import { reply, servedRequests } from "./helpers/mock-api.ts";
import { useFixtures } from "./helpers/trace.ts";

const JEV_PATH = "/api/system/models/jev";
const AGENT_PATH = "/api/system/models/agent";
/** The address the gateway line resolves to: a preset line sends and shows it, and the saved value stays null. */
const JEV_GATEWAY_ENDPOINT = "https://ai-gateway.vercel.sh/typesafe/v1/systemone";

/** The Jev card is the first of the two model cards, the learning agent's the second. */
function card(page: Page, which: "jev" | "agent"): Locator {
  return page.locator("section.sys-model").nth(which === "jev" ? 0 : 1);
}

/** The save dialog of a model, by its title. */
function saveDialog(page: Page, title: string): Locator {
  return page.getByRole("dialog", { name: title });
}

/** The calls the page made to one path, as the mock recorded them. */
function callsTo(page: Page, method: string, path: string) {
  return servedRequests(page).filter((call) => call.method === method && call.path === path);
}

/** The gateway instance row of an edge, found by its name (system tab). */
function edgeBody(page: Page, edge: string): Locator {
  return page
    .getByRole("table", { name: "网关实例" })
    .locator("tbody")
    .filter({ has: page.getByText(edge, { exact: true }) });
}

/** The Jev configuration with edge-2 still on version 13, which the gateway refused (design 3.6). */
function behindModels(): ModelsState {
  const models = structuredClone(systemModels);
  models.jev.loaded = [
    { edge: "edge-1", online: true, source: "console", version: 14, error: null },
    {
      edge: "edge-2",
      online: true,
      source: "console",
      version: 13,
      error: "MODEL_KEY_UNREADABLE",
    },
  ];
  return models;
}

/** Answers the first save of the Jev configuration with a version conflict; later calls reach the mock. */
async function conflictOnFirstSave(page: Page, current: number): Promise<void> {
  let answered = false;
  await page.route(
    (url) => url.pathname === JEV_PATH,
    async (route) => {
      if (answered || route.request().method() !== "PUT") {
        await route.fallback();
        return;
      }
      answered = true;
      await route.fulfill({
        status: 409,
        contentType: "application/json",
        body: JSON.stringify({ error: "VERSION_CONFLICT", current_version: current }),
      });
    },
  );
}

test("the models tab shows both configurations and what the gateways run", async ({ page }) => {
  await useFixtures(page);
  await page.goto("/system?tab=models");
  await expect(page.getByRole("tab", { name: MODEL_TEXT.tab })).toHaveAttribute(
    "aria-selected",
    "true",
  );

  const jev = card(page, "jev");
  await expect(jev.getByText(MODEL_TEXT.jevTitle)).toBeVisible();
  await expect(jev.getByText("2/2 个网关已加载第 14 版")).toBeVisible();
  await expect(jev.getByText(JEV_GATEWAY_ENDPOINT)).toBeVisible();
  await expect(jev.getByText(/已设置 · 末 4 位 …9f3a/)).toBeVisible();
  await expect(jev.getByText("调用 1,284 · 失败 1.3% · p95 812 ms")).toBeVisible();

  const agent = card(page, "agent");
  await expect(agent.getByText(MODEL_TEXT.agentTitle)).toBeVisible();
  await expect(agent.getByText(MODEL_TEXT.agentLastOk)).toBeVisible();
  await expect(agent.getByText(systemModels.agent.endpoint, { exact: true })).toBeVisible();
  await expect(
    agent.getByText("调用 52 · 成功 50 · 失败 2（超时） · 2 个站点开启了学习代理"),
  ).toBeVisible();
});

test("the agent's failing calls show in its status, and the sites' use opens to a table", async ({
  page,
}) => {
  const models = structuredClone(systemModels);
  models.agent = {
    ...models.agent,
    recent_failures: ["timeout", "timeout", "timeout", "timeout", "timeout"],
  };
  await useFixtures(page, { models });
  await page.goto("/system?tab=models");

  const agent = card(page, "agent");
  await expect(agent.getByText("最近 5 次失败：超时")).toBeVisible();
  const toggle = agent.getByRole("button", { name: MODEL_TEXT.sitesClosed });
  await expect(toggle).toHaveAttribute("aria-expanded", "false");
  await toggle.click();

  const table = agent.getByRole("table", { name: MODEL_TEXT.sitesCaption });
  await expect(table.getByRole("link", { name: "emr" })).toHaveAttribute("href", /\/sites\/emr/);
  await expect(table.getByRole("cell", { name: "31 / 200" })).toBeVisible();
  await expect(table.getByRole("cell", { name: "21 / 200" })).toBeVisible();
  await expect(agent.getByRole("button", { name: MODEL_TEXT.sitesOpen })).toHaveAttribute(
    "aria-expanded",
    "true",
  );
});

test("a test runs the form's values, and a configuration that tested is saved as tested", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/system?tab=models");
  const jev = card(page, "jev");
  await jev.getByRole("button", { name: MODEL_TEXT.btnEdit }).click();
  await jev.getByLabel("超时（毫秒）").fill("3000");
  await jev.getByRole("button", { name: MODEL_TEXT.btnTest }).click();
  await expect(jev.getByRole("status")).toContainText("成功");
  expect(callsTo(page, "POST", `${JEV_PATH}/test`).at(-1)?.body).toEqual({
    route: "gateway",
    endpoint: JEV_GATEWAY_ENDPOINT,
    model: "typesafe-ai/jev",
    timeout_ms: 3000,
  });

  await jev.getByRole("button", { name: MODEL_TEXT.btnSave }).click();
  const dialog = saveDialog(page, MODEL_TEXT.saveTitle(MODEL_TEXT.jevTitle, 15));
  await expect(dialog.getByText("2000 ms → 3000 ms")).toBeVisible();
  await expect(dialog.getByText(/用这份配置测试成功$/)).toBeVisible();
  await dialog.getByRole("button", { name: MODEL_TEXT.btnSaveVersion(15) }).click();

  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(jev.getByText("2/2 个网关已加载第 15 版")).toBeVisible();
  expect(callsTo(page, "PUT", JEV_PATH)).toEqual([
    expect.objectContaining({
      body: {
        route: "gateway",
        endpoint: JEV_GATEWAY_ENDPOINT,
        model: "typesafe-ai/jev",
        timeout_ms: 3000,
        expected_version: 14,
        note: "",
        tested: true,
      },
    }),
  ]);
});

test("a configuration that did not test waits for an acknowledgement, and the save records it", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/system?tab=models");
  const jev = card(page, "jev");
  await jev.getByRole("button", { name: MODEL_TEXT.btnEdit }).click();
  await jev.getByLabel("模型", { exact: true }).fill("typesafe-ai/jev-2");
  await jev.getByRole("button", { name: MODEL_TEXT.btnSave }).click();

  const dialog = saveDialog(page, MODEL_TEXT.saveTitle(MODEL_TEXT.jevTitle, 15));
  await expect(dialog.getByText("模型 typesafe-ai/jev → typesafe-ai/jev-2")).toBeVisible();
  await expect(dialog.getByText(MODEL_TEXT.testedMissing)).toBeVisible();
  // emr runs in enforce mode, so a failing Jev would refuse its requests: the dialog says so.
  await expect(dialog.getByText(MODEL_TEXT.impactFailClosed(["emr"]))).toBeVisible();
  await expect(dialog.getByText(MODEL_TEXT.failClosedSave)).toBeVisible();

  const save = dialog.getByRole("button", { name: MODEL_TEXT.btnSaveVersion(15) });
  await expect(save).toBeDisabled();
  await dialog.getByRole("checkbox", { name: MODEL_TEXT.ackUntested }).check();
  await expect(save).toBeEnabled();
  await save.click();

  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(callsTo(page, "PUT", JEV_PATH).at(-1)?.body).toMatchObject({
    model: "typesafe-ai/jev-2",
    tested: false,
    expected_version: 14,
  });
});

test("the history lists each version, and a restore fills the dialog and keeps the key", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/system?tab=models");
  const jev = card(page, "jev");
  await jev.getByRole("button", { name: MODEL_TEXT.btnHistory }).click();

  const history = jev.getByRole("table", { name: MODEL_TEXT.historyTitle });
  await expect(history.getByRole("row")).toHaveCount(4);
  await expect(history.getByText("已替换（…1c2e → …9f3a）")).toBeVisible();
  await expect(history.getByText("线路 TypeSafe 直连 → Vercel AI Gateway")).toBeVisible();
  await history.getByRole("button", { name: MODEL_TEXT.btnRestore(13) }).click();

  const dialog = saveDialog(page, MODEL_TEXT.saveTitle(MODEL_TEXT.jevTitle, 15));
  await expect(dialog.getByRole("textbox", { name: MODEL_TEXT.noteLabel })).toHaveValue(
    MODEL_TEXT.restoreNote(13),
  );
  await expect(dialog.getByText(MODEL_TEXT.keyKept("9f3a"))).toBeVisible();
  await expect(dialog.getByText(MODEL_TEXT.testedMissing)).toBeVisible();
  await dialog.getByRole("checkbox", { name: MODEL_TEXT.ackUntested }).check();
  await dialog.getByRole("button", { name: MODEL_TEXT.btnSaveVersion(15) }).click();

  await expect(jev.getByText("2/2 个网关已加载第 15 版")).toBeVisible();
  const restore = callsTo(page, "PUT", JEV_PATH).at(-1);
  expect(restore?.body).toMatchObject({
    note: MODEL_TEXT.restoreNote(13),
    tested: false,
    expected_version: 14,
    route: "gateway",
    timeout_ms: 2000,
  });
  // A key is never part of a restore: the saved one stays as it is.
  expect(restore?.body).not.toHaveProperty("key");
});

test("a save that meets a newer version says so, and reloading takes the version in use", async ({
  page,
}) => {
  await useFixtures(page);
  await conflictOnFirstSave(page, 15);
  await page.goto("/system?tab=models");
  const jev = card(page, "jev");
  await jev.getByRole("button", { name: MODEL_TEXT.btnEdit }).click();
  await jev.getByLabel("超时（毫秒）").fill("3000");
  await jev.getByRole("button", { name: MODEL_TEXT.btnTest }).click();
  await expect(jev.getByRole("status")).toContainText("成功");
  await jev.getByRole("button", { name: MODEL_TEXT.btnSave }).click();

  const dialog = saveDialog(page, MODEL_TEXT.saveTitle(MODEL_TEXT.jevTitle, 15));
  await dialog.getByRole("button", { name: MODEL_TEXT.btnSaveVersion(15) }).click();
  await expect(dialog.getByText(MODEL_TEXT.conflict(15))).toBeVisible();
  await expect(dialog.getByRole("button", { name: MODEL_TEXT.btnSaveVersion(15) })).toBeDisabled();

  await dialog.getByRole("button", { name: MODEL_TEXT.btnReload }).click();
  await expect(page.getByRole("dialog")).toHaveCount(0);
  await expect(jev.getByLabel("超时（毫秒）")).toHaveValue("2000");
});

test("a failed test names the reason, and the model's own text is shown as plain text", async ({
  page,
}) => {
  const failed: ModelTestResult = {
    ok: false,
    latency_ms: 35,
    status: 401,
    failure: null,
    detail: "<b>invalid api key</b>",
    answer_valid: null,
    answer_reason: null,
  };
  await useFixtures(page, { overrides: { [`POST ${JEV_PATH}/test`]: reply(200, failed) } });
  await page.goto("/system?tab=models");
  const jev = card(page, "jev");
  await jev.getByRole("button", { name: MODEL_TEXT.btnTest }).click();

  await expect(jev.getByRole("status")).toContainText(MODEL_TEXT.testFailUnauthorized);
  await expect(jev.getByRole("button", { name: MODEL_TEXT.testCooldown(10) })).toBeDisabled();
  await jev.getByText(MODEL_TEXT.testDetail).click();
  await expect(jev.locator("pre", { hasText: "<b>invalid api key</b>" })).toBeVisible();
  await expect(jev.locator("b")).toHaveCount(0);
});

test("a configuration only the environment supplies can be taken over, and its key is not shown again", async ({
  page,
}) => {
  const models = structuredClone(systemModels);
  models.jev = {
    ...models.jev,
    source: "env",
    key: { set: true, last4: null, updated_at: null, shared_with_jev: false },
    loaded: models.jev.loaded.map((load) => ({ ...load, source: "env", version: null })),
  };
  await useFixtures(page, { models });
  await page.goto("/system?tab=models");
  const jev = card(page, "jev");
  await expect(jev.getByText("2 个网关读取环境变量的配置")).toBeVisible();
  await expect(jev.getByText(MODEL_TEXT.sourceEnv)).toBeVisible();
  await expect(jev.getByRole("button", { name: MODEL_TEXT.btnBackToEnv })).toHaveCount(0);
  // The read-only test needs the console's key, which an environment configuration does not have.
  await expect(jev.getByRole("button", { name: MODEL_TEXT.btnTest })).toBeDisabled();
  await expect(jev.getByText(MODEL_TEXT.testNeedsKey)).toBeVisible();
  await jev.getByRole("button", { name: MODEL_TEXT.btnTakeOver }).click();

  // The console cannot read the environment's key, so the first save needs one typed in.
  const key = jev.locator('input[type="password"]');
  await key.focus();
  await key.blur();
  await expect(jev.getByText(MODEL_TEXT.keyRequired)).toBeVisible();
  const save = jev.getByRole("button", { name: MODEL_TEXT.btnSave });
  await expect(save).toBeDisabled();
  await key.fill("sk-live-7d20");
  await expect(save).toBeEnabled();
  await save.click();

  const dialog = saveDialog(page, MODEL_TEXT.saveTitle(MODEL_TEXT.jevTitle, 15));
  await expect(dialog.getByText("已设置（…7d20）")).toBeVisible();
  await dialog.getByRole("checkbox", { name: MODEL_TEXT.ackUntested }).check();
  await dialog.getByRole("button", { name: MODEL_TEXT.btnSaveVersion(15) }).click();

  await expect(jev.getByText("2/2 个网关已加载第 15 版")).toBeVisible();
  expect(callsTo(page, "PUT", JEV_PATH).at(-1)?.body).toMatchObject({
    key: "sk-live-7d20",
    expected_version: 14,
    tested: false,
  });
  await expect(page.getByText("sk-live-7d20")).toHaveCount(0);
});

test("a console configuration can go back to the environment, after a confirmation", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/system?tab=models");
  const jev = card(page, "jev");
  await jev.getByRole("button", { name: MODEL_TEXT.btnBackToEnv }).click();

  const confirm = page.getByRole("dialog", { name: MODEL_TEXT.backTitle });
  await confirm.getByRole("button", { name: MODEL_TEXT.backOk }).click();
  await expect(jev.getByText("2 个网关读取环境变量的配置")).toBeVisible();
  await expect(jev.getByRole("button", { name: MODEL_TEXT.btnHistory })).toBeVisible();
  expect(callsTo(page, "DELETE", JEV_PATH).at(-1)?.query).toBe("expected_version=14");
});

test("a gateway that has not loaded the saved version is named on the card and in the overview", async ({
  page,
}) => {
  const warning = MODEL_TEXT.attentionNotLoaded(14, "edge-2", "密钥无法解密");
  await useFixtures(page, { models: behindModels() });
  await page.goto("/system?tab=models");
  const jev = card(page, "jev");
  await expect(jev.getByText("edge-2 仍在用第 13 版：密钥无法解密")).toBeVisible();
  await expect(jev.getByText(warning)).toBeVisible();

  await page.goto("/");
  await expect(page.getByText(warning).first()).toBeVisible();
  await page.getByRole("link", { name: MODEL_TEXT.attentionAction }).first().click();
  await expect(page).toHaveURL(/tab=models/);
});

test("the gateway tab shows which configuration each gateway runs, and names one that is behind", async ({
  page,
}) => {
  const edited = structuredClone(system);
  const [first, second] = edited.edges;
  if (first === undefined || second === undefined) throw new Error("two gateways are expected");
  first.jev = { ...first.jev, config_source: "console", config_version: 14 };
  second.jev = {
    ...second.jev,
    config_source: "console",
    config_version: 13,
    config_error: "MODEL_KEY_UNREADABLE",
  };
  await useFixtures(page, { overrides: { "/api/system": edited } });
  await page.goto("/system");

  await edgeBody(page, "edge-2").getByRole("button", { name: "详情" }).click();
  await expect(page.getByText(MODEL_TEXT.edgeSourceConsole(13))).toBeVisible();
  await expect(page.getByText(MODEL_TEXT.edgeBehind(14, "密钥无法解密"))).toBeVisible();
  await page.getByRole("link", { name: MODEL_TEXT.edgeLinkModels }).click();
  await expect(page).toHaveURL(/tab=models/);
});

test("an agent that is not configured says so, and its form asks for a key", async ({ page }) => {
  const models = structuredClone(systemModels);
  models.agent = {
    ...models.agent,
    configured: false,
    source: null,
    version: 0,
    updated_at: null,
    key: { set: false, last4: null, updated_at: null, shared_with_jev: false },
  };
  await useFixtures(page, { models });
  await page.goto("/system?tab=models");
  const agent = card(page, "agent");
  await expect(agent.getByText(MODEL_TEXT.agentLead)).toBeVisible();
  await expect(agent.getByText(MODEL_TEXT.agentOff)).toBeVisible();
  await agent.getByRole("button", { name: MODEL_TEXT.btnConfigure }).click();

  await expect(agent.locator('input[type="password"]')).toBeVisible();
  await expect(agent.getByRole("button", { name: MODEL_TEXT.btnSave })).toBeDisabled();
});

test("an agent on the same gateway as Jev can share its key, and then sends none", async ({
  page,
}) => {
  await useFixtures(page);
  await page.goto("/system?tab=models");
  const agent = card(page, "agent");
  await agent.getByRole("button", { name: MODEL_TEXT.btnEdit }).click();
  await agent.getByRole("checkbox", { name: MODEL_TEXT.shareKeyLabel }).check();
  await expect(agent.getByText(MODEL_TEXT.keyShared, { exact: true })).toBeVisible();
  await expect(agent.locator('input[type="password"]')).toHaveCount(0);
  await agent.getByRole("button", { name: MODEL_TEXT.btnSave }).click();

  const dialog = saveDialog(page, MODEL_TEXT.saveTitle(MODEL_TEXT.agentTitle, 4));
  await dialog.getByRole("checkbox", { name: MODEL_TEXT.ackUntested }).check();
  await dialog.getByRole("button", { name: MODEL_TEXT.btnSaveVersion(4) }).click();

  await expect(page.getByRole("dialog")).toHaveCount(0);
  expect(callsTo(page, "PUT", AGENT_PATH).at(-1)?.body).toEqual({
    provider: "gateway",
    endpoint: systemModels.agent.endpoint,
    model: systemModels.agent.model,
    timeout_ms: 30000,
    share_key_with_jev: true,
    expected_version: 3,
    note: "",
    tested: false,
  });
});

test("an agent that shares Jev's key asks for its own key once it stops sharing", async ({
  page,
}) => {
  const models = structuredClone(systemModels);
  models.agent = {
    ...models.agent,
    share_key_with_jev: true,
    key: {
      set: true,
      last4: models.jev.key.last4,
      updated_at: models.jev.key.updated_at,
      shared_with_jev: true,
    },
  };
  await useFixtures(page, { models });
  await page.goto("/system?tab=models");
  const agent = card(page, "agent");
  await agent.getByRole("button", { name: MODEL_TEXT.btnEdit }).click();
  await expect(agent.getByText(MODEL_TEXT.keyShared, { exact: true })).toBeVisible();
  await agent.getByRole("checkbox", { name: MODEL_TEXT.shareKeyLabel }).uncheck();

  // Sharing cleared the agent's own key, so the form asks for one, and a test needs it typed in.
  const key = agent.locator('input[type="password"]');
  await expect(key).toBeVisible();
  const save = agent.getByRole("button", { name: MODEL_TEXT.btnSave });
  const runTest = agent.getByRole("button", { name: MODEL_TEXT.btnTest });
  await expect(save).toBeDisabled();
  await expect(runTest).toBeDisabled();
  await expect(agent.getByText(MODEL_TEXT.testNeedsSaveOrKey)).toBeVisible();
  await key.fill("sk-agent-41c8");
  await expect(save).toBeEnabled();
  await expect(runTest).toBeEnabled();
  await expect(agent.getByText(MODEL_TEXT.testNeedsSaveOrKey)).toHaveCount(0);
});

for (const theme of ["light", "dark"] satisfies Theme[]) {
  test(`the models tab passes axe in the ${theme} theme`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto("/system?tab=models");
    await expect(card(page, "jev").getByText(MODEL_TEXT.jevTitle)).toBeVisible();
    await expectNoAxeViolations(page);
  });

  test(`the model form passes axe in the ${theme} theme`, async ({ page }) => {
    await useFixtures(page);
    await setTheme(page, theme);
    await page.goto("/system?tab=models");
    await card(page, "jev").getByRole("button", { name: MODEL_TEXT.btnEdit }).click();
    await expect(card(page, "jev").getByLabel("超时（毫秒）")).toBeVisible();
    await expectNoAxeViolations(page);
  });
}
