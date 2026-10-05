/**
 * Original-content and export-package downloads. The bytes go to the browser as an attachment and
 * are never rendered; the client validates headers, scope, target and the exact length first, and
 * a download never outlives the screen, target or session it was started for.
 */
import { readFile } from "node:fs/promises";
import { expect, type Page, test } from "@playwright/test";
import {
  ACCESS_ID,
  accessInspectionFixture,
  accessListFixture,
  downloadHeaders,
} from "./access-fixtures";
import {
  exportDownloadHeaders,
  exportFixture,
  exportListFixture,
  exportListItemFixture,
} from "./export-fixtures";
import { ARTIFACT_ID } from "./fixtures";
import { seamState, signIn } from "./shell-helpers";
import { apiCalls, CASE_ID, EXPORT_ID, mockWork, type Override, refuse } from "./work-helpers";

const PAYLOAD = Buffer.from([0, 255, 60, 115, 99, 114, 105, 112, 116, 62]);
const PACKAGE = Buffer.from("0123456789abcdefg");

/** Records every object URL the page creates and revokes. */
async function trackObjectUrls(page: Page) {
  await page.addInitScript(() => {
    const store = { created: [] as string[], revoked: [] as string[] };
    Object.defineProperty(window, "__urls", { value: store });
    const create = URL.createObjectURL.bind(URL);
    const revoke = URL.revokeObjectURL.bind(URL);
    URL.createObjectURL = (blob) => {
      const url = create(blob);
      store.created.push(url);
      return url;
    };
    URL.revokeObjectURL = (url) => {
      store.revoked.push(url);
      revoke(url);
    };
  });
  return () =>
    page.evaluate(
      () => (window as unknown as { __urls: { created: string[]; revoked: string[] } }).__urls,
    );
}

function approved(status: "approved" | "pending" | "denied" | "expired" | "revoked" = "approved") {
  return (url: URL, request: { method(): string }) => {
    if (request.method() !== "GET") return undefined;
    if (url.pathname === "/control/v1/evidence-access-requests") {
      const list = accessListFixture("mine");
      const [first] = list.items;
      if (first) first.stored_status = status;
      return { body: list };
    }
    if (url.pathname === `/control/v1/evidence-access-requests/${ACCESS_ID}`)
      return { body: accessInspectionFixture(status) };
    return undefined;
  };
}

async function openAccessDrawer(page: Page) {
  await page.locator(`a[href="/cases/${CASE_ID}"]`).first().click();
  await page.getByRole("tab", { name: "访问申请" }).click();
  await page.getByRole("button", { name: "详情" }).click();
  return page.getByRole("dialog", { name: "访问申请详情" });
}

async function openExportDrawer(page: Page) {
  await page.locator(`a[href="/cases/${CASE_ID}"]`).first().click();
  await page.getByRole("tab", { name: "导出" }).click();
  await page.getByRole("button", { name: "查看并下载" }).click();
  return page.getByRole("dialog", { name: "导出详情" });
}

const contentReply = (headers = downloadHeaders(PAYLOAD.length), raw = PAYLOAD) => ({
  raw,
  headers,
});

test.describe("original-content download", () => {
  test("hands the exact bytes to the browser as a .bin attachment and releases the object URL", async ({
    page,
  }) => {
    const urls = await trackObjectUrls(page);
    let requestHeaders: Record<string, string> = {};
    const base = approved();
    const calls = await mockWork(page, async (url, request) => {
      if (url.pathname === `/control/v1/artifacts/${ARTIFACT_ID}/content`) {
        requestHeaders = await request.allHeaders();
        return contentReply();
      }
      return base(url, request);
    });
    await signIn(page, "/cases");
    const drawer = await openAccessDrawer(page);
    await expect(drawer).toContainText("已批准");
    // Reading the record grants nothing; the download is a separate, explicit act.
    expect(apiCalls(calls).some((call) => call.path.endsWith("/content"))).toBe(false);
    const saved = page.waitForEvent("download");
    await drawer.getByRole("button", { name: "下载原文（.bin）" }).click();
    const download = await saved;
    expect(download.suggestedFilename()).toBe(`${ARTIFACT_ID}.bin`);
    expect(await readFile((await download.path()) as string)).toEqual(PAYLOAD);
    await download.delete();
    await expect(
      drawer.getByText(`已发起附件保存：${ARTIFACT_ID}.bin（${PAYLOAD.length} 字节）`),
    ).toBeVisible();
    expect(requestHeaders["x-xshield-evidence-access-request"]).toBe(ACCESS_ID);
    expect(requestHeaders.accept).toBe("application/octet-stream");
    // The plaintext is never part of the page.
    await expect(page.getByText("<script>")).toHaveCount(0);
    expect(await page.content()).not.toContain("<script>\u0000");
    // One object URL, revoked promptly.
    await expect.poll(async () => (await urls()).revoked.length).toBe(1);
    const { created, revoked } = await urls();
    expect(created).toHaveLength(1);
    expect(revoked).toEqual(created);
  });

  for (const [status, label] of [
    ["pending", "待审批"],
    ["denied", "已拒绝"],
    ["expired", "已过期"],
    ["revoked", "已撤销"],
  ] as const) {
    test(`a ${status} request offers no download`, async ({ page }) => {
      await mockWork(page, approved(status));
      await signIn(page, "/cases");
      const drawer = await openAccessDrawer(page);
      await expect(drawer).toContainText(label);
      await expect(drawer.getByRole("button", { name: "下载原文（.bin）" })).toHaveCount(0);
    });
  }

  test("an approved request whose target is gone says why it cannot be downloaded", async ({
    page,
  }) => {
    await mockWork(page, (url, request) => {
      if (url.pathname === `/control/v1/evidence-access-requests/${ACCESS_ID}`) {
        const detail = accessInspectionFixture("approved");
        detail.access_request.case_status = "closed";
        detail.access_request.artifact_status = "deleted";
        return { body: detail };
      }
      return approved()(url, request);
    });
    await signIn(page, "/cases");
    const drawer = await openAccessDrawer(page);
    const button = drawer.getByRole("button", { name: "下载原文（.bin）" });
    await expect(button).toBeDisabled();
    await expect(drawer).toContainText("当前不可下载：案件已关闭、证据已删除");
  });

  for (const failure of ["scope", "unauthorized", "audit", "length", "target"] as const) {
    test(`a ${failure} failure never releases a browser attachment`, async ({ page }) => {
      const downloads: string[] = [];
      page.on("download", (download) => downloads.push(download.suggestedFilename()));
      const urls = await trackObjectUrls(page);
      const base = approved();
      await mockWork(page, (url, request) => {
        if (url.pathname !== `/control/v1/artifacts/${ARTIFACT_ID}/content`)
          return base(url, request);
        if (failure === "scope")
          return contentReply(
            { ...downloadHeaders(3), "X-Xshield-Tenant-Id": "tenant_other" },
            Buffer.from([1, 2, 3]),
          );
        if (failure === "length")
          return contentReply({ ...downloadHeaders(5) }, Buffer.from([1, 2, 3]));
        if (failure === "target")
          return contentReply(
            { ...downloadHeaders(3), "X-Xshield-Artifact-Id": ARTIFACT_ID.replace(/11$/, "12") },
            Buffer.from([1, 2, 3]),
          );
        return failure === "unauthorized"
          ? refuse(401, "CONTROL_AUTH_REQUIRED")
          : refuse(503, "AUDIT_DURABILITY_FAILED");
      });
      await signIn(page, "/cases");
      const drawer = await openAccessDrawer(page);
      await drawer.getByRole("button", { name: "下载原文（.bin）" }).click();
      if (failure === "scope" || failure === "unauthorized")
        await expect(page.getByRole("heading", { name: "连接管理服务" })).toBeVisible();
      else
        await expect(
          drawer.getByRole("alert").filter({
            hasText: failure === "audit" ? "AUDIT_DURABILITY_FAILED" : "INVALID_RESPONSE",
          }),
        ).toBeVisible();
      await page.waitForTimeout(300);
      expect(downloads).toEqual([]);
      expect((await urls()).created).toEqual([]);
    });
  }

  test("changing the target discards a download that was still on its way", async ({ page }) => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let started = false;
    const downloads: string[] = [];
    page.on("download", (download) => downloads.push(download.suggestedFilename()));
    const urls = await trackObjectUrls(page);
    const base = approved();
    await mockWork(page, async (url, request) => {
      if (url.pathname === `/control/v1/artifacts/${ARTIFACT_ID}/content`) {
        started = true;
        await gate;
        return contentReply();
      }
      return base(url, request);
    });
    await signIn(page, "/cases");
    const drawer = await openAccessDrawer(page);
    await drawer.getByRole("button", { name: "下载原文（.bin）" }).click();
    await expect.poll(() => started).toBe(true);
    // Close the record the download belongs to, then let the late reply arrive.
    await drawer
      .getByRole("button", { name: /关闭|close/i })
      .first()
      .click();
    await expect(drawer).toHaveCount(0);
    release();
    await page.waitForTimeout(400);
    expect(downloads).toEqual([]);
    expect((await urls()).created).toEqual([]);
  });

  test("leaving the page discards it too", async ({ page }) => {
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    let started = false;
    const downloads: string[] = [];
    page.on("download", (download) => downloads.push(download.suggestedFilename()));
    const base = approved();
    await mockWork(page, async (url, request) => {
      if (url.pathname === `/control/v1/artifacts/${ARTIFACT_ID}/content`) {
        started = true;
        await gate;
        return contentReply();
      }
      return base(url, request);
    });
    await signIn(page, "/cases");
    const drawer = await openAccessDrawer(page);
    await drawer.getByRole("button", { name: "下载原文（.bin）" }).click();
    await expect.poll(() => started).toBe(true);
    // Browser back leaves the tab with the record still open.
    await page.goBack();
    await expect(page).toHaveURL(new RegExp(`/cases/${CASE_ID}$`));
    await expect(page.getByRole("dialog", { name: "访问申请详情" })).toHaveCount(0);
    release();
    await page.waitForTimeout(400);
    expect(downloads).toEqual([]);
  });

  test("a machine credential cannot step up: the server's refusal is explained, no dialog", async ({
    page,
  }) => {
    const base = approved();
    await mockWork(page, (url, request) =>
      url.pathname === `/control/v1/artifacts/${ARTIFACT_ID}/content`
        ? refuse(403, "CONTROL_STEP_UP_REQUIRED")
        : base(url, request),
    );
    await signIn(page, "/cases");
    const drawer = await openAccessDrawer(page);
    await drawer.getByRole("button", { name: "下载原文（.bin）" }).click();
    const alert = drawer.getByRole("alert").filter({ hasText: "CONTROL_STEP_UP_REQUIRED" });
    await expect(alert).toContainText("机器凭证无法完成再认证");
    await expect(page.getByRole("dialog", { name: "需要 MFA 再认证" })).toHaveCount(0);
    expect((await seamState(page)).status).toBe("connected");
  });
});

function readyExports(over: (item: ReturnType<typeof exportFixture>) => void = () => {}): Override {
  return (url, request) => {
    if (request.method() !== "GET") return undefined;
    if (url.pathname === "/control/v1/exports") {
      const list = exportListFixture("mine");
      list.items = [exportListItemFixture("ready")];
      return { body: list };
    }
    if (url.pathname === `/control/v1/exports/${EXPORT_ID}`) {
      const detail = exportFixture("ready");
      over(detail);
      return { body: detail };
    }
    return undefined;
  };
}

test.describe("export package download", () => {
  test("hands the package over as a JSON attachment and the claim counter follows", async ({
    page,
  }) => {
    let claimed = 0;
    const urls = await trackObjectUrls(page);
    const base = readyExports((detail) => {
      detail.download_count = claimed;
    });
    const calls = await mockWork(page, (url, request, call, count) => {
      if (url.pathname === `/control/v1/exports/${EXPORT_ID}/download`) {
        claimed += 1;
        return { raw: PACKAGE, headers: exportDownloadHeaders(PACKAGE.length) };
      }
      return base(url, request, call, count);
    });
    await signIn(page, "/cases");
    const drawer = await openExportDrawer(page);
    await expect(drawer).toContainText("剩余领取 2/2 次");
    expect(apiCalls(calls).some((call) => call.path.endsWith("/download"))).toBe(false);
    const saved = page.waitForEvent("download");
    await drawer.getByRole("button", { name: "下载导出包" }).click();
    const download = await saved;
    expect(download.suggestedFilename()).toBe("investigation-export.json");
    expect(await readFile((await download.path()) as string)).toEqual(PACKAGE);
    await download.delete();
    await expect(
      drawer.getByText("已发起附件保存：investigation-export.json（17 字节）"),
    ).toBeVisible();
    // The claim was consumed on the server; the detail is read again to show what is left.
    await expect(drawer).toContainText("剩余领取 1/2 次");
    await expect(drawer).toContainText("1 / 2 次");
    await expect.poll(async () => (await urls()).revoked.length).toBe(1);
  });

  test("a used-up export offers no more claims", async ({ page }) => {
    await mockWork(
      page,
      readyExports((detail) => {
        detail.download_count = 2;
      }),
    );
    await signIn(page, "/cases");
    const drawer = await openExportDrawer(page);
    await expect(drawer.getByRole("button", { name: "下载导出包" })).toBeDisabled();
    await expect(drawer).toContainText("领取次数已用完");
  });

  test("an export past its expiry on the server's own clock cannot be claimed", async ({
    page,
  }) => {
    const base = readyExports();
    await mockWork(page, (url, request, call, count) => {
      if (url.pathname === "/control/v1/exports") {
        const list = exportListFixture("mine");
        const ready = exportListItemFixture("ready");
        ready.expires_at = "2026-09-20T08:10:00.000Z";
        list.items = [ready];
        list.as_of = "2026-09-20T08:30:00.000000Z";
        return { body: list };
      }
      return base(url, request, call, count);
    });
    await signIn(page, "/cases");
    const drawer = await openExportDrawer(page);
    await expect(drawer.getByRole("button", { name: "下载导出包" })).toBeDisabled();
    await expect(drawer).toContainText("导出包期限已过");
  });

  for (const failure of ["size", "artifact", "audit"] as const) {
    test(`a ${failure} mismatch never releases the package`, async ({ page }) => {
      const downloads: string[] = [];
      page.on("download", (download) => downloads.push(download.suggestedFilename()));
      const base = readyExports();
      await mockWork(page, (url, request, call, count) => {
        if (url.pathname !== `/control/v1/exports/${EXPORT_ID}/download`)
          return base(url, request, call, count);
        if (failure === "audit") return refuse(503, "AUDIT_DURABILITY_FAILED");
        if (failure === "size")
          return { raw: PACKAGE, headers: exportDownloadHeaders(PACKAGE.length + 1) };
        return {
          raw: PACKAGE,
          headers: {
            ...exportDownloadHeaders(PACKAGE.length),
            "X-Xshield-Package-Artifact-Id": ARTIFACT_ID,
          },
        };
      });
      await signIn(page, "/cases");
      const drawer = await openExportDrawer(page);
      await drawer.getByRole("button", { name: "下载导出包" }).click();
      await expect(
        drawer.getByRole("alert").filter({
          hasText: failure === "audit" ? "AUDIT_DURABILITY_FAILED" : "INVALID_RESPONSE",
        }),
      ).toBeVisible();
      await page.waitForTimeout(300);
      expect(downloads).toEqual([]);
    });
  }
});
