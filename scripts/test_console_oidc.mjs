/** Live local smoke: real OIDC/control reads; no business mutations or persisted cookies. */
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
import { mkdir } from 'node:fs/promises';
const require = createRequire(new URL('../web/console/package.json', import.meta.url));
const { chromium, expect } = require('@playwright/test');
const origin = 'http://127.0.0.1:55173';
const screenshots = process.env.XSHIELD_SMOKE_SCREENSHOTS || '/tmp/xshield-console-smoke';
await mkdir(screenshots, { recursive: true });
const browser = await chromium.launch();
try {
  const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
  const errors = []; const responses = [];
  let unexpectedConsoleMessages = 0;
  page.on('console', message => {
    // The unauthenticated bootstrap intentionally returns 401 before login.
    if (['error', 'warning'].includes(message.type()) && !message.text().includes('401 (Unauthorized)')) unexpectedConsoleMessages++;
  });
  page.on('pageerror', e => errors.push(e.message));
  page.on('response', r => { const url = new URL(r.url()); if (url.pathname.startsWith('/control/v1/')) responses.push({ path: url.pathname, status: r.status() }); });
  await page.goto(origin + '/sites');
  await page.getByRole('button', { name: '使用企业身份登录' }).click();
  await page.locator('#username').fill('developer');
  await page.locator('#password').fill('xshield-dev-password');
  await page.getByRole('button', { name: 'Sign In', exact: true }).click();
  await page.waitForURL(origin + '/**');
  await page.getByRole('link', { name: '受保护站点', exact: true }).click();
  await page.getByRole('heading', { name: '站点列表', exact: true }).waitFor();
  await page.getByText('正在读取站点列表…').waitFor({ state: 'hidden' });
  assert.equal(await page.getByRole('alert').count(), 0);
  await expect.poll(() => responses.some(r => r.path === '/control/v1/sites' && r.status === 200)).toBeTruthy();
  await page.screenshot({ path: screenshots + '/sites-desktop.png' });
  await page.getByRole('button', { name: '新建站点', exact: true }).click();
  await page.getByLabel('站点名称', { exact: true }).waitFor();
  assert.equal(await page.getByLabel('每秒请求数', { exact: true }).count(), 0);
  await page.screenshot({ path: screenshots + '/site-network-desktop.png' });
  await page.getByRole('navigation', { name: '站点运营导航' }).getByRole('link', { name: '安全入口', exact: true }).click();
  await page.getByRole('combobox', { name: '安全入口', exact: true }).waitFor();
  assert.equal(await page.getByLabel('站点名称', { exact: true }).count(), 0);

  await page.getByRole('link', { name: '资格与身份账本', exact: true }).click();
  assert.equal(new URL(page.url()).pathname, '/investigation/grants');
  await page.getByLabel('资格 ID', { exact: true }).waitFor();
  await page.goto(origin + '/sites/site_dev/network');
  await page.getByRole('region', { name: '受保护站点配置' }).waitFor();
  await page.getByText('正在读取站点配置…').waitFor({ state: 'hidden' });
  assert.equal(await page.getByText('INVALID_RESPONSE', { exact: false }).count(), 0);
  await expect.poll(() => responses.some(r => r.path === '/control/v1/sites/site_dev/config' && r.status === 200)).toBeTruthy();
  await page.getByRole('link', { name: '权限中心', exact: true }).click();
  await page.getByRole('heading', { name: '当前管理会话', exact: true }).waitFor();
  assert((await page.locator('main').innerText()).includes('system_admin'));
  await page.getByRole('link', { name: '受保护站点', exact: true }).click();
  await page.getByText('正在读取站点列表…').waitFor({ state: 'hidden' });
  await page.setViewportSize({ width: 390, height: 844 });
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false);
  assert.equal(await page.locator('vite-error-overlay').count(), 0);
  await page.screenshot({ path: screenshots + '/sites-mobile.png', fullPage: true });
  assert.deepEqual(errors, []);
  assert.equal(unexpectedConsoleMessages, 0, "Unexpected browser console warnings/errors");
  console.log(JSON.stringify({ passed: true, title: await page.title(), viewports: ['1440x1000', '390x844'], responses, screenshots }, null, 2));
} finally { await browser.close(); }
