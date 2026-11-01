// Shell wiring: top bar, navigation, command palette (docs/06 6.3.3), shortcuts (6.3.4), theme, login, first render.
'use strict';
(function () {
  const X = window.X; const M = X.M; const { $, $$, h, esc } = X; const go = (hash) => X.go(hash);

  // ---------------------------------------------------------------- site scope + navigation chips
  X.renderSiteSelect = () => {
    const sel = $('#site-select'); const cur = X.state.site; sel.innerHTML = '';
    sel.appendChild(h('<option value="all">全部站点</option>'));
    X.sites.forEach((s) => sel.appendChild(h(`<option value="${esc(s.name)}">${esc(s.name)}（${s.mode === 'enforce' ? '拦截' : '观察'}）</option>`)));
    sel.value = X.sites.some((s) => s.name === cur) || cur === 'all' ? cur : 'all';
  };
  X.updateModes = () => {
    const o = X.sites.filter((s) => s.mode === 'observe').length; const e = X.sites.filter((s) => s.mode === 'enforce').length;
    $('#modes').innerHTML = `<a class="chip" href="#/sites" title="观察模式的站点">观察 ${o}</a><a class="chip" href="#/sites" title="拦截模式的站点">拦截 ${e}</a>`;
  };
  const baseRender = X.render;
  X.render = function () { baseRender(); X.renderSiteSelect(); X.updateModes(); };
  $('#site-select').onchange = (e) => { X.state.site = e.target.value; X.render(); };
  $$('.nav-item[data-href]').forEach((b) => { b.onclick = () => go(b.dataset.href); });
  $('#nav-toggle').onclick = () => { $('#app').classList.toggle('nav-collapsed'); };
  $('#search-box').onclick = () => openPalette();
  $('#light-gw').onclick = (e) => X.openGatewayPopover(e.currentTarget);
  $('#light-jev').onclick = (e) => X.openJevPopover(e.currentTarget);
  $('#help-btn').onclick = () => openShortcuts();
  $('#logout-btn').onclick = () => showLogin();

  // ---------------------------------------------------------------- theme
  const THEMES = ['system', 'light', 'dark']; const THEME_LABEL = { system: '跟随系统', light: '浅色', dark: '深色' }; let themeIdx = 0;
  function applyTheme(t) {
    if (t === 'system') document.documentElement.removeAttribute('data-theme'); else document.documentElement.setAttribute('data-theme', t);
    $('#theme-toggle').textContent = `主题：${THEME_LABEL[t]}`;
  }
  X.setTheme = (t) => { themeIdx = Math.max(0, THEMES.indexOf(t)); applyTheme(THEMES[themeIdx]); };
  $('#theme-toggle').onclick = () => { themeIdx = (themeIdx + 1) % THEMES.length; applyTheme(THEMES[themeIdx]); };
  applyTheme('system');

  // ---------------------------------------------------------------- login (docs/06 6.4.1)
  function showLogin() {
    const root = $('#login-root'); $('#app').classList.add('hidden'); root.classList.remove('hidden'); root.innerHTML = '';
    root.appendChild(h(`<div class="login"><div class="box"><div class="logo"></div><h2 style="margin-bottom:14px">Xshield 控制台</h2>
      ${window.isSecureContext ? '' : '<div class="notice">控制台需要经 HTTPS 或 localhost 访问，否则浏览器不会保存登录状态。可以用 SSH 隧道把控制台端口转发到本机。</div>'}
      <div class="field"><input type="password" id="pw" placeholder="管理员口令" aria-label="管理员口令" autofocus></div><div class="inlinemsg err hidden" id="pwerr">口令不正确</div>
      <button type="button" class="btn primary" id="login-btn" style="width:100%">登录</button><div class="dim small" style="margin-top:10px">原型：任意口令都能登录</div></div></div>`));
    const ok = () => { root.classList.add('hidden'); $('#app').classList.remove('hidden'); X.render(); };
    $('#login-btn').onclick = ok; $('#pw').onkeydown = (e) => { if (e.key === 'Enter') ok(); };
    $('#pw').focus();
  }

  // ---------------------------------------------------------------- shortcuts dialog
  const SHORTCUTS = [
    ['⌘K / Ctrl+K', '命令面板', '全局'], ['/', '聚焦本页的筛选输入框', '列表页'], ['g 然后 o r s j c y', '跳到 总览、请求追溯、会话、Jev 调用、站点、系统', '全局'], ['j / k', '下一行 / 上一行，预览面板跟随', '列表、会话时间线'],
    ['回车', '打开选中行的详情', '列表'], ['Esc', '关闭预览面板、对话框；详情页返回列表并保持滚动位置', '全局'], ['[ / ]', '同一会话的上一个 / 下一个请求', '请求详情'], ['1–5', '切换详情页标签', '请求详情'],
    ['v', '循环切换 Jev 视图（结构化、JSON、原文、指令）', 'Jev 上下文'], ['c', '复制当前（或选中行的）请求 ID', '详情、列表'], ['l', '实时模式开关', '请求追溯'], ['⌘S / Ctrl+S', '打开保存对话框', '站点配置'], ['?', '快捷键帮助', '全局'],
  ];
  function openShortcuts() {
    const body = h(`<div class="kbdgrid">${SHORTCUTS.map(([k, d, s]) => `<div class="kbdrow"><span class="keys">${k.split(' / ').map((x) => `<kbd>${esc(x)}</kbd>`).join(' / ')}</span><span>${esc(d)}</span><span class="dim small">${esc(s)}</span></div>`).join('')}</div>`);
    const api = X.dialog('键盘快捷键', body, [X.btn('关闭', () => api.close(), 'primary')]);
  }
  X.openShortcuts = openShortcuts;

  // ---------------------------------------------------------------- command palette
  function openPalette(initial) {
    const prev = document.activeElement; const ov = h('<div class="overlay palette-ov"></div>');
    const box = h('<div class="palette" role="dialog" aria-modal="true" aria-label="命令面板"><input type="text" placeholder="粘贴请求 ID、会话、路径或站点名…  可以直接粘贴多个 ID" aria-label="命令面板输入" autocomplete="off" spellcheck="false"><div class="results" role="listbox"></div><div class="pfoot dim small">↑↓ 选择 · ⏎ 执行 · ⌘⏎ 在新标签页打开 · Esc 关闭</div></div>');
    ov.appendChild(box); document.body.appendChild(ov); const input = $('input', box); const results = $('.results', box); let items = []; let active = 0;
    const close = () => { ov.remove(); document.removeEventListener('keydown', onKey, true); X.dialogs = X.dialogs.filter((x) => x !== api); if (prev && prev.focus) prev.focus(); };
    const api = { close }; X.dialogs.push(api);
    const run = (it, newTab) => { close(); if (newTab && it.href) window.open(location.pathname + it.href, '_blank'); else it.run(); };
    const add = (group, title, sub, href, fn) => items.push({ group, title, sub, href, run: fn || (() => go(href)) });
    function build() {
      const v = input.value.trim(); items = []; const ids = [...new Set(v.match(/req_[0-9a-f]{32}/g) || [])];
      if (ids.length === 1) add('请求', `打开请求 …${ids[0].slice(-8)}`, M.RECORD_BY_ID[ids[0]] ? `${X.fmtTime(M.idTime(ids[0]), true)} · ${M.RECORD_BY_ID[ids[0]].method} ${M.RECORD_BY_ID[ids[0]].path}` : `${X.fmtTime(M.idTime(ids[0]), true)}（ID 里的时间）`, `#/requests/${ids[0]}`);
      else if (ids.length > 1) add('批量', `批量对照 ${ids.length} 个请求 ID`, '带入粘贴内容', null, () => X.openBatch(input.value));
      if (/^[0-9a-f]{16}$/.test(v)) add('会话', `打开会话 ${v}`, M.SESSIONS.find((s) => s.label === v) ? '时间线' : '当前范围内没有记录', `#/sessions/${v}`);
      let m;
      if ((m = v.match(/^(GET|POST|PUT|PATCH|DELETE|HEAD)\s+(\/\S*)$/i))) add('路径', `按方法和路径筛选 ${m[1].toUpperCase()} ${m[2]}`, '', `#/requests?q=${encodeURIComponent(`method:${m[1].toUpperCase()} path:${m[2]}`)}`);
      if (v.startsWith('/') && !/\s/.test(v)) {
        add('路径', `筛选路径 ${v}`, '', `#/requests?q=${encodeURIComponent(`path:${v}`)}`);
        const dir = `${v.split('/').slice(0, -1).join('/')}/*`; if (dir !== '/*' && !v.endsWith('*')) add('路径', `筛选路径前缀 ${dir}`, '', `#/requests?q=${encodeURIComponent(`path:${dir}`)}`);
        X.sites.forEach((s) => { const e = s.spec.entries.find((r) => X.matchRule(r, v)); const b = s.spec.bypass.find((r) => X.matchRule(r, v)); if (e) add('路径', `在 ${s.name} 中命中入口 ${e}`, '', `#/sites/${s.name}?tab=config&group=entries`); if (b) add('路径', `在 ${s.name} 中命中绕过 ${b}`, '', `#/sites/${s.name}?tab=config&group=bypass`); });
      }
      if (v) X.sites.filter((s) => s.name.includes(v.toLowerCase())).forEach((s) => { add('站点', `打开 ${s.name}`, `${s.mode === 'enforce' ? '拦截' : '观察'} · v${s.version}`, `#/sites/${s.name}`); add('站点', `${s.name} 的配置`, '', `#/sites/${s.name}?tab=config`); add('站点', `${s.name} 的调优建议`, '', `#/sites/${s.name}?tab=insights`); });
      if (v.includes(':') && !/^req_/.test(v)) { const r = X.parseDsl(v); if (r.errors.length) add('条件', `条件语法有误：${r.errors[0].msg}`, r.errors[0].tok, null, () => X.toast(r.errors[0].msg)); else add('条件', `按条件打开请求追溯：${v}`, `${X.filterRows(new URLSearchParams({ q: v })).rows.length} 条`, `#/requests?q=${encodeURIComponent(v)}`); }
      const lc = v.toLowerCase();
      const cmds = [['新建站点', '#/sites/new'], ['导入判定日志', '#/system?tab=import'], ['切换主题', null, () => $('#theme-toggle').click()], ['复制当前页链接', null, () => X.copy(location.href, '已复制当前页链接')], ['查看快捷键', null, () => openShortcuts()], ['批量对照', null, () => X.openBatch()]];
      cmds.forEach(([t, href, fn]) => { if (!v || t.includes(v)) add('命令', t, '', href, fn); });
      [['总览', '#/'], ['请求追溯', '#/requests'], ['会话', '#/sessions'], ['Jev 调用', '#/jev'], ['站点', '#/sites'], ['系统', '#/system']].forEach(([t, href]) => { if (!v || t.toLowerCase().includes(lc)) add('前往', t, '', href); });
      if (!v && X.recent.length) { X.recent.forEach((r) => add('最近', r.title, r.kind === 'request' ? '请求' : r.kind === 'session' ? '会话' : '站点', r.href)); }
      const order = ['请求', '批量', '会话', '路径', '站点', '条件', '最近', '命令', '前往']; items.sort((a, b) => order.indexOf(a.group) - order.indexOf(b.group)); items = items.slice(0, 14); active = 0; draw();
    }
    function draw() {
      results.innerHTML = ''; let g = '';
      items.forEach((it, i) => {
        if (it.group !== g) { g = it.group; results.appendChild(h(`<div class="pgroup">${esc(g)}</div>`)); }
        const r = h(`<div class="pres ${i === active ? 'active' : ''}" role="option" aria-selected="${i === active}"><span>${esc(it.title)}</span><span class="sub">${esc(it.sub || '')}</span></div>`);
        r.onclick = () => run(it); r.onmousemove = () => { if (active !== i) { active = i; $$('.pres', results).forEach((x, j) => { x.classList.toggle('active', j === i); x.setAttribute('aria-selected', String(j === i)); }); } }; results.appendChild(r);
      });
      if (!items.length) { results.appendChild(h('<div class="pgroup">没有匹配项</div>')); results.appendChild(h('<div class="dim small" style="padding:6px 14px 10px">路径以 / 开头（例如 /rest/basket/*，* 结尾为前缀）；请求 ID 以 req_ 开头；会话是 16 位十六进制；站点输入名字；条件例如 outcome:blocked。</div>')); }
      const a = $('.pres.active', results); if (a) a.scrollIntoView({ block: 'nearest' });
    }
    function onKey(e) {
      if (X.dialogs[X.dialogs.length - 1] !== api) return;
      if (e.key === 'Escape') { e.stopPropagation(); e.preventDefault(); close(); }
      else if (e.key === 'ArrowDown') { e.preventDefault(); active = Math.min(items.length - 1, active + 1); draw(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); active = Math.max(0, active - 1); draw(); }
      else if (e.key === 'Enter') { e.preventDefault(); if (items[active]) run(items[active], e.metaKey || e.ctrlKey); }
    }
    document.addEventListener('keydown', onKey, true);
    ov.addEventListener('mousedown', (e) => { if (e.target === ov) close(); });
    input.oninput = build; if (initial) input.value = initial; build(); input.focus();
  }
  X.openPalette = openPalette;

  // ---------------------------------------------------------------- global keys
  let gPending = false;
  document.addEventListener('keydown', (e) => {
    const mod = e.metaKey || e.ctrlKey;
    if (mod && e.key.toLowerCase() === 'k') { e.preventDefault(); if (!X.dialogs.length) openPalette(); return; }
    if (mod && e.key.toLowerCase() === 's') { if (X.saveShortcut) { e.preventDefault(); X.saveShortcut(); } return; }
    if (X.dialogs.length || X._pop) return;
    const t = e.target; const typing = t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable);
    if (typing) { if (e.key === 'Escape') t.blur(); return; }
    if (e.altKey || mod) return;
    if (e.key === '?') { openShortcuts(); return; }
    if (gPending) { gPending = false; const m = { o: '#/', r: '#/requests', s: '#/sessions', j: '#/jev', c: '#/sites', y: '#/system' }[e.key]; if (m) go(m); return; }
    if (e.key === 'g') { gPending = true; setTimeout(() => { gPending = false; }, 900); return; }
    const fn = X.pageKeys[e.key]; if (fn) fn(e);
  });

  // ---------------------------------------------------------------- start
  window.addEventListener('hashchange', () => X.render());
  setInterval(() => X.renderLights(), 15000);
  X.renderSiteSelect(); X.renderLights(); X.render();
})();
