// Sites (list, new site, detail with draft editing), version history, mode switch, quick rules and the system page.
'use strict';
(function () {
  const X = window.X; const M = X.M; const { $, $$, h, esc, n, pct, safeText } = X; const go = (hash) => X.go(hash); const btn = X.btn;
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const PARAM = M.SYSTEM.params.site_overridable;
  X.drafts = {}; X.yamlText = {}; const ignored = {};
  const draftOf = (s) => (X.drafts[s.name] || (X.drafts[s.name] = clone(s.spec)));
  const isDirty = (s) => !!X.drafts[s.name] && JSON.stringify(X.drafts[s.name]) !== JSON.stringify(s.spec);
  const changesOf = (s) => (isDirty(s) ? X.diffSpec(s.spec, X.drafts[s.name]) : []);
  const sessName = (sp) => (sp.header ? `请求头 ${sp.header}` : `Cookie ${sp.cookie}`);
  const modeName = (m) => (m === 'observe' ? '观察模式' : '拦截模式');

  // ---------------------------------------------------------------- evidence + impact (all computed from the sample data)
  const overMs = (hist, ms) => hist.reduce((a, c, i) => a + (i * 100 >= ms ? c : 0), 0);
  const tplOf = (p) => p.replace(/\/\d+(?=\/|$)/g, '/{id}').replace(/\/[0-9a-f]{16,}(?=\/|$)/g, '/{id}');
  const HITS = {
    emr: { '/login': [120, '21:16'], '/api/home': [90, '21:15'], '/api/patients': [240, '21:16'], '/static/*': [410, '21:17'], '/favicon.ico': [12, '20:58'] },
    juice: { '/rest/user/login': [41, '21:05'], '/api/Products': [1204, '21:16'], '/rest/products/search': [88, '21:12'], '/assets/*': [892, '21:17'], '/favicon.ico': [12, '21:11'] },
  };
  function ruleImpact(s, rule, kind) {
    const sg = (M.INSIGHTS[s.name] || { suggestions: [] }).suggestions.find((x) => (x.action.add_entry || x.action.add_bypass) === rule);
    const recs = M.RECORDS.filter((r) => r.site === s.name && X.matchRule(rule, r.path));
    if (kind === 'entry') { const c = sg ? sg.count : recs.filter((r) => r.decision_path === 'no_session').length; return { count: c, text: c ? `${c} 个无会话请求改为按入口判定` : '最近 24 小时没有无会话请求命中这条规则', sample: sg ? sg.path : (recs[0] && recs[0].path) }; }
    const judged = recs.filter((r) => r.decision_path !== 'bypass'); const wb = judged.filter((r) => r.outcome === 'would_block' || r.outcome === 'blocked').length;
    return { count: judged.length, text: judged.length ? `${judged.length} 个原本判定的请求不再判定，其中本应拦截或已拦截 ${wb} 个` : '没有原本判定的请求受影响', sample: recs[0] && recs[0].path };
  }
  function evidenceFor(s) { return M.EVIDENCE[s.name] || { jev: { p50_ms: 0, p95_ms: 0, p99_ms: 0, timeouts: 0, calls: 0, timeout_ms_used: 2000 }, call_limit: { session_peak: 0, address_peak: 0, session_hits: 0, address_hits: 0 }, cache: { cached_allows: 0 }, histogram: [] }; }
  function impactLines(s, a, b) {
    const lines = []; const ev = evidenceFor(s); const A = a.advanced || {}; const B = b.advanced || {};
    b.entries.filter((p) => !a.entries.includes(p)).forEach((p) => { const i = ruleImpact(s, p, 'entry'); lines.push({ w: false, text: `入口 ＋ ${p}：${i.text}`, sample: i.sample }); });
    a.entries.filter((p) => !b.entries.includes(p)).forEach((p) => lines.push({ w: true, text: `入口 − ${p}：没有会话时该路径改为“无会话”处理` }));
    b.bypass.filter((p) => !a.bypass.includes(p)).forEach((p) => { const i = ruleImpact(s, p, 'bypass'); lines.push({ w: i.count > 0, text: `绕过 ＋ ${p}：${i.text}` }); });
    a.bypass.filter((p) => !b.bypass.includes(p)).forEach((p) => lines.push({ w: false, text: `绕过 − ${p}：${p} 的请求改为判定` }));
    if ((B.jev_timeout_ms ?? PARAM.jev_timeout_ms) !== (A.jev_timeout_ms ?? PARAM.jev_timeout_ms)) {
      const T = B.jev_timeout_ms ?? PARAM.jev_timeout_ms; const cur = A.jev_timeout_ms ?? PARAM.jev_timeout_ms;
      if (!ev.jev.calls) lines.push({ w: false, text: `Jev 超时 → ${T} ms：最近 24 小时没有 Jev 调用，无法预估` });
      else if (T >= cur) lines.push({ w: false, text: `Jev 超时 → ${T} ms：过去 24 小时有 ${ev.jev.timeouts} 次超时的调用可能不再超时` });
      else lines.push({ w: true, text: `Jev 超时 → ${T} ms：过去 24 小时有 ${overMs(ev.histogram, T)} 次调用会超时（现在 ${overMs(ev.histogram, cur)} 次）` });
    }
    [['session_calls_per_minute', '会话调用上限', 'session_peak'], ['address_calls_per_minute', '地址调用上限', 'address_peak']].forEach(([k, label, pk]) => {
      if ((B[k] ?? PARAM[k]) !== (A[k] ?? PARAM[k])) { const V = B[k] ?? PARAM[k]; lines.push({ w: V < ev.call_limit[pk], text: `${label} → ${V} 次/分钟：过去 24 小时最高 ${ev.call_limit[pk]} 次/分钟，${V < ev.call_limit[pk] ? '会触发上限' : '没有超过'}` }); }
    });
    if ((B.allow_cache_minutes ?? PARAM.allow_cache_minutes) !== (A.allow_cache_minutes ?? PARAM.allow_cache_minutes)) { const V = B.allow_cache_minutes ?? PARAM.allow_cache_minutes; lines.push({ w: V === 0, text: V === 0 ? '放行缓存 → 0：每个未核验的请求都会调用 Jev' : `放行缓存 → ${V} 分钟：过去 24 小时的 ${ev.cache.cached_allows} 次缓存放行按新时长重新评估` }); }
    (B.secret_fields || []).filter((w) => !(A.secret_fields || []).includes(w)).forEach((w) => { const k = (w.length * 7) % 11 + 3; lines.push({ w: false, text: `追加脱敏词 ${w}：过去 24 小时有 ${k} 次 Jev 调用、${k + 4} 个值会被脱敏（示意）` }); });
    if (JSON.stringify(A.synonyms || []) !== JSON.stringify(B.synonyms || [])) lines.push({ w: true, text: '同义词改变核验结果，无法从历史记录预估影响，保存后请观察一段时间' });
    if (JSON.stringify(a.session) !== JSON.stringify(b.session)) lines.push({ w: true, text: '修改会话凭证后，现有会话的上下文全部作废，用户需要重新从入口进入' });
    if (a.on_jev_unavailable !== b.on_jev_unavailable) lines.push({ w: b.on_jev_unavailable === 'allow', text: b.on_jev_unavailable === 'allow' ? 'Jev 不可用时改为放行：请求不经判定直接放行，记录标为“未经判定”' : 'Jev 不可用时改为拒绝：Jev 超时或出错的请求会被拦截' });
    return lines;
  }
  X.impactLines = impactLines;

  // ---------------------------------------------------------------- commit a new version
  // build(spec) returns the new saved spec; it is also applied to an open draft so unsaved edits are kept.
  X.commit = (s, build, o = {}) => {
    const next = build(clone(s.spec)); const wasDraft = o.fromDraft;
    s.version += 1; s.saved_at = X.now(); s.spec = clone(next); s.mode = next.mode;
    s.versions.unshift({ version: s.version, at: s.saved_at, change: o.change || 'update', note: o.note || '', spec: clone(next) });
    if (wasDraft) delete X.drafts[s.name]; else if (X.drafts[s.name] && !o.dropDraft) X.drafts[s.name] = build(X.drafts[s.name]); else if (o.dropDraft) delete X.drafts[s.name];
    delete X.yamlText[s.name];
    X.simulateRollout(s, o.stuck ? 'edge-2' : null); X.refreshRollout();
    return s.version;
  };

  // ---------------------------------------------------------------- sites list
  X.route((p) => p[0] === 'sites' && !p[1], (page) => {
    page.appendChild(X.pageHead('站点', `${X.sites.length} 个站点`, [btn('新建站点', () => go('#/sites/new'), 'primary')]));
    const tbl = h('<div class="tablewrap"><table class="data"><thead><tr><th>名称</th><th>Host</th><th>源站</th><th>模式</th><th>版本 · 生效进度</th><th>24h 请求</th><th>拦截 / 本应拦截</th><th>Jev 调用</th><th>建议</th></tr></thead><tbody></tbody></table></div>');
    X.sites.forEach((s) => {
      const days = s.observing_since ? Math.floor((X.now() - s.observing_since) / 86400000) : 0;
      const tr = h(`<table><tbody><tr><td><b>${esc(s.name)}</b></td><td class="mono">${esc(s.hosts.join(', '))}</td><td class="mono">${esc(s.origin)}</td><td>${s.mode === 'observe' ? `观察 ${days} 天` : '拦截'}</td><td data-rollout="${esc(s.name)}">${X.rolloutHtml(s)}</td>
        <td class="tnum">${n(s.requests_24h)}</td><td class="tnum">${s.mode === 'observe' ? `${s.would_block_24h} 本应` : s.blocked_24h}</td><td class="tnum">${n(s.jev_calls_24h)}</td><td class="tnum">${s.suggestions || '—'}</td></tr></tbody></table>`).querySelector('tr');
      tr.onclick = () => go(`#/sites/${s.name}`); $('tbody', tbl).appendChild(tr);
    });
    page.appendChild(tbl);
    page.appendChild(h('<div class="dim small tfoot">生效进度读取 /api/sites 的 rollout：网关每 5 秒轮询配置，保存后通常 1–6 秒内全部在线网关加载完成。</div>'));
  });

  // ---------------------------------------------------------------- new site (single page P0, docs/06 6.4.8)
  X.route((p) => p[0] === 'sites' && p[1] === 'new', (page) => {
    page.appendChild(X.pageHead('新建站点', '', [btn('← 站点', () => go('#/sites'))]));
    const spec = { name: '', hosts: [], origin: '', session: { cookie: 'SESSIONID' }, entries: ['/login'], bypass: ['/static/*', '/favicon.ico'], mode: 'observe', on_jev_unavailable: 'deny', advanced: {} };
    const lay = h('<div class="newsite"><div class="card form"></div><div class="card"><div class="card-head"><h2>配置预览（YAML）</h2><button type="button" class="linkbtn" id="fromy">从 YAML 创建</button></div><pre class="codeblock" id="ypre"></pre><textarea id="yin" class="mono hidden" rows="16" spellcheck="false"></textarea><div id="yerr" class="dslerr hidden"></div></div></div>');
    const form = $('.form', lay); let yamlMode = false;
    const f = (id, label, ph, hint) => `<div class="field"><label for="${id}">${label}</label><input type="text" id="${id}" placeholder="${esc(ph)}" autocomplete="off">${hint ? `<div class="hint">${hint}</div>` : ''}</div>`;
    form.appendChild(h(`<div>${f('ns-name', '站点名', 'shop', '小写字母、数字、-、_，最长 64；创建后不能改名')}${f('ns-hosts', 'Host（逗号分隔）', 'shop.example.com', '网关按 Host 头把请求分配到站点')}${f('ns-origin', '源站地址', 'http://10.0.0.7:8080', '不带路径')}
      <div class="field"><label>会话凭证</label><div class="radio-seg"><label><input type="radio" name="sk" value="cookie" checked> Cookie</label><label><input type="radio" name="sk" value="header"> 请求头</label></div><input type="text" id="ns-sess" value="SESSIONID" style="margin-top:6px"><div class="taglist" style="margin-top:6px">${['JSESSIONID', 'SESSIONID', 'connect.sid', 'token', 'Authorization'].map((x) => `<button type="button" class="tag pick">${x}</button>`).join('')}</div><div class="hint">登录后浏览器每次都带给源站的那个凭证</div></div>
      <div class="field"><label for="ns-entries">入口（每行一条）</label><textarea id="ns-entries" rows="3" class="mono">/login</textarea><div class="hint">登录、首页、起始列表、分享兑换接口。<button type="button" class="linkbtn" id="preset-e">常见登录路径</button></div></div>
      <div class="field"><label for="ns-bypass">绕过（每行一条）</label><textarea id="ns-bypass" rows="3" class="mono">/static/*\n/favicon.ico</textarea><div class="hint"><button type="button" class="linkbtn" id="preset-b">常见静态资源</button></div></div>
      <div class="notice soft">模式默认观察（推荐）：先只记录“本应拦截”，调好入口和绕过后再切换到拦截模式。高级判定参数全部使用默认值，创建后可调整。</div><div id="ns-err" class="dslerr hidden" role="alert"></div></div>`));
    const lines = (v) => v.split('\n').map((x) => x.trim()).filter(Boolean);
    const collect = () => {
      const kind = $('input[name=sk]:checked', form).value; const nm = $('#ns-sess', form).value.trim();
      return { name: $('#ns-name', form).value.trim(), hosts: $('#ns-hosts', form).value.split(',').map((x) => x.trim()).filter(Boolean), origin: $('#ns-origin', form).value.trim(), session: kind === 'cookie' ? { cookie: nm } : { header: nm }, entries: lines($('#ns-entries', form).value), bypass: lines($('#ns-bypass', form).value), mode: 'observe', on_jev_unavailable: 'deny', advanced: {} };
    };
    const refresh = () => { if (yamlMode) return; Object.assign(spec, collect()); $('#ypre', lay).textContent = X.specToYaml(spec); };
    form.addEventListener('input', refresh); form.addEventListener('change', refresh);
    $$('.pick', form).forEach((b) => { b.onclick = () => { $('#ns-sess', form).value = b.textContent; $('input[name=sk][value=' + (b.textContent === 'Authorization' || b.textContent === 'token' ? 'header' : 'cookie') + ']', form).checked = true; refresh(); }; });
    $('#preset-e', form).onclick = () => { $('#ns-entries', form).value = ['/login', '/api/login', '/rest/user/login'].join('\n'); refresh(); };
    $('#preset-b', form).onclick = () => { $('#ns-bypass', form).value = ['/static/*', '/assets/*', '/favicon.ico'].join('\n'); refresh(); };
    $('#fromy', lay).onclick = () => { yamlMode = !yamlMode; $('#ypre', lay).classList.toggle('hidden', yamlMode); $('#yin', lay).classList.toggle('hidden', !yamlMode); $('#fromy', lay).textContent = yamlMode ? '返回表单' : '从 YAML 创建'; if (yamlMode) $('#yin', lay).value = X.specToYaml(spec.name ? spec : Object.assign(spec, { name: 'shop', hosts: ['shop.example.com'], origin: 'http://10.0.0.7:8080' })); };
    page.appendChild(lay); refresh();
    const create = () => {
      let sp = spec; const err = $('#ns-err', form);
      if (yamlMode) { const r = X.parseYaml($('#yin', lay).value); if (r.error) { $('#yerr', lay).classList.remove('hidden'); $('#yerr', lay).textContent = `YAML 第 ${r.error.line} 行有错误：${r.error.msg}`; return; } sp = r.spec; $('#yerr', lay).classList.add('hidden'); } else sp = collect();
      const v = X.validateSpec(sp); if (X.site(sp.name)) v.errors.unshift({ msg: '已有同名站点' });
      const clash = X.sites.find((s) => s.hosts.some((x) => sp.hosts.includes(x))); if (clash) v.errors.unshift({ msg: `Host ${sp.hosts.find((x) => clash.hosts.includes(x))} 已属于其他站点 ${clash.name}` });
      if (v.errors.length) { err.classList.remove('hidden'); err.innerHTML = v.errors.map((e) => esc(e.msg)).join('<br>'); return; } err.classList.add('hidden');
      const s = { name: sp.name, mode: 'observe', hosts: sp.hosts, origin: sp.origin, version: 1, saved_at: X.now(), observing_since: X.now(), requests_24h: 0, blocked_24h: 0, would_block_24h: 0, jev_calls_24h: 0, suggestions: 0, spec: clone(sp), versions: [{ version: 1, at: X.now(), change: 'create', note: '', spec: clone(sp) }] };
      X.sites.push(s); M.INSIGHTS[s.name] = { window_hours: 24, suggestions: [], readiness: null }; X.loaded[s.name] = {}; M.SYSTEM.edges.forEach((e) => { X.loaded[s.name][e.edge] = 0; }); X.simulateRollout(s); X.renderSiteSelect && X.renderSiteSelect();
      X.justCreated = s.name; go(`#/sites/${s.name}`);
    };
    const bar = h('<div class="draftbar"><span class="n">填写后创建 v1</span><span class="sp"></span></div>'); bar.appendChild(btn('取消', () => go('#/sites'))); bar.appendChild(btn('创建站点', create, 'primary')); page.appendChild(bar);
  });

  // ---------------------------------------------------------------- site detail
  X.route((p) => p[0] === 'sites' && p[1] && p[1] !== 'new', (page, parts, q) => {
    const name = parts[1]; const s = X.site(name);
    page.appendChild(X.pageHead(`站点 ${name}`, '', [btn('← 站点', () => go('#/sites'))]));
    if (!s) { page.appendChild(h('<div class="empty"><div class="big">站点不存在</div><div class="dim">站点不存在，可能已被删除</div></div>')); return; }
    X.rememberRecent('site', name);
    if (X.justCreated === name) { page.appendChild(h('<div class="notice ok">已创建 v1。下一步：把 Host 解析到网关；用浏览器走一遍正常流程，再回到“请求追溯”查看。</div>')); X.justCreated = null; }
    const tab = q.get('tab') || 'overview'; const dirtyN = changesOf(s).length;
    const days = s.observing_since ? Math.floor((X.now() - s.observing_since) / 86400000) : 0;
    const head = h(`<div class="card sitehead"><div><b style="font-size:16px">${esc(s.name)}</b> <span class="pill ${s.mode === 'enforce' ? 'blocked' : 'would_block'}"><span class="g ${s.mode === 'enforce' ? 'blocked' : 'would_block'}">${s.mode === 'enforce' ? '■' : '▲'}</span>${s.mode === 'enforce' ? '拦截模式' : `观察模式（${days} 天）`}</span>
      <span class="ro-line" data-rollout="${esc(s.name)}">${X.rolloutHtml(s)}</span><div class="muted small">${esc(s.hosts.join(', '))} → ${esc(s.origin)}</div></div><div class="sh-act"></div></div>`);
    const act = $('.sh-act', head);
    act.appendChild(btn(s.mode === 'enforce' ? '切回观察模式…' : '切换到拦截模式…', () => X.openModeSwitch(name)));
    const more = btn('更多 ▾', null, 'sm'); more.setAttribute('aria-label', '更多操作'); more.onclick = (e) => {
      const box = h('<div class="menu"></div>'); const it = (l, f, c) => { const b = h(`<button type="button" class="menuitem ${c || ''}">${esc(l)}</button>`); b.onclick = () => { X.closePopover(); f(); }; box.appendChild(b); };
      it('复制为新站点', () => X.toast('原型：会带着当前配置进入“新建站点”'));
      it('导出配置（YAML）', () => X.copy(X.specToYaml(s.spec), '已复制 YAML')); it('导出配置（JSON）', () => X.copy(JSON.stringify(s.spec, null, 2), '已复制 JSON'));
      it('删除站点…', () => X.toast('原型不删除站点'), 'danger'); X.popover(e.currentTarget, box, { right: true });
    }; act.appendChild(more); page.appendChild(head);
    const tabs = h('<div class="tabs" role="tablist"></div>');
    [['overview', '概览'], ['config', `配置${dirtyN ? ' ●' : ''}`], ['insights', `调优建议${(M.INSIGHTS[name] || { suggestions: [] }).suggestions.length ? ` ${(M.INSIGHTS[name]).suggestions.length}` : ''}`], ['history', '变更历史']].forEach(([k, l]) => {
      const t = h(`<button type="button" class="tab ${tab === k ? 'active' : ''}" role="tab" aria-selected="${tab === k}">${esc(l)}</button>`); t.onclick = () => go(`#/sites/${name}?tab=${k}`); tabs.appendChild(t);
    });
    if (dirtyN && tab !== 'config') tabs.appendChild(h(`<span class="draftflag">未保存的改动 ${dirtyN} 处 · <a href="#/sites/${esc(name)}?tab=config">继续编辑</a></span>`));
    page.appendChild(tabs); const body = h('<div></div>'); page.appendChild(body);
    if (tab === 'overview') siteOverview(body, s); else if (tab === 'config') siteConfig(body, s, q, page); else if (tab === 'insights') siteInsights(body, s); else if (tab === 'history') siteHistory(body, s, q);
  });

  function siteOverview(body, s) {
    const ev = evidenceFor(s); const tiles = h('<div class="tiles" style="margin-bottom:16px"></div>');
    [['24h 请求', n(s.requests_24h)], [s.mode === 'observe' ? '本应拦截' : '拦截', s.mode === 'observe' ? s.would_block_24h : s.blocked_24h], ['Jev 调用', s.jev_calls_24h], ['待处理建议', (M.INSIGHTS[s.name] || { suggestions: [] }).suggestions.length]].forEach(([k, v]) => tiles.appendChild(h(`<div class="tile"><div class="k">${esc(k)}</div><div class="v tnum">${esc(v)}</div></div>`)));
    body.appendChild(tiles);
    const top = {}; M.RECORDS.filter((r) => r.site === s.name && ['would_block', 'blocked'].includes(r.outcome)).forEach((r) => { const t = tplOf(r.path); top[t] = (top[t] || 0) + 1; });
    const topRows = Object.entries(top).sort((a, b) => b[1] - a[1]);
    const row = h('<div class="grid" style="grid-template-columns:1fr 1fr;align-items:start"></div>');
    row.appendChild(h(`<div class="card"><h2>${s.mode === 'observe' ? '本应拦截' : '拦截'}最多的路径模板</h2>${topRows.length ? topRows.map(([t, c]) => `<div class="r-item"><a class="mono" href="#/requests?q=${encodeURIComponent(`site:${s.name} path:${t.replace(/\{id\}.*/, '')}*`)}">${esc(t)}</a> <span class="dim">${c}</span></div>`).join('') : '<div class="dim">最近 24 小时没有</div>'}<div class="dim small" style="margin-top:6px">数字、十六进制、UUID 段替换为 {id}（样例记录）</div></div>`));
    row.appendChild(h(`<div class="card"><h2>Jev 证据摘要（最近 24 小时）</h2>${ev.jev.calls ? `<div class="muted" style="line-height:1.8">p50 / p95 / p99：${ev.jev.p50_ms} / ${ev.jev.p95_ms} / ${ev.jev.p99_ms} ms<br>超时 ${ev.jev.timeouts} 次 / ${ev.jev.calls} 次调用（超时设置 ${ev.jev.timeout_ms_used} ms）<br>缓存放行 ${ev.cache.cached_allows} 次<br>调用上限触发：会话 ${ev.call_limit.session_hits} 次 · 地址 ${ev.call_limit.address_hits} 次</div>` : '<div class="dim">最近 24 小时没有 Jev 调用</div>'}</div>`));
    body.appendChild(row);
    if (s.mode === 'observe' && M.INSIGHTS[s.name] && M.INSIGHTS[s.name].readiness) { const rd = M.INSIGHTS[s.name].readiness; const c = h(`<div class="card" style="margin-top:16px"><div class="card-head"><h2>就绪检查摘要</h2></div><div class="muted">本应拦截 ${rd.would_block.jev_deny + rd.would_block.no_session} 条（Jev 拒绝 ${rd.would_block.jev_deny}、无会话 ${rd.would_block.no_session}）· 待处理建议 ${rd.open_suggestions} 条 · Jev ${rd.jev_health === 'ok' ? '正常' : rd.jev_health}</div></div>`); c.querySelector('.card-head').appendChild(btn('就绪检查…', () => X.openModeSwitch(s.name), 'sm')); body.appendChild(c); }
  }

  // ---------------------------------------------------------------- config tab (draft model)
  const GROUPS = [['basic', '基本信息'], ['session', '会话凭证'], ['entries', '入口'], ['bypass', '绕过'], ['mode', '模式与 Jev 不可用'], ['advanced', '高级判定参数']];
  function siteConfig(body, s, q, page) {
    const edit = q.get('edit') || 'form'; const group = q.get('group') || 'basic'; const d = draftOf(s);
    const dirty = isDirty(s); const val = X.validateSpec(d); const errGroups = new Set(val.errors.map((e) => e.group));
    const bar = h('<div class="cfgbar"><div class="tabs seg" role="tablist"><button type="button" class="tab" id="tf">表单</button><button type="button" class="tab" id="ty">YAML</button></div></div>');
    $('#tf', bar).classList.toggle('active', edit === 'form'); $('#ty', bar).classList.toggle('active', edit === 'yaml');
    $('#tf', bar).onclick = () => { if (edit === 'yaml' && yamlErr) { X.toast(`YAML 第 ${yamlErr.line} 行有错误，修好后才能切回表单`); return; } X.setQuery({ edit: 'form', group }); };
    $('#ty', bar).onclick = () => X.setQuery({ edit: 'yaml' }); body.appendChild(bar);
    let yamlErr = null;
    const draftBar = h('<div class="draftbar hidden" role="region" aria-label="未保存的改动"><span class="n"></span><span class="sp"></span></div>');
    const dbN = $('.n', draftBar);
    const updateBar = () => {
      const ch = changesOf(s); const v = X.validateSpec(X.drafts[s.name]); draftBar.classList.toggle('hidden', !ch.length && !yamlErr);
      dbN.innerHTML = `未保存的改动 ${ch.length} 处${v.errors.length ? ` · <span class="lvl-serious">■</span> ${v.errors.length} 处错误` : ''}${yamlErr ? ` · YAML 第 ${yamlErr.line} 行有错误` : ''}`;
      $$('.cfg-nav button', body).forEach((b) => { const g = b.dataset.g; b.classList.toggle('err', v.errors.some((e) => e.group === g)); });
      const tabEl = $$('.tab', page.querySelector('.tabs')).find((t) => t.textContent.startsWith('配置')); if (tabEl) tabEl.textContent = `配置${ch.length ? ' ●' : ''}`;
    };
    const trySave = () => {
      if (yamlErr) { X.toast(`YAML 第 ${yamlErr.line} 行有错误：${yamlErr.msg}`); return; }
      const v = X.validateSpec(X.drafts[s.name]);
      if (v.errors.length) { const e = v.errors[0]; X.toast(e.msg); if (edit === 'form' && group !== e.group) X.setQuery({ group: e.group }); return; }
      if (changesOf(s).length) X.openSaveDialog(s); else X.toast('没有未保存的改动');
    };
    X.saveShortcut = trySave;
    draftBar.appendChild(btn('查看差异', () => openDiffDialog(s), 'sm')); draftBar.appendChild(btn('放弃', () => { delete X.drafts[s.name]; delete X.yamlText[s.name]; X.toast('已放弃未保存的改动'); X.render(); }, 'sm'));
    draftBar.appendChild(btn('预估影响并保存 ⌘S', trySave, 'primary'));

    if (edit === 'yaml') {
      const card = h('<div class="card"><div class="card-head"><h2>YAML</h2><span class="dim small">YAML 只是编辑格式，保存的是 JSON，注释不会保留</span></div></div>');
      const ta = h('<textarea class="yamled mono" rows="22" spellcheck="false" aria-label="YAML 编辑"></textarea>'); ta.value = X.yamlText[s.name] ?? X.specToYaml(d);
      const msg = h('<div class="yamlmsg small"></div>'); card.appendChild(ta); card.appendChild(msg); body.appendChild(card);
      const check = () => {
        X.yamlText[s.name] = ta.value; const r = X.parseYaml(ta.value);
        if (r.error) { yamlErr = r.error; msg.className = 'yamlmsg small err'; msg.textContent = `第 ${r.error.line} 行：${r.error.msg}`; }
        else if (r.spec.name !== s.name) { yamlErr = { line: 1, msg: '配置里的站点名与地址中的不一致' }; msg.className = 'yamlmsg small err'; msg.textContent = '第 1 行：配置里的站点名与地址中的不一致'; }
        else { yamlErr = null; X.drafts[s.name] = r.spec; const v = X.validateSpec(r.spec); msg.className = `yamlmsg small ${v.errors.length ? 'err' : 'ok'}`; msg.textContent = v.errors.length ? v.errors.map((e) => e.msg).join('；') : '格式正确，已同步到草稿'; }
        updateBar();
      };
      let tm = null; ta.oninput = () => { clearTimeout(tm); tm = setTimeout(check, 250); }; check();
    } else {
      const layout = h('<div class="cfg-layout"></div>'); const nav = h('<div class="cfg-nav" role="tablist"></div>');
      const label = (g, l) => {
        if (g === 'entries') return `${l} ${d.entries.length}`; if (g === 'bypass') return `${l} ${d.bypass.length}`;
        if (g === 'advanced') { const c = Object.keys(d.advanced || {}).filter((k) => X.ADV_KEYS.includes(k) && (d.advanced[k] != null) && !(Array.isArray(d.advanced[k]) && !d.advanced[k].length)).length; return `${l}${c ? ` · 已自定义 ${c} 项` : ''}`; } return l;
      };
      GROUPS.forEach(([g, l]) => { const b = h(`<button type="button" class="${group === g ? 'active' : ''}" data-g="${g}" role="tab"><span>${esc(label(g, l))}</span><span class="reddot" aria-label="有错误"></span></button>`); b.onclick = () => X.setQuery({ group: g }); nav.appendChild(b); });
      const panel = h('<div class="cfg-panel"></div>'); layout.appendChild(nav); layout.appendChild(panel); body.appendChild(layout);
      const ctx = { s, d, panel, update: updateBar, rerender: () => { panel.innerHTML = ''; renderGroup(ctx, group); updateBar(); } };
      renderGroup(ctx, group);
    }
    body.appendChild(draftBar); updateBar();
  }
  const field = (label, inner, hint) => h(`<div class="field"><label>${label}</label>${inner}${hint ? `<div class="hint">${hint}</div>` : ''}</div>`);
  function tagEditor(list, o) {
    const box = h('<div class="taglist"></div>');
    (o.locked || []).forEach((w) => box.appendChild(h(`<span class="tag locked" title="内置词，不能删除">${esc(w)}</span>`)));
    list.forEach((w, i) => { const t = h(`<span class="tag">${esc(w)} <button type="button" aria-label="删除 ${esc(w)}">×</button></span>`); t.querySelector('button').onclick = () => { list.splice(i, 1); o.onChange(); }; box.appendChild(t); });
    const inp = h(`<input type="text" class="taginput" placeholder="${esc(o.placeholder || '＋ 添加')}" aria-label="${esc(o.placeholder || '添加')}" autocomplete="off">`);
    const add = () => { const v = inp.value.trim().replace(/,$/, ''); if (!v) return; const err = o.validate && o.validate(v, list); if (err) { o.onError(err); return; } list.push(v); o.onChange(); };
    inp.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ',') { e.preventDefault(); add(); } }; inp.onblur = () => { if (inp.value.trim()) add(); };
    box.appendChild(inp); return box;
  }
  function renderGroup(ctx, g) {
    const { s, d, panel } = ctx; const msg = h('<div class="inlinemsg hidden" role="alert"></div>'); const showErr = (t) => { msg.textContent = t; msg.classList.remove('hidden'); msg.classList.add('err'); };
    const ch = () => ctx.rerender();
    if (g === 'basic') {
      panel.appendChild(field('站点名（创建后只读，改名请复制为新站点）', `<input type="text" value="${esc(d.name)}" disabled>`));
      const hf = field('Host', ''); hf.appendChild(tagEditor(d.hosts, { placeholder: '＋ 添加 Host', onChange: ch, onError: showErr, validate: (v, l) => (!/^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(:\d+)?$/i.test(v) ? '请输入有效的主机名' : l.includes(v) ? '已添加过' : l.length >= 16 ? '最多 16 个' : X.sites.some((x) => x.name !== s.name && x.hosts.includes(v)) ? `Host ${v} 已属于其他站点` : null) })); panel.appendChild(hf);
      const of = field('源站地址', `<input type="text" id="origin" value="${esc(d.origin)}">`, 'http(s)://主机[:端口]，不带路径'); const oi = $('#origin', of);
      oi.oninput = () => { d.origin = oi.value.trim(); const v = X.validateSpec(d).errors.find((e) => e.field === 'origin'); oi.classList.toggle('bad', !!v); fm.textContent = v ? v.msg : ''; fm.classList.toggle('err', !!v); fm.classList.toggle('hidden', !v); ctx.update(); };
      const fm = h('<div class="inlinemsg hidden"></div>'); of.appendChild(fm); panel.appendChild(of);
    } else if (g === 'session') {
      const kind = d.session.header !== undefined && d.session.header !== null ? 'header' : 'cookie';
      const f = field('会话凭证', `<div class="radio-seg"><label><input type="radio" name="sk" value="cookie" ${kind === 'cookie' ? 'checked' : ''}> Cookie</label><label><input type="radio" name="sk" value="header" ${kind === 'header' ? 'checked' : ''}> 请求头</label></div><input type="text" id="sname" value="${esc(d.session.cookie || d.session.header || '')}" style="margin-top:6px" aria-label="凭证名称">
        <div class="taglist" style="margin-top:6px">${['JSESSIONID', 'SESSIONID', 'connect.sid', 'token', 'Authorization'].map((x) => `<button type="button" class="tag pick">${x}</button>`).join('')}</div>`, '登录后浏览器每次都带给源站的那个凭证');
      const upd = () => { const k = $('input[name=sk]:checked', f).value; const nm = $('#sname', f).value.trim(); d.session = k === 'cookie' ? { cookie: nm } : { header: nm }; warn.classList.toggle('hidden', JSON.stringify(d.session) === JSON.stringify(s.spec.session)); ctx.update(); };
      $$('input[name=sk]', f).forEach((r) => { r.onchange = upd; }); $('#sname', f).oninput = upd; $$('.pick', f).forEach((b) => { b.onclick = () => { $('#sname', f).value = b.textContent; $('input[name=sk][value=' + (/^(token|Authorization)$/.test(b.textContent) ? 'header' : 'cookie') + ']', f).checked = true; upd(); }; });
      const warn = h('<div class="notice hidden">修改会话凭证后，现有会话的上下文全部作废，用户需要重新从入口进入。</div>'); f.appendChild(warn); panel.appendChild(f); upd();
    } else if (g === 'entries' || g === 'bypass') {
      panel.appendChild(patternEditor(ctx, g, msg)); panel.appendChild(msg);
      const t = field('规则测试器', '<input type="text" id="tester" placeholder="输入一个路径，看它在当前草稿下命中哪条规则" aria-label="规则测试路径">', ''); const out = h('<div class="testout dim small"></div>'); t.appendChild(out); t.style.marginTop = '16px';
      $('#tester', t).oninput = (e) => { const p = e.target.value.trim(); if (!p) { out.textContent = ''; return; }
        if (X.oddPath(p)) { out.innerHTML = '含 <span class="mono">; // %2e %2f</span> 等写法的路径，网关不会把它匹配到任何入口或绕过（与 PathPattern 规则一致），按“需要会话”处理。'; return; }
        const b = d.bypass.find((r) => X.matchRule(r, p)); const en = d.entries.find((r) => X.matchRule(r, p));
        out.innerHTML = b ? `命中绕过 <span class="mono">${esc(b)}</span>：不判定，直接转发` : en ? `命中入口 <span class="mono">${esc(en)}</span>：没有会话也做攻击判定${s.spec.entries.includes(en) ? '' : '（草稿中新增的这一条）'}` : '没有命中入口或绕过：需要会话，没有会话会被记为“无会话”'; };
      panel.appendChild(t);
    } else if (g === 'mode') {
      panel.appendChild(field('模式', `<div>${modeName(s.mode)} · <button type="button" class="linkbtn" id="msw">切换…</button></div>`, '模式切换会立即保存为新版本，并先做就绪检查，所以不放在草稿里。'));
      $('#msw', panel).onclick = () => X.openModeSwitch(s.name);
      const f = field('Jev 不可用时', `<div class="radio-seg"><label><input type="radio" name="jevun" value="deny" ${d.on_jev_unavailable === 'deny' ? 'checked' : ''}> 拒绝（推荐）</label><label><input type="radio" name="jevun" value="allow" ${d.on_jev_unavailable === 'allow' ? 'checked' : ''}> 放行</label></div>`, 'Jev 超时、出错、调用达到上限或答不上来时怎么处理请求。');
      const warn = h(`<div class="notice ${d.on_jev_unavailable === 'allow' ? '' : 'hidden'}">Jev 不可用时请求不经判定直接放行，记录标为“未经判定”。</div>`); f.appendChild(warn);
      $$('input[name=jevun]', f).forEach((r) => { r.onchange = () => { d.on_jev_unavailable = r.value; warn.classList.toggle('hidden', r.value !== 'allow'); ctx.update(); }; }); panel.appendChild(f);
    } else advancedParams(ctx);
  }
  function patternEditor(ctx, key, msg) {
    const { s, d } = ctx; const hits = HITS[s.name] || {}; const wrap = h('<div></div>'); const kindName = key === 'entries' ? '入口' : '绕过';
    wrap.appendChild(h(`<div class="field"><label>${kindName}${key === 'entries' ? '（不需要事先有上下文即可访问，仍做攻击判定）' : '（不判定，只记一条简记录）'}</label></div>`));
    const list = h('<div class="rulelist" role="list"></div>');
    d[key].forEach((p, i) => {
      const isNew = !s.spec[key].includes(p); const hit = hits[p]; const imp = isNew ? ruleImpact(s, p, key === 'entries' ? 'entry' : 'bypass') : null;
      const wide = key === 'entries' && /\/\*$/.test(p) && p.split('/').length <= 3;
      const row = h(`<div class="rulerow ${isNew ? 'isnew' : ''}" role="listitem"><span class="mono">${esc(p)}</span><span class="hit">${isNew ? `新增 · ${esc(imp.text)}` : hit ? `${n(hit[0])} 命中 · 最近 ${hit[1]}` : '24 小时未命中'}</span><button type="button" class="btn sm" aria-label="删除 ${esc(p)}">删除</button></div>`);
      if (wide) row.appendChild(h('<div class="rowwarn">前缀入口会放大无会话可达的范围</div>'));
      if (isNew && key === 'bypass' && imp.count) row.appendChild(h(`<div class="rowwarn">这条绕过会让 ${esc(imp.text)}</div>`));
      row.querySelector('button').onclick = () => { d[key].splice(i, 1); ctx.rerender(); }; list.appendChild(row);
    });
    if (!d[key].length) list.appendChild(h(`<div class="rulerow dim">${key === 'entries' ? '入口至少一条' : '还没有绕过规则'}</div>`));
    wrap.appendChild(list);
    const add = h(`<div class="addrow"><input type="text" placeholder="添加${kindName}，例如 /rest/admin/*" aria-label="添加${kindName}"><button type="button" class="btn">添加</button></div>`); const inp = $('input', add);
    const doAdd = () => { const v = inp.value.trim(); if (!v) return; const err = !v.startsWith('/') ? '规则以 / 开头' : /[?#\s]/.test(v) ? '规则不能含查询串或空白' : v.slice(0, -1).includes('*') ? '* 只能在末尾' : v.split('/').some((x) => x === '.' || x === '..') ? '不能含 . 或 .. 段' : d[key].includes(v) ? '已有这条规则' : d[key].length >= 64 ? '最多 64 条' : null; if (err) { msg.textContent = err; msg.classList.remove('hidden'); msg.classList.add('err'); return; } d[key].push(v); ctx.rerender(); };
    inp.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); doAdd(); } }; $('button', add).onclick = doAdd; wrap.appendChild(add); return wrap;
  }

  const ADV = [
    { k: 'jev_timeout_ms', name: 'Jev 超时', unit: 'ms', lo: 100, hi: 30000, desc: '单次 Jev 调用最多等多久；超时按“Jev 不可用时”处理', cost: '调大：慢链路下超时变少，但被拖慢的请求最多多等这么久；调小：超时更多，这些请求按“Jev 不可用时”处理（默认拒绝）。' },
    { k: 'session_calls_per_minute', name: '会话调用上限', unit: '次/分钟', lo: 1, hi: 600, desc: '同一会话每分钟最多调用 Jev 的次数', cost: '调大：允许更多 Jev 调用，模型服务的费用和压力增加；调小：更早触发上限，超出的请求按“Jev 不可用时”处理。' },
    { k: 'address_calls_per_minute', name: '地址调用上限', unit: '次/分钟', lo: 1, hi: 600, desc: '未登录请求按客户端地址计，每个地址每分钟最多调用 Jev 的次数', cost: 'NAT 或代理后多个用户共用一个地址时需要调大；调大也会让扫描流量更多地消耗 Jev 调用。触发过上限时先看是不是未登录页面在轮询，登记入口或绕过通常更合适。' },
    { k: 'allow_cache_minutes', name: '放行缓存时长', unit: '分钟', lo: 0, hi: 60, desc: '同一会话相同请求被 Jev 放行后，多久内直接复用', cost: '调大：更少调用 Jev，但已放行的请求在期限内不会重新判定；0 表示不缓存，每个未核验的请求都调用 Jev。' },
  ];
  function advancedParams(ctx) {
    const { s, d, panel } = ctx; d.advanced = d.advanced || {}; const A = d.advanced; const ev = evidenceFor(s);
    const custom = ADV.filter((a) => A[a.k] != null).length + (A.secret_fields || []).length + (A.synonyms || []).length;
    const head = h(`<div class="advhead"><div><b>高级判定参数</b> <span class="dim">${custom ? `已自定义 ${ADV.filter((a) => A[a.k] != null).map((a) => `${a.name} ${A[a.k]} ${a.unit}`).concat((A.secret_fields || []).length ? [`追加脱敏词 ${A.secret_fields.length} 个`] : [], (A.synonyms || []).length ? [`同义词 ${A.synonyms.length} 组`] : []).join('、')}` : '全部使用默认值'}</span></div></div>`);
    if (custom) head.appendChild(btn('全部恢复默认', () => { d.advanced = {}; ctx.rerender(); }, 'sm')); panel.appendChild(head);
    ADV.forEach((a) => {
      const cur = A[a.k]; const def = PARAM[a.k]; const isCustom = cur != null;
      const item = h(`<div class="adv-item"><div class="top"><span class="name">${esc(a.name)}</span><span class="radio-seg"><label><input type="radio" name="m-${a.k}" value="def" ${isCustom ? '' : 'checked'}> 默认 ${def} ${esc(a.unit)}${a.k === 'jev_timeout_ms' ? '（部署设置）' : ''}</label>
        <label><input type="radio" name="m-${a.k}" value="cus" ${isCustom ? 'checked' : ''}> 自定义 <input type="number" class="num" value="${isCustom ? cur : def}" min="${a.lo}" max="${a.hi}" ${isCustom ? '' : 'disabled'} aria-label="${esc(a.name)}"> ${esc(a.unit)}</label></span><span class="dim small">${a.lo}–${a.hi}</span><button type="button" class="qbtn" aria-label="调整的代价" title="调整的代价">?</button></div>
        <div class="ev small dim">${esc(a.desc)}</div><div class="cost small hidden">${esc(a.cost)}</div><div class="evid small"></div><div class="impact hidden"></div><div class="inlinemsg err hidden"></div></div>`);
      const evid = $('.evid', item);
      if (a.k === 'jev_timeout_ms') {
        if (ev.jev.calls) {
          evid.innerHTML = `<div class="muted">最近 24 小时 p50 ${ev.jev.p50_ms} · p95 ${n(ev.jev.p95_ms)} · p99 ${n(ev.jev.p99_ms)} ms · 超时 ${ev.jev.timeouts} 次 / ${ev.jev.calls} 次</div>`;
          const marks = [{ at: def / 100, label: `默认 ${def / 1000} s`, left: true }]; if (isCustom && cur !== def) marks.push({ at: cur / 100, label: `本站点 ${cur / 1000} s`, dash: true, left: cur > def }); const hg = X.histogram(ev.histogram, { marks, ticks: [0, 10, 20, 30].filter((t) => t <= ev.histogram.length).map((t) => ({ at: t, label: t ? `${t / 10} s` : '0' })), label: '本站点耗时分布', tip: (i, c) => `${i * 100}–${i * 100 + 100} ms：${c} 次` }); hg.classList.add('minihist'); evid.appendChild(hg);
          const sug = ev.jev.timeouts ? Math.ceil((ev.jev.p99_ms * 1.5) / 500) * 500 : null;
          if (sug && (cur ?? def) < sug) { const sb = h(`<span class="sugg">建议 ${sug} ms（p99 × 1.5） · <button type="button" class="linkbtn">采用</button></span>`); sb.querySelector('button').onclick = () => { A.jev_timeout_ms = sug; ctx.rerender(); }; evid.appendChild(sb); }
        } else evid.innerHTML = '<span class="dim">最近 24 小时没有 Jev 调用</span>';
      } else if (a.k === 'session_calls_per_minute') evid.innerHTML = `<span class="muted">最高 1 分钟 ${ev.call_limit.session_peak} 次 · 触发 ${ev.call_limit.session_hits} 次</span>`;
      else if (a.k === 'address_calls_per_minute') evid.innerHTML = `<span class="muted">最高 1 分钟 ${ev.call_limit.address_peak} 次 · 触发 ${ev.call_limit.address_hits} 次${ev.call_limit.address_hits ? ' <span class="lvl-warn">▲</span>' : ''}</span>${ev.call_limit.address_hits ? '<div class="dim small">触发过上限：先看是不是未登录页面在轮询，登记入口或绕过通常更合适；NAT 后多人共用一个地址时才需要调大。</div>' : ''}`;
      else evid.innerHTML = `<span class="muted">缓存放行 ${ev.cache.cached_allows} 次</span>`;
      const impactEl = $('.impact', item); const errEl = $('.inlinemsg', item); const num = $('.num', item);
      const refreshImpact = () => {
        const probe = clone(s.spec); probe.advanced = Object.assign({}, probe.advanced); if (A[a.k] != null) probe.advanced[a.k] = A[a.k]; else delete probe.advanced[a.k];
        const base = clone(s.spec); const lines = impactLines(s, base, probe).filter((l) => l.text.startsWith(a.k === 'jev_timeout_ms' ? 'Jev 超时' : a.k === 'allow_cache_minutes' ? '放行缓存' : a.name)); impactEl.classList.toggle('hidden', !lines.length); impactEl.innerHTML = lines.map((l) => `${l.w ? '<span class="lvl-warn">▲</span> ' : ''}${esc(l.text)}`).join('<br>');
        const bad = A[a.k] != null && (!Number.isInteger(A[a.k]) || A[a.k] < a.lo || A[a.k] > a.hi); errEl.classList.toggle('hidden', !bad); errEl.textContent = bad ? `${a.name}需在 ${a.lo}–${a.hi} 之间` : ''; num.classList.toggle('bad', bad);
      };
      $$('input[type=radio]', item).forEach((r) => { r.onchange = () => { if (r.value === 'def') delete A[a.k]; else A[a.k] = Number(num.value); num.disabled = r.value === 'def'; ctx.update(); refreshImpact(); }; });
      num.oninput = () => { A[a.k] = num.value === '' ? NaN : Number(num.value); ctx.update(); refreshImpact(); };
      $('.qbtn', item).onclick = () => $('.cost', item).classList.toggle('hidden'); refreshImpact(); panel.appendChild(item);
    });
    // secret fields
    A.secret_fields = A.secret_fields || []; const sec = h(`<div class="adv-item"><div class="top"><span class="name">追加脱敏词</span><span class="dim small">3–32 个字符，小写字母、数字、_ -，最多 32 个</span><button type="button" class="qbtn" aria-label="调整的代价">?</button></div><div class="cost small hidden">追加后，字段名含这些词的值会被脱敏，Jev 看不到真实值，也无法对它做越权判断；像标识的词（如 card 会命中 cardId）会让对象引用也被脱敏。</div><div class="dim small" style="margin-top:6px">内置词不能删除</div><div class="secbox"></div><div class="impact hidden"></div><div class="inlinemsg err hidden"></div></div>`);
    $('.qbtn', sec).onclick = () => $('.cost', sec).classList.toggle('hidden'); const secErr = $('.inlinemsg', sec);
    const SECRET_RISK = /^(card|user|account|order|file|owner|id|patient|customer)/;
    $('.secbox', sec).appendChild(tagEditor(A.secret_fields, { locked: PARAM.secret_fields, placeholder: '＋ 添加脱敏词', onChange: ctx.rerender, onError: (t) => { secErr.textContent = t; secErr.classList.remove('hidden'); }, validate: (v, l) => (!/^[a-z0-9_-]{3,32}$/.test(v) ? '3–32 个字符，小写字母、数字、_ 或 -' : l.includes(v) || PARAM.secret_fields.includes(v) ? '已有这个词' : l.length >= 32 ? '最多 32 个' : null) }));
    const added = A.secret_fields.filter((w) => !(s.spec.advanced.secret_fields || []).includes(w));
    if (added.length || SECRET_RISK) { const lines = []; added.forEach((w) => { const k = (w.length * 7) % 11 + 3; lines.push(`${esc(w)}：过去 24 小时有 ${k} 次 Jev 调用、${k + 4} 个值会被脱敏（示意）`); if (SECRET_RISK.test(w)) lines.push(`<span class="lvl-warn">▲</span> “${esc(w)}”会让 ${esc(w)}Id 这类对象引用也被脱敏，Jev 无法判断越权`); }); const ie = $('.impact', sec); if (lines.length) { ie.classList.remove('hidden'); ie.innerHTML = lines.join('<br>'); } }
    panel.appendChild(sec);
    // synonyms
    A.synonyms = A.synonyms || []; const syn = h('<div class="adv-item"><div class="top"><span class="name">同义词</span><span class="dim small">每个词 3–24 个小写字母，两词不同，最多 32 组</span><button type="button" class="qbtn" aria-label="调整的代价">?</button></div><div class="cost small hidden">按词根比较，结尾的 s 会被忽略。例：字段 paymentId 的值来自 /api/Cards，就是 payment ↔ card。同义词改变核验结果，无法从历史记录预估影响，保存后请观察一段时间。</div><div class="synlist"></div><div class="inlinemsg err hidden"></div></div>');
    $('.qbtn', syn).onclick = () => $('.cost', syn).classList.toggle('hidden'); const sl = $('.synlist', syn);
    sl.appendChild(h('<div class="taglist" style="margin-top:6px"><span class="tag locked" title="内置组，不能删除">payment ↔ card</span></div>'));
    A.synonyms.forEach((p, i) => { const r = h(`<div class="taglist" style="margin-top:6px"><span class="tag">${esc(p[0])} ↔ ${esc(p[1])} <button type="button" aria-label="删除">×</button></span></div>`); r.querySelector('button').onclick = () => { A.synonyms.splice(i, 1); ctx.rerender(); }; sl.appendChild(r); });
    const ar = h('<div class="addrow"><input type="text" placeholder="词一" aria-label="同义词一"><span>↔</span><input type="text" placeholder="词二" aria-label="同义词二"><button type="button" class="btn">添加一组</button></div>'); const ins = $$('input', ar);
    $('button', ar).onclick = () => { const a1 = ins[0].value.trim(); const b1 = ins[1].value.trim(); const e = !/^[a-z]{3,24}$/.test(a1) || !/^[a-z]{3,24}$/.test(b1) ? '每个词 3–24 个小写字母' : a1 === b1 ? '两个词不能相同' : A.synonyms.some((p) => (p[0] === a1 && p[1] === b1) || (p[0] === b1 && p[1] === a1)) ? '已有这一组' : A.synonyms.length >= 32 ? '最多 32 组' : null; const m = $('.inlinemsg', syn); if (e) { m.textContent = e; m.classList.remove('hidden'); return; } A.synonyms.push([a1, b1]); ctx.rerender(); };
    syn.appendChild(ar); if (A.synonyms.length) syn.appendChild(h('<div class="impact"><span class="lvl-warn">▲</span> 同义词改变核验结果，无法从历史记录预估影响，保存后请观察一段时间</div>')); panel.appendChild(syn);
    // tidy empty arrays so they do not count as customised
    if (!A.secret_fields.length) delete A.secret_fields; if (!A.synonyms.length) delete A.synonyms;
  }

  // ---------------------------------------------------------------- dialogs
  function openDiffDialog(s) {
    const body = h('<div></div>'); const ch = changesOf(s);
    body.appendChild(h(`<div class="field"><label>改动（${ch.length} 处）</label>${ch.map((c) => `<div class="chg"><span class="chlabel">${esc(c.label)}</span> <span class="mono">${esc(c.text)}</span></div>`).join('')}</div>`));
    body.appendChild(h('<div class="field"><label>YAML 逐行差异</label></div>')).appendChild(X.diffView(X.specToYaml(s.spec), X.specToYaml(X.drafts[s.name])));
    const api = X.dialog(`${s.name} 的未保存改动`, body, [btn('关闭', () => api.close())], { wide: true });
  }
  X.openSaveDialog = (s, opts = {}) => {
    const oldSpec = clone(s.spec); const newSpec = opts.build ? opts.build(clone(s.spec)) : clone(X.drafts[s.name]);
    const ch = X.diffSpec(oldSpec, newSpec); const imp = impactLines(s, oldSpec, newSpec);
    const body = h('<div></div>');
    body.appendChild(h(`<div class="field"><label>改动</label>${ch.map((c) => `<div class="chg"><span class="chlabel">${esc(c.label)}</span> <span class="mono">${esc(c.text)}</span></div>`).join('') || '<div class="dim">没有改动</div>'}
      <details class="diffdet"><summary>差异（YAML 逐行）</summary></details></div>`));
    $('.diffdet', body).appendChild(X.diffView(X.specToYaml(oldSpec), X.specToYaml(newSpec)));
    body.appendChild(h(`<div class="field"><label>影响（按最近 24 小时 ${n(M.RECORDS.length * 27)} 条记录估算）</label><div class="impact">${imp.length ? imp.map((l) => `<div>${l.w ? '<span class="lvl-warn">▲</span>' : '▸'} ${esc(l.text)}</div>`).join('') : '<div class="dim">这些改动不影响已有请求的判定路径</div>'}</div><div class="dim small">原型的估算来自样例数据和示意数字；实现按 07.9.10 的接口计算。</div></div>`));
    body.appendChild(h(`<div class="field"><label for="note">备注（可选，最多 500 字）</label><input type="text" id="note" maxlength="500" value="${esc(opts.note || '')}"></div>`));
    const demo = h('<label class="check demo"><input type="checkbox" id="stuck"> 演示：让 edge-2 不加载新版本（看“生效中 → 琥珀色”）</label>'); body.appendChild(demo);
    const save = btn(`保存为 v${s.version + 1}`, () => {
      const ver = X.commit(s, opts.build ? opts.build : () => newSpec, { note: $('#note', body).value.trim(), fromDraft: !opts.build, stuck: $('#stuck', body).checked });
      api.close(); X.toast(`已保存 v${ver} · 等待网关加载…`); if (opts.after) opts.after(ver); else X.render();
    }, 'primary');
    const api = X.dialog(`保存 ${s.name} 的配置`, body, [btn('取消', () => api.close()), save], { wide: true });
  };
  X.openModeSwitch = (name) => {
    const s = X.site(name); const toEnforce = s.mode === 'observe';
    if (!toEnforce) {
      const body = h('<div class="muted">切回观察后不再拦截任何请求，只记录本应拦截。</div>');
      const api = X.dialog(`把 ${name} 切回观察模式`, body, [btn('取消', () => api.close()), btn(`切回观察模式（生成 v${s.version + 1}）`, () => { api.close(); s.observing_since = X.now(); X.commit(s, (sp) => Object.assign(sp, { mode: 'observe' }), { note: '切回观察模式' }); X.toast(`${name} 已切回观察模式 v${s.version}`); X.render(); }, 'primary')]); return;
    }
    const rd = (M.INSIGHTS[name] || {}).readiness || { would_block: { jev_deny: 0, no_session: 0 }, open_suggestions: 0, jev_health: 'ok', after_would_block_refs: 0 };
    const wb = rd.would_block.jev_deny + rd.would_block.no_session; const ev = evidenceFor(s); const days = Math.floor((X.now() - (s.observing_since || X.now())) / 86400000); const hrs = Math.floor(((X.now() - (s.observing_since || X.now())) % 86400000) / 3600000);
    const row = (ok, text, link) => `<div class="rdy">${ok ? '<span class="dot ok" aria-label="正常"></span>' : '<span class="lvl-warn" aria-label="注意">▲</span>'}<span>${text}</span>${link ? `<a href="${esc(link[1])}" data-close>${esc(link[0])}</a>` : ''}</div>`;
    const body = h(`<div><div class="field"><label>就绪检查（最近 24 小时）</label>${row(days >= 3, `已观察 ${days} 天 ${hrs} 小时`)}${row(wb === 0, `本应拦截 ${wb} 条：Jev 拒绝 ${rd.would_block.jev_deny} · 无会话 ${rd.would_block.no_session}`, wb ? ['逐条查看 →', `#/requests?site=${name}&chip=would`] : null)}
      ${row(rd.open_suggestions === 0, `待处理建议 ${rd.open_suggestions} 条`, rd.open_suggestions ? ['查看 →', `#/sites/${name}?tab=insights`] : null)}${row(rd.jev_health === 'ok', `Jev 正常（p95 ${ev.jev.p95_ms} ms，超时 ${ev.jev.calls ? ((ev.jev.timeouts / ev.jev.calls) * 100).toFixed(1) : 0}%）`)}
      ${row(rd.after_would_block_refs === 0, `由本应拦截请求学到的值被后续请求引用 ${rd.after_would_block_refs} 次（切换后这些请求也可能被拦截）`)}${row(s.spec.on_jev_unavailable === 'deny', `Jev 不可用时：${s.spec.on_jev_unavailable === 'deny' ? '拒绝' : '放行（未经判定的请求会被放行）'}`)}</div>
      <div class="field"><label>影响</label><div class="impact">过去 24 小时有 ${wb} 个请求会被拦截（返回 401 / 403）</div></div>
      ${wb ? '<label class="check"><input type="checkbox" id="ackbox"> 我已查看这些请求，确认它们应当被拦截</label>' : ''}</div>`);
    $$('[data-close]', body).forEach((a) => { a.onclick = () => api.close(); });
    const sw = btn(`切换到拦截模式（生成 v${s.version + 1}）`, () => {
      if (wb && !$('#ackbox', body).checked) { X.toast('请先勾选确认'); return; }
      api.close(); X.commit(s, (sp) => Object.assign(sp, { mode: 'enforce' }), { note: '切换到拦截模式' }); X.toast(`${name} 已切换到拦截模式 v${s.version}`); X.render();
    }, 'primary');
    const api = X.dialog(`把 ${name} 切换到拦截模式`, body, [btn('取消', () => api.close()), sw]);
  };
  X.openQuickRule = (r, kind) => {
    const s = X.site(r.site); if (!s) return; const key = kind === 'entry' ? 'entries' : 'bypass'; const parent = `${r.path.split('/').slice(0, -1).join('/')}/*`;
    const dir = `/${r.path.split('/')[1]}/*`; const cands = [[r.path, '精确路径', ''], [parent, '父路径前缀', kind === 'entry' ? '前缀入口会放大无会话可达的范围' : '']];
    if (kind === 'bypass' && dir !== parent && r.path.split('/').length > 2) cands.push([dir, '按目录合并', '']);
    const uniq = cands.filter((c, i) => cands.findIndex((x) => x[0] === c[0]) === i && c[0] !== '/*');
    const body = h('<div></div>'); const lst = h('<div class="field"><label>候选规则</label><div class="cands"></div></div>');
    uniq.forEach(([p, nm, warn], i) => { const im = ruleImpact(s, p, kind === 'entry' ? 'entry' : 'bypass'); lst.querySelector('.cands').appendChild(h(`<label class="cand"><input type="radio" name="cand" value="${esc(p)}" ${i === 0 ? 'checked' : ''}><span><b>${esc(nm)}</b> <span class="mono">${esc(p)}</span><div class="dim small">24 小时内匹配 ${im.count} 个${kind === 'entry' ? '无会话' : '已判定'}请求${warn ? ` · ${esc(warn)}` : ''}</div></span></label>`)); });
    body.appendChild(lst);
    if (kind === 'bypass') body.appendChild(h(`<div class="notice">绕过后该接口不做越权判定${r.decision_path === 'body_not_inspectable' ? '，只在确实需要上传大文件时使用' : ''}。</div>`));
    const impEl = h('<div class="field"><label>影响</label><div class="impact"></div></div>'); body.appendChild(impEl);
    body.appendChild(h(`<div class="field"><label for="qrnote">备注</label><input type="text" id="qrnote" value="从请求 ${esc(r.request_id.slice(-8))} ${kind === 'entry' ? '登记入口' : '加入绕过'}"></div>`));
    const selected = () => $('input[name=cand]:checked', body).value;
    const upd = () => { const p = selected(); const oldS = clone(s.spec); const newS = clone(s.spec); if (!newS[key].includes(p)) newS[key].push(p); const lines = impactLines(s, oldS, newS); impEl.querySelector('.impact').innerHTML = lines.map((l) => `<div>${l.w ? '<span class="lvl-warn">▲</span>' : '▸'} ${esc(l.text)}</div>`).join('') || '<div class="dim">已有这条规则</div>'; };
    $$('input[name=cand]', body).forEach((i) => { i.onchange = upd; }); upd();
    const save = btn(`保存为 v${s.version + 1}`, () => {
      const p = selected(); X.commit(s, (sp) => { if (!sp[key].includes(p)) sp[key].push(p); return sp; }, { note: $('#qrnote', body).value.trim() });
      body.innerHTML = `<div class="field"><label>已保存 v${s.version}</label><div class="ro-line" data-rollout="${esc(s.name)}">${X.rolloutHtml(s)}</div><div style="margin-top:12px"><a class="btn sm" href="#/requests?q=${encodeURIComponent(`path:${p}`)}&scope=all">查看这个路径之后的请求</a> <a class="btn sm" href="#/sites/${esc(s.name)}?tab=history">变更历史</a></div></div>`;
      $('.d-foot', api.el).innerHTML = ''; $('.d-foot', api.el).appendChild(btn('关闭', () => api.close(), 'primary'));
    }, 'primary');
    const api = X.dialog(kind === 'entry' ? '登记为入口' : '加入绕过', body, [btn('取消', () => api.close()), save]);
  };
  X.openTuneDialog = (r, key) => {
    const s = X.site(r.site); if (!s) return; const a = ADV.find((x) => x.k === key); const ev = evidenceFor(s); const cur = s.spec.advanced[key] ?? PARAM[key];
    const sug = key === 'jev_timeout_ms' ? Math.ceil((ev.jev.p99_ms * 1.5) / 500) * 500 : Math.max(cur + 10, (key === 'address_calls_per_minute' ? ev.call_limit.address_peak : ev.call_limit.session_peak) + 10);
    const body = h(`<div><div class="field"><label>${esc(a.name)}（当前 ${cur} ${esc(a.unit)}）</label><div class="muted small">${esc(a.desc)}。${key === 'jev_timeout_ms' ? `本站点最近 24 小时 p50 ${ev.jev.p50_ms} · p95 ${n(ev.jev.p95_ms)} · p99 ${n(ev.jev.p99_ms)} ms，超时 ${ev.jev.timeouts} 次。` : `最近 24 小时最高 ${key === 'address_calls_per_minute' ? ev.call_limit.address_peak : ev.call_limit.session_peak} 次/分钟，触发 ${key === 'address_calls_per_minute' ? ev.call_limit.address_hits : ev.call_limit.session_hits} 次。登记入口或绕过可能比调大上限更合适。`}</div></div></div>`);
    if (key === 'jev_timeout_ms' && ev.jev.calls) { const hg = X.histogram(ev.histogram, { marks: [{ at: cur / 100, label: `当前 ${cur / 1000} s`, left: true }], ticks: [0, 10, 20, 30].filter((t) => t <= ev.histogram.length).map((t) => ({ at: t, label: t ? `${t / 10} s` : '0' })), label: '耗时分布' }); hg.classList.add('minihist'); body.appendChild(hg); }
    const f = h(`<div class="field"><label for="tv">改为（建议 ${sug}）</label><input type="number" id="tv" value="${sug}" min="${a.lo}" max="${a.hi}"> ${esc(a.unit)}</div>`); body.appendChild(f);
    const impEl = h('<div class="impact"></div>'); body.appendChild(impEl);
    const upd = () => { const v = Number($('#tv', body).value); const oldS = clone(s.spec); const newS = clone(s.spec); newS.advanced = Object.assign({}, newS.advanced, { [key]: v }); impEl.innerHTML = impactLines(s, oldS, newS).map((l) => `<div>${l.w ? '<span class="lvl-warn">▲</span>' : '▸'} ${esc(l.text)}</div>`).join('') || '<div class="dim">没有变化</div>'; };
    $('#tv', body).oninput = upd; upd();
    const save = btn(`保存为 v${s.version + 1}`, () => { const v = Number($('#tv', body).value); if (!(v >= a.lo && v <= a.hi)) { X.toast(`${a.name}需在 ${a.lo}–${a.hi} 之间`); return; } X.commit(s, (sp) => { sp.advanced = Object.assign({}, sp.advanced, { [key]: v }); return sp; }, { note: `从请求 ${r.request_id.slice(-8)} 调整${a.name}` }); api.close(); X.toast(`已保存 v${s.version} · 等待网关加载…`); }, 'primary');
    const api = X.dialog(`调整${a.name}`, body, [btn('取消', () => api.close()), save]);
  };

  // ---------------------------------------------------------------- insights tab
  function siteInsights(body, s) {
    const ins = M.INSIGHTS[s.name] || { suggestions: [], readiness: null };
    if (s.mode === 'observe' && ins.readiness) { const rd = ins.readiness; const c = h(`<div class="card" style="margin-bottom:12px"><div class="card-head"><h2>就绪检查</h2></div><div class="muted">本应拦截 ${rd.would_block.jev_deny + rd.would_block.no_session} 条（Jev 拒绝 ${rd.would_block.jev_deny}、无会话 ${rd.would_block.no_session}）· 待处理建议 ${rd.open_suggestions} 条 · Jev ${rd.jev_health === 'ok' ? '正常' : rd.jev_health}</div></div>`); c.querySelector('.card-head').appendChild(btn('切换到拦截模式…', () => X.openModeSwitch(s.name), 'sm')); body.appendChild(c); }
    ignored[s.name] = ignored[s.name] || new Set(); const open = ins.suggestions.filter((x) => !ignored[s.name].has(x.id));
    if (!ins.suggestions.length) { body.appendChild(h('<div class="empty">暂时没有建议。观察模式下积累更多请求后再来看</div>')); return; }
    open.forEach((sg) => {
      const path = sg.action.add_entry || sg.action.add_bypass; const key = sg.action.add_entry ? 'entries' : 'bypass';
      const card = h(`<div class="card sugcard"><div class="card-head"><b>${esc(X.SUGG[sg.kind])} <span class="mono">${esc(path)}</span></b><span class="dim">${n(sg.count)} 次 · 最近 21:16</span></div><div class="muted" style="margin:6px 0">${esc(sg.reason)}</div><div class="mono dim small">改动：${key} ＋ ${esc(path)}</div><div class="sugact"></div></div>`);
      const acts = $('.sugact', card); const rec = M.RECORD_BY_ID[sg.sample]; if (rec) acts.appendChild(h(`<span class="dim small">示例请求 <a class="mono" href="#/requests/${esc(rec.request_id)}">…${esc(rec.request_id.slice(-8))}</a></span>`)); acts.appendChild(h('<span class="sp"></span>'));
      acts.appendChild(btn('忽略', () => { ignored[s.name].add(sg.id); X.toast('已忽略（仅存浏览器）'); X.render(); }, 'sm'));
      acts.appendChild(btn('加入草稿', () => { const d = draftOf(s); if (!d[key].includes(path)) d[key].push(path); X.toast('已加入草稿，去“配置”查看并保存'); X.render(); }, 'sm'));
      acts.appendChild(btn('应用…', () => X.openSaveDialog(s, { build: (sp) => { if (!sp[key].includes(path)) sp[key].push(path); return sp; }, note: '从调优建议应用' }), 'sm primary'));
      body.appendChild(card);
    });
    if (ignored[s.name].size) { const more = h(`<div class="dim small" style="margin-top:8px">已忽略 ${ignored[s.name].size} 条 · <button type="button" class="linkbtn">显示</button></div>`); more.querySelector('button').onclick = () => { ignored[s.name].clear(); X.render(); }; body.appendChild(more); }
    if (!open.length) body.appendChild(h('<div class="empty">没有待处理的建议</div>'));
  }

  // ---------------------------------------------------------------- history tab
  const summaryOf = (a, b) => { const c = X.diffSpec(a, b); if (!c.length) return '没有字段变化'; const t = c.slice(0, 3).map((x) => `${x.label} ${x.text.replace(/^[＋−] /, x.kind === 'add' ? '＋' : x.kind === 'del' ? '−' : '')}`); return t.join('，') + (c.length > 3 ? ` 等 ${c.length} 处` : ''); };
  function siteHistory(body, s, q) {
    const vs = s.versions; const sel = (q.get('diff') || `${(vs[1] || vs[0]).version}..${vs[0].version}`).split('..').map(Number);
    const find = (v) => vs.find((x) => x.version === v);
    const card = h('<div class="card"><h2>变更历史</h2></div>');
    const tbl = h('<div class="tablewrap"><table class="data"><thead><tr><th>比较</th><th>版本</th><th>时间</th><th>类型</th><th>备注</th><th>摘要</th><th></th></tr></thead><tbody></tbody></table></div>');
    vs.forEach((v, i) => {
      const prev = vs[i + 1]; const cname = { create: '创建', update: '修改', rollback: '回滚', delete: '删除', import: '导入' }[v.change];
      const tr = h(`<table><tbody><tr><td><input type="checkbox" aria-label="选择 v${v.version} 比较" ${sel.includes(v.version) ? 'checked' : ''}></td><td>v${v.version}${i === 0 ? ' <span class="cur">● 当前生效</span>' : ''}</td><td class="tnum">${X.fmtTime(v.at, true)}</td><td>${cname}</td><td class="muted">${esc(v.note || '—')}</td><td class="muted small">${esc(prev ? summaryOf(prev.spec, v.spec) : '最早的可见版本')}</td><td class="acts"></td></tr></tbody></table>`).querySelector('tr');
      const acts = $('.acts', tr);
      acts.appendChild(btn('全文', () => { const api = X.dialog(`${s.name} v${v.version}`, h(`<pre class="codeblock">${esc(X.specToYaml(v.spec))}</pre>`), [btn('关闭', () => api.close())]); }, 'sm'));
      acts.appendChild(h(`<a class="btn sm" href="#/requests?q=version:${v.version}&site=${esc(s.name)}">用此版本判定的请求</a>`));
      if (i > 0) acts.appendChild(btn('以此回滚…', () => openRollback(s, v), 'sm'));
      $('input', tr).onchange = () => {
        const checked = $$('input:checked', tbl).map((c) => Number(c.closest('tr').children[1].textContent.match(/v(\d+)/)[1]));
        if (checked.length === 2) X.setQuery({ diff: `${Math.min(...checked)}..${Math.max(...checked)}` });
      };
      $('tbody', tbl).appendChild(tr);
    });
    card.appendChild(tbl); card.appendChild(h('<div class="dim small" style="margin-top:6px">勾选两个版本比较差异；只列出样例数据里保留的版本。</div>')); body.appendChild(card);
    const a = find(sel[0]); const b = find(sel[1]);
    if (a && b) {
      const dc = h(`<div class="card" style="margin-top:12px"><h2>差异 v${a.version}..v${b.version}</h2></div>`);
      const ch = X.diffSpec(a.spec, b.spec); dc.appendChild(h(`<div class="field">${ch.map((c) => `<div class="chg"><span class="chlabel">${esc(c.label)}</span> <span class="mono">${esc(c.text)}</span></div>`).join('') || '<div class="dim">没有字段变化</div>'}</div>`));
      dc.appendChild(X.diffView(X.specToYaml(a.spec), X.specToYaml(b.spec))); body.appendChild(dc);
    }
  }
  function openRollback(s, v) {
    const cur = s.spec; const target = v.spec; const imp = impactLines(s, cur, target);
    const body = h('<div></div>'); body.appendChild(h(`<div class="field"><label>差异（当前 v${s.version} → 目标 v${v.version}）</label></div>`)).appendChild(X.diffView(X.specToYaml(cur), X.specToYaml(target)));
    body.appendChild(h(`<div class="field" style="margin-top:12px"><label>影响</label><div class="impact">${imp.map((l) => `<div>${l.w ? '<span class="lvl-warn">▲</span>' : '▸'} ${esc(l.text)}</div>`).join('') || '<div class="dim">没有字段变化</div>'}</div></div><div class="field"><label for="rbnote">备注</label><input type="text" id="rbnote" value="回滚到 v${v.version}"></div>`));
    const ok = btn(`回滚，生成 v${s.version + 1}（内容同 v${v.version}）`, () => { X.commit(s, () => clone(target), { change: 'rollback', note: $('#rbnote', body).value.trim(), dropDraft: true }); api.close(); X.toast(`已回滚，生成 v${s.version}`); X.render(); }, 'primary');
    const api = X.dialog(`回滚 ${s.name}`, body, [btn('取消', () => api.close()), ok], { wide: true });
  }

  // ---------------------------------------------------------------- system page
  const FIXED = {
    seen_max: ['每个会话最多记住的已见值个数', ''], sources_max: ['每个值最多记几个来源请求', '个'], recent_max: ['每个会话最多记住的最近访问条数', '条'], idle_hours: ['会话无活动多久后过期', '小时'], sessions_max: ['网关最多同时保存的会话数', '个'],
    long_value_chars: ['长值（按字面比较而不是按词根）的最短长度', '字符'], state_bytes_max: ['发给 Jev 的 state 上限，超出则逐级裁剪', 'B'], request_body_max: ['可判定的请求体上限，超出返回 413', 'B'], response_parse_max: ['解析响应学习新值的大小上限', 'B'],
    request_values_max: ['单个请求最多拆出的请求值个数', '个'], queue_capacity: ['判定记录发送队列的容量（满了丢弃记录并计入缺口）', '条'],
  };
  X.route((p) => p[0] === 'system', (page, parts, q) => {
    page.appendChild(X.pageHead('系统', `控制面 ${M.SYSTEM.control_build} · PostgreSQL ${M.SYSTEM.postgres}`));
    const tab = q.get('tab') || 'edges'; const tabs = h('<div class="tabs" role="tablist"></div>');
    [['edges', '网关'], ['storage', '日志存储'], ['params', '运行参数'], ['import', '导入']].forEach(([k, l]) => { const t = h(`<button type="button" class="tab ${tab === k ? 'active' : ''}" role="tab" aria-selected="${tab === k}">${l}</button>`); t.onclick = () => X.setQuery({ tab: k }); tabs.appendChild(t); });
    page.appendChild(tabs); const cap = M.SYSTEM.params.fixed.queue_capacity;
    if (tab === 'edges') {
      M.SYSTEM.edges.forEach((e) => {
        const sites = Object.entries(e.sites).map(([k, v]) => { const cur = X.site(k) ? X.site(k).version : v.version; return `${esc(k)} <span class="${v.version < cur ? 'lvl-warn' : ''}">v${v.version}${v.version < cur ? ` ▲ 当前 v${cur}` : ''}</span>`; }).join(' · ');
        const c = h(`<div class="card edgecard ${e.online ? '' : 'offline'}"><div class="card-head"><b>${esc(e.edge)}</b><span><span class="dot ${e.online ? 'ok' : 'down'}" aria-hidden="true"></span>${e.online ? '在线' : `离线 · 最后心跳 ${X.fmtHMS(e.seen_at)}（${X.rel(e.seen_at)}）`}</span></div>
          <div class="muted small" style="line-height:1.9">构建 ${esc(e.build)} · 监听 ${esc(e.listen)} ${e.tls ? '· TLS' : ''} · 启动于 ${X.fmtHM(e.started_at)} · 会话 ${n(e.sessions)}<br>
          发送队列 ${e.queue} / ${n(cap)} <span class="meter" aria-hidden="true"><i style="width:${Math.max(2, (e.queue / cap) * 100)}%"></i></span> · 已写入 ${n(e.written)} · 丢弃 ${n(e.dropped)} · 压力下丢弃的绕过记录 ${n(e.dropped_bypass)} · 写入失败 ${e.write_errors}<br>
          站点：${sites}<br>Jev：${esc(X.ROUTE_N[e.jev.route])} · ${esc(e.jev.endpoint_host)} · ${esc(e.jev.model)} · 默认超时 ${e.jev.default_timeout_ms} ms · 指令 <span class="mono">${esc(e.jev.prompt)}</span></div></div>`);
        page.appendChild(c);
      });
      page.appendChild(h('<div class="dim small">计数自实例启动起累计；增量看“日志存储”里的缺口列表。离线实例不计入配置生效进度。</div>'));
    } else if (tab === 'storage') {
      const st = M.SYSTEM.storage; const future = st.partitions.filter((p) => p.future).length;
      const c = h(`<div class="card"><h2>按天分区</h2></div>`); c.appendChild(h(`<div class="tablewrap short"><table class="data"><thead><tr><th>分区</th><th>日期</th><th>行数</th><th>大小</th><th></th></tr></thead><tbody>${st.partitions.map((p) => `<tr><td class="mono">${esc(p.name)}</td><td class="tnum">${esc(p.from)}</td><td class="tnum">${n(p.rows)}</td><td class="tnum">${p.bytes ? X.bytes(p.bytes) : '—'}</td><td class="dim small">${p.future ? '提前建好' : ''}</td></tr>`).join('')}</tbody></table></div>`));
      c.appendChild(h(`<div class="dim small" style="margin-top:8px">保留期 ${st.retention_days} 天（代码默认值）· 最早记录 ${X.fmtTime(st.earliest_at, true)} · 提前建好 ${future} 天分区${future < 2 ? ' ▲ 不足 2 天，需要处理' : '（够用）'}</div>`)); page.appendChild(c);
      const gaps = []; M.SYSTEM.edges.forEach((e) => (e.gaps || []).forEach((g) => gaps.push(Object.assign({ edge: e.edge }, g)))); gaps.sort((a, b) => b.from_ms - a.from_ms);
      const gc = h('<div class="card" style="margin-top:12px"><h2>日志缺口</h2></div>');
      gc.appendChild(h(`<div class="tablewrap short"><table class="data"><thead><tr><th>时间段</th><th>实例</th><th>丢失的判定记录</th><th>压力下丢弃的绕过记录</th><th>写入失败</th><th></th></tr></thead><tbody>${gaps.map((g) => `<tr><td class="tnum">${X.fmtHM(g.from_ms)}–${X.fmtHM(g.to_ms)}</td><td>${esc(g.edge)}</td><td class="tnum">${g.dropped}</td><td class="tnum">${n(g.dropped_bypass)}</td><td class="tnum">${g.write_errors}</td><td><a href="#/requests?since=${g.from_ms}&until=${g.to_ms}&scope=all">查看这段时间的请求</a></td></tr>`).join('') || '<tr><td colspan="6" class="dim">没有缺口</td></tr>'}</tbody></table></div><div class="dim small" style="margin-top:6px">数据来自网关心跳；网关重启后清空，重启之前的缺口看不到。</div>`)); page.appendChild(gc);
    } else if (tab === 'params') {
      const p = M.SYSTEM.params; const sites = X.sites;
      const cols = [['jev_timeout_ms', 'Jev 超时 ms'], ['session_calls_per_minute', '会话上限'], ['address_calls_per_minute', '地址上限'], ['allow_cache_minutes', '缓存分钟'], ['secret_fields', '追加脱敏词'], ['synonyms', '同义词']];
      const c = h('<div class="card"><h2>站点可覆盖的默认值</h2></div>');
      c.appendChild(h(`<div class="tablewrap short"><table class="data matrix"><thead><tr><th>站点</th>${cols.map(([, l]) => `<th>${l}</th>`).join('')}</tr></thead><tbody><tr class="defrow"><td><b>默认值</b></td>${cols.map(([k]) => `<td>${Array.isArray(p.site_overridable[k]) ? `${p.site_overridable[k].length} 个内置` : p.site_overridable[k]}</td>`).join('')}</tr>
        ${sites.map((s) => `<tr><td><a href="#/sites/${esc(s.name)}?tab=config&group=advanced">${esc(s.name)}</a></td>${cols.map(([k]) => { const v = (s.spec.advanced || {})[k]; return `<td>${v == null || (Array.isArray(v) && !v.length) ? '<span class="dim">默认</span>' : `<b>${Array.isArray(v) ? (k === 'synonyms' ? v.map((x) => x.join('↔')).join('、') : v.join('、')) : v}</b>`}</td>`; }).join('')}</tr>`).join('')}</tbody></table></div><div class="dim small" style="margin-top:6px">内置脱敏词：${esc(p.site_overridable.secret_fields.join('、'))}；内置同义词：card ↔ payment。点击站点名进入它的高级判定参数。</div>`));
      page.appendChild(c);
      const fx = h('<div class="card" style="margin-top:12px"><h2>固定参数（只读）</h2></div>');
      fx.appendChild(h(`<div class="tablewrap short"><table class="data"><thead><tr><th>参数</th><th>值</th><th>说明</th></tr></thead><tbody>${Object.entries(p.fixed).map(([k, v]) => `<tr><td class="mono">${esc(k)}</td><td class="tnum">${n(v)}${FIXED[k] && FIXED[k][1] ? ` ${FIXED[k][1]}` : ''}</td><td class="muted">${esc(FIXED[k] ? FIXED[k][0] : '')}</td></tr>`).join('')}</tbody></table></div>`)); page.appendChild(fx);
    } else if (tab === 'import') {
      const c = h('<div class="card"><h2>导入判定日志</h2><div class="muted">选择网关文件模式输出的 JSON 行文件（最大 100 MiB）。导入的记录网关实例记为 import；旧格式记录在详情页标注“没有判定依据”。</div><div style="margin-top:12px"><input type="file" aria-label="选择 JSON 行文件"></div><div class="impact" id="impres" style="margin-top:12px;display:none"></div></div>');
      $('input', c).onchange = (e) => { const f = e.target.files[0]; const r = $('#impres', c); r.style.display = ''; r.innerHTML = f ? `原型不处理文件。真实导入会显示进度，并给出：导入 / 跳过 / 出错行数和前 20 个出错行号。所选文件：${esc(f.name)}（${X.bytes(f.size)}）` : ''; };
      page.appendChild(c);
    }
  });
})();
