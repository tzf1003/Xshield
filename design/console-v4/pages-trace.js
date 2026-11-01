// Overview, request list, request detail, sessions and the session timeline.
'use strict';
(function () {
  const X = window.X; const M = X.M;
  const { $, $$, h, esc, safeText, mid, n, pct, bytes } = Object.assign({}, X, { $: X.$, $$: X.$$ });
  const go = (hash) => X.go(hash);
  const btn = X.btn;

  // ================================================================ filtering
  const KEYS = ['outcome', 'decision', 'path', 'method', 'status', 'session', 'client', 'id', 'access', 'attack', 'failure', 'version', 'entry', 'site'];
  const KEY_HELP = { outcome: '结论', decision: '判定路径', path: '路径（* 结尾为前缀）', method: '方法', status: '状态码或 4xx', session: '会话标签', client: '客户端 IP', id: '请求 ID', access: 'Jev 访问回答', attack: 'Jev 攻击回答', failure: 'Jev 失败码', version: '配置版本', entry: '是否命中入口', site: '站点' };
  const ENUMS = { outcome: Object.keys(X.OUT), decision: Object.keys(X.DP), method: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS'], access: ['ALLOW', 'DENY', 'UNKNOWN'], attack: ['BENIGN', 'ATTACK', 'UNKNOWN'], failure: Object.keys(X.FAIL), entry: ['true', 'false'] };
  X.parseDsl = (text) => {
    const conds = []; const errors = [];
    (text || '').split(/\s+/).filter(Boolean).forEach((tok) => {
      let m;
      if ((m = tok.match(/^conf<(\d*\.?\d+)(%?)$/))) { let v = Number(m[1]); if (m[2] || v > 1) v /= 100; conds.push({ k: 'conf', v }); return; }
      if ((m = tok.match(/^ms>(\d+)$/))) { conds.push({ k: 'ms', v: Number(m[1]) }); return; }
      if (/^(conf<|ms>)/.test(tok)) { errors.push({ tok, msg: `${tok.split(/[<>]/)[0]} 后面需要数字` }); return; }
      const i = tok.indexOf(':');
      if (i > 0) {
        const key = tok.slice(0, i); const vals = tok.slice(i + 1).split(',').filter(Boolean);
        if (!KEYS.includes(key)) { errors.push({ tok, msg: `不认识的条件 ${key}` }); return; }
        if (!vals.length) { errors.push({ tok, msg: `${key}: 后面需要取值` }); return; }
        const norm = vals.map((v) => (key === 'method' ? v.toUpperCase() : v));
        if (ENUMS[key] && norm.some((v) => !ENUMS[key].includes(v))) { errors.push({ tok, msg: `${key} 的取值是 ${ENUMS[key].join('、')}` }); return; }
        if (key === 'status' && vals.some((v) => !/^\d{3}$|^[1-5]xx$/.test(v))) { errors.push({ tok, msg: 'status 的取值是 3 位状态码或 4xx 这样的类别' }); return; }
        if (key === 'version' && vals.some((v) => !/^\d+$/.test(v))) { errors.push({ tok, msg: 'version 的取值是整数' }); return; }
        conds.push({ k: key, v: norm }); return;
      }
      if (/^req_[0-9a-f]{32}$/.test(tok)) conds.push({ k: 'id', v: [tok] });
      else if (/^[0-9a-f]{16}$/.test(tok)) conds.push({ k: 'session', v: [tok] });
      else if (tok.startsWith('/')) conds.push({ k: 'path', v: [tok] });
      else if (ENUMS.method.includes(tok.toUpperCase())) conds.push({ k: 'method', v: [tok.toUpperCase()] });
      else errors.push({ tok, msg: `看不懂 “${tok}”，请用“键:值”的写法` });
    });
    return { conds, errors };
  };
  function condMatch(r, c) {
    const j = r.jev;
    switch (c.k) {
      case 'outcome': return c.v.includes(r.outcome);
      case 'decision': return c.v.includes(r.decision_path);
      case 'path': return c.v.some((p) => (p.endsWith('*') ? r.path.startsWith(p.slice(0, -1)) : r.path === p));
      case 'method': return c.v.includes(r.method);
      case 'status': return c.v.some((s) => (/xx$/.test(s) ? Math.floor(r.status / 100) === Number(s[0]) : r.status === Number(s)));
      case 'session': return c.v.some((s) => r.session && r.session.startsWith(s));
      case 'client': return c.v.includes(r.client);
      case 'id': return c.v.some((s) => r.request_id === s || r.request_id.endsWith(s));
      case 'access': return !!j && !j.failure && c.v.includes(j.access);
      case 'attack': return !!j && !j.failure && c.v.includes(j.attack);
      case 'failure': return !!j && c.v.includes(j.failure);
      case 'conf': return !!j && j.confidence != null && j.confidence < c.v;
      case 'ms': return r.total_ms > c.v;
      case 'version': return c.v.includes(String(r.site_version));
      case 'entry': return !!r.trace && !!r.trace.entry === (c.v[0] === 'true');
      case 'site': return c.v.includes(r.site);
      default: return true;
    }
  }
  X.condMatch = condMatch;
  const CHIPS = [['', '已判定'], ['attention', '需要关注'], ['blocked', '拦截'], ['would', '本应拦截'], ['unjudged', '未经判定'], ['jev', 'Jev 调用'], ['no_session', '无会话'], ['bypass', '绕过']];
  const chipTest = {
    '': () => true, attention: (r) => ['blocked', 'would_block', 'unjudged'].includes(r.outcome), blocked: (r) => r.outcome === 'blocked', would: (r) => r.outcome === 'would_block',
    unjudged: (r) => r.outcome === 'unjudged', jev: (r) => !!r.jev, no_session: (r) => r.decision_path === 'no_session', bypass: (r) => r.decision_path === 'bypass',
  };
  // Everything except the chip: site scope, scope=judged|all, conditions, time window.
  function baseRows(q) {
    const dsl = X.parseDsl(q.get('q') || ''); const all = q.get('scope') === 'all';
    const lookup = dsl.conds.some((c) => c.k === 'id' || c.k === 'session' || (c.k === 'path' && c.v.some((p) => !p.endsWith('*'))));
    const wantsExcluded = dsl.conds.some((c) => c.k === 'decision' && c.v.some((v) => v === 'unknown_site' || v === 'bypass'));
    const win = X.customWindow(q) || { since: 0, until: Infinity }; const since = win.since; const until = win.until;
    let rows = M.RECORDS.slice();
    if (X.state.site !== 'all') rows = rows.filter((r) => r.site === X.state.site);
    rows = rows.filter((r) => r.at_millis >= since && r.at_millis <= until);
    rows = rows.filter((r) => dsl.conds.every((c) => condMatch(r, c)));
    return { rows, includeAll: all || lookup || q.get('chip') === 'bypass' || wantsExcluded, autoIncluded: !all && lookup, dsl };
  }
  const isJudged = (r) => r.decision_path !== 'bypass' && r.decision_path !== 'unknown_site';
  X.filterRows = (q) => {
    const b = baseRows(q); const chip = q.get('chip') || '';
    let rows = b.rows;
    if (!b.includeAll) rows = rows.filter(isJudged);
    if (chipTest[chip]) rows = rows.filter(chipTest[chip]);
    return { rows, base: b };
  };

  // ================================================================ status wording for gaps
  function gapBanners(q) {
    const out = []; const win = X.customWindow(q) || { since: 0, until: Infinity }; const since = win.since; const until = win.until;
    M.SYSTEM.edges.forEach((e) => (e.gaps || []).forEach((g) => {
      if (g.to_ms < since || g.from_ms > until) return;
      if (X.state.site !== 'all' && false) return;
      if (X.gapLost(g) > 0) out.push({ kind: 'lost', text: `${X.fmtHM(g.from_ms)}–${X.fmtHM(g.to_ms)} ${e.edge} 有 ${X.gapLost(g)} 条记录未写入（${X.gapCause(g)}），这段时间的请求可能查不到`, href: '#/system?tab=storage', act: '查看系统' });
      else if (g.dropped_bypass > 0) out.push({ kind: 'soft', text: `${e.edge} 在 ${X.fmtHM(g.from_ms)}–${X.fmtHM(g.to_ms)} 丢弃了 ${n(g.dropped_bypass)} 条绕过记录，判定记录不受影响`, href: '#/system?tab=storage', act: '查看系统' });
    }));
    return out;
  }
  function notFoundReason(id) {
    if (!/^req_[0-9a-f]{32}$/.test(id)) return '不是有效的请求 ID（req_ 加 32 位小写十六进制）';
    const t = M.idTime(id); const now = X.now();
    if (now - t > 7 * 86400000) return `生成于 ${X.fmtFull(t).slice(0, 16)}，已超过 7 天保留期`;
    if (t > now + 60000 || t < now - 40 * 86400000) return 'ID 时间异常，可能不是本系统生成的';
    for (const e of M.SYSTEM.edges) for (const g of e.gaps || []) { if (t >= g.from_ms && t <= g.to_ms && X.gapLost(g) > 0) return `生成于 ${X.fmtHMS(t)}，当时 ${e.edge} 丢失了 ${X.gapLost(g)} 条记录（${X.gapCause(g)}）`; }
    return '可能来自其他环境的网关';
  }
  X.notFoundReason = notFoundReason;

  // ================================================================ OVERVIEW
  function summaryFor(site) {
    const base = { emr: { judged: 4000 }, juice: { judged: 2204 } }; const baseOf = (nm) => base[nm] || { judged: 0 };
    const names = site === 'all' ? X.sites.map((st) => st.name) : [site]; const s = { judged: 0, blocked: 0, would_block: 0, unjudged: 0, jev_calls: 0, timeouts: 0 }; const hist = [];
    names.forEach((nm) => {
      const st = X.site(nm); const ev = X.evidence(nm);
      s.judged += baseOf(nm).judged; s.blocked += st.blocked_24h; s.would_block += st.would_block_24h; s.jev_calls += st.jev_calls_24h; s.timeouts += ev.jev.timeouts;
      ev.histogram.forEach((c, i) => { hist[i] = (hist[i] || 0) + c; });
    });
    const total = hist.reduce((a, b) => a + b, 0); let acc = 0; let p95 = 0;
    for (let i = 0; i < hist.length; i++) { acc += hist[i]; if (total && acc >= total * 0.95) { p95 = i * 100 + 50; break; } }
    const calls = names.reduce((a, nm) => a + X.evidence(nm).jev.calls, 0);
    s.p95 = calls ? Math.round(names.reduce((a, nm) => a + X.evidence(nm).jev.p95_ms * X.evidence(nm).jev.calls, 0) / calls) : 0;
    s.jev_pct = s.judged ? (s.jev_calls / s.judged) * 100 : 0; s.hist = hist; s.p95bucket = p95; return s;
  }
  function attentionItems() {
    const items = []; const st = X.computeStatus();
    st.problems.forEach((p) => items.push({ lvl: p.level, msg: p.text, acts: [[p.act, p.href]] }));
    M.SYSTEM.edges.forEach((e) => (e.gaps || []).forEach((g) => { if (!X.gapLost(g) && g.dropped_bypass) items.push({ lvl: 'info', msg: `${e.edge} 在队列压力下丢弃了 ${n(g.dropped_bypass)} 条绕过记录（静态资源），判定记录不受影响`, acts: [['查看系统', '#/system?tab=storage']] }); }));
    X.sites.forEach((s) => {
      if (X.state.site !== 'all' && X.state.site !== s.name) return;
      if (s.mode === 'observe' && s.would_block_24h) {
        const rd = M.INSIGHTS[s.name].readiness; const days = Math.floor((X.now() - s.observing_since) / 86400000);
        items.push({ lvl: 'warn', msg: `${s.name} 观察中 ${days} 天：本应拦截 ${s.would_block_24h} 条（Jev 拒绝 ${rd.would_block.jev_deny}、无会话 ${rd.would_block.no_session}）`, acts: [['查看', `#/requests?site=${s.name}&chip=would`], ['就绪检查', () => X.openModeSwitch(s.name)]] });
      }
      const sg = M.INSIGHTS[s.name].suggestions;
      if (sg.length) items.push({ lvl: 'info', msg: `${s.name} 有 ${sg.length} 条调优建议：${X.list(sg.map((x) => X.SUGG[x.kind]))}`, acts: [['查看建议', `#/sites/${s.name}?tab=insights`]] });
      const ev = X.evidence(s.name);
      if (ev.call_limit.address_hits || ev.call_limit.session_hits) items.push({ lvl: 'info', msg: `${s.name} 地址调用上限最近 24 小时触发 ${ev.call_limit.address_hits} 次（最高 ${ev.call_limit.address_peak} 次/分钟，默认上限 30）；Jev 超时 ${ev.jev.timeouts} 次 / ${ev.jev.calls} 次调用`, acts: [['查看证据', `#/sites/${s.name}?tab=config&group=advanced`]] });
    });
    const order = { serious: 0, warn: 1, info: 2 }; items.sort((a, b) => order[a.lvl] - order[b.lvl]); return items;
  }
  const LVL_G = { serious: '<span class="lvl lvl-serious" aria-label="严重">■</span>', warn: '<span class="lvl lvl-warn" aria-label="警告">▲</span>', info: '<span class="lvl lvl-info infog" aria-label="提示">i</span>' };

  X.route((p) => !p.length || p[0] === 'overview', (page) => {
    page.appendChild(X.pageHead('总览', `${X.scopeLabel()} · 最近 24 小时 · 最后检查 ${X.fmtHMS(X.now())}`));
    const items = attentionItems();
    const attn = h('<div class="card" style="margin-bottom:16px"><h2>需要处理</h2><div class="attn"></div></div>');
    if (!items.length) attn.querySelector('.attn').appendChild(h(`<div class="allgood"><span class="dot ok" aria-hidden="true"></span>一切正常 · 最后检查 ${X.fmtHMS(X.now())}</div>`));
    items.forEach((it) => {
      const row = h(`<div class="attn-row">${LVL_G[it.lvl]}<div class="msg">${esc(it.msg)}</div></div>`);
      it.acts.forEach((a) => { const b = btn(a[0], null, 'sm'); b.onclick = typeof a[1] === 'function' ? a[1] : () => go(a[1]); row.appendChild(b); });
      attn.querySelector('.attn').appendChild(row);
    });
    page.appendChild(attn);

    const s = summaryFor(X.state.site); const scope = X.state.site === 'all' ? '' : `site=${X.state.site}&`;
    const sc = (k) => X.spark(Array.from({ length: 12 }, (_, i) => Math.max(0, Math.round(Math.abs(Math.sin(i * 1.7 + k.length) * 6 + (k === 'x' ? 0 : 3))))), 84, 22, 'var(--s1)');
    const tdef = [
      ['已判定请求', n(s.judged), '不含绕过和未知站点', `#/requests?${scope}`], ['拦截', n(s.blocked), '', `#/requests?${scope}chip=blocked`],
      ['本应拦截', n(s.would_block), '', `#/requests?${scope}chip=would`], ['未经判定', n(s.unjudged), '', `#/requests?${scope}chip=unjudged`],
      ['Jev 调用', n(s.jev_calls), `占已判定 ${s.jev_pct.toFixed(1)}%`, `#/requests?${scope}chip=jev`], ['Jev 耗时 p95', `${n(s.p95)} ms`, `超时 ${s.timeouts} 次`, '#/jev'],
    ];
    const tiles = h('<div class="tiles" style="margin-bottom:16px"></div>');
    tdef.forEach(([k, v, x, href], i) => {
      const t = h(`<a class="tile clickable" href="${href}"><div class="k">${esc(k)}</div><div class="v tnum">${esc(v)}</div><div class="x">${esc(x) || '&nbsp;'}</div><div class="sp"></div></a>`);
      t.querySelector('.sp').appendChild(sc(`${k}${i}`)); tiles.appendChild(t);
    });
    page.appendChild(tiles);

    const share = X.state.site === 'all' ? 1 : ({ emr: 0.64, juice: 0.36 })[X.state.site] || 0;
    const ts = M.TIMESERIES.map((d) => ({ hour: d.hour, fast: Math.round(d.fast * share), jev: Math.round(d.jev * share), no_session: Math.round(d.no_session * share) }));
    const chart = X.chartCard('每小时请求（不含绕过）', X.stackedChart(ts), ts.map((d) => [`${String(d.hour).padStart(2, '0')}:00`, d.fast, d.jev, d.no_session]), ['小时', '免调用放行', 'Jev 判定', '无会话']);
    chart.appendChild(h('<div class="legend" style="margin-top:8px"><span><span class="sw" style="background:var(--s1)"></span>免调用放行</span><span><span class="sw" style="background:var(--s2)"></span>Jev 判定</span><span><span class="sw" style="background:var(--s3)"></span>无会话</span></div>'));
    const sitesCard = h('<div class="card"><h2>站点</h2></div>');
    X.sites.filter((st) => X.state.site === 'all' || st.name === X.state.site).forEach((st) => {
      const modeTxt = st.mode === 'observe' ? `观察 ${Math.floor((X.now() - st.observing_since) / 86400000)} 天` : '拦截';
      const extra = st.mode === 'observe' ? `本应拦截 ${st.would_block_24h}` : `拦截 ${st.blocked_24h}`;
      const c = h(`<a class="siterow" href="#/sites/${esc(st.name)}"><div class="top"><b>${esc(st.name)}</b><span class="dim">${esc(modeTxt)}</span></div>
        <div class="muted" style="font-size:12px">24h ${n(st.requests_24h)} · ${esc(extra)}${st.suggestions ? ` · 建议 ${st.suggestions}` : ''}</div><div class="ro-line" data-rollout="${esc(st.name)}">${X.rolloutHtml(st)}</div></a>`);
      sitesCard.appendChild(c);
    });
    const row = h('<div class="grid ov-grid"></div>'); row.appendChild(chart); row.appendChild(sitesCard); page.appendChild(row);

    const recent = M.RECORDS.filter((r) => (r.outcome === 'blocked' || r.outcome === 'would_block') && (X.state.site === 'all' || r.site === X.state.site)).slice(0, 10);
    const rc = h('<div class="card" style="margin-top:16px"><div class="card-head"><h2>最近的拦截与本应拦截</h2><a href="#/requests?chip=attention">全部 →</a></div></div>');
    rc.appendChild(requestTable(recent, { compact: true }));
    page.appendChild(rc);
  });

  // ================================================================ REQUEST TABLE
  function rowHtml(r, showSite) {
    const qs = r.query ? `<span class="qs">?${esc(r.query)}</span>` : '';
    // 窄容器下，被隐藏的列依次并入路径列下方的副行（docs/06 6.8.1）：a=站点/耗时/ID，b=状态，c=Jev
    const sub = `<span class="sl sl-b">${r.status == null ? '—' : r.status} · </span>${showSite && r.site ? `<span class="sl sl-a">${esc(r.site)} · </span>` : ''}<span class="sl sl-a">${r.total_ms} ms · …${esc(r.request_id.slice(-8))}</span>${r.jev ? `<span class="sl sl-c"> · ${X.jevCell(r.jev)}</span>` : ''}`;
    return `<tr data-id="${esc(r.request_id)}" aria-selected="false">
      <td class="tnum c-time" title="本地 ${esc(X.fmtFull(r.at_millis))}（UTC+8） · UTC ${esc(X.fmtUtc(r.at_millis))}">${X.fmtTime(r.at_millis)}</td>
      ${showSite ? `<td class="c-site">${esc(r.site || '—')}</td>` : ''}
      <td class="mono c-method">${esc(r.method)}</td>
      <td class="c-path"><span class="mprefix mono">${esc(r.method)} </span><span class="path" title="${esc(r.path + (r.query ? `?${r.query}` : ''))}">${esc(mid(r.path, 52))}${qs}</span><span class="subline">${sub}</span></td>
      <td class="tnum c-status">${r.status == null ? '—' : r.status}</td>
      <td class="c-dp">${X.dpBadge(r.decision_path)}</td><td class="c-out">${X.outPill(r.outcome)}</td><td class="c-jev">${X.jevCell(r.jev)}</td>
      <td class="tnum c-ms">${r.total_ms} ms</td><td class="c-id">${X.idCell(r.request_id)}</td>
      <td class="c-menu"><button type="button" class="rowmenu" aria-label="更多操作" title="更多操作">⋯</button></td></tr>`;
  }
  function tableShell(showSite) {
    return h(`<div class="tablewrap qtable"><table class="data req" role="grid"><thead><tr>
      <th class="c-time">时间</th>${showSite ? '<th class="c-site">站点</th>' : ''}<th class="c-method">方法</th><th class="c-path">路径</th><th class="c-status">状态</th><th class="c-dp">判定</th><th class="c-out">结论</th><th class="c-jev">Jev</th><th class="c-ms">耗时</th><th class="c-id">请求 ID</th><th class="c-menu"></th>
    </tr></thead><tbody></tbody></table></div>`);
  }
  function requestTable(rows, opts = {}) {
    const showSite = X.state.site === 'all'; const wrap = tableShell(showSite); const tb = wrap.querySelector('tbody');
    if (!rows.length) { wrap.querySelector('table').remove(); wrap.appendChild(h('<div class="empty">没有匹配的请求</div>')); return wrap; }
    rows.forEach((r) => {
      const tr = h(`<table><tbody>${rowHtml(r, showSite)}</tbody></table>`).querySelector('tr');
      tr.onclick = (e) => { if (e.target.closest('.rowmenu')) return; if (opts.compact) go(`#/requests/${r.request_id}`); else if (opts.onSelect) opts.onSelect(r.request_id); };
      tr.ondblclick = () => go(`#/requests/${r.request_id}`);
      const mb = tr.querySelector('.rowmenu'); mb.onclick = (e) => { e.stopPropagation(); rowMenu(mb, r); };
      tb.appendChild(tr);
    });
    return wrap;
  }
  function rowMenu(anchor, r) {
    const box = h('<div class="menu"></div>');
    const item = (label, fn) => { const b = h(`<button type="button" class="menuitem">${esc(label)}</button>`); b.onclick = () => { X.closePopover(); fn(); }; box.appendChild(b); };
    item('复制请求 ID', () => X.copy(r.request_id, '已复制请求 ID'));
    item('复制详情链接', () => X.copy(`${location.origin}${location.pathname}#/requests/${r.request_id}`, '已复制详情链接'));
    if (r.session) { item('打开会话时间线', () => go(`#/sessions/${r.session}?at=${r.request_id}`)); item('只看这个会话', () => go(`#/requests?q=session:${r.session}`)); }
    item('只看这个路径', () => go(`#/requests?q=path:${encodeURIComponent(r.path)}`));
    if (r.decision_path === 'no_session') item('登记为入口…', () => X.openQuickRule(r, 'entry'));
    if (r.decision_path === 'bypass' || r.decision_path === 'body_not_inspectable' || /\.(js|css|png|jpe?g|svg|ico|woff2?)$/.test(r.path)) item('加入绕过…', () => X.openQuickRule(r, 'bypass'));
    X.popover(anchor, box, { right: true });
  }

  // ================================================================ REQUESTS PAGE
  let liveSeq = 0;
  function liveRecord() {
    liveSeq += 1; const juice = liveSeq % 3 !== 0; const t = Math.round(X.now()); const tail = Array.from({ length: 20 }, () => '0123456789abcdef'[Math.floor(Math.random() * 16)]).join('');
    const id = `req_${t.toString(16).padStart(12, '0')}${tail}`;
    const pool = juice
      ? [['GET', '/rest/basket/1', 'fast_allow', 12], ['GET', '/api/Products', 'fast_allow', 14], ['GET', '/rest/user/whoami', 'fast_allow', 9], ['GET', '/rest/products/search', 'cached_allow', 17]]
      : [['GET', '/api/patients/7', 'fast_allow', 21], ['GET', '/api/home', 'fast_allow', 17]];
    const [method, path, dp, ms] = pool[liveSeq % pool.length]; const site = juice ? 'juice' : 'emr';
    const r = {
      id: 91400 + liveSeq, request_id: id, at_millis: t, site, site_version: X.site(site).version, edge: 'edge-1', method, host: `${site}.example.com`, path, query: path.endsWith('search') ? 'q=apple' : null, status: 200,
      decision_path: dp, outcome: 'allowed', session: juice ? '7c1e9a40d2b35f61' : 'a913ee40771c2b05', context: 'session', client: juice ? '192.168.1.20' : '10.2.0.44', total_ms: ms, jev: null, jevFull: null,
      trace: { v: 1, entry: null, bypass: null, refused: null, values_truncated: false, values: [{ at: 'path[0]', key: null, value: path.split('/')[1], kind: 'route', inert: true, seen: false, verified: false, sources: [] }], session: { age_seconds: 600, known_values: 320 }, cache_source: dp === 'cached_allow' ? M.ID.j_search1 : null, timing: { total_ms: ms, judge_ms: 1, origin_ms: ms - 3 }, response: { content_type: 'application/json', bytes: 600, observed: 'json', skip: null, values: 0, new_values: 0, fields: [], issued_session: null, entry_passed: false, after_would_block: false }, upstream_error: null },
    };
    M.RECORDS.unshift(r); M.RECORD_BY_ID[id] = r; return r;
  }

  X.route((p) => p[0] === 'requests' && !p[1], (page, parts, q) => {
    X.lastListHash = location.hash || '#/requests';
    const cur = { sel: q.get('peek') || null, pinned: null, pending: 0, live: false };
    const actions = [btn('批量对照', () => X.openBatch()), btn('导出', () => X.openExport()), btn('⟳ 实时', null, 'live-btn')];
    page.appendChild(X.pageHead('请求追溯', `${X.scopeLabel()} · 最近 24 小时`, actions));
    const liveBtn = actions[2]; liveBtn.setAttribute('aria-pressed', 'false'); liveBtn.title = '实时模式（l）';

    // ---- chips with counts that follow the other conditions
    const base = baseRows(q); const curChip = q.get('chip') || ''; const chipsEl = h('<div class="chips" role="group" aria-label="快捷筛选"></div>');
    const countOf = (key) => {
      let rows = base.rows; if (key !== 'bypass' && !base.includeAll) rows = rows.filter(isJudged);
      return rows.filter(chipTest[key]).length;
    };
    CHIPS.forEach(([key, label]) => {
      const c = h(`<button type="button" class="chip ${curChip === key ? 'active' : ''}" aria-pressed="${curChip === key}">${esc(label)} <span class="n">${countOf(key)}</span></button>`);
      c.onclick = () => X.setQuery({ chip: key, peek: null });
      chipsEl.appendChild(c);
    });
    const unknownN = base.rows.filter((r) => r.decision_path === 'unknown_site').length;
    if (unknownN && curChip !== 'bypass') {
      const l = h(`<span class="chips-note">另有 ${unknownN} 条未知站点请求 · <a href="#/requests?q=decision:unknown_site">查看</a></span>`); chipsEl.appendChild(l);
    }
    page.appendChild(chipsEl);

    // ---- filter bar
    const dslText = q.get('q') || '';
    const fb = h(`<div class="filterbar"><div class="dsl" id="dslbox">⌕ <input type="text" id="dslin" value="${esc(dslText)}" placeholder="outcome:would_block path:/rest/*  （按 / 聚焦）" aria-label="筛选条件" autocomplete="off" spellcheck="false"><div class="suggest hidden" role="listbox"></div></div>
      <button type="button" class="btn sm" id="addcond">＋条件</button>
      <label class="check"><input type="checkbox" id="scopebox" ${q.get('scope') === 'all' ? 'checked' : ''}> 含绕过请求</label></div>`);
    page.appendChild(fb);
    const dslIn = $('#dslin', fb); const errBox = h('<div class="dslerr hidden" role="alert"></div>'); page.appendChild(errBox);
    const checkDsl = () => {
      const r = X.parseDsl(dslIn.value);
      $('#dslbox', fb).classList.toggle('bad', r.errors.length > 0); errBox.classList.toggle('hidden', !r.errors.length);
      errBox.innerHTML = r.errors.map((e) => `<span class="mono">${esc(e.tok)}</span> ${esc(e.msg)}`).join('；');
      return r;
    };
    const sug = $('.suggest', fb);
    const showSuggest = () => {
      const tok = dslIn.value.split(/\s+/).pop(); let list = [];
      if (tok && !tok.includes(':') && !/[<>]/.test(tok)) list = KEYS.filter((k) => k.startsWith(tok) && k !== tok).map((k) => [`${k}:`, KEY_HELP[k]]);
      else if (tok.includes(':')) { const [k, v] = [tok.slice(0, tok.indexOf(':')), tok.slice(tok.indexOf(':') + 1)]; const last = v.split(',').pop(); if (ENUMS[k]) list = ENUMS[k].filter((x) => x.toLowerCase().startsWith(last.toLowerCase()) && x !== last).slice(0, 8).map((x) => [x, '']); }
      sug.classList.toggle('hidden', !list.length); sug.innerHTML = '';
      list.forEach(([val, help]) => {
        const it = h(`<button type="button" class="sugitem" role="option"><span class="mono">${esc(val)}</span><span class="dim">${esc(help)}</span></button>`);
        it.onmousedown = (e) => { e.preventDefault(); const parts2 = dslIn.value.split(/\s+/); const lastTok = parts2.pop(); const ci = lastTok.lastIndexOf(','); const ki = lastTok.indexOf(':');
          parts2.push(ki < 0 ? val : lastTok.slice(0, (ci > ki ? ci + 1 : ki + 1)) + val); dslIn.value = parts2.join(' ') + (val.endsWith(':') ? '' : ' '); dslIn.focus(); showSuggest(); checkDsl(); };
        sug.appendChild(it);
      });
    };
    dslIn.oninput = () => { checkDsl(); showSuggest(); };
    dslIn.onblur = () => setTimeout(() => sug.classList.add('hidden'), 120);
    dslIn.onkeydown = (e) => { if (e.key === 'Enter') { const r = checkDsl(); if (!r.errors.length) X.setQuery({ q: dslIn.value.trim(), peek: null }); } else if (e.key === 'Escape') { dslIn.blur(); } };
    $('#scopebox', fb).onchange = (e) => X.setQuery({ scope: e.target.checked ? 'all' : null, peek: null });
    $('#addcond', fb).onclick = (e) => {
      const box = h('<div class="menu wide"></div>');
      KEYS.forEach((k) => { const b = h(`<button type="button" class="menuitem"><span class="mono">${k}:</span><span class="dim">${esc(KEY_HELP[k])}</span></button>`); b.onclick = () => { X.closePopover(); dslIn.value = `${dslIn.value.trim()} ${k}:`.trim(); dslIn.focus(); showSuggest(); }; box.appendChild(b); });
      X.popover(e.currentTarget, box);
    };
    if (base.autoIncluded) page.appendChild(h('<div class="notice soft">已包含绕过请求：按请求 ID、会话或精确路径查找时不隐藏绕过记录。</div>'));
    const cw = X.customWindow(q);
    if (cw) {
      const nb = h(`<div class="notice soft">时间窗 ${X.fmtHMS(cw.since)}–${X.fmtHMS(cw.until)} · <a href="${esc(X.hashWith({ range: '24h', since: null, until: null }))}">清除</a></div>`); page.appendChild(nb);
    }
    const banners = gapBanners(q);
    banners.forEach((b) => page.appendChild(h(`<div class="banner ${b.kind}" role="status"><span class="bi">${b.kind === 'lost' ? '▲' : 'i'}</span><span>${esc(b.text)} · <a href="${esc(b.href)}">${esc(b.act)}</a></span></div>`)));
    if (banners.length) page.appendChild(h('<div class="dim small" style="margin:-6px 0 10px">缺口数据来自网关心跳；网关重启会清空缺口历史，所以重启之前的缺口看不到。</div>'));

    // ---- table + peek
    const dslBad = X.parseDsl(dslText).errors.length > 0; const { rows } = dslBad ? { rows: [] } : X.filterRows(q);
    if (dslBad) checkDsl();
    const split = h('<div class="split reqsplit"></div>'); const left = h('<div class="leftcol"></div>'); const peekCol = h('<div class="peekcol"></div>');
    const newBar = h('<button type="button" class="newbar hidden"></button>');
    left.appendChild(newBar);
    const tbl = requestTable(rows, { onSelect: (id) => select(id) }); left.appendChild(tbl);
    left.appendChild(h(`<div class="dim small tfoot">共 ${rows.length} 条${rows.length === 1 ? '' : '；'}原型只含 ${M.RECORDS.length} 条样例记录，总览里的数字是示意，与列表不对应。</div>`));
    split.appendChild(left); split.appendChild(peekCol); page.appendChild(split);
    const lbl = $('.tfoot', left); if (rows.length < 2) lbl.textContent = `共 ${rows.length} 条；原型只含 ${M.RECORDS.length} 条样例记录，总览里的数字是示意，与列表不对应。`;
    if (!rows.length) {
      const e = $('.empty', tbl); const hints = [];
      if (curChip) hints.push(['清除快捷筛选', () => X.setQuery({ chip: null })]);
      if (dslText) hints.push(['清除条件', () => X.setQuery({ q: null })]);
      if (q.get('scope') !== 'all') hints.push(['包含绕过请求', () => X.setQuery({ scope: 'all' })]);
      if (e && dslBad) e.innerHTML = '<div class="big">条件有误，没有查询</div><div class="dim">修正上面标红的条件，按回车再查</div>';
      else if (e) { e.innerHTML = '<div class="big">没有匹配的请求</div><div class="dim">可以放宽这些条件：</div><div class="hintbtns"></div>'; hints.forEach(([l, f]) => e.querySelector('.hintbtns').appendChild(btn(l, f, 'sm'))); }
    }

    function peekOpen() { split.classList.toggle('nopeek', !cur.sel); }
    function renderPeek() {
      peekCol.innerHTML = ''; const id = cur.pinned || cur.sel; if (!id) return;
      const el = X.peekPanel(id, { pinned: !!cur.pinned, onClose: closePeek, onPin: () => { cur.pinned = cur.pinned ? null : cur.sel; renderPeek(); } });
      peekCol.appendChild(el);
    }
    function closePeek() { cur.sel = null; cur.pinned = null; $$('tbody tr.sel', tbl).forEach((t) => { t.classList.remove('sel'); t.setAttribute('aria-selected', 'false'); }); peekOpen(); peekCol.innerHTML = ''; X.setQuery({ peek: null }, true); }
    function select(id, scroll) {
      cur.sel = id; $$('tbody tr', tbl).forEach((t) => { const on = t.dataset.id === id; t.classList.toggle('sel', on); t.setAttribute('aria-selected', String(on)); if (on && scroll) t.scrollIntoView({ block: 'nearest' }); });
      peekOpen(); if (!cur.pinned) renderPeek(); X.setQuery({ peek: id }, true);
    }
    if (cur.sel && M.RECORD_BY_ID[cur.sel]) select(cur.sel); else { cur.sel = null; peekOpen(); }

    const trs = () => $$('tbody tr[data-id]', tbl);
    const move = (d) => { const l = trs(); if (!l.length) return; let i = l.findIndex((t) => t.dataset.id === cur.sel); i = i < 0 ? (d > 0 ? 0 : l.length - 1) : Math.max(0, Math.min(l.length - 1, i + d)); select(l[i].dataset.id, true); };
    X.pageKeys.j = () => move(1); X.pageKeys.k = () => move(-1);
    X.pageKeys.Enter = () => { if (cur.sel) go(`#/requests/${cur.sel}`); };
    X.pageKeys.Escape = () => { if (cur.sel) closePeek(); };
    X.pageKeys['/'] = (e) => { e.preventDefault(); dslIn.focus(); dslIn.select(); };
    X.pageKeys.c = () => { if (cur.sel) X.copy(cur.sel, '已复制请求 ID'); };

    // ---- live mode (docs/06 6.4.3)
    let timer = null; let lastAct = Date.now();
    const noteAct = () => { lastAct = Date.now(); };
    page.addEventListener('mousemove', noteAct);
    const stopLive = (msg) => { cur.live = false; clearInterval(timer); timer = null; liveBtn.classList.remove('on'); liveBtn.setAttribute('aria-pressed', 'false'); liveBtn.textContent = '⟳ 实时'; if (msg) X.toast(msg); };
    const toggleLive = () => {
      if (cur.live) { stopLive(); return; }
      cur.live = true; liveBtn.classList.add('on'); liveBtn.setAttribute('aria-pressed', 'true'); liveBtn.textContent = '■ 实时中（点击暂停）'; lastAct = Date.now();
      timer = setInterval(() => {
        if (Date.now() - lastAct > 10 * 60000) { stopLive('实时模式已暂停（10 分钟无操作）'); return; }
        const r = liveRecord(); const probe = new URLSearchParams(q.toString()); const passes = X.filterRows(probe).rows.some((x) => x.request_id === r.request_id);
        if (!passes) return;
        const scrolled = page.scrollTop > 40 || cur.sel;
        if (scrolled) { cur.pending += 1; newBar.textContent = `↑ ${cur.pending} 条新请求`; newBar.classList.remove('hidden'); newBar.setAttribute('aria-live', 'polite'); return; }
        insertLive(r);
      }, 2400);
      X.toast('实时模式：每 2 秒读取最近的请求（回看 60 秒，按请求 ID 去重）');
    };
    function insertLive(r) {
      const showSite = X.state.site === 'all'; const tr = h(`<table><tbody>${rowHtml(r, showSite)}</tbody></table>`).querySelector('tr'); tr.classList.add('fadein');
      tr.onclick = (e) => { if (!e.target.closest('.rowmenu')) select(r.request_id); }; tr.ondblclick = () => go(`#/requests/${r.request_id}`);
      const mb = tr.querySelector('.rowmenu'); mb.onclick = (e) => { e.stopPropagation(); rowMenu(mb, r); };
      const tb = $('tbody', tbl); if (!tb) return; tb.insertBefore(tr, tb.firstChild);
      $$('.chip .n', chipsEl).forEach((el, i) => { const key = CHIPS[i][0]; el.textContent = String(Number(el.textContent) + (chipTest[key](r) && (key === 'bypass' ? r.decision_path === 'bypass' : isJudged(r)) ? 1 : 0)); });
    }
    newBar.onclick = () => { cur.pending = 0; newBar.classList.add('hidden'); X.render(); };
    liveBtn.onclick = toggleLive; X.pageKeys.l = toggleLive;
    X.pageCleanup = () => { if (timer) clearInterval(timer); };
    if (q.get('live') === '1') toggleLive();
  });

  // ================================================================ PEEK PANEL (shared by list and timeline)
  X.peekPanel = (id, o = {}) => {
    const r = M.RECORD_BY_ID[id]; const p = h(`<div class="peek ${o.pinned ? 'pinned' : ''}" role="complementary" aria-label="请求预览"></div>`);
    p.appendChild(h(`<div class="peek-bar"><span class="dim small">${o.pinned ? '已固定 · 浏览其他行时保留' : '预览'}</span><span class="sp"></span>${o.onPin ? `<button type="button" class="linkbtn" id="pin">${o.pinned ? '取消固定' : '固定'}</button>` : ''}<button type="button" class="closex sm" aria-label="关闭预览">×</button></div>`));
    p.querySelector('.closex').onclick = () => o.onClose && o.onClose(); if (o.onPin) p.querySelector('#pin').onclick = o.onPin;
    if (!r) { p.appendChild(h(`<div class="empty">找不到 ${esc(id)}</div>`)); return p; }
    p.appendChild(h(`<h3 class="mono breakall">${esc(r.method)} ${esc(r.path)}</h3>`));
    p.appendChild(h(`<div class="peek-tags">${X.outPill(r.outcome)} ${X.dpBadge(r.decision_path)}</div>`));
    p.appendChild(h(`<div class="explain">${esc(X.explain(r))}</div>`));
    const need = ((r.trace || {}).values || []).filter((v) => !v.inert && !v.verified);
    if (need.length) {
      const rowsHtml = need.slice(0, 5).map((v) => {
        const hint = X.HINT[X.valueHint(v)]; const s0 = (v.sources || [])[0];
        return `<div class="pv"><span class="mono">${esc(v.at)}</span> <span class="mono">${v.redacted ? '已脱敏' : safeText(mid(v.value, 32))}</span> <span class="hint ${hint.cls}">${hint.g} ${esc(hint.text)}</span>${s0 && s0.request_id ? ` <a class="srcchip" href="#/requests/${esc(s0.request_id)}">${esc(s0.field)} · ${esc(mid(s0.request, 26))}</a>` : ''}</div>`;
      }).join('');
      p.appendChild(h(`<div class="peek-sec"><div class="k">需核验的值 ${need.length}</div>${rowsHtml}</div>`));
    }
    const t = r.trace.timing;
    p.appendChild(h(`<div class="kv"><div class="k">会话</div><div>${r.session ? `<a class="mono" href="#/sessions/${esc(r.session)}?at=${esc(r.request_id)}">${esc(X.shortSess(r.session))}</a> · ${r.context === 'address' ? '按地址' : `已 ${r.trace.session ? Math.max(1, Math.round(r.trace.session.age_seconds / 60)) : 0} 分钟`}` : '—'}</div>
      <div class="k">耗时</div><div class="tnum">${r.total_ms} ms${t ? `（判定 ${t.judge_ms}${t.origin_ms != null ? ` · 源站 ${t.origin_ms}` : ''}）` : ''}</div><div class="k">请求 ID</div><div class="mono small">${X.idCell(r.request_id)} · ${esc(r.edge)} · v${r.site_version == null ? '—' : r.site_version}</div></div>`));
    if (r.jevFull) p.appendChild(X.miniAnswer(r.jevFull));
    const foot = h('<div class="peek-foot"></div>');
    foot.appendChild(btn('打开详情 ⏎', () => go(`#/requests/${id}`), 'primary sm'));
    if (r.session) foot.appendChild(btn('会话时间线', () => go(`#/sessions/${r.session}?at=${id}`), 'sm'));
    foot.appendChild(btn('复制 ID', () => X.copy(id, '已复制请求 ID'), 'sm'));
    p.appendChild(foot); return p;
  };

  // ================================================================ BATCH LOOKUP (docs/06 6.4.3)
  const norm = (v) => {
    const s = String(v == null ? '' : v).trim().toLowerCase();
    if (['blocked', 'block', 'deny', 'denied', '403', '401', '拦截'].includes(s)) return 'block';
    if (['allowed', 'allow', 'pass', 'ok', '200', '放行'].includes(s)) return 'allow';
    return null;
  };
  const SAMPLE_TSV = () => {
    const t8 = X.now() - 8 * 86400000; const old = `req_${Math.round(t8).toString(16).padStart(12, '0')}a1b2c3d4e5f60718293a`;
    const rows = [
      [M.ID.j_basket6, '2026-11-01T13:16:26Z', 'GET', '200', 'blocked', 'P-017'], [M.ID.j_basket1, '2026-11-01T13:16:25Z', 'GET', '200', 'allowed', 'P-016'],
      [M.ID.j_bypass, '2026-11-01T13:15:40Z', 'GET', '200', 'blocked', 'P-021'], [M.ID.e_p8, '2026-11-01T13:15:02Z', 'GET', '403', 'blocked', 'P-033'],
      [M.ID.j_cards3, '2026-11-01T13:16:44Z', 'GET', '200', 'allowed', 'P-019'], [M.ID.j_deliv, '2026-11-01T13:04:04Z', 'GET', '200', 'allowed', 'P-009'], [old, '2026-10-24T13:00:00Z', 'GET', '200', 'allowed', 'P-001'],
    ];
    return ['x_xshield_request_id\tstarted_at\tmethod\thttp_status\toutcome\tprobe_id'].concat(rows.map((r) => r.join('\t'))).join('\n');
  };
  const csvSafe = (s) => (/^[=+\-@\t\r]/.test(String(s)) ? `'${s}` : String(s));
  X.openBatch = (prefill) => {
    const body = h(`<div><div class="field"><label for="batchin">① 粘贴：测试套件的 TSV、日志或任意文本（最多 1000 个 ID）</label>
      <textarea id="batchin" rows="6" class="mono" placeholder="x_xshield_request_id&#9;started_at&#9;method&#9;http_status&#9;outcome&#9;probe_id&#10;req_01a19741107477ff9224781077354552&#9;…" spellcheck="false"></textarea>
      <div class="batchmeta"><span id="bmeta" class="dim">还没有内容</span><span class="sp"></span><label class="check" id="expwrap" hidden>预期结论列 <select id="expcol"></select></label><button type="button" class="linkbtn" id="sample">填入示例</button></div></div><div id="batchres"></div></div>`);
    const ta = $('#batchin', body);
    const parse = () => {
      const text = ta.value; const ids = [...new Set(text.match(/req_[0-9a-f]{32}/g) || [])]; const all = (text.match(/req_[0-9a-f]{32}/g) || []).length;
      const lines = text.split('\n'); const hdr = lines[0] && !/req_[0-9a-f]{32}/.test(lines[0]) && lines[0].includes('\t') ? lines[0].split('\t') : null;
      return { ids, all, hdr, lines };
    };
    const refresh = () => {
      const p = parse(); const meta = $('#bmeta', body);
      meta.textContent = p.ids.length ? `识别到 ${p.all} 个请求 ID（去重后 ${p.ids.length}）${p.hdr ? ` · 表头 ${p.hdr.length} 列` : ''}` : '没有识别到请求 ID';
      const sel = $('#expcol', body); sel.innerHTML = '<option value="-1">不对照</option>'; $('#expwrap', body).hidden = !p.hdr;
      if (p.hdr) { p.hdr.forEach((c, i) => { const o = h(`<option value="${i}">${esc(c)}</option>`); sel.appendChild(o); }); const guess = p.hdr.findIndex((c) => ['outcome', 'expected', 'expect', '预期'].includes(c.trim().toLowerCase())); sel.value = String(guess); }
    };
    ta.oninput = refresh; $('#sample', body).onclick = () => { ta.value = SAMPLE_TSV(); refresh(); run(); };
    let results = [];
    function run() {
      const p = parse(); const res = $('#batchres', body); res.innerHTML = '';
      if (!p.ids.length) { res.appendChild(h('<div class="empty">没有识别到请求 ID</div>')); return; }
      if (p.ids.length > 1000) { res.appendChild(h('<div class="notice">一次最多对照 1000 个请求 ID</div>')); return; }
      const col = Number($('#expcol', body).value);
      const lineOf = {}; p.lines.forEach((ln) => { const m = ln.match(/req_[0-9a-f]{32}/); if (m && !lineOf[m[0]]) lineOf[m[0]] = ln.split('\t'); });
      const extraCols = p.hdr ? p.hdr.map((c, i) => [c, i]).filter(([c, i]) => i !== col && !/req_|request_id/i.test(c) && !['started_at', 'method', 'http_status'].includes(c.trim())).slice(0, 3) : [];
      results = p.ids.map((id) => {
        const r = M.RECORD_BY_ID[id]; const cells = lineOf[id] || []; const exp = col >= 0 ? norm(cells[col]) : null;
        const pastedStatus = p.hdr ? cells[p.hdr.findIndex((c) => c.trim() === 'http_status')] : null;
        const actual = r ? (r.outcome === 'blocked' || r.outcome === 'would_block' ? 'block' : 'allow') : null;
        let ok = '—'; let why = '';
        if (!r) { ok = '?'; why = `查不到：${notFoundReason(id)}`; } else if (exp) { ok = exp === actual ? '✓' : '✗'; if (ok === '✗') why = r.decision_path === 'bypass' ? `命中绕过 ${r.trace.bypass}` : `实际 ${X.OUT[r.outcome][0]}（${X.DP[r.decision_path].name}）`; else if (r.outcome === 'unjudged') why = '未经判定放行'; }
        return { id, r, exp, actual, ok, why, extra: extraCols.map(([c, i]) => cells[i] || ''), pastedStatus };
      });
      const found = results.filter((x) => x.r).length; const miss = results.length - found; const bad = results.filter((x) => x.ok === '✗').length;
      res.appendChild(h(`<div class="field"><label>② 结果：${results.length} 个 · 找到 ${found} · 查不到 ${miss}${col >= 0 ? ` · 预期不一致 ${bad}` : ''}</label>
        <div class="batchfilter"><label class="check"><input type="checkbox" id="onlybad"> 只看不一致</label><label class="check"><input type="checkbox" id="onlymiss"> 只看查不到</label><span class="sp"></span><button type="button" class="linkbtn" id="copyres">复制结果（TSV）</button></div></div>`));
      const tbl = h(`<div class="tablewrap short"><table class="data"><thead><tr><th>请求 ID</th>${extraCols.map(([c]) => `<th>${esc(c)}</th>`).join('')}${col >= 0 ? '<th>预期</th>' : ''}<th>实际结论</th><th>判定路径</th><th>状态 粘贴/实际</th>${col >= 0 ? '<th>一致</th>' : ''}</tr></thead><tbody></tbody></table></div>`);
      const draw = () => {
        const ob = $('#onlybad', res).checked; const om = $('#onlymiss', res).checked; const tb = $('tbody', tbl); tb.innerHTML = '';
        results.filter((x) => (!ob || x.ok === '✗') && (!om || !x.r)).forEach((x) => {
          const tr = h(`<tr class="${x.ok === '✗' ? 'bad' : ''}"><td>${x.r ? `<a class="mono" href="#/requests/${esc(x.id)}">…${esc(x.id.slice(-8))}</a>` : `<span class="mono dim">…${esc(x.id.slice(-8))}</span>`}</td>${x.extra.map((c) => `<td class="mono">${safeText(c)}</td>`).join('')}
            ${col >= 0 ? `<td>${x.exp ? (x.exp === 'block' ? '拦截' : '放行') : '—'}</td>` : ''}<td>${x.r ? X.outPill(x.r.outcome) : '<span class="dim">查不到</span>'}</td><td>${x.r ? X.dpBadge(x.r.decision_path) : '—'}</td>
            <td class="tnum">${x.r ? `${esc(x.pastedStatus || '—')} / ${x.r.status}` : '—'}</td>${col >= 0 ? `<td>${x.ok === '✓' ? '<span class="okmark">✓</span>' : x.ok === '✗' ? '<span class="badmark">✗</span>' : x.ok === '?' ? '?' : '—'} <span class="dim small">${esc(x.why)}</span></td>` : ''}</tr>`);
          tb.appendChild(tr);
        });
      };
      res.appendChild(tbl); draw(); $('#onlybad', res).onchange = draw; $('#onlymiss', res).onchange = draw;
      $('#copyres', res).onclick = () => {
        const head = ['request_id', ...extraCols.map(([c]) => c), 'expected', 'actual_outcome', 'decision_path', 'match', 'note'];
        const lines = results.map((x) => [x.id, ...x.extra, x.exp || '', x.r ? x.r.outcome : '', x.r ? x.r.decision_path : '', x.ok, x.why].map(csvSafe).join('\t'));
        X.copy([head.join('\t'), ...lines].join('\n'), '已复制结果（TSV，公式前缀已转义）');
      };
    }
    const runBtn = btn('对照 ⏎', run, 'primary'); const api = X.dialog('批量对照', body, [btn('关闭', () => api.close()), runBtn], { wide: true });
    ta.onkeydown = (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run(); };
    if (prefill) { ta.value = prefill; refresh(); run(); }
  };
  X.openExport = () => {
    const q = X.parseHash().q; const n0 = X.filterRows(q).rows.length;
    const body = h(`<div><div class="field"><label>格式</label><div class="radio-seg"><label><input type="radio" name="fmt" checked> JSONL（完整记录）</label><label><input type="radio" name="fmt"> CSV（列表列）</label></div></div>
      <div class="field"><label>范围</label><div>当前筛选条件下约 ${n0} 行（来自计数接口；超过 10 万行时提示缩小范围）</div></div>
      <div class="notice">导出文件包含请求值、查询串和客户端 IP，属于个人信息，请按数据规定保管。</div></div>`);
    const api = X.dialog('导出', body, [btn('取消', () => api.close()), btn('导出（原型不生成文件）', () => { api.close(); X.toast('原型不生成导出文件'); }, 'primary')]);
  };

  // ================================================================ REQUEST DETAIL
  const tabDefs = (r) => [['pipeline', '判定过程'], ['values', `请求值 ${(r.trace.values || []).length}`], ['jev', 'Jev 上下文'], ['session', '会话上下文'], ['raw', '原始记录']];
  const sessionRows = (r) => {
    if (!r.session && !(r.trace.response && r.trace.response.issued_session)) return [];
    const label = r.session; const issued = r.trace.response && r.trace.response.issued_session;
    return M.RECORDS.filter((x) => (label && x.session === label) || (x.trace.response && x.trace.response.issued_session === label && label) || (issued && (x.session === issued || x.request_id === r.request_id))).sort((a, b) => a.at_millis - b.at_millis);
  };
  X.sessionRows = (label) => {
    const s = M.SESSIONS.find((x) => x.label === label); const rows = M.RECORDS.filter((r) => r.session === label);
    const issuer = s && s.issued_by && M.RECORD_BY_ID[s.issued_by]; if (issuer && !rows.includes(issuer)) rows.push(issuer);
    return rows.sort((a, b) => a.at_millis - b.at_millis);
  };

  X.route((p) => p[0] === 'requests' && p[1], (page, parts, q) => {
    const id = parts[1]; const r = M.RECORD_BY_ID[id];
    const back = btn('← 请求追溯', () => { X.restoreScroll = true; go(X.lastListHash || '#/requests'); });
    if (!r) {
      page.appendChild(X.pageHead('请求详情', '', [back]));
      page.appendChild(h(`<div class="empty"><div class="big">找不到这个请求</div><div class="dim">${esc(notFoundReason(id))}</div><div class="mono small" style="margin-top:8px">${esc(id)}</div><div class="hintbtns"><a class="btn sm" href="#/requests?q=${encodeURIComponent(id)}">在请求追溯中查找</a></div></div>`));
      return;
    }
    const sess = r.session ? X.sessionRows(r.session) : []; const si = sess.findIndex((x) => x.request_id === id);
    const prev = si > 0 ? sess[si - 1] : null; const next = si >= 0 && si < sess.length - 1 ? sess[si + 1] : null;
    const topRow = h('<div class="detail-top"></div>'); topRow.appendChild(back);
    topRow.appendChild(h(`<span class="mono dim small idfull">${esc(r.site || '未知站点')} · ${esc(id)}</span>`));
    const cp = h('<button type="button" class="linkbtn" aria-label="复制请求 ID">⧉ 复制</button>'); cp.onclick = () => X.copy(id, '已复制请求 ID'); topRow.appendChild(cp);
    topRow.appendChild(h('<span class="sp"></span>'));
    const navBtn = (label, rec, key) => { const b = btn(label, rec ? () => go(`#/requests/${rec.request_id}${location.hash.includes('?') ? `?${location.hash.split('?')[1]}` : ''}`) : null, 'sm'); b.disabled = !rec; b.title = rec ? `${rec.method} ${rec.path}（${key}）` : '同一会话里没有更多请求'; return b; };
    topRow.appendChild(navBtn('‹ 上一个', prev, '[')); if (r.session) { const sb = btn('同一会话', () => go(`#/sessions/${r.session}?at=${id}`), 'sm'); topRow.appendChild(sb); } topRow.appendChild(navBtn('下一个 ›', next, ']'));
    page.appendChild(topRow);
    X.pageKeys['['] = () => prev && go(`#/requests/${prev.request_id}`); X.pageKeys[']'] = () => next && go(`#/requests/${next.request_id}`);

    const t = r.trace; const ex = X.explainParts(r); const tm = t.timing;
    const spec = (X.site(r.site) || {}).spec;
    const head = h(`<div class="detail-head"><div class="dh-row"><div><div class="req">${esc(r.method)} <span class="mono">${esc(r.path)}</span></div>${r.query ? `<div class="mono small dim breakall">?${esc(r.query)}</div>` : ''}</div><div class="dh-tags">${X.outPill(r.outcome)} ${X.dpBadge(r.decision_path)}</div></div>
      <div class="explain">${esc(ex.reason)}${ex.act ? ` <b>${esc(ex.act)}</b>` : ''}</div>
      <div class="meta"><span title="UTC ${esc(X.fmtUtc(r.at_millis))}">${esc(X.fmtFull(r.at_millis))}（UTC ${esc(X.fmtUtc(r.at_millis).slice(11, 23))}）</span><span>状态 ${r.status == null ? '—' : r.status}</span>
        <span>${r.total_ms} ms${tm ? `（判定 ${tm.judge_ms}${tm.origin_ms != null ? ` · 源站 ${tm.origin_ms}` : ''}）` : ''}</span>
        ${r.site_version != null ? `<span>配置 <a href="#/sites/${esc(r.site)}?tab=history&diff=${r.site_version}..${(X.site(r.site) || {}).version}">v${r.site_version}</a></span>` : ''}<span>${esc(r.edge)}</span>
        ${r.session ? `<span>${r.context === 'address' ? '地址上下文' : '会话'} <a href="#/sessions/${esc(r.session)}?at=${esc(id)}" class="mono">${esc(r.session)}</a>${t.session ? `（已 ${X.dur(t.session.age_seconds * 1000)}）` : ''}</span>` : ''}<span>客户端 ${esc(r.client)}</span></div></div>`);
    if (t.v === 0) head.insertBefore(h('<div class="notice">旧格式记录：没有判定依据</div>'), head.firstChild);
    page.appendChild(head); void spec;

    const tabId = q.get('tab') || 'pipeline'; const tabs = h('<div class="tabs" role="tablist"></div>');
    tabDefs(r).forEach(([k, lbl], i) => {
      const b = h(`<button type="button" class="tab ${tabId === k ? 'active' : ''}" role="tab" aria-selected="${tabId === k}" title="按 ${i + 1} 切换">${esc(lbl)}</button>`);
      b.onclick = () => X.setQuery({ tab: k === 'pipeline' ? null : k }); tabs.appendChild(b); X.pageKeys[String(i + 1)] = () => X.setQuery({ tab: k === 'pipeline' ? null : k });
    });
    page.appendChild(tabs);
    const layout = h('<div class="split detailsplit"><div id="tabbody" class="tabbody"></div><div class="rail" id="rail"></div></div>'); page.appendChild(layout);
    const body = $('#tabbody', layout);
    if (tabId === 'pipeline') body.appendChild(pipelineView(r));
    else if (tabId === 'values') body.appendChild(valuesView(r, q));
    else if (tabId === 'jev') body.appendChild(X.jevTab(r, q));
    else if (tabId === 'session') body.appendChild(sessionCtxView(r));
    else if (tabId === 'raw') body.appendChild(rawView(r));
    renderRail($('#rail', layout), r, prev, next);
    X.pageKeys.c = () => X.copy(id, '已复制请求 ID');
    X.pageKeys.Escape = () => { X.restoreScroll = true; go(X.lastListHash || '#/requests'); };
  });

  // ---- pipeline (docs/06 6.4.4 tab 1)
  function waterfall(r) {
    const t = r.trace.timing; if (!t) return null;
    const total = Math.max(t.total_ms, 1); const jevMs = r.jevFull ? r.jevFull.millis || 0 : 0;
    const origin = t.origin_ms || 0; const other = Math.max(0, total - t.judge_ms - origin); const jevPart = Math.min(jevMs, t.judge_ms); const judgeRest = t.judge_ms - jevPart;
    const seg = (cls, ms, name) => (ms > 0 ? `<div class="wseg ${cls}" style="flex:${ms}" title="${esc(name)} ${ms} ms · ${Math.max(1, Math.round((ms / total) * 100))}%"></div>` : '');
    const leg = (cls, ms, name) => (ms > 0 ? `<span><i class="sw ${cls}" aria-hidden="true"></i>${esc(name)} <b class="tnum">${ms} ms</b></span>` : '');
    return h(`<div class="waterfall"><div class="wlabel">耗时 <b class="tnum">总计 ${total} ms</b></div>
      <div class="wbar" role="img" aria-label="耗时瀑布条：判定 ${judgeRest} ms，Jev ${jevPart} ms，源站 ${origin} ms，其他 ${other} ms">${seg('judge', judgeRest, '判定')}${seg('jev', jevPart, 'Jev')}${seg('origin', origin, '源站')}${seg('other', other, '其他')}</div>
      <div class="wlegend">${leg('judge', judgeRest, '判定')}${leg('jev', jevPart, 'Jev')}${leg('origin', origin, '源站')}${leg('other', other, '其他')}${jevPart ? `<span class="dim">Jev ${jevPart} ms 在判定 ${t.judge_ms} ms 内</span>` : ''}</div></div>`);
  }
  const DECISIVE = { unknown_site: '站点', bypass: '绕过', body_not_inspectable: '请求体', no_session: '会话', fast_allow: '快速放行', cached_allow: '缓存', jev_allow: 'Jev', jev_deny: 'Jev', jev_unavailable: 'Jev' };
  function pipelineView(r) {
    const t = r.trace; const dp = r.decision_path; const site = X.site(r.site); const spec = site && site.spec; const vals = t.values || []; const nv = vals.filter((v) => !v.inert); const need = nv.filter((v) => !v.verified);
    const steps = []; // [mark, name, note(html), {skip, ms, warn, action}]
    const S = (mark, name, note, o) => steps.push(Object.assign({ mark, name, note }, o || {}));
    if (dp === 'unknown_site') S('–', '站点', `Host ${esc(r.host)} 不属于任何站点`, { skip: true });
    else S('✓', '站点', `${esc(r.site)}（Host ${esc(r.host)}）· 配置 v${r.site_version} · ${spec && spec.mode === 'observe' ? '观察模式' : '拦截模式'}`);
    if (dp !== 'unknown_site') S(dp === 'bypass' ? '✓' : '✓', '绕过', dp === 'bypass' ? `命中 <span class="mono">${esc(t.bypass)}</span>，不判定` : `未命中（${spec ? spec.bypass.length : 0} 条规则）`);
    if (dp === 'body_not_inspectable') S('–', '请求体', '超过 48 KiB 判定上限或没有 Content-Length', { skip: true });
    if (!['bypass', 'unknown_site', 'body_not_inspectable'].includes(dp)) {
      if (dp === 'no_session') S('–', '会话', `没有会话凭证（${spec && spec.session.header ? `请求头 ${esc(spec.session.header)}` : `Cookie ${esc(spec && spec.session.cookie)}`}）`, { skip: true });
      else if (r.context === 'address') S('✓', '会话', `未登录请求，按客户端地址 ${esc(r.client)} 记账（上下文类型：地址）`);
      else S('✓', '会话', `${spec && spec.session.header ? `请求头 ${esc(spec.session.header)}` : `Cookie ${esc(spec && spec.session.cookie)}`} → 会话 <a class="mono" href="#/sessions/${esc(r.session)}?at=${esc(r.request_id)}">${esc(r.session.slice(0, 8))}…</a>（已 ${X.dur(t.session.age_seconds * 1000)}，已见 ${n(t.session.known_values)} 个值）`);
      if (dp !== 'no_session') {
        S(t.entry ? '✓' : '–', '入口', t.entry ? `命中 <span class="mono">${esc(t.entry)}</span>` : '未命中', t.entry ? {} : { skip: true });
        S('✓', '请求值', `${vals.length} 个：${vals.length - nv.length} 个惰性，${nv.length} 个需核验${need.length ? ` → ${need.map((v) => esc(v.key || v.value)).slice(0, 4).join('、')} 未核验` : ' → 全部已核验或为输入'}`);
        if (dp === 'fast_allow') S('✓', '快速放行', nv.length ? '全部已核验，不调用 Jev' : '没有需核验的值，不调用 Jev');
        else S('–', '快速放行', need.length ? `不满足：${need.map((v) => esc(v.key || v.value)).slice(0, 3).join('、')} 未核验` : '不满足', { skip: true });
        if (dp === 'cached_allow') { const src = M.RECORD_BY_ID[t.cache_source]; S('✓', '缓存', `复用一次 Jev 放行：${src ? `<a href="#/requests/${esc(src.request_id)}">${esc(src.method)} ${esc(src.path)}</a>（${X.fmtHMS(src.at_millis)}）` : '来源已过保留期'}`); }
        else if (!['fast_allow'].includes(dp)) S('–', '缓存', '没有可复用的放行', { skip: true });
        else S('–', '缓存', '未检查（已快速放行）', { skip: true });
        if (r.jevFull) {
          const j = r.jevFull; let desc;
          if (j.failure) desc = `${esc(X.failName(j.failure))}${j.failure === 'JEV_CALL_LIMIT' || j.failure === 'JEV_STATE_TOO_LARGE' ? '，没有发出调用' : `（${j.millis} ms，超时设置 ${j.timeout_ms} ms）`}`;
          else desc = `${X.ACCESS[X.argmax(j.access)]} ${esc(X.argmax(j.access))} ${pct(j.access[X.argmax(j.access)])} · ${X.ATTACK[X.argmax(j.attack)]} ${esc(X.argmax(j.attack))} ${pct(j.attack[X.argmax(j.attack)])} · 耗时 ${j.millis} ms（超时设置 ${j.timeout_ms} ms）`;
          S('✦', 'Jev', desc, { ms: j.failure && j.millis === 0 ? null : j.millis, action: true, effect: r.outcome === 'would_block' ? '▲ 本应拦截' : null });
        }
      }
    }
    // the gateway action
    const exec = { allowed: dp === 'bypass' ? '绕过 → 转发' : '放行 → 转发', blocked: `拦截 → 返回 ${r.status}（没有转发）`, would_block: '观察模式 → 转发', unjudged: '未经判定 → 转发' }[r.outcome];
    const forwarded = r.outcome !== 'blocked';
    if (dp !== 'unknown_site') S(forwarded ? '✓' : '–', '执行', `${exec}${forwarded && t.timing && t.timing.origin_ms != null ? `，源站 ${r.status}` : ''}`, forwarded ? { ms: t.timing && t.timing.origin_ms } : { skip: false });
    else S('–', '执行', `返回 ${r.status}`, {});
    if (t.response && forwarded && dp !== 'bypass') {
      const rs = t.response;
      if (rs.observed === 'json') {
        const extra = [];
        if (rs.issued_session) extra.push(`签发会话 <a class="mono" href="#/sessions/${esc(rs.issued_session)}">${esc(rs.issued_session.slice(0, 8))}…</a>`);
        if (rs.entry_passed) extra.push(`会话第一次经过入口 <span class="mono">${esc(r.path)}</span>`);
        S(rs.after_would_block ? '!' : '✓', '学习', `JSON 响应 ${bytes(rs.bytes)}：取出 ${rs.values} 个值，新增 ${rs.new_values} 个${extra.length ? ` · ${extra.join(' · ')}` : ''}`, rs.after_would_block ? { warn: '本应拦截请求的响应也进入了上下文，后续请求可能引用它学到的值（观察模式）' } : {});
      } else S('–', '学习', `未观察（${esc(X.SKIP[rs.skip] || rs.skip)}）`, { skip: true });
    }
    const dec = DECISIVE[dp];
    const wrap = h('<div class="card"><h2>判定过程</h2></div>'); const wf = waterfall(r); if (wf) wrap.appendChild(wf); const list = h('<div class="steps"></div>');
    steps.forEach((s) => {
      const isDec = s.name === dec;
      const row = h(`<div class="step ${s.skip ? 'skip' : ''} ${isDec ? 'decisive' : ''}"><div class="s-mark" aria-hidden="true">${s.mark}</div><div class="s-name">${esc(s.name)}</div><div class="s-note">${s.note}${s.warn ? `<div class="warnline"><span class="lvl-warn">▲</span> ${esc(s.warn)}</div>` : ''}</div>
        <div class="s-right">${s.ms != null ? `<span class="tnum dim">${s.ms} ms</span>` : ''}${isDec ? X.outPill(r.outcome) : ''}</div></div>`);
      if (s.action) { const b = btn('查看 Jev 上下文', () => X.setQuery({ tab: 'jev' }), 'sm'); const bw = h('<div class="s-action"></div>'); bw.appendChild(b); $('.s-note', row).appendChild(bw); }
      list.appendChild(row);
    });
    wrap.appendChild(list); return wrap;
  }

  // ---- values (tab 2)
  function valuesView(r, q) {
    const vals = r.trace.values || []; const wrap = h('<div class="card"><div class="card-head"><h2>请求值</h2><label class="check"><input type="checkbox" id="onlyneed"> 只看需核验的值</label></div></div>');
    if (!vals.length) { wrap.appendChild(h('<div class="empty">这个请求没有拆出请求值</div>')); return wrap; }
    if (r.trace.values_truncated) wrap.appendChild(h('<div class="notice" style="margin-bottom:10px">请求体未结构化或超过 64 KiB 解析上限，只拆出了部分值</div>'));
    const tb = h('<div class="tablewrap"><table class="data vals"><thead><tr><th>位置</th><th>字段</th><th>值</th><th>类型</th><th>已见</th><th>已核验</th><th>来源</th><th title="该值在发给 Jev 的 state.request.values 中的序号">Jev 序号</th></tr></thead><tbody></tbody></table></div>');
    const body = $('tbody', tb); let jevIdx = -1; let inertN = 0; let showInert = false; const hl = q.get('hl');
    const rowsData = vals.map((v) => { if (!v.inert) jevIdx += 1; return { v, idx: v.inert ? null : jevIdx }; });
    const draw = () => {
      body.innerHTML = ''; const onlyNeed = $('#onlyneed', wrap).checked; inertN = rowsData.filter((x) => x.v.inert).length;
      rowsData.forEach(({ v, idx }) => {
        if (v.inert && !showInert) return; if (onlyNeed && (v.inert || v.verified)) return;
        const srcs = (v.sources || []).slice(0, 3).map((s) => {
          const rec = s.request_id && M.RECORD_BY_ID[s.request_id];
          if (!s.request_id) return `<span class="srcchip off" title="这条来源没有记录请求 ID">${esc(s.field)} · ${esc(mid(s.request, 28))}</span>`;
          if (!rec) return `<span class="srcchip off" title="来源请求已过保留期">${esc(s.field)} · ${esc(mid(s.request, 28))}（已过保留期）</span>`;
          return `<a class="srcchip" href="#/requests/${esc(s.request_id)}" title="${esc(`${rec.method} ${rec.path} · ${rec.status} · ${X.DP[rec.decision_path].name} · ${X.fmtHMS(rec.at_millis)}`)}">${esc(s.field)} · ${esc(mid(s.request, 28))}</a>`;
        }).join('');
        const valCell = v.redacted ? `<span class="redacted" title="字段名含 ${esc(v.key || '')}（内置）">已脱敏 · ${v.len || '?'} 字符</span>` : `<span class="mono breakall">${safeText(mid(v.value, 120))}</span>${v.value.length > 256 ? ' <span class="dim small">已截断</span>' : ''}`;
        const need = !v.inert && !v.verified && v.kind === 'reference';
        const tr = h(`<table><tbody><tr class="${need ? 'vzone' : ''} ${v.inert ? 'inert' : ''} ${hl != null && idx != null && String(idx) === hl ? 'hit' : ''}"><td class="mono">${esc(v.at)}</td><td class="mono">${esc(v.key || '—')}</td><td>${valCell}</td><td>${esc(X.KIND[v.kind] || v.kind)}${v.inert ? ' <span class="dim small">惰性</span>' : ''}</td>
          <td>${v.seen ? '✓' : '<span class="dim">–</span>'}</td><td>${v.verified ? '<span class="okmark">✓</span>' : v.inert ? '' : '<span class="dim">–</span>'}</td><td>${srcs || '<span class="dim">—</span>'}</td>
          <td>${idx == null ? '<span class="dim">—</span>' : r.jevFull ? `<a href="${esc(X.hashWith({ tab: 'jev', jev_view: 'structured', hl: idx }))}" class="mono">#${idx}</a>` : `<span class="mono dim">#${idx}</span>`}</td></tr></tbody></table>`).querySelector('tr');
        body.appendChild(tr);
      });
      if (!showInert && inertN) { const row = h(`<table><tbody><tr class="foldrow"><td colspan="8">另有 ${inertN} 个惰性值（路由词、分页参数）· <button type="button" class="linkbtn">显示</button></td></tr></tbody></table>`).querySelector('tr'); row.querySelector('button').onclick = () => { showInert = true; draw(); }; body.appendChild(row); }
    };
    wrap.appendChild(tb); $('#onlyneed', wrap).onchange = draw; draw();
    wrap.appendChild(h('<div class="dim small" style="margin-top:8px">来源标签表示“首次学到”：同一字段、同一请求再次返回同一个值时不更新来源。左侧琥珀色竖条标出交给 Jev 的、未核验的引用值。</div>'));
    return wrap;
  }

  // ---- session context (tab 4)
  function sessionCtxView(r) {
    const t = r.trace; const wrap = h('<div class="card"><h2>会话上下文</h2></div>');
    if (!t.session) { wrap.appendChild(h('<div class="empty">这条记录没有会话上下文（无会话或绕过）</div>')); return wrap; }
    wrap.appendChild(h(`<div class="kv"><div class="k">已存在</div><div>${X.dur(t.session.age_seconds * 1000)}</div><div class="k">已见值</div><div>${n(t.session.known_values)}</div><div class="k">上下文类型</div><div>${r.context === 'address' ? '地址（未登录请求按客户端地址记账）' : '会话'}</div></div>`));
    wrap.appendChild(h('<h2 style="margin-top:14px">经过的入口</h2>'));
    if ((t.session.entries_passed || []).length) wrap.appendChild(h(`<div>${t.session.entries_passed.map((e) => `<div class="r-item"><a href="#/requests/${esc(e.request_id)}" class="mono">${esc(e.path)}</a> <span class="dim">首次经过 ${X.fmtTime(e.at_millis)}</span></div>`).join('')}</div>`));
    else wrap.appendChild(h('<div class="dim">还没有经过入口</div>'));
    wrap.appendChild(h('<h2 style="margin-top:14px">最近访问</h2>'));
    if ((t.session.recent || []).length) wrap.appendChild(h(`<div>${[...t.session.recent].reverse().map((e) => `<div class="r-item mono">${esc(e.method)} <a href="#/requests/${esc(e.request_id)}">${esc(e.path)}</a> <span class="dim">${e.status} · ${X.fmtTime(e.at_millis)}</span></div>`).join('')}</div>`));
    else wrap.appendChild(h('<div class="dim">最近访问只在调用 Jev 的记录里保存；完整顺序见会话时间线</div>'));
    if (r.session) { const b = btn('打开会话时间线（定位到本请求）', () => go(`#/sessions/${r.session}?at=${r.request_id}`), 'sm'); b.style.marginTop = '14px'; wrap.appendChild(b); }
    return wrap;
  }

  // ---- raw record (tab 5)
  function rawView(r) {
    const summary = { id: r.id, request_id: r.request_id, at_millis: r.at_millis, site: r.site, site_version: r.site_version, edge: r.edge, method: r.method, host: r.host, path: r.path, query: r.query, status: r.status, decision_path: r.decision_path, outcome: r.outcome, session: r.session, context: r.context, client: r.client, total_ms: r.total_ms };
    const doc = { summary, trace: r.trace };
    if (r.jevFull) { const j = Object.assign({}, r.jevFull); doc.jev = j; }
    const wrap = h('<div class="card"><div class="card-head"><h2>原始记录</h2><div class="toolrow"><input type="search" id="rawq" placeholder="搜索键或值" aria-label="搜索原始记录"><span class="dim small" id="rawcount"></span><button type="button" class="linkbtn" id="expall">全部展开</button><button type="button" class="linkbtn" id="colall">全部折叠</button><button type="button" class="linkbtn" id="rawcopy">复制 JSON</button></div></div><div class="treebox"></div></div>');
    const box = $('.treebox', wrap); const tree = X.jsonTree(doc, { open: ['summary'] }); box.appendChild(tree.el);
    $('#expall', wrap).onclick = tree.expandAll; $('#colall', wrap).onclick = tree.collapseAll; $('#rawcopy', wrap).onclick = () => X.copy(JSON.stringify(doc, null, 2), '已复制整条记录的 JSON');
    $('#rawq', wrap).oninput = (e) => { const c = tree.search(e.target.value); $('#rawcount', wrap).textContent = e.target.value ? `${c} 处匹配` : ''; };
    return wrap;
  }

  // ---- related rail
  function renderRail(rail, r, prev, next) {
    const srcIds = []; (r.trace.values || []).forEach((v) => (v.sources || []).forEach((s) => { if (s.request_id && !srcIds.includes(s.request_id)) srcIds.push(s.request_id); }));
    const item = (rec, fallback) => (rec ? `<div class="r-item"><a href="#/requests/${esc(rec.request_id)}"><span class="mono">${esc(rec.method)} ${esc(mid(rec.path, 30))}</span></a><div class="dim small">${esc(X.DP[rec.decision_path].name)} · ${X.fmtTime(rec.at_millis)}</div></div>` : `<div class="r-item dim small">${esc(fallback)}</div>`);
    if (srcIds.length) { const c = h('<div class="card"><h2>值的来源</h2></div>'); srcIds.forEach((sid) => c.appendChild(h(item(M.RECORD_BY_ID[sid], `…${sid.slice(-8)}（已过保留期）`)))); rail.appendChild(c); }
    if (r.trace.cache_source) rail.appendChild(h(`<div class="card"><h2>缓存来源</h2>${item(M.RECORD_BY_ID[r.trace.cache_source], '来源已过保留期')}</div>`));
    if (r.trace.response && r.trace.response.issued_session) rail.appendChild(h(`<div class="card"><h2>签发的会话</h2><div class="r-item"><a href="#/sessions/${esc(r.trace.response.issued_session)}" class="mono">${esc(r.trace.response.issued_session)}</a></div></div>`));
    const sRow = M.SESSIONS.find((s) => s.label === r.session);
    if (sRow && sRow.issued_by && sRow.issued_by !== r.request_id) rail.appendChild(h(`<div class="card"><h2>签发本会话</h2>${item(M.RECORD_BY_ID[sRow.issued_by], '登录请求已过保留期')}</div>`));
    if (prev || next) rail.appendChild(h(`<div class="card"><h2>同一会话</h2>${prev ? `<div class="dim small">‹ 上一个 <kbd>[</kbd></div>${item(prev)}` : ''}${next ? `<div class="dim small">› 下一个 <kbd>]</kbd></div>${item(next)}` : ''}</div>`));
    const same = M.RECORDS.filter((x) => x.site === r.site && x.path === r.path);
    if (same.length) {
      const cnt = {}; same.forEach((x) => { cnt[x.outcome] = (cnt[x.outcome] || 0) + 1; });
      const links = Object.keys(cnt).map((o) => `<a href="#/requests?q=${encodeURIComponent(`path:${r.path} outcome:${o}`)}">${esc(X.OUT[o][0])} ${cnt[o]}</a>`).join(' · ');
      rail.appendChild(h(`<div class="card"><h2>同路径 24 小时</h2><div class="r-item">${links}</div></div>`));
    }
    const ops = h('<div class="card"><h2>操作</h2></div>');
    const add = (label, fn) => { const b = h(`<div class="r-item"><a href="#" role="button">${esc(label)}</a></div>`); b.querySelector('a').onclick = (e) => { e.preventDefault(); fn(); }; ops.appendChild(b); };
    if (r.decision_path === 'no_session' && r.site) add('登记为入口…', () => X.openQuickRule(r, 'entry'));
    if (r.site && (r.decision_path === 'bypass' || r.decision_path === 'body_not_inspectable' || /\.(js|css|png|jpe?g|svg|ico|woff2?)$/.test(r.path))) add('加入绕过…', () => X.openQuickRule(r, 'bypass'));
    if (r.jev && r.jev.failure === 'JEV_TIMEOUT') add('调整 Jev 超时…', () => X.openTuneDialog(r, 'jev_timeout_ms'));
    if (r.jev && r.jev.failure === 'JEV_CALL_LIMIT') add('调整调用上限…', () => X.openTuneDialog(r, r.context === 'address' ? 'address_calls_per_minute' : 'session_calls_per_minute'));
    if (r.site) add('在配置中打开', () => go(`#/sites/${r.site}?tab=config`));
    add('复制链接', () => X.copy(location.href, '已复制链接'));
    rail.appendChild(ops);
  }

  // ================================================================ SESSIONS
  X.route((p) => p[0] === 'sessions' && !p[1], (page, parts, q) => {
    page.appendChild(X.pageHead('会话', `${X.scopeLabel()} · 最近 24 小时`));
    let rows = M.SESSIONS.filter((s) => X.state.site === 'all' || s.site === X.state.site);
    const flag = q.get('flag') || ''; const prefix = q.get('q') || '';
    const cnt = { '': rows.length, blocked: rows.filter((s) => s.blocked + s.would_block > 0).length, jev: rows.filter((s) => s.jev_calls > 0).length };
    if (flag === 'blocked') rows = rows.filter((s) => s.blocked + s.would_block > 0); else if (flag === 'jev') rows = rows.filter((s) => s.jev_calls > 0);
    if (prefix) rows = rows.filter((s) => s.label.startsWith(prefix.toLowerCase()));
    const chips = h('<div class="chips"></div>');
    [['', '全部'], ['blocked', '有拦截'], ['jev', '有 Jev 调用']].forEach(([k, l]) => { const c = h(`<button type="button" class="chip ${flag === k ? 'active' : ''}">${l} <span class="n">${cnt[k]}</span></button>`); c.onclick = () => X.setQuery({ flag: k }); chips.appendChild(c); });
    page.appendChild(chips);
    const fb = h(`<div class="filterbar"><div class="dsl">⌕ <input type="text" value="${esc(prefix)}" placeholder="按会话标签前缀搜索" aria-label="会话标签前缀"></div></div>`); fb.querySelector('input').onkeydown = (e) => { if (e.key === 'Enter') X.setQuery({ q: e.target.value.trim() }); }; page.appendChild(fb);
    const tbl = h('<div class="tablewrap"><table class="data"><thead><tr><th>会话</th><th>上下文</th><th>站点</th><th>首次</th><th>最后活动</th><th>请求</th><th>Jev</th><th>拦截</th><th>本应拦截</th><th>签发它的登录请求</th></tr></thead><tbody></tbody></table></div>');
    rows.sort((a, b) => b.last_at - a.last_at).forEach((s) => {
      const tr = h(`<table><tbody><tr><td class="mono" title="${esc(s.label)}">${esc(X.shortSess(s.label))}</td><td>${s.context === 'session' ? '会话' : '地址'}</td><td>${esc(s.site)}</td><td class="tnum">${X.fmtTime(s.first_at)}</td><td class="tnum">${X.fmtTime(s.last_at)} <span class="dim small">${X.rel(s.last_at)}</span></td><td class="tnum">${s.requests}</td><td class="tnum">${s.jev_calls}</td><td class="tnum">${s.blocked}</td><td class="tnum">${s.would_block}</td><td>${s.issued_by ? `<a class="idcell" href="#/requests/${esc(s.issued_by)}">…${esc(s.issued_by.slice(-8))}</a>` : '<span class="dim">—</span>'}</td></tr></tbody></table>`).querySelector('tr');
      tr.onclick = (e) => { if (!e.target.closest('a')) go(`#/sessions/${s.label}`); }; $('tbody', tbl).appendChild(tr);
    });
    if (!rows.length) tbl.innerHTML = '<div class="empty">没有匹配的会话</div>';
    page.appendChild(tbl);
  });

  X.route((p) => p[0] === 'sessions' && p[1], (page, parts, q) => {
    const label = parts[1]; const s = M.SESSIONS.find((x) => x.label === label); X.rememberRecent('session', label);
    page.appendChild(X.pageHead('会话时间线', label, [btn('← 会话', () => go('#/sessions'))]));
    if (!s) { page.appendChild(h('<div class="empty"><div class="big">找不到这个会话</div><div class="dim">这个会话在当前时间范围内没有记录；会话在 24 小时无活动后过期，网关重启后也会清空</div></div>')); return; }
    const site = X.site(s.site); const only = q.get('only') || '';
    let rows = X.sessionRows(label); const issuer = s.issued_by && M.RECORD_BY_ID[s.issued_by];
    const issuerNote = issuer && issuer.session !== label ? '登录请求发生在会话建立之前，按客户端地址记账，所以它的会话标签不同；它在这里排在第一行。' : '';
    // cumulative seen values: known_values before + learned now
    const cum = []; let run = 0; rows.forEach((r) => { const rs = r.trace.response; const before = r.trace.session ? r.trace.session.known_values : 0; run = Math.max(run, before) + (rs && rs.observed === 'json' ? rs.new_values : 0); cum.push({ r, v: run }); });
    const head = h(`<div class="card" style="margin-bottom:12px"><div class="muted" style="line-height:1.8">${esc(s.site)} · ${site.spec.session.header ? `请求头 ${esc(site.spec.session.header)}` : `Cookie ${esc(site.spec.session.cookie)}`} · ${X.fmtHMS(s.first_at)} – ${X.fmtHMS(s.last_at)}（${X.dur(s.last_at - s.first_at)}）<br>
      签发于 ${issuer ? `<a href="#/requests/${esc(issuer.request_id)}">${esc(issuer.method)} ${esc(issuer.path)} ↗</a>` : '—（网关重启前签发，没有记录）'} · 请求 ${s.requests} · Jev 调用 ${s.jev_calls} · 本应拦截 ${s.would_block} · 拦截 ${s.blocked}</div>
      <div class="cumrow"><span class="dim small">已见值</span><span class="cumspark"></span><b class="tnum">${run ? n(run) : '—'}</b><span class="dim small">累计学到的值，随时间增长</span><span class="sp"></span>
      <label class="check">显示 <select id="onlysel"><option value="">全部请求</option><option value="judged">只看已判定</option><option value="jev">只看 Jev 调用</option><option value="blocks">只看拦截与本应拦截</option></select></label></div>
      ${issuerNote ? `<div class="dim small">${esc(issuerNote)}</div>` : ''}<div class="dim small">绕过请求不识别会话，不在时间线里。</div></div>`);
    if (cum.length > 1) $('.cumspark', head).appendChild(X.spark(cum.map((c) => c.v), 140, 28)); $('#onlysel', head).value = only; $('#onlysel', head).onchange = (e) => X.setQuery({ only: e.target.value });
    page.appendChild(head);
    const f = { judged: (r) => isJudged(r), jev: (r) => !!r.jev, blocks: (r) => ['blocked', 'would_block'].includes(r.outcome) };
    if (only && f[only]) rows = rows.filter(f[only]);
    const gaps = []; M.SYSTEM.edges.forEach((e) => (e.gaps || []).forEach((g) => { if (X.gapLost(g) > 0) gaps.push(Object.assign({ edge: e.edge }, g)); }));
    const maxLearn = Math.max(...rows.map((r) => (r.trace.response && r.trace.response.new_values) || 0), 1);
    const split = h('<div class="split reqsplit nopeek"></div>'); const left = h('<div class="leftcol"></div>'); const peekCol = h('<div class="peekcol"></div>');
    const tl = h('<div class="card"><div class="timeline" role="list"></div></div>'); const tlEl = $('.timeline', tl);
    let last = null; let sel = null;
    rows.forEach((r) => {
      if (last != null && r.at_millis - last > 300000) {
        const g = gaps.find((x) => x.to_ms > last && x.from_ms < r.at_millis);
        tlEl.appendChild(h(`<div class="tl-gap">⋯ ${X.dur(r.at_millis - last)}无请求${g ? ` <span class="gapnote">▲ 其中 ${X.fmtHM(g.from_ms)}–${X.fmtHM(g.to_ms)} ${esc(g.edge)} 有 ${X.gapLost(g)} 条记录未写入（${X.gapCause(g)}），这段时间可能有请求查不到</span>` : ''}</div>`));
      }
      last = r.at_millis;
      const tags = []; const rs = r.trace.response || {};
      if (rs.issued_session === label) tags.push('签发本会话'); if (rs.entry_passed) tags.push('首次经过入口'); if (r.outcome === 'would_block') tags.push('▲ 本应拦截'); if (rs.after_would_block) tags.push('▲ 学自本应拦截请求');
      const learned = rs.observed === 'json' ? rs.new_values : 0;
      const row = h(`<div class="tl-row ${q.get('at') === r.request_id ? 'fadein' : ''}" role="listitem" data-id="${esc(r.request_id)}" tabindex="0">
        <span class="tnum">${X.fmtTime(r.at_millis)}</span><span class="mono">${esc(r.method)}</span><span class="mono path" title="${esc(r.path)}">${esc(mid(r.path, 40))}</span><span class="tnum">${r.status}</span>
        <span>${X.dpBadge(r.decision_path)}</span><span class="tl-tag">${esc(tags.join(' · '))}</span><span class="learn" title="学到 ${learned} 个值"><span class="lbar"><i style="width:${Math.round(Math.sqrt(learned / maxLearn) * 100)}%"></i></span><span class="tnum dim small">${learned ? `学到 ${learned}` : ''}</span></span></div>`);
      row.onclick = () => selectRow(r.request_id); row.ondblclick = () => go(`#/requests/${r.request_id}`);
      row.onkeydown = (e) => { if (e.key === 'Enter') go(`#/requests/${r.request_id}`); };
      tlEl.appendChild(row);
    });
    if (!rows.length) tlEl.appendChild(h('<div class="empty">当前筛选下没有这个会话的记录</div>'));
    left.appendChild(tl); split.appendChild(left); split.appendChild(peekCol); page.appendChild(split);
    function selectRow(id) {
      sel = id; $$('.tl-row', tlEl).forEach((t) => t.classList.toggle('sel', t.dataset.id === id)); split.classList.remove('nopeek'); peekCol.innerHTML = '';
      peekCol.appendChild(X.peekPanel(id, { onClose: () => { sel = null; split.classList.add('nopeek'); $$('.tl-row', tlEl).forEach((t) => t.classList.remove('sel')); } }));
      const el = $(`.tl-row[data-id="${CSS.escape(id)}"]`, tlEl); if (el) el.scrollIntoView({ block: 'nearest' });
    }
    const idx = () => rows.findIndex((r) => r.request_id === sel);
    X.pageKeys.j = () => { const i = idx(); const nx = rows[Math.min(rows.length - 1, i + 1)]; if (nx) selectRow(nx.request_id); };
    X.pageKeys.k = () => { const i = idx(); const nx = rows[Math.max(0, i < 0 ? 0 : i - 1)]; if (nx) selectRow(nx.request_id); };
    X.pageKeys.Enter = () => { if (sel) go(`#/requests/${sel}`); }; X.pageKeys.Escape = () => { if (sel) { sel = null; split.classList.add('nopeek'); $$('.tl-row', tlEl).forEach((t) => t.classList.remove('sel')); } };
    if (q.get('at')) { const el = $(`.tl-row[data-id="${CSS.escape(q.get('at'))}"]`, tlEl); if (el) setTimeout(() => el.scrollIntoView({ block: 'center' }), 30); }
  });

  X.requestTable = requestTable;
})();
