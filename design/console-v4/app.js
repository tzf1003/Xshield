// Xshield v4 console prototype — vanilla JS, no build step.
// Hash routing mirrors docs/06 section 6.2.2. All record text is rendered
// through esc(); nothing is inserted as HTML from the mock data.
'use strict';
(function () {
  const M = window.MOCK;
  const $ = (s, r = document) => r.querySelector(s);

  // ---- escaping + small DOM helpers ----
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }
  // Show control / zero-width / bidi chars as visible escapes (docs/06 6.5.5).
  // Control, zero-width and bidi code points, listed as numbers so this
  // source never contains an invisible character itself.
  const HIDDEN_RANGES = [[0x0000, 0x001f], [0x200b, 0x200f], [0x2060, 0x2060], [0xfeff, 0xfeff], [0x202a, 0x202e], [0x2066, 0x2069]];
  const uesc = (cp) => String.fromCharCode(92) + 'u' + cp.toString(16).padStart(4, '0');
  const HIDDEN = new RegExp('[' + HIDDEN_RANGES.map(([a, b]) => (a === b ? uesc(a) : uesc(a) + '-' + uesc(b))).join('') + ']', 'g');
  function safeText(s) {
    // Escape first, then make the hidden characters visible as \\uXXXX.
    return esc(s).replace(HIDDEN, (c) => `<span class="escw">${esc(uesc(c.codePointAt(0)))}</span>`);
  }
  function h(html) { const t = document.createElement('template'); t.innerHTML = html.trim(); return t.content.firstElementChild; }

  // ---- formatting ----
  const z = (n) => String(n).padStart(2, '0');
  function fmtTime(ms, withDate) {
    const d = new Date(ms);
    const t = `${z(d.getHours())}:${z(d.getMinutes())}:${z(d.getSeconds())}.${String(d.getMilliseconds()).padStart(3, '0')}`;
    return withDate ? `${d.getMonth() + 1}-${z(d.getDate())} ${t}` : t;
  }
  function rel(ms) {
    const s = Math.round((M.NOW - ms) / 1000);
    if (s < 60) return `${s} 秒前`;
    if (s < 3600) return `${Math.round(s / 60)} 分钟前`;
    if (s < 86400) return `${Math.round(s / 3600)} 小时前`;
    return `${Math.round(s / 86400)} 天前`;
  }
  const n = (x) => (x == null ? '—' : x.toLocaleString('en-US'));
  function bytes(b) { if (b < 1024) return `${b} B`; if (b < 1048576) return `${(b / 1024).toFixed(1)} KiB`; return `${(b / 1048576).toFixed(1)} MiB`; }
  const pct = (p) => (p == null ? '—' : `${Math.round(p * 100)}%`);

  // ---- vocab (docs/06 6.6) ----
  const DP = {
    bypass: { name: '绕过', g: '⤳' }, fast_allow: { name: '快速放行', g: '⚡' },
    cached_allow: { name: '缓存放行', g: '↺' }, jev_allow: { name: 'Jev 放行', g: '✦' },
    jev_deny: { name: 'Jev 拒绝', g: '✦' }, jev_unavailable: { name: 'Jev 不可用', g: '⚠' },
    no_session: { name: '无会话', g: '⊘' }, body_not_inspectable: { name: '请求体不可判定', g: '⧉' },
    unknown_site: { name: '未知站点', g: '⌀' },
  };
  const OUT = { allowed: '放行', blocked: '拦截', would_block: '本应拦截', unjudged: '未经判定' };
  const FAIL = {
    JEV_TIMEOUT: '超时', JEV_RATE_LIMITED: '服务限流', JEV_TRANSPORT: '连接失败', JEV_HTTP_ERROR: '服务出错',
    JEV_RESPONSE_TOO_LARGE: '响应过大', JEV_RESPONSE_INVALID: '响应无效', JEV_UNKNOWN: '答不上来',
    JEV_STATE_TOO_LARGE: '上下文过大', JEV_CALL_LIMIT: '达到上限',
  };
  const ACCESS = { ALLOW: '有依据', DENY: '越权', UNKNOWN: '不确定' };
  const ATTACK = { BENIGN: '无攻击', ATTACK: '攻击', UNKNOWN: '不确定' };
  function dpBadge(dp) { const v = DP[dp] || { name: dp, g: '·' }; return `<span class="badge" title="${esc(dp)}"><span class="g">${v.g}</span>${esc(v.name)}</span>`; }
  function outPill(o) { return `<span class="pill ${o}"><span class="g ${o}">${o === 'blocked' ? '■' : o === 'would_block' ? '▲' : o === 'unjudged' ? '◆' : '○'}</span>${esc(OUT[o] || o)}</span>`; }
  function jevCell(j) {
    if (!j) return '<span class="dim">—</span>';
    if (j.failure) return `<span class="muted">${esc(FAIL[j.failure] || j.failure)}</span>`;
    if (j.attack === 'ATTACK') return `攻击 ${pct(j.confidence)}`;
    if (j.access === 'DENY') return `越权 ${pct(j.confidence)}`;
    return `放行 ${pct(j.confidence)}`;
  }

  // ---- app state ----
  const state = { route: location.hash || '#/', site: 'all', range: '24h', toasts: [], sites: JSON.parse(JSON.stringify(M.SITES)), drafts: {} };

  function toast(msg) {
    const t = h(`<div class="toast">${esc(msg)}</div>`);
    $('#toasts').appendChild(t);
    setTimeout(() => t.remove(), 3200);
  }

  // ===================== ROUTER =====================
  function parseHash() {
    const raw = (location.hash || '#/').slice(1);
    const [path, qs] = raw.split('?');
    const q = new URLSearchParams(qs || '');
    return { parts: path.split('/').filter(Boolean), q };
  }
  function go(hash) { location.hash = hash; }

  const AUTHED = { v: true };
  function render() {
    if (!AUTHED.v) { $('#app').classList.add('hidden'); renderLogin(); return; }
    $('#login-root').classList.add('hidden');
    $('#app').classList.remove('hidden');
    const { parts, q } = parseHash();
    document.querySelectorAll('.nav-item').forEach((b) => b.classList.toggle('active', b.dataset.route === (parts[0] || 'overview')));
    const page = $('#page');
    page.innerHTML = '';
    const r0 = parts[0] || 'overview';
    try {
      if (r0 === 'overview' || !parts.length) renderOverview(page);
      else if (r0 === 'requests' && parts[1]) renderDetail(page, parts[1], q);
      else if (r0 === 'requests') renderRequests(page, q);
      else if (r0 === 'sessions' && parts[1]) renderTimeline(page, parts[1], q);
      else if (r0 === 'sessions') renderSessions(page, q);
      else if (r0 === 'jev') renderJevPage(page, q);
      else if (r0 === 'sites' && parts[1]) renderSiteDetail(page, parts[1], q);
      else if (r0 === 'sites') renderSites(page);
      else if (r0 === 'system') renderSystem(page, q);
      else page.appendChild(h(`<div class="empty"><div class="big">页面不存在</div></div>`));
    } catch (e) {
      page.appendChild(h(`<div class="empty"><div class="big">渲染出错（原型）</div><div class="dim">${esc(e.message)}</div></div>`));
      console.error(e);
    }
    page.scrollTop = 0;
  }

  function pageHead(title, sub, actions) {
    const el = h(`<div class="page-head"><h1>${esc(title)}</h1><div class="sub">${esc(sub || '')}</div><div class="actions"></div></div>`);
    (actions || []).forEach((a) => el.querySelector('.actions').appendChild(a));
    return el;
  }

  // ===================== LOGIN =====================
  function renderLogin() {
    const root = $('#login-root');
    root.classList.remove('hidden');
    root.innerHTML = '';
    root.appendChild(h(`
      <div class="login"><div class="box">
        <div class="logo"></div>
        <h2 style="margin-bottom:14px">Xshield 控制台</h2>
        <div class="notice">控制台需要经 HTTPS 或 localhost 访问，否则浏览器不会保存登录状态。可以用 SSH 隧道把控制台端口转发到本机。</div>
        <div class="field"><input type="password" id="pw" placeholder="管理员口令" autofocus></div>
        <button class="btn primary" id="login-btn" style="width:100%">登录</button>
      </div></div>`));
    $('#login-btn').onclick = () => { AUTHED.v = true; render(); };
    $('#pw').onkeydown = (e) => { if (e.key === 'Enter') { AUTHED.v = true; render(); } };
  }

  // ===================== OVERVIEW =====================
  function renderOverview(page) {
    page.appendChild(pageHead('总览', `全部站点 · 最近 24 小时`));
    const s = M.SUMMARY;
    // attention
    const attn = h(`<div class="card" style="margin-bottom:16px"><h2>需要处理</h2><div class="attn"></div></div>`);
    const items = [
      { lvl: 'warn', g: '▲', msg: `juice 观察中 6 天：本应拦截 14 条（Jev 拒绝 11、无会话 3）`, act: ['查看', () => go('#/requests?site=juice&chip=would')], act2: ['就绪检查', () => openModeSwitch('juice')] },
      { lvl: 'info', g: '▲', msg: `juice 有 2 条调优建议：登记入口 1、加入绕过 1`, act: ['查看建议', () => go('#/sites/juice?tab=insights')] },
      { lvl: 'serious', g: '■', msg: `edge-1 有 37 条判定记录未写入（21:02–21:05 队列满），这段时间的请求可能查不到`, act: ['查看系统', () => go('#/system?tab=storage')] },
      { lvl: 'info', g: '●', msg: `emr Jev 超时 3 次 / 412 次调用（p95 1.8 s，超时 3 s）`, act: ['查看证据', () => go('#/sites/emr?tab=config&group=advanced')] },
    ];
    items.forEach((it) => {
      const row = h(`<div class="attn-row"><div class="lvl lvl-${it.lvl}">${it.g}</div><div class="msg">${esc(it.msg)}</div></div>`);
      [it.act, it.act2].forEach((a) => { if (a) { const b = h(`<button class="btn sm">${esc(a[0])}</button>`); b.onclick = a[1]; row.appendChild(b); } });
      attn.querySelector('.attn').appendChild(row);
    });
    page.appendChild(attn);

    // tiles
    const tiles = h(`<div class="tiles" style="margin-bottom:16px"></div>`);
    const tdef = [
      ['已判定请求', n(s.judged), '不含绕过', '#/requests'],
      ['拦截', n(s.blocked), '', '#/requests?chip=blocked'],
      ['本应拦截', n(s.would_block), '', '#/requests?chip=would'],
      ['未经判定', n(s.unjudged), '', '#/requests?chip=unjudged'],
      ['Jev 调用', `${n(s.jev_calls)}`, `占已判定 ${s.jev_pct}%`, '#/jev'],
      ['Jev 耗时 p95', `${s.jev_p95_ms} ms`, `超时 ${s.jev_timeouts} 次`, '#/jev'],
    ];
    tdef.forEach(([k, v, x, href]) => {
      const t = h(`<div class="tile clickable"><div class="k">${esc(k)}</div><div class="v tnum">${esc(v)}</div><div class="x">${esc(x)}</div></div>`);
      t.onclick = () => go(href);
      tiles.appendChild(t);
    });
    page.appendChild(tiles);

    // chart + sites
    const row = h(`<div class="grid" style="grid-template-columns:1.6fr 1fr;align-items:start"></div>`);
    const chart = h(`<div class="card"><h2>每小时请求（不含绕过）</h2></div>`);
    chart.appendChild(stackedChart(M.TIMESERIES));
    chart.appendChild(h(`<div class="legend" style="margin-top:8px"><span><span class="sw" style="background:var(--s1)"></span>免调用放行</span><span><span class="sw" style="background:var(--s2)"></span>Jev 判定</span><span><span class="sw" style="background:var(--s3)"></span>无会话</span></div>`));
    row.appendChild(chart);

    const sitesCard = h(`<div class="card"><h2>站点</h2></div>`);
    state.sites.forEach((st) => {
      const modeTxt = st.mode === 'observe' ? `观察 6 天` : '拦截';
      const extra = st.mode === 'observe' ? `本应拦截 ${st.would_block_24h}` : `拦截 ${st.blocked_24h}`;
      const c = h(`<div style="padding:10px 0;border-top:1px solid var(--border);cursor:pointer">
        <div style="display:flex;justify-content:space-between"><b>${esc(st.name)}</b><span class="dim">v${st.version} <span class="dot ok" style="display:inline-block"></span> 已生效</span></div>
        <div class="muted" style="font-size:12px">${esc(modeTxt)} · 24h ${n(st.requests_24h)} · ${esc(extra)}${st.suggestions ? ` · 建议 ${st.suggestions}` : ''}</div></div>`);
      c.onclick = () => go(`#/sites/${st.name}`);
      sitesCard.appendChild(c);
    });
    row.appendChild(sitesCard);
    page.appendChild(row);

    // recent blocks
    const recent = M.RECORDS.filter((r) => r.outcome === 'blocked' || r.outcome === 'would_block').slice(0, 6);
    const rc = h(`<div class="card" style="margin-top:16px"><h2>最近的拦截与本应拦截</h2></div>`);
    const tbl = requestTable(recent, { compact: true });
    rc.appendChild(tbl);
    page.appendChild(rc);
  }

  // ===================== REQUESTS =====================
  function filterRecords(q) {
    const chip = q.get('chip');
    const incBypass = q.get('bypass') === '1';
    let rows = M.RECORDS.slice();
    const site = state.site;
    if (site !== 'all') rows = rows.filter((r) => r.site === site);
    if (!incBypass && chip !== 'bypass') rows = rows.filter((r) => r.decision_path !== 'bypass');
    const chipMap = {
      attention: (r) => ['blocked', 'would_block', 'unjudged'].includes(r.outcome),
      blocked: (r) => r.outcome === 'blocked', would: (r) => r.outcome === 'would_block',
      unjudged: (r) => r.outcome === 'unjudged', jev: (r) => !!r.jev, no_session: (r) => r.decision_path === 'no_session',
      bypass: (r) => r.decision_path === 'bypass',
    };
    if (chip && chipMap[chip]) rows = rows.filter(chipMap[chip]);
    // simple DSL: path:, decision:, outcome:, id:, session:
    const dsl = q.get('q') || '';
    dsl.split(/\s+/).filter(Boolean).forEach((term) => {
      const [k, v] = term.includes(':') ? term.split(':') : [null, term];
      if (k === 'path') rows = rows.filter((r) => v.endsWith('*') ? r.path.startsWith(v.slice(0, -1)) : r.path === v);
      else if (k === 'decision') rows = rows.filter((r) => v.split(',').includes(r.decision_path));
      else if (k === 'outcome') rows = rows.filter((r) => v.split(',').includes(r.outcome));
      else if (k === 'session') rows = rows.filter((r) => r.session === v);
      else if (k === 'method') rows = rows.filter((r) => r.method === v.toUpperCase());
      else if (k === 'id' || /^req_[0-9a-f]{32}$/.test(v)) rows = rows.filter((r) => r.request_id === v);
      else if (!k && v.startsWith('/')) rows = rows.filter((r) => r.path.includes(v));
    });
    return rows;
  }

  function requestTable(rows, opts = {}) {
    const showSite = state.site === 'all';
    const wrap = h(`<div class="tablewrap"><table class="data"><thead><tr>
      <th>时间</th>${showSite ? '<th>站点</th>' : ''}<th>方法</th><th>路径</th><th>状态</th><th>判定</th><th>结论</th><th>Jev</th><th>耗时</th><th>请求 ID</th>
    </tr></thead><tbody></tbody></table></div>`);
    const tb = wrap.querySelector('tbody');
    if (!rows.length) { wrap.querySelector('table').remove(); wrap.appendChild(h(`<div class="empty">没有匹配的请求</div>`)); return wrap; }
    rows.forEach((r) => {
      const tr = h(`<tr data-id="${esc(r.request_id)}">
        <td class="tnum">${fmtTime(r.at_millis)}</td>${showSite ? `<td>${esc(r.site || '—')}</td>` : ''}
        <td class="mono">${esc(r.method)}</td>
        <td><span class="path" title="${esc(r.path)}">${esc(r.path)}</span></td>
        <td class="tnum">${r.status == null ? '—' : r.status}</td>
        <td>${dpBadge(r.decision_path)}</td>
        <td>${outPill(r.outcome)}</td>
        <td>${jevCell(r.jev)}</td>
        <td class="tnum">${r.total_ms} ms</td>
        <td class="idcell" title="${esc(r.request_id)}">…${esc(r.request_id.slice(-8))}</td>
      </tr>`);
      tr.onclick = () => { if (opts.compact) go(`#/requests/${r.request_id}`); else openPeek(r.request_id, wrap); };
      tr.ondblclick = () => go(`#/requests/${r.request_id}`);
      tb.appendChild(tr);
    });
    return wrap;
  }

  function renderRequests(page, q) {
    const actions = [btn('批量对照', openBatch), btn('导出', () => toast('原型不生成导出文件')), btn('⟳ 实时', () => toast('实时模式：原型仅示意'))];
    page.appendChild(pageHead('请求追溯', `${state.site === 'all' ? '全部站点' : state.site} · 最近 24 小时`, actions));

    // chips
    const counts = {};
    M.RECORDS.forEach((r) => { counts.all = (counts.all || 0); });
    const chipDefs = [['', '已判定'], ['attention', '需要关注'], ['blocked', '拦截'], ['would', '本应拦截'], ['unjudged', '未经判定'], ['jev', 'Jev 调用'], ['no_session', '无会话'], ['bypass', '绕过']];
    const chips = h(`<div class="chips" style="margin-bottom:10px"></div>`);
    const curChip = q.get('chip') || '';
    chipDefs.forEach(([key, label]) => {
      const rows = filterRecords(new URLSearchParams(key ? `chip=${key}` + (key === 'bypass' ? '&bypass=1' : '') : ''));
      const c = h(`<button class="chip ${curChip === key ? 'active' : ''}">${esc(label)} <span class="n">${rows.length}</span></button>`);
      c.onclick = () => { const nq = new URLSearchParams(location.hash.split('?')[1] || ''); if (key) nq.set('chip', key); else nq.delete('chip'); go(`#/requests?${nq}`); };
      chips.appendChild(c);
    });
    page.appendChild(chips);

    // filter bar
    const fb = h(`<div class="filterbar">
      <div class="dsl">⌕ <input value="${esc(q.get('q') || '')}" placeholder="outcome:would_block path:/rest/* …"></div>
      <label class="check"><input type="checkbox" ${q.get('bypass') === '1' ? 'checked' : ''}> 含绕过请求</label>
    </div>`);
    fb.querySelector('input[type=text], .dsl input').onkeydown = (e) => {
      if (e.key === 'Enter') { const nq = new URLSearchParams(location.hash.split('?')[1] || ''); nq.set('q', e.target.value); go(`#/requests?${nq}`); }
    };
    fb.querySelector('input[type=checkbox]').onchange = (e) => { const nq = new URLSearchParams(location.hash.split('?')[1] || ''); if (e.target.checked) nq.set('bypass', '1'); else nq.delete('bypass'); go(`#/requests?${nq}`); };
    page.appendChild(fb);

    const rows = filterRecords(q);
    const peekId = q.get('peek');
    const split = h(`<div class="split ${peekId ? '' : 'nopeek'}"></div>`);
    const left = h(`<div></div>`);
    left.appendChild(requestTable(rows));
    split.appendChild(left);
    if (peekId) split.appendChild(peekPanel(peekId));
    page.appendChild(split);
  }

  function openPeek(id, wrap) {
    const nq = new URLSearchParams(location.hash.split('?')[1] || '');
    nq.set('peek', id);
    history.replaceState(null, '', `#/requests?${nq}`);
    // re-render only split
    renderRequests($('#page'), new URLSearchParams(location.hash.split('?')[1] || ''));
    const tr = document.querySelector(`tr[data-id="${CSS.escape(id)}"]`);
    if (tr) tr.classList.add('sel');
  }

  function peekPanel(id) {
    const r = M.RECORD_BY_ID[id];
    const p = h(`<div class="peek"></div>`);
    if (!r) { p.appendChild(h(`<div class="empty">找不到 ${esc(id)}</div>`)); return p; }
    p.appendChild(h(`<h3 class="mono">${esc(r.method)} ${esc(r.path)}</h3>`));
    p.appendChild(h(`<div style="margin:6px 0">${outPill(r.outcome)} ${dpBadge(r.decision_path)}</div>`));
    p.appendChild(h(`<div class="explain">${esc(explain(r))}</div>`));
    const needs = (r.trace.values || []).filter((v) => !v.inert && !v.verified);
    if (needs.length) {
      const list = needs.slice(0, 5).map((v) => `${esc(v.at)} = ${v.value === '<redacted>' ? '🔒' : esc(v.value)}`).join('<br>');
      p.appendChild(h(`<div class="kv"><div class="k">需核验</div><div>${list}</div></div>`));
    }
    if (r.session) p.appendChild(h(`<div class="kv"><div class="k">会话</div><div class="mono">${esc(r.session.slice(0, 8))}</div></div>`));
    p.appendChild(h(`<div class="kv"><div class="k">耗时</div><div class="tnum">${r.total_ms} ms</div></div>`));
    if (r.jevFull) p.appendChild(answerBars(r.jevFull));
    const foot = h(`<div style="display:flex;gap:8px;margin-top:12px"></div>`);
    foot.appendChild(btn('打开详情', () => go(`#/requests/${id}`), 'primary sm'));
    foot.appendChild(btn('复制 ID', () => { navigator.clipboard && navigator.clipboard.writeText(id); toast('已复制请求 ID'); }, 'sm'));
    p.appendChild(foot);
    return p;
  }

  // explain sentence (docs/06 6.4.4)
  function explain(r) {
    const t = r.trace; const j = r.jevFull;
    let reason = '';
    switch (r.decision_path) {
      case 'bypass': reason = `命中绕过规则 ${t.bypass}，没有判定，直接转发。`; break;
      case 'unknown_site': reason = `Host ${r.host} 不属于任何站点。`; break;
      case 'body_not_inspectable': reason = `请求体超过 48 KiB 判定上限或没有 Content-Length，无法判定。`; break;
      case 'no_session': reason = `请求没有会话凭证，路径也不是入口。`; break;
      case 'fast_allow': { const nv = (t.values || []).filter((v) => !v.inert).length; reason = nv ? `${nv} 个需核验的值都已核验，没有调用 Jev。` : `请求里没有需要核验的值，没有调用 Jev。`; break; }
      case 'cached_allow': reason = `同一会话此前的相同请求已由 Jev 放行，在缓存时长内直接复用。`; break;
      case 'jev_allow': reason = `Jev 判定访问有依据（ALLOW ${pct(j.access.ALLOW)}）、内容无攻击（BENIGN ${pct(j.attack.BENIGN)}）。`; break;
      case 'jev_deny':
        if (j && j.attack.ATTACK > j.attack.BENIGN) reason = `Jev 判定为攻击（ATTACK ${pct(j.attack.ATTACK)}）。`;
        else { const v = (t.values || []).find((x) => x.seen && !x.verified) || {}; const src = (v.sources || [])[0]; reason = `Jev 判定越权（DENY ${pct(j.access.DENY)}）：${v.at || '某个值'} 的 ${v.value || ''} ${src ? `只以 ${src.field} 出现在 ${src.request} 的响应里` : '在这个会话里没有以同类对象出现过'}。`; }
        break;
      case 'jev_unavailable':
        if (j && j.failure === 'JEV_TIMEOUT') reason = `Jev 调用超时（${j.timeout_ms} ms）。`;
        else if (j && j.failure === 'JEV_CALL_LIMIT') reason = `每分钟 Jev 调用已达上限，没有调用 Jev。`;
        else reason = `Jev 不可用（${j ? FAIL[j.failure] : '未知'}）。`;
        break;
      default: reason = '';
    }
    let act = '';
    if (r.outcome === 'blocked') act = ` 返回 ${r.status}。`;
    else if (r.outcome === 'would_block') act = ' 站点处于观察模式，请求照常转发。';
    else if (r.outcome === 'unjudged') act = ' 站点设置为 Jev 不可用时放行，这个请求没有经过判定。';
    return reason + act;
  }

  // ===================== REQUEST DETAIL =====================
  function renderDetail(page, id, q) {
    const r = M.RECORD_BY_ID[id];
    const back = btn('← 请求追溯', () => go('#/requests'));
    if (!r) {
      page.appendChild(pageHead('请求详情', '', [back]));
      page.appendChild(notFound(id));
      return;
    }
    const head = h(`<div class="detail-head">
      <div style="display:flex;justify-content:space-between;align-items:flex-start;gap:12px">
        <div class="req">${esc(r.method)} ${esc(r.path)}</div>
        <div>${outPill(r.outcome)} ${dpBadge(r.decision_path)}</div>
      </div>
      <div class="explain">${esc(explain(r))}</div>
      <div class="meta">
        <span>${fmtTime(r.at_millis, true)} 本地</span>
        <span>状态 ${r.status == null ? '—' : r.status}</span>
        <span>${r.total_ms} ms（判定 ${r.trace.timing ? r.trace.timing.judge_ms : '—'} · 源站 ${r.trace.timing && r.trace.timing.origin_ms != null ? r.trace.timing.origin_ms : '—'}）</span>
        <span>配置 v${r.site_version}</span><span>${esc(r.edge)}</span>
        ${r.session ? `<span>会话 <a href="#/sessions/${esc(r.session)}" class="mono">${esc(r.session.slice(0, 8))}</a></span>` : ''}
        <span>客户端 ${esc(r.client)}</span>
      </div></div>`);
    const topRow = h(`<div style="display:flex;gap:8px;margin-bottom:10px;align-items:center"></div>`);
    topRow.appendChild(back);
    topRow.appendChild(h(`<div class="mono dim" style="font-size:12px">${esc(id)}</div>`));
    page.appendChild(topRow);
    page.appendChild(head);

    const tabId = q.get('tab') || 'pipeline';
    const tabs = h(`<div class="tabs"></div>`);
    const tdefs = [['pipeline', '判定过程'], ['values', `请求值 ${(r.trace.values || []).length}`], ['jev', 'Jev 上下文'], ['session', '会话上下文'], ['raw', '原始记录']];
    tdefs.forEach(([k, lbl]) => {
      const t = h(`<button class="tab ${tabId === k ? 'active' : ''}">${esc(lbl)}</button>`);
      t.onclick = () => { const nq = new URLSearchParams(q.toString()); nq.set('tab', k); go(`#/requests/${id}?${nq}`); };
      tabs.appendChild(t);
    });
    page.appendChild(tabs);

    const layout = h(`<div class="split"><div id="tabbody"></div><div class="rail" id="rail"></div></div>`);
    page.appendChild(layout);
    const body = layout.querySelector('#tabbody');
    if (tabId === 'pipeline') body.appendChild(pipelineView(r));
    else if (tabId === 'values') body.appendChild(valuesView(r, id, q));
    else if (tabId === 'jev') body.appendChild(jevView(r, id, q));
    else if (tabId === 'session') body.appendChild(sessionCtxView(r));
    else if (tabId === 'raw') body.appendChild(h(`<div class="codeblock wrap">${esc(JSON.stringify({ summary: summaryOf(r), trace: r.trace, jev: r.jevFull }, null, 2))}</div>`));
    renderRail(layout.querySelector('#rail'), r);
  }

  function summaryOf(r) { return { id: r.id, request_id: r.request_id, at_millis: r.at_millis, site: r.site, site_version: r.site_version, method: r.method, host: r.host, path: r.path, status: r.status, decision_path: r.decision_path, outcome: r.outcome, session: r.session, context: r.context, client: r.client, total_ms: r.total_ms, jev: r.jev }; }

  function pipelineView(r) {
    const t = r.trace;
    const st = state.sites.find((s) => s.name === r.site) || {};
    const steps = [];
    const dp = r.decision_path;
    steps.push(['●', '站点', `${esc(r.site || '—')}（Host ${esc(r.host)}）· 配置 v${r.site_version} · ${st.mode === 'observe' ? '观察模式' : '拦截模式'}`, false, dp === 'unknown_site']);
    steps.push(['●', '绕过', dp === 'bypass' ? `命中 ${esc(t.bypass)}` : '未命中', false, dp === 'bypass']);
    if (dp !== 'bypass' && dp !== 'unknown_site') {
      steps.push(['●', '会话', r.session ? `会话 ${esc(r.session.slice(0, 8))}…（已见 ${t.session ? n(t.session.known_values) : '—'} 个值）` : '没有会话凭证', false, dp === 'no_session']);
      steps.push(['●', '入口', t.entry ? `命中 ${esc(t.entry)}` : '未命中', false, false]);
      const nv = (t.values || []).filter((v) => !v.inert);
      steps.push(['●', '请求值', `${(t.values || []).length} 个：${(t.values || []).length - nv.length} 个惰性，${nv.length} 个需核验`, false, false]);
      steps.push([dp === 'fast_allow' ? '◆' : '○', '快速放行', dp === 'fast_allow' ? '全部已核验' : '不满足：有未核验的值', dp !== 'fast_allow', dp === 'fast_allow']);
      steps.push([dp === 'cached_allow' ? '◆' : '○', '缓存', dp === 'cached_allow' ? '复用了一次 Jev 放行' : '没有可复用的放行', dp !== 'cached_allow', dp === 'cached_allow']);
      if (r.jevFull) {
        const j = r.jevFull;
        const desc = j.failure ? `${FAIL[j.failure]} · ${j.millis} ms / 超时 ${j.timeout_ms} ms`
          : `${ACCESS[argmax(j.access)]} ${pct(j.access[argmax(j.access)])} · ${ATTACK[argmax(j.attack)]} ${pct(j.attack[argmax(j.attack)])} · ${j.millis} ms / 超时 ${j.timeout_ms} ms`;
        steps.push(['◆', 'Jev', desc, false, dp === 'jev_allow' || dp === 'jev_deny' || dp === 'jev_unavailable']);
      }
    }
    const execTxt = { allowed: '放行 → 转发', blocked: `拦截 → 返回 ${r.status}`, would_block: '本应拦截（观察模式）→ 转发', unjudged: '未经判定 → 转发' }[r.outcome];
    const origin = t.timing && t.timing.origin_ms != null ? `，源站 ${r.status}，${t.timing.origin_ms} ms` : '';
    steps.push(['●', '执行', execTxt + origin, false, false]);
    if (t.response && t.response.observed === 'json') {
      let learn = `JSON 响应 ${bytes(t.response.bytes)}：取出 ${t.response.values} 个值，新增 ${t.response.new_values} 个`;
      steps.push(['●', '学习', learn, false, false, t.response.after_would_block ? '▲ 本应拦截请求的响应也进入了上下文' : null]);
    } else if (t.response) {
      steps.push(['●', '学习', `未观察（${skipReason(t.response.skip)}）`, true, false]);
    }
    const wrap = h(`<div class="card"><h2>判定过程</h2><div class="steps"></div></div>`);
    steps.forEach(([g, name, note, skip, dec, warn]) => {
      const el = h(`<div class="step ${skip ? 'skip' : ''} ${dec ? 'decisive' : ''}">
        <div class="s-ico">${g}</div><div class="s-name">${esc(name)}</div>
        <div class="note">${esc(note)}${warn ? `<div class="warnline">${esc(warn)}</div>` : ''}</div></div>`);
      if (name === 'Jev' && r.jevFull) { const b = h(`<button class="btn sm" style="margin-top:4px">查看 Jev 上下文</button>`); b.onclick = () => go(`#/requests/${r.request_id}?tab=jev`); el.querySelector('.note').appendChild(b); }
      wrap.querySelector('.steps').appendChild(el);
    });
    return wrap;
  }
  function skipReason(s) { return ({ status: '非 2xx', content_type: '类型不是 JSON/HTML', compressed: '响应被压缩', too_large: '超过 1 MiB', head: 'HEAD 请求', not_forwarded: '请求没有转发' })[s] || s; }
  function argmax(o) { return Object.keys(o).reduce((a, b) => (o[a] >= o[b] ? a : b)); }

  function valuesView(r, id, q) {
    const wrap = h(`<div class="card"><h2>请求值</h2></div>`);
    const vals = r.trace.values || [];
    if (!vals.length) { wrap.appendChild(h(`<div class="empty">这个请求没有拆出请求值</div>`)); return wrap; }
    const tbl = h(`<div class="tablewrap"><table class="data"><thead><tr><th>位置</th><th>字段</th><th>值</th><th>类型</th><th>已见</th><th>已核验</th><th>来源</th></tr></thead><tbody></tbody></table></div>`);
    const tb = tbl.querySelector('tbody');
    let jevIdx = -1;
    vals.forEach((v) => {
      if (!v.inert) jevIdx += 1;
      const srcs = (v.sources || []).map((s) => {
        if (!s.request_id) return `<span class="srcchip" title="网关重启前，未记录 ID">${esc(s.field)} · ${esc(s.request)}</span>`;
        return `<a class="srcchip" href="#/requests/${esc(s.request_id)}">${esc(s.field)} · ${esc(s.request)}</a>`;
      }).join('');
      const valCell = v.value === '<redacted>' ? `<span class="redacted">🔒 已脱敏</span>` : `<span class="mono">${safeText(v.value)}</span>`;
      const tr = h(`<tr class="${!v.inert && !v.verified ? 'vzone' : ''}" style="${v.inert ? 'opacity:.6' : ''}">
        <td class="mono">${esc(v.at)}</td><td class="mono">${esc(v.key || '—')}</td>
        <td>${valCell}</td><td>${esc(v.kind)}${v.inert ? ' · 惰性' : ''}</td>
        <td>${v.seen ? '✓' : '—'}</td><td>${v.verified ? '✓' : (!v.inert ? '—' : '')}</td>
        <td>${srcs || '<span class="dim">—</span>'}</td></tr>`);
      tb.appendChild(tr);
    });
    wrap.appendChild(tbl);
    if (r.trace.values_truncated) wrap.appendChild(h(`<div class="notice" style="margin-top:10px">请求体未结构化或超过 64 KiB 解析上限，只拆出了部分值</div>`));
    return wrap;
  }

  function sessionCtxView(r) {
    const t = r.trace;
    const wrap = h(`<div class="card"><h2>会话上下文</h2></div>`);
    if (!t.session) { wrap.appendChild(h(`<div class="empty">这条记录没有会话上下文（无会话或绕过）</div>`)); return wrap; }
    wrap.appendChild(h(`<div class="kv"><div class="k">已存在</div><div>${Math.round(t.session.age_seconds / 60)} 分钟</div><div class="k">已见值</div><div>${n(t.session.known_values)}</div></div>`));
    if ((t.session.entries_passed || []).length) {
      const list = t.session.entries_passed.map((e) => `<div class="r-item"><a href="#/requests/${esc(e.request_id)}" class="mono">${esc(e.path)}</a> · ${fmtTime(e.at_millis)}</div>`).join('');
      wrap.appendChild(h(`<h2 style="margin-top:12px">经过的入口</h2><div>${list}</div>`));
    }
    if ((t.session.recent || []).length) {
      const list = t.session.recent.map((e) => `<div class="r-item mono">${esc(e.method)} <a href="#/requests/${esc(e.request_id)}">${esc(e.path)}</a> ${e.status}</div>`).join('');
      wrap.appendChild(h(`<h2 style="margin-top:12px">最近访问（Jev 记录）</h2><div>${list}</div>`));
    } else {
      wrap.appendChild(h(`<div class="dim" style="margin-top:12px">最近访问只在调用 Jev 的记录里保存；完整顺序见会话时间线</div>`));
    }
    if (r.session) { const b = btn('打开会话时间线', () => go(`#/sessions/${r.session}?at=${r.request_id}`), 'sm'); b.style.marginTop = '12px'; wrap.appendChild(b); }
    return wrap;
  }

  function renderRail(rail, r) {
    const srcIds = new Set();
    (r.trace.values || []).forEach((v) => (v.sources || []).forEach((s) => s.request_id && srcIds.add(s.request_id)));
    if (srcIds.size) {
      const c = h(`<div class="card"><h2>值的来源</h2></div>`);
      srcIds.forEach((sid) => { const sr = M.RECORD_BY_ID[sid]; c.appendChild(h(`<div class="r-item"><a href="#/requests/${esc(sid)}" class="mono">${sr ? esc(sr.method + ' ' + sr.path) : esc(sid.slice(-8))}</a></div>`)); });
      rail.appendChild(c);
    }
    if (r.trace.response && r.trace.response.issued_session) {
      rail.appendChild(h(`<div class="card"><h2>签发的会话</h2><div class="r-item"><a href="#/sessions/${esc(r.trace.response.issued_session)}" class="mono">${esc(r.trace.response.issued_session.slice(0, 8))}</a></div></div>`));
    }
    // ops
    const ops = h(`<div class="card"><h2>操作</h2></div>`);
    if (r.decision_path === 'no_session') ops.appendChild(railBtn('登记为入口…', () => openQuickRule(r, 'entry')));
    if (r.decision_path === 'bypass' || r.decision_path === 'body_not_inspectable' || /\.(js|css|png|jpg|svg|ico|woff2?)$/.test(r.path)) ops.appendChild(railBtn('加入绕过…', () => openQuickRule(r, 'bypass')));
    if (r.jev && r.jev.failure === 'JEV_TIMEOUT') ops.appendChild(railBtn('调整 Jev 超时…', () => go(`#/sites/${r.site}?tab=config&group=advanced`)));
    ops.appendChild(railBtn('在配置中打开', () => go(`#/sites/${r.site}?tab=config`)));
    ops.appendChild(railBtn('复制链接', () => { navigator.clipboard && navigator.clipboard.writeText(location.href); toast('已复制链接'); }));
    rail.appendChild(ops);
  }
  function railBtn(label, fn) { const b = h(`<div class="r-item"><a href="javascript:void 0">${esc(label)}</a></div>`); b.querySelector('a').onclick = (e) => { e.preventDefault(); fn(); }; return b; }

  // ===================== JEV VIEWER =====================
  function answerBars(j) {
    const box = h(`<div style="margin:8px 0"></div>`);
    if (j.failure) {
      box.appendChild(h(`<div class="notice">Jev ${esc(FAIL[j.failure] || j.failure)}${j.http_status ? `（HTTP ${j.http_status}）` : ''}。按站点“Jev 不可用时”设置处理。</div>`));
      return box;
    }
    const q = (label, o, passKey, failKey) => {
      const a = o[passKey] || 0, b = o[failKey] || 0, u = o.UNKNOWN || 0;
      const seg = (cls, p, txt) => `<div class="seg ${cls}" style="flex:${Math.max(p, 0.001)}" title="${esc(txt)}">${p >= 0.25 ? esc(txt) : ''}</div>`;
      const concl = argmax(o);
      const label2 = passKey === 'ALLOW' ? ACCESS[concl] : ATTACK[concl];
      return `<div class="qrow"><div class="ql">${esc(label)}</div>
        <div class="answerbar">${seg('pass', a, `${passKey} ${pct(a)}`)}${seg('fail', b, `${failKey} ${pct(b)}`)}${seg('unk', u, 'UNKNOWN')}</div>
        <div class="qc">→ ${esc(label2)}</div></div>`;
    };
    box.appendChild(h(`<div>${q('访问有依据吗', j.access, 'ALLOW', 'DENY')}${q('内容是攻击吗', j.attack, 'BENIGN', 'ATTACK')}</div>`));
    const conf = j.conclusion === 'deny' ? Math.max(j.access.DENY || 0, j.attack.ATTACK || 0) : (j.access.ALLOW || 0);
    box.appendChild(h(`<div class="muted" style="font-size:13px">结论：${esc({ allow: '放行', deny: '拦截', unknown: '无法判定' }[j.conclusion])} · 置信度 ${pct(conf)}${conf < 0.7 ? ' · 置信度低' : ''}</div>`));
    return box;
  }

  function jevView(r, id, q) {
    const wrap = h(`<div class="card"><h2>Jev 上下文</h2></div>`);
    if (!r.jevFull) { wrap.appendChild(h(`<div class="empty">这个请求没有调用 Jev（${esc(DP[r.decision_path] ? DP[r.decision_path].name : r.decision_path)}）</div>`)); return wrap; }
    const j = r.jevFull;
    wrap.appendChild(answerBars(j));
    wrap.appendChild(h(`<div class="jevmeta">
      ${esc(j.model)} · ${esc({ gateway: '经 AI Gateway', direct: '直连 TypeSafe', custom: '自定义地址' }[j.route])} · ${j.millis} ms / 超时 ${j.timeout_ms} ms${j.timeout_ms !== 2000 ? '（站点设置）' : '（默认）'} · 请求 ${bytes(j.request_bytes)} · 裁剪 ${j.trim} 级<br>
      指令 <a href="javascript:void 0" id="promptlink">${esc(j.prompt)}</a>${j.usage ? ` · 用量 输入 ${n(j.usage.input_tokens)} / 输出 ${n(j.usage.output_tokens)} token` : ''}
    </div>`));
    const view = q.get('jev_view') || 'structured';
    const vtabs = h(`<div class="tabs" style="margin:12px 0 8px"></div>`);
    [['structured', '结构化'], ['json', 'JSON'], ['raw', '原文'], ['prompt', '指令']].forEach(([k, lbl]) => {
      const t = h(`<button class="tab ${view === k ? 'active' : ''}">${esc(lbl)}</button>`);
      t.onclick = () => { const nq = new URLSearchParams(q.toString()); nq.set('tab', 'jev'); nq.set('jev_view', k); go(`#/requests/${id}?${nq}`); };
      vtabs.appendChild(t);
    });
    wrap.appendChild(vtabs);
    wrap.querySelector('#promptlink').onclick = (e) => { e.preventDefault(); const nq = new URLSearchParams(q.toString()); nq.set('tab', 'jev'); nq.set('jev_view', 'prompt'); go(`#/requests/${id}?${nq}`); };

    if (view === 'structured') wrap.appendChild(jevStructured(j));
    else if (view === 'json') wrap.appendChild(h(`<div class="codeblock">${esc(j.state)}</div>`));
    else if (view === 'raw') {
      wrap.appendChild(h(`<div class="dim" style="font-size:12px;margin-bottom:4px">state 原文（${bytes(new Blob([j.state]).size)}）</div><div class="codeblock wrap">${esc(j.state)}</div>`));
      wrap.appendChild(h(`<div class="dim" style="font-size:12px;margin:10px 0 4px">原始响应${j.response ? '' : '（超时/连接失败，无响应）'}</div>${j.response ? `<div class="codeblock wrap">${esc(j.response)}</div>` : ''}`));
    } else if (view === 'prompt') {
      const p = M.PROMPTS[j.prompt];
      if (p) {
        wrap.appendChild(h(`<div class="struct">
          <div class="sec"><h4>access · 访问有依据吗</h4><div style="font-size:13px">${esc(p.questions.access.instructions)}</div><div class="dim" style="margin-top:6px">选项：${p.questions.access.choices.join(' / ')}</div></div>
          <div class="sec"><h4>attack · 内容是攻击吗</h4><div style="font-size:13px">${esc(p.questions.attack.instructions)}</div><div class="dim" style="margin-top:6px">选项：${p.questions.attack.choices.join(' / ')}</div></div>
          <div class="dim" style="font-size:12px">指令版本 ${esc(p.id)} · 首次出现 ${esc(p.first_seen)}</div></div>`));
      }
    }
    return wrap;
  }

  function jevStructured(j) {
    const s = JSON.parse(j.state);
    const box = h(`<div class="struct"></div>`);
    box.appendChild(h(`<div class="sec"><h4>入口</h4><div>${s.entry.matched ? '命中 ' + esc(s.entry.pattern) : '未命中'}</div></div>`));
    box.appendChild(h(`<div class="sec"><h4>会话</h4><div>已 ${s.session.age_seconds} 秒 · 经过入口 ${(s.session.entries_passed || []).map(esc).join(' · ') || '—'}</div></div>`));
    const recent = h(`<div class="sec"><h4>最近访问 ${s.recent.length} 条</h4></div>`);
    s.recent.forEach((rr) => recent.appendChild(h(`<div class="stv mono"><span>${esc(rr.method)} ${esc(rr.path)}</span><span class="dim">${rr.status}</span></div>`)));
    box.appendChild(recent);
    const req = h(`<div class="sec"><h4>本次请求 ${esc(s.request.method)} ${esc(s.request.path)}</h4></div>`);
    s.request.values.forEach((v, i) => {
      const seen = (v.seen_as || []).length;
      const mark = v.kind === 'input' ? '' : (seen ? '<span class="mark cross">▲ 见过但不是同类对象</span>' : '<span class="mark new">● 从未见过</span>');
      const val = v.value === '<redacted>' ? '🔒 已脱敏' : v.value;
      req.appendChild(h(`<div class="stv"><span class="mono">#${i} ${esc(v.at)} = ${esc(val)}</span><span class="dim">${esc(v.kind)}</span>${mark}</div>
        ${seen ? `<div class="dim" style="font-size:12px;padding-left:12px">见过：${(v.seen_as || []).map(esc).join('；')}</div>` : ''}`));
    });
    box.appendChild(req);
    return box;
  }

  // ===================== SESSIONS =====================
  function renderSessions(page, q) {
    page.appendChild(pageHead('会话', `${state.site === 'all' ? '全部站点' : state.site} · 最近 24 小时`));
    let rows = M.SESSIONS.slice();
    if (state.site !== 'all') rows = rows.filter((s) => s.site === state.site);
    if (q.get('flag') === 'blocked') rows = rows.filter((s) => s.blocked + s.would_block > 0);
    const chips = h(`<div class="chips" style="margin-bottom:10px">
      <button class="chip ${!q.get('flag') ? 'active' : ''}">全部 <span class="n">${M.SESSIONS.length}</span></button>
      <button class="chip ${q.get('flag') === 'blocked' ? 'active' : ''}">有拦截 <span class="n">${M.SESSIONS.filter((s) => s.blocked + s.would_block > 0).length}</span></button>
    </div>`);
    chips.children[0].onclick = () => go('#/sessions');
    chips.children[1].onclick = () => go('#/sessions?flag=blocked');
    page.appendChild(chips);
    const tbl = h(`<div class="tablewrap"><table class="data"><thead><tr><th>会话</th><th>站点</th><th>首次</th><th>最后</th><th>请求</th><th>Jev</th><th>拦截</th><th>本应拦截</th></tr></thead><tbody></tbody></table></div>`);
    rows.forEach((s) => {
      const tr = h(`<tr><td class="mono" title="${esc(s.label)}">${esc(s.label.slice(0, 8))}</td><td>${esc(s.site)}</td><td class="tnum">${fmtTime(s.first_at)}</td><td class="tnum">${fmtTime(s.last_at)}</td><td class="tnum">${s.requests}</td><td class="tnum">${s.jev_calls}</td><td class="tnum">${s.blocked}</td><td class="tnum">${s.would_block}</td></tr>`);
      tr.onclick = () => go(`#/sessions/${s.label}`);
      tbl.querySelector('tbody').appendChild(tr);
    });
    page.appendChild(tbl);
  }

  function renderTimeline(page, label, q) {
    const s = M.SESSIONS.find((x) => x.label === label);
    page.appendChild(pageHead('会话时间线', esc(label), [btn('← 会话', () => go('#/sessions'))]));
    if (!s) { page.appendChild(h(`<div class="empty"><div class="big">找不到这个会话</div><div class="dim">会话在 24 小时无活动后过期，网关重启后也会清空</div></div>`)); return; }
    page.appendChild(h(`<div class="card" style="margin-bottom:12px"><div class="muted">${esc(s.site)} · 请求头 Authorization · ${fmtTime(s.first_at)} – ${fmtTime(s.last_at)}<br>签发于 ${s.issued_by ? `<a href="#/requests/${esc(s.issued_by)}">登录请求</a>` : '—'} · 请求 ${s.requests} · Jev 调用 ${s.jev_calls} · 本应拦截 ${s.would_block}</div></div>`));
    const rows = M.RECORDS.filter((r) => r.session === label).sort((a, b) => a.at_millis - b.at_millis);
    const tl = h(`<div class="card"><div class="timeline"></div></div>`);
    let last = null;
    rows.forEach((r) => {
      if (last && r.at_millis - last > 300000) tl.querySelector('.timeline').appendChild(h(`<div class="tl-gap">⋯ ${Math.round((r.at_millis - last) / 60000)} 分钟无请求</div>`));
      last = r.at_millis;
      const tags = [];
      if (r.trace.response && r.trace.response.issued_session) tags.push('◆ 签发本会话');
      if (r.trace.response && r.trace.response.entry_passed) tags.push('⇢ 首次经过入口');
      if (r.outcome === 'would_block') tags.push('▲ 本应拦截');
      const row = h(`<div class="tl-row ${q.get('at') === r.request_id ? 'fadein' : ''}">
        <span class="tnum">${fmtTime(r.at_millis)}</span><span class="mono">${esc(r.method)}</span>
        <span class="mono path" title="${esc(r.path)}">${esc(r.path)}</span>
        <span>${dpBadge(r.decision_path)}</span><span class="tl-tag">${esc(tags.join(' · '))}</span></div>`);
      row.onclick = () => go(`#/requests/${r.request_id}`);
      tl.querySelector('.timeline').appendChild(row);
    });
    if (!rows.length) tl.querySelector('.timeline').appendChild(h(`<div class="empty">当前时间范围内没有这个会话的记录</div>`));
    page.appendChild(tl);
  }

  // ===================== JEV PAGE =====================
  function renderJevPage(page, q) {
    page.appendChild(pageHead('Jev 调用', `${state.site === 'all' ? '全部站点' : state.site} · 最近 24 小时`));
    const js = M.JEV_STATUS;
    const row = h(`<div class="grid" style="grid-template-columns:1fr 1fr 1fr;margin-bottom:16px"></div>`);
    row.appendChild(h(`<div class="card"><h2>健康</h2>
      <div style="display:flex;align-items:center;gap:8px;font-size:15px"><span class="dot ${js.health}"></span>${esc({ ok: '正常', idle: '空闲', degraded: '降级', down: '不可用' }[js.health])}</div>
      <div class="muted" style="margin-top:6px;font-size:13px">最近 5 分钟 ${js.calls} 次，全部成功<br>p50 ${js.p50_ms} ms · p95 ${js.p95_ms} ms<br>${esc(js.config.model)} · 经 AI Gateway<br>默认超时 ${js.config.default_timeout_ms} ms · 指令 ${esc(js.config.prompt.slice(0, 11))}…</div></div>`));
    const evAll = M.EVIDENCE.emr;
    const histCard = h(`<div class="card"><h2>耗时分布（100 ms 一档）</h2></div>`);
    histCard.appendChild(histogram(evAll.histogram, evAll.jev.timeout_ms_used));
    row.appendChild(histCard);
    const confCard = h(`<div class="card"><h2>置信度分布</h2></div>`);
    confCard.appendChild(histogram([2, 1, 1, 2, 3, 5, 8, 12, 20, 18], null, '0.1 一档'));
    row.appendChild(confCard);
    page.appendChild(row);

    const jevRows = M.RECORDS.filter((r) => r.jev);
    const chips = h(`<div class="chips" style="margin-bottom:10px">
      <span class="chip active">全部 <span class="n">${jevRows.length}</span></span>
      <span class="chip">拦截 <span class="n">${jevRows.filter((r) => r.outcome === 'blocked' || r.outcome === 'would_block').length}</span></span>
      <span class="chip">失败 <span class="n">${jevRows.filter((r) => r.jev.failure).length}</span></span>
    </div>`);
    page.appendChild(chips);
    const tbl = h(`<div class="tablewrap"><table class="data"><thead><tr><th>时间</th><th>站点</th><th>请求</th><th>结论</th><th>访问</th><th>攻击</th><th>置信度</th><th>耗时/超时</th><th>裁剪</th></tr></thead><tbody></tbody></table></div>`);
    jevRows.forEach((r) => {
      const j = r.jevFull;
      const tr = h(`<tr><td class="tnum">${fmtTime(r.at_millis)}</td><td>${esc(r.site)}</td>
        <td class="mono path">${esc(r.method)} ${esc(r.path)}</td><td>${outPill(r.outcome)}</td>
        <td>${j && !j.failure ? esc(argmax(j.access) + ' ' + pct(j.access[argmax(j.access)])) : '—'}</td>
        <td>${j && !j.failure ? esc(argmax(j.attack) + ' ' + pct(j.attack[argmax(j.attack)])) : '—'}</td>
        <td class="tnum">${r.jev.confidence != null ? pct(r.jev.confidence) : esc(FAIL[r.jev.failure] || '—')}</td>
        <td class="tnum">${r.jev.ms} / ${j ? j.timeout_ms : '—'}</td><td class="tnum">${j ? j.trim : '—'}</td></tr>`);
      tr.onclick = () => go(`#/requests/${r.request_id}?tab=jev`);
      tbl.querySelector('tbody').appendChild(tr);
    });
    page.appendChild(tbl);
  }

  // ===================== SITES =====================
  function renderSites(page) {
    page.appendChild(pageHead('站点', `${state.sites.length} 个站点`, [btn('新建站点', () => toast('接入向导：原型未实现完整四步，见 docs/06 6.4.8'), 'primary')]));
    const tbl = h(`<div class="tablewrap"><table class="data"><thead><tr><th>名称</th><th>Host</th><th>源站</th><th>模式</th><th>版本</th><th>24h 请求</th><th>拦截/本应</th><th>建议</th></tr></thead><tbody></tbody></table></div>`);
    state.sites.forEach((s) => {
      const loaded = s.loaded_version === s.version ? `● v${s.version} 已生效` : `◌ v${s.version} 生效中…`;
      const tr = h(`<tr><td><b>${esc(s.name)}</b></td><td class="mono">${esc(s.hosts.join(', '))}</td><td class="mono">${esc(s.origin)}</td>
        <td>${s.mode === 'observe' ? '观察 6 天' : '拦截'}</td><td class="dim">${esc(loaded)}</td>
        <td class="tnum">${n(s.requests_24h)}</td><td class="tnum">${s.mode === 'observe' ? s.would_block_24h + ' 本应' : s.blocked_24h}</td>
        <td class="tnum">${s.suggestions || '—'}</td></tr>`);
      tr.onclick = () => go(`#/sites/${s.name}`);
      tbl.querySelector('tbody').appendChild(tr);
    });
    page.appendChild(tbl);
  }

  function renderSiteDetail(page, name, q) {
    const s = state.sites.find((x) => x.name === name);
    page.appendChild(pageHead(`站点 ${name}`, '', [btn('← 站点', () => go('#/sites'))]));
    if (!s) { page.appendChild(h(`<div class="empty"><div class="big">站点不存在</div></div>`)); return; }
    const tab = q.get('tab') || 'overview';
    const tabs = h(`<div class="tabs"></div>`);
    [['overview', '概览'], ['config', '配置'], ['insights', '调优建议'], ['history', '变更历史']].forEach(([k, lbl]) => {
      const t = h(`<button class="tab ${tab === k ? 'active' : ''}">${esc(lbl)}</button>`);
      t.onclick = () => go(`#/sites/${name}?tab=${k}`);
      tabs.appendChild(t);
    });
    const head = h(`<div class="card" style="margin-bottom:12px"><div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px">
      <div><b style="font-size:16px">${esc(s.name)}</b> <span class="pill ${s.mode === 'enforce' ? 'blocked' : 'would_block'}" style="margin-left:8px">${s.mode === 'enforce' ? '拦截模式' : '观察模式（6 天）'}</span>
      <div class="muted" style="font-size:13px;margin-top:4px">${esc(s.hosts.join(', '))} → ${esc(s.origin)} · ● v${s.version} 已生效</div></div>
      <div></div></div></div>`);
    const switchBtn = btn(s.mode === 'enforce' ? '切回观察模式…' : '切换到拦截模式…', () => openModeSwitch(name));
    head.querySelector('div > div:last-child').appendChild(switchBtn);
    page.appendChild(head);
    page.appendChild(tabs);
    const body = h(`<div></div>`);
    page.appendChild(body);
    if (tab === 'overview') siteOverview(body, s);
    else if (tab === 'config') siteConfig(body, s, q);
    else if (tab === 'insights') siteInsights(body, s);
    else if (tab === 'history') siteHistory(body, s, q);
  }

  function siteOverview(body, s) {
    const tiles = h(`<div class="tiles" style="margin-bottom:16px"></div>`);
    [['24h 请求', n(s.requests_24h)], [s.mode === 'observe' ? '本应拦截' : '拦截', s.mode === 'observe' ? s.would_block_24h : s.blocked_24h], ['Jev 调用', s.jev_calls_24h], ['待处理建议', s.suggestions]].forEach(([k, v]) => tiles.appendChild(h(`<div class="tile"><div class="k">${esc(k)}</div><div class="v tnum">${esc(v)}</div></div>`)));
    body.appendChild(tiles);
    body.appendChild(h(`<div class="card"><h2>Jev 证据摘要（最近 24 小时）</h2><div class="muted">p50/p95/p99 ${M.EVIDENCE[s.name].jev.p50_ms}/${M.EVIDENCE[s.name].jev.p95_ms}/${M.EVIDENCE[s.name].jev.p99_ms} ms · 超时 ${M.EVIDENCE[s.name].jev.timeouts} / ${M.EVIDENCE[s.name].jev.calls} 次 · 缓存放行 ${M.EVIDENCE[s.name].cache.cached_allows} 次</div></div>`));
  }

  function siteConfig(body, s, q) {
    const edit = q.get('edit') || 'form';
    const group = q.get('group') || 'basic';
    const bar = h(`<div style="display:flex;gap:8px;margin-bottom:12px;align-items:center">
      <div class="tabs" style="border:none;margin:0"><button class="tab ${edit === 'form' ? 'active' : ''}">表单</button><button class="tab ${edit === 'yaml' ? 'active' : ''}">YAML</button></div>
      <div style="flex:1"></div></div>`);
    bar.querySelectorAll('.tab')[0].onclick = () => go(`#/sites/${s.name}?tab=config&edit=form&group=${group}`);
    bar.querySelectorAll('.tab')[1].onclick = () => go(`#/sites/${s.name}?tab=config&edit=yaml`);
    body.appendChild(bar);

    if (edit === 'yaml') {
      body.appendChild(h(`<div class="card"><h2>YAML（原型用只读文本框代替 CodeMirror）</h2><div class="codeblock wrap">${esc(toYaml(s.spec))}</div><div class="dim" style="margin-top:8px">YAML 只是编辑格式，保存的是 JSON，注释不会保留。完整编辑器见实现线程。</div></div>`));
      return;
    }

    const layout = h(`<div class="cfg-layout"></div>`);
    const nav = h(`<div class="cfg-nav"></div>`);
    const groups = [['basic', '基本信息'], ['session', '会话凭证'], ['entries', `入口 ${s.spec.entries.length}`], ['bypass', `绕过 ${s.spec.bypass.length}`], ['mode', '模式与 Jev 不可用'], ['advanced', advLabel(s)]];
    groups.forEach(([k, lbl]) => { const b = h(`<button class="${group === k ? 'active' : ''}">${esc(lbl)}</button>`); b.onclick = () => go(`#/sites/${s.name}?tab=config&group=${k}`); nav.appendChild(b); });
    layout.appendChild(nav);
    const panel = h(`<div></div>`);
    layout.appendChild(panel);
    body.appendChild(layout);

    if (group === 'basic') {
      panel.appendChild(h(`<div class="field"><label>站点名（创建后只读）</label><input type="text" value="${esc(s.spec.name)}" disabled></div>
        <div class="field"><label>Host</label><div class="taglist">${s.spec.hosts.map((x) => `<span class="tag">${esc(x)}</span>`).join('')}</div></div>
        <div class="field"><label>源站地址</label><input type="text" value="${esc(s.spec.origin)}"></div>`));
    } else if (group === 'session') {
      const cred = s.spec.session.header ? `请求头 ${s.spec.session.header}` : `Cookie ${s.spec.session.cookie}`;
      panel.appendChild(h(`<div class="field"><label>会话凭证</label><input type="text" value="${esc(cred)}"><div class="hint">修改会话凭证后，现有会话的上下文全部作废，用户需要重新从入口进入。</div></div>`));
    } else if (group === 'entries' || group === 'bypass') {
      const key = group;
      const list = h(`<div class="rulelist"></div>`);
      const impact = group === 'entries' ? { '/rest/user/login': 41, '/api/Products': 1204, '/rest/products/search': 88, '/login': 120, '/api/home': 90, '/api/patients': 240 } : { '/assets/*': 892, '/favicon.ico': 12, '/static/*': 410 };
      s.spec[key].forEach((p) => list.appendChild(h(`<div class="rulerow"><span class="mono">${esc(p)}</span><span class="hit">${impact[p] != null ? n(impact[p]) + ' 命中' : '24 小时未命中'}</span><button class="btn sm">删除</button></div>`)));
      panel.appendChild(h(`<div class="field"><label>${group === 'entries' ? '入口' : '绕过'}</label></div>`));
      panel.appendChild(list);
      panel.appendChild(h(`<div style="display:flex;gap:8px;margin-top:10px"><input type="text" placeholder="添加规则，例如 /rest/admin/*" style="flex:1"><button class="btn">添加</button></div>`));
      panel.appendChild(h(`<div class="field" style="margin-top:14px"><label>规则测试器</label><input type="text" placeholder="输入一个路径看它命中哪条规则"><div class="hint">含 ; // %2e %2f 的路径网关不会匹配到任何入口或绕过（与 PathPattern 规则一致）。</div></div>`));
    } else if (group === 'mode') {
      panel.appendChild(h(`<div class="field"><label>模式</label><div>${s.mode === 'enforce' ? '拦截模式' : '观察模式'} · <a href="javascript:void 0" id="msw">切换…</a></div></div>
        <div class="field"><label>Jev 不可用时</label><div class="radio-seg"><label><input type="radio" name="jevun" ${s.spec.on_jev_unavailable === 'deny' ? 'checked' : ''}> 拒绝（推荐）</label><label><input type="radio" name="jevun" ${s.spec.on_jev_unavailable === 'allow' ? 'checked' : ''}> 放行</label></div><div class="hint">选放行时，Jev 不可用的请求不经判定直接放行，记录标为“未经判定”。</div></div>`));
      panel.querySelector('#msw').onclick = (e) => { e.preventDefault(); openModeSwitch(s.name); };
    } else if (group === 'advanced') {
      panel.appendChild(advancedParams(s));
    }

    // draft bar (demo)
    const draft = h(`<div class="draftbar"><span class="n">未保存的改动 2 处（演示）</span><span class="sp"></span><button class="btn">放弃</button><button class="btn primary">预估影响并保存 ⌘S</button></div>`);
    draft.querySelector('.primary').onclick = () => openSaveDialog(s);
    body.appendChild(draft);
  }

  function advLabel(s) { const a = s.spec.advanced || {}; const nkeys = Object.keys(a).length; return nkeys ? `高级判定参数 · 已自定义 ${nkeys} 项` : '高级判定参数'; }

  function advancedParams(s) {
    const a = s.spec.advanced || {};
    const ev = M.EVIDENCE[s.name];
    const box = h(`<div></div>`);
    // Jev timeout
    const tmo = a.jev_timeout_ms;
    const timeoutItem = h(`<div class="adv-item">
      <div class="top"><span class="name">Jev 超时</span>
        <span class="radio-seg"><label><input type="radio" name="tmo" ${tmo == null ? 'checked' : ''}> 默认 2000 ms（部署设置）</label>
        <label><input type="radio" name="tmo" ${tmo != null ? 'checked' : ''}> 自定义 <input type="number" value="${tmo || 3000}" style="width:90px" ${tmo == null ? 'disabled' : ''}> ms</label></span>
        <span class="dim">100–30000</span></div>
      <div class="ev">单次 Jev 调用最多等多久；超时按“Jev 不可用时”处理<br>最近 24 小时 p50 ${ev.jev.p50_ms} · p95 ${ev.jev.p95_ms} · p99 ${ev.jev.p99_ms} ms · 超时 ${ev.jev.timeouts} 次 / ${ev.jev.calls} 次</div>
      ${tmo != null ? `<div class="impact">改为 ${tmo} ms：过去 24 小时有 ${ev.jev.timeouts} 次超时的调用可能不再超时</div>` : ''}</div>`);
    box.appendChild(timeoutItem);
    // call limits
    box.appendChild(h(`<div class="adv-item"><div class="top"><span class="name">会话调用上限</span>
      <span class="radio-seg"><label><input type="radio" ${a.session_calls_per_minute == null ? 'checked' : ''}> 默认 60 次/分钟</label><label><input type="radio" ${a.session_calls_per_minute != null ? 'checked' : ''}> 自定义</label></span>
      <span class="dim">最高 1 分钟 ${ev.call_limit.session_peak} 次 · 触发 ${ev.call_limit.session_hits} 次</span></div></div>`));
    box.appendChild(h(`<div class="adv-item"><div class="top"><span class="name">地址调用上限</span>
      <span class="radio-seg"><label><input type="radio" ${a.address_calls_per_minute == null ? 'checked' : ''}> 默认 30 次/分钟</label><label><input type="radio" ${a.address_calls_per_minute != null ? 'checked' : ''}> 自定义</label></span>
      <span class="dim">最高 1 分钟 ${ev.call_limit.address_peak} 次 · 触发 ${ev.call_limit.address_hits} 次${ev.call_limit.address_hits ? ' ▲' : ''}</span></div>
      <div class="ev">NAT 或代理后多个用户共用一个地址时需要调大；触发过上限时先看是不是未登录页面在轮询</div></div>`));
    // cache
    box.appendChild(h(`<div class="adv-item"><div class="top"><span class="name">放行缓存时长</span>
      <span class="radio-seg"><label><input type="radio" ${a.allow_cache_minutes == null ? 'checked' : ''}> 默认 10 分钟</label><label><input type="radio" ${a.allow_cache_minutes != null ? 'checked' : ''}> 自定义（0 = 不缓存）</label></span>
      <span class="dim">缓存放行 ${ev.cache.cached_allows} 次</span></div></div>`));
    // secret fields
    const builtins = M.SYSTEM.params.site_overridable.secret_fields;
    const site_secret = a.secret_fields || [];
    box.appendChild(h(`<div class="adv-item"><div class="top"><span class="name">追加脱敏词</span></div>
      <div style="margin-top:8px"><div class="dim" style="font-size:12px;margin-bottom:4px">内置（不可删除）</div><div class="taglist">${builtins.slice(0, 9).map((w) => `<span class="tag locked">🔒 ${esc(w)}</span>`).join('')}</div></div>
      <div style="margin-top:8px"><div class="dim" style="font-size:12px;margin-bottom:4px">本站点</div><div class="taglist">${site_secret.map((w) => `<span class="tag">${esc(w)} <button>×</button></span>`).join('')}<input type="text" placeholder="＋ 添加" style="width:120px"></div></div>
      <div class="ev">3–32 个字符，小写字母、数字、_ -，最多 32 个。像标识的词（如 card 会命中 cardId）会提示风险。</div></div>`));
    // synonyms
    const syn = a.synonyms || [];
    box.appendChild(h(`<div class="adv-item"><div class="top"><span class="name">同义词</span></div>
      <div style="margin-top:8px"><div class="dim" style="font-size:12px;margin-bottom:4px">内置</div><div class="taglist"><span class="tag locked">🔒 payment ↔ card</span></div></div>
      <div style="margin-top:8px"><div class="dim" style="font-size:12px;margin-bottom:4px">本站点</div><div class="taglist">${syn.map((p) => `<span class="tag">${esc(p[0])} ↔ ${esc(p[1])} <button>×</button></span>`).join('')}<button class="btn sm">＋ 添加一组</button></div></div>
      <div class="ev">按词根比较，结尾的 s 会被忽略。同义词改变核验结果，无法从历史记录预估影响。</div></div>`));
    return box;
  }

  function siteInsights(body, s) {
    const ins = M.INSIGHTS[s.name];
    if (!ins.suggestions.length) { body.appendChild(h(`<div class="empty">暂时没有建议。观察模式下积累更多请求后再来看</div>`)); return; }
    if (ins.readiness) {
      body.appendChild(h(`<div class="card" style="margin-bottom:12px"><h2>就绪检查</h2><div class="muted">本应拦截 ${ins.readiness.would_block.jev_deny + ins.readiness.would_block.no_session} 条（Jev 拒绝 ${ins.readiness.would_block.jev_deny}、无会话 ${ins.readiness.would_block.no_session}）· 待处理建议 ${ins.readiness.open_suggestions} 条 · Jev ${ins.readiness.jev_health === 'ok' ? '正常' : ins.readiness.jev_health}</div></div>`));
    }
    ins.suggestions.forEach((sg) => {
      const kindName = { entry_candidate: '登记入口', bypass_candidate: '加入绕过', upload_candidate: '上传接口加入绕过', raise_jev_timeout: '调大 Jev 超时', raise_call_limit: '调大调用上限', secret_field_candidate: '追加脱敏词', hot_would_block: '本应拦截集中' }[sg.kind];
      const card = h(`<div class="card" style="margin-bottom:10px"><div style="display:flex;justify-content:space-between;gap:10px"><b>${esc(kindName)} ${esc(sg.path)}</b><span class="dim">${n(sg.count)} 次</span></div>
        <div class="muted" style="margin:6px 0">${esc(sg.reason)}</div>
        <div class="mono dim" style="font-size:12px">改动：${esc(JSON.stringify(sg.action))}</div>
        <div style="display:flex;gap:8px;margin-top:10px"></div></div>`);
      const acts = card.querySelector('div:last-child');
      acts.appendChild(btn('忽略', () => { toast('已忽略（仅存浏览器）'); }, 'sm'));
      acts.appendChild(btn('应用…', () => openSaveDialog(s, sg), 'sm primary'));
      body.appendChild(card);
    });
  }

  function siteHistory(body, s, q) {
    const versions = [];
    for (let v = s.version; v >= 1; v--) versions.push({ version: v, at: M.NOW - (s.version - v) * 86400000, change: v === 1 ? 'create' : 'update', note: v === s.version ? '当前生效' : '', summary: v === s.version ? '入口 ＋1，Jev 超时 默认 → 3000 ms' : '修改配置' });
    const tbl = h(`<div class="tablewrap"><table class="data"><thead><tr><th>版本</th><th>时间</th><th>类型</th><th>摘要</th><th></th></tr></thead><tbody></tbody></table></div>`);
    versions.forEach((v) => {
      const tr = h(`<tr><td>v${v.version}${v.version === s.version ? ' ●' : ''}</td><td class="tnum">${fmtTime(v.at, true)}</td><td>${esc({ create: '创建', update: '修改', rollback: '回滚', delete: '删除', import: '导入' }[v.change])}</td><td class="muted">${esc(v.summary)}</td><td></td></tr>`);
      if (v.version !== s.version) { const b = h(`<button class="btn sm">以此回滚…</button>`); b.onclick = (e) => { e.stopPropagation(); openRollback(s, v.version); }; tr.lastElementChild.appendChild(b); }
      tbl.querySelector('tbody').appendChild(tr);
    });
    body.appendChild(h(`<div class="card"><h2>变更历史</h2></div>`)).appendChild(tbl);
    body.appendChild(h(`<div class="card" style="margin-top:12px"><h2>差异 v${s.version - 1}..v${s.version}</h2><div class="diff"><div class="line">  "mode": "observe",</div><div class="line add">+ "advanced": { "jev_timeout_ms": 3000 }</div><div class="line del">- "advanced": {}</div></div></div>`));
  }

  // ===================== SYSTEM =====================
  function renderSystem(page, q) {
    page.appendChild(pageHead('系统', `控制面 ${M.SYSTEM.control_build} · PostgreSQL ${M.SYSTEM.postgres}`));
    const tab = q.get('tab') || 'edges';
    const tabs = h(`<div class="tabs"></div>`);
    [['edges', '网关'], ['storage', '日志存储'], ['params', '运行参数'], ['import', '导入']].forEach(([k, lbl]) => { const t = h(`<button class="tab ${tab === k ? 'active' : ''}">${esc(lbl)}</button>`); t.onclick = () => go(`#/system?tab=${k}`); tabs.appendChild(t); });
    page.appendChild(tabs);
    if (tab === 'edges') {
      M.SYSTEM.edges.forEach((e) => {
        page.appendChild(h(`<div class="card" style="margin-bottom:12px"><div style="display:flex;justify-content:space-between"><b>${esc(e.edge)}</b><span><span class="dot ${e.online ? 'ok' : 'down'}"></span>${e.online ? '在线' : '离线'}</span></div>
          <div class="muted" style="font-size:13px;margin-top:8px">构建 ${esc(e.build)} · 监听 ${esc(e.listen)} ${e.tls ? '· TLS' : ''} · 会话 ${n(e.sessions)} · 队列 ${e.queue}<br>
          已写入 ${n(e.written)} · 丢弃 ${n(e.dropped)} · 写入失败 ${e.write_errors}<br>
          站点：${Object.entries(e.sites).map(([k, v]) => `${esc(k)} v${v.version}`).join(' · ')}<br>
          Jev：${esc(e.jev.route)} · ${esc(e.jev.endpoint_host)} · ${esc(e.jev.model)} · 默认超时 ${e.jev.default_timeout_ms} ms</div></div>`));
      });
    } else if (tab === 'storage') {
      const st = M.SYSTEM.storage;
      const tbl = h(`<div class="card"><h2>按天分区</h2><div class="tablewrap"><table class="data"><thead><tr><th>分区</th><th>行数</th><th>大小</th></tr></thead><tbody>${st.partitions.map((p) => `<tr><td class="mono">${esc(p.name)}</td><td class="tnum">${n(p.rows)}</td><td class="tnum">${bytes(p.bytes)}</td></tr>`).join('')}</tbody></table></div><div class="dim" style="margin-top:8px">保留期 7 天（代码默认值）· 最早记录 ${fmtTime(st.earliest_at, true)}</div></div>`);
      page.appendChild(tbl);
      if (st.gaps.length) page.appendChild(h(`<div class="card" style="margin-top:12px"><h2>日志缺口</h2>${st.gaps.map((g) => `<div class="muted">${esc(g.edge)} ${fmtTime(g.from)}–${fmtTime(g.to)} 丢失 ${g.rows} 条</div>`).join('')}</div>`));
    } else if (tab === 'params') {
      const p = M.SYSTEM.params;
      page.appendChild(h(`<div class="card" style="margin-bottom:12px"><h2>站点可覆盖的默认值</h2><div class="codeblock">${esc(JSON.stringify(p.site_overridable, null, 2))}</div></div>`));
      page.appendChild(h(`<div class="card"><h2>固定参数（只读）</h2><div class="codeblock">${esc(JSON.stringify(p.fixed, null, 2))}</div></div>`));
    } else if (tab === 'import') {
      page.appendChild(h(`<div class="card"><h2>导入判定日志</h2><div class="muted">选择网关文件模式输出的 JSON 行文件（最大 100 MiB）。导入的记录网关实例记为 import。</div><div style="margin-top:12px"><input type="file"></div></div>`));
    }
  }

  // ===================== DIALOGS =====================
  function openDialog(title, bodyEl, footEls) {
    const ov = h(`<div class="overlay"></div>`);
    const d = h(`<div class="dialog"><div class="d-head">${esc(title)}<button class="closex">×</button></div><div class="d-body"></div><div class="d-foot"></div></div>`);
    d.querySelector('.d-body').appendChild(bodyEl);
    (footEls || []).forEach((f) => d.querySelector('.d-foot').appendChild(f));
    d.querySelector('.closex').onclick = () => ov.remove();
    ov.onclick = (e) => { if (e.target === ov) ov.remove(); };
    ov.appendChild(d);
    document.body.appendChild(ov);
    return ov;
  }

  function openSaveDialog(s, sg) {
    const changes = sg ? [`${sg.kind === 'entry_candidate' ? '入口' : '绕过'} ＋ ${sg.path}`] : ['入口 ＋1：/rest/admin/application-configuration', 'Jev 超时  默认 → 3000 ms'];
    const body = h(`<div>
      <div class="field"><label>改动</label><div>${changes.map((c) => `<div class="mono">${esc(c)}</div>`).join('')}</div></div>
      <div class="field"><label>影响（按最近 24 小时估算）</label>
      <div class="impact">▸ 312 个无会话请求改为按入口判定 · GET /rest/admin/application-configuration 312<br>▸ 3 次超时的 Jev 调用可能不再超时</div></div>
      <div class="field"><label>备注（可选）</label><input type="text" value="${sg ? '从建议应用' : ''}"></div></div>`);
    const save = btn(`保存为 v${s.version + 1}`, () => {
      ov.remove(); s.version += 1; s.loaded_version = s.version - 1;
      toast(`已保存 v${s.version} · 等待网关加载…`);
      setTimeout(() => { s.loaded_version = s.version; toast(`● v${s.version} 已生效（edge-1，2.1 秒）`); }, 1600);
      if (location.hash.includes('/sites/')) render();
    }, 'primary');
    const ov = openDialog(`保存 ${s.name} 的配置`, body, [btn('取消', () => ov.remove()), save]);
  }

  function openRollback(s, v) {
    const body = h(`<div><div class="field"><label>回滚到 v${v}</label><div class="diff"><div class="line add">+ 恢复 v${v} 的全文</div><div class="line del">- 当前 v${s.version}</div></div></div><div class="field"><label>影响</label><div class="impact">按最近 24 小时估算，若干请求的判定路径会变化</div></div></div>`);
    const ov = openDialog(`回滚 ${s.name}`, body, [btn('取消', () => ov.remove()), btn(`回滚，生成 v${s.version + 1}（内容同 v${v}）`, () => { ov.remove(); s.version += 1; toast(`已回滚，生成 v${s.version}`); render(); }, 'primary')]);
  }

  function openModeSwitch(name) {
    const s = state.sites.find((x) => x.name === name);
    const toEnforce = s.mode === 'observe';
    if (!toEnforce) {
      const body = h(`<div class="muted">切回观察后不再拦截任何请求，只记录本应拦截。</div>`);
      const ov = openDialog(`把 ${name} 切回观察模式`, body, [btn('取消', () => ov.remove()), btn(`切回观察模式（生成 v${s.version + 1}）`, () => { ov.remove(); s.mode = 'observe'; s.version += 1; toast(`${name} 已切回观察模式 v${s.version}`); render(); }, 'primary')]);
      return;
    }
    const rd = M.INSIGHTS[name].readiness || { would_block: { jev_deny: 11, no_session: 3 }, open_suggestions: 1, jev_health: 'ok', after_would_block_refs: 5 };
    const wb = rd.would_block.jev_deny + rd.would_block.no_session;
    const body = h(`<div>
      <div class="field"><label>就绪检查（最近 24 小时）</label>
      <div style="line-height:2">
        <div>✓ 已观察 6 天 4 小时</div>
        <div><span class="lvl-warn">▲</span> 本应拦截 ${wb} 条：Jev 拒绝 ${rd.would_block.jev_deny} · 无会话 ${rd.would_block.no_session}</div>
        <div><span class="lvl-warn">▲</span> 待处理建议 ${rd.open_suggestions} 条</div>
        <div>✓ Jev 正常（p95 910 ms，超时 0.7%）</div>
        <div><span class="lvl-warn">▲</span> 由本应拦截请求学到的值被后续请求引用 ${rd.after_would_block_refs} 次（切换后这些请求也可能被拦截）</div>
        <div>✓ Jev 不可用时：拒绝</div>
      </div></div>
      <div class="field"><label>影响</label><div class="impact">过去 24 小时有 ${wb} 个请求会被拦截（返回 401 / 403）</div></div>
      <label class="check"><input type="checkbox" id="ackbox"> 我已查看这些请求，确认它们应当被拦截</label></div>`);
    const go2 = btn(`切换到拦截模式（生成 v${s.version + 1}）`, () => {
      if (!body.querySelector('#ackbox').checked) { toast('请先勾选确认'); return; }
      ov.remove(); s.mode = 'enforce'; s.version += 1; toast(`${name} 已切换到拦截模式 v${s.version}`); render();
    }, 'primary');
    const ov = openDialog(`把 ${name} 切换到拦截模式`, body, [btn('取消', () => ov.remove()), go2]);
  }

  function openQuickRule(r, kind) {
    const path = r.path;
    const parent = path.split('/').slice(0, -1).join('/') + '/*';
    const body = h(`<div>
      <div class="field"><label>候选规则</label>
      <div class="radio-seg" style="flex-direction:column;gap:8px">
        <label><input type="radio" name="cand" checked> 精确路径 <span class="mono">${esc(path)}</span></label>
        <label><input type="radio" name="cand"> 前缀 <span class="mono">${esc(parent)}</span> ${kind === 'entry' ? '<span class="dim">前缀入口会放大无会话可达的范围</span>' : ''}</label>
      </div></div>
      ${kind === 'bypass' ? '<div class="notice">绕过后该接口不做越权判定，只在确实需要时使用。</div>' : ''}
      <div class="field"><label>影响</label><div class="impact">过去 24 小时匹配 312 个${kind === 'entry' ? '无会话' : ''}请求</div></div>
      <div class="field"><label>备注</label><input type="text" value="从请求 ${esc(r.request_id.slice(-8))} ${kind === 'entry' ? '登记入口' : '加入绕过'}"></div></div>`);
    const s = state.sites.find((x) => x.name === r.site);
    const ov = openDialog(kind === 'entry' ? '登记为入口' : '加入绕过', body, [btn('取消', () => ov.remove()), btn(`保存为 v${s.version + 1}`, () => { ov.remove(); s.version += 1; s.loaded_version = s.version - 1; toast(`已保存 v${s.version}`); setTimeout(() => { s.loaded_version = s.version; toast(`● v${s.version} 已生效`); }, 1500); }, 'primary')]);
  }

  function openBatch() {
    const body = h(`<div>
      <div class="field"><label>① 粘贴测试套件的 TSV、日志或任意文本（最多 1000 个 ID）</label>
      <textarea id="batchin" rows="6" placeholder="x_xshield_request_id\tstarted_at\tmethod\thttp_status\toutcome\treq_01a19741107477ff9224781077354552\t2026-11-01T13:16:26Z\tGET\t200\tblocked"></textarea></div>
      <div id="batchres"></div></div>`);
    const run = btn('对照', () => {
      const text = body.querySelector('#batchin').value;
      const ids = [...new Set((text.match(/req_[0-9a-f]{32}/g) || []))];
      const res = body.querySelector('#batchres');
      if (!ids.length) { res.innerHTML = '<div class="empty">没有识别到请求 ID</div>'; return; }
      const rows = ids.map((id) => { const r = M.RECORD_BY_ID[id]; return { id, found: !!r, outcome: r ? r.outcome : null, dp: r ? r.decision_path : null }; });
      res.innerHTML = `<div class="field"><label>② 结果：${ids.length} 个 · 找到 ${rows.filter((r) => r.found).length} · 查不到 ${rows.filter((r) => !r.found).length}</label></div>`;
      const tbl = h(`<div class="tablewrap"><table class="data"><thead><tr><th>请求 ID</th><th>实际结论</th><th>判定路径</th></tr></thead><tbody></tbody></table></div>`);
      rows.forEach((r) => tbl.querySelector('tbody').appendChild(h(`<tr><td class="mono">…${esc(r.id.slice(-8))}</td><td>${r.found ? outPill(r.outcome) : '<span class="dim">查不到</span>'}</td><td>${r.found ? dpBadge(r.dp) : '—'}</td></tr>`)));
      res.appendChild(tbl);
    }, 'primary');
    const ov = openDialog('批量对照', body, [btn('关闭', () => ov.remove()), run]);
  }

  function notFound(id) {
    let why = '可能来自其他环境的网关';
    const t = M.idTime(id);
    if (M.NOW - t > 7 * 86400000) why = `生成于 ${fmtTime(t, true)}，已超过 7 天保留期`;
    else if (t > M.NOW) why = 'ID 时间异常，可能不是本系统生成的';
    return h(`<div class="empty"><div class="big">找不到这个请求</div><div class="dim">${esc(why)}</div></div>`);
  }

  // ===================== COMMAND PALETTE =====================
  function openPalette() {
    const ov = h(`<div class="overlay" style="align-items:flex-start;padding-top:12vh"></div>`);
    const box = h(`<div class="palette"><input placeholder="粘贴请求 ID、会话、路径或站点名…" autofocus><div class="results"></div></div>`);
    ov.appendChild(box); document.body.appendChild(ov);
    const input = box.querySelector('input'); const results = box.querySelector('.results');
    ov.onclick = (e) => { if (e.target === ov) ov.remove(); };
    function update() {
      const v = input.value.trim(); results.innerHTML = ''; const out = [];
      const ids = v.match(/req_[0-9a-f]{32}/g) || [];
      if (ids.length === 1) out.push(['请求', `打开 ${ids[0].slice(-8)}`, fmtTime(M.idTime(ids[0]), true), () => go(`#/requests/${ids[0]}`)]);
      else if (ids.length > 1) out.push(['批量', `对照 ${ids.length} 个请求 ID`, '', () => { ov.remove(); openBatch(); }]);
      if (/^[0-9a-f]{16}$/.test(v)) out.push(['会话', `打开会话 ${v}`, '', () => go(`#/sessions/${v}`)]);
      if (v.startsWith('/')) out.push(['路径', `筛选路径 ${v}`, '', () => go(`#/requests?q=path:${encodeURIComponent(v)}`)]);
      state.sites.forEach((s) => { if (s.name.includes(v.toLowerCase()) && v) { out.push(['站点', `打开 ${s.name}`, '', () => go(`#/sites/${s.name}`)]); out.push(['站点', `${s.name} 的配置`, '', () => go(`#/sites/${s.name}?tab=config`)]); } });
      [['总览', '#/'], ['请求追溯', '#/requests'], ['会话', '#/sessions'], ['Jev 调用', '#/jev'], ['站点', '#/sites'], ['系统', '#/system']].forEach(([nm, hr]) => { if (!v || nm.includes(v)) out.push(['前往', nm, '', () => go(hr)]); });
      let group = '';
      out.slice(0, 12).forEach((o, i) => {
        if (o[0] !== group) { group = o[0]; results.appendChild(h(`<div class="pgroup">${esc(group)}</div>`)); }
        const r = h(`<div class="pres ${i === 0 ? 'active' : ''}"><span>${esc(o[1])}</span><span class="sub">${esc(o[2])}</span></div>`);
        r.onclick = () => { ov.remove(); o[3](); };
        results.appendChild(r);
      });
    }
    input.oninput = update;
    input.onkeydown = (e) => { if (e.key === 'Enter') { const first = results.querySelector('.pres'); if (first) first.click(); } if (e.key === 'Escape') ov.remove(); };
    update();
  }

  // ===================== CHARTS (inline SVG) =====================
  function stackedChart(data) {
    const W = 640, H = 180, pad = 24;
    const max = Math.max(...data.map((d) => d.fast + d.jev + d.no_session));
    const bw = (W - pad * 2) / data.length;
    let bars = '';
    data.forEach((d, i) => {
      const x = pad + i * bw + 2; const w = bw - 4;
      let y = H - pad;
      [['no_session', 'var(--s3)'], ['jev', 'var(--s2)'], ['fast', 'var(--s1)']].forEach(([k, c]) => {
        const hgt = (d[k] / max) * (H - pad * 2);
        y -= hgt;
        bars += `<rect x="${x}" y="${y}" width="${w}" height="${Math.max(hgt - 2, 0)}" rx="2" fill="${c}"><title>${k} ${d[k]}</title></rect>`;
      });
    });
    return h(`<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="每小时请求堆叠柱">
      <line x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}" stroke="var(--axis)" stroke-width="1"/>
      ${bars}<text class="axislabel" x="${pad}" y="${H - 6}">00:00</text><text class="axislabel" x="${W - pad - 30}" y="${H - 6}">现在</text></svg>`);
  }
  function histogram(buckets, markIdx, label) {
    const W = 360, H = 120, pad = 20; const max = Math.max(...buckets, 1); const bw = (W - pad * 2) / buckets.length;
    let bars = '';
    buckets.forEach((b, i) => { const hgt = (b / max) * (H - pad * 2); bars += `<rect x="${pad + i * bw + 1}" y="${H - pad - hgt}" width="${bw - 2}" height="${hgt}" rx="2" fill="var(--s1)"><title>${b}</title></rect>`; });
    let mark = '';
    if (markIdx) { const mx = W - pad - 8; mark = `<line x1="${mx}" y1="${pad - 6}" x2="${mx}" y2="${H - pad}" stroke="var(--ink-2)" stroke-width="1"/><text class="axislabel" x="${mx - 6}" y="${pad - 8}" text-anchor="end">超时</text>`; }
    return h(`<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(label || '直方图')}"><line x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}" stroke="var(--axis)"/>${bars}${mark}</svg>`);
  }

  // ===================== helpers =====================
  function btn(label, fn, cls) { const b = h(`<button class="btn ${cls || ''}">${esc(label)}</button>`); b.onclick = fn; return b; }
  function toYaml(spec) {
    const lines = [`name: ${spec.name}`, `hosts: [${spec.hosts.join(', ')}]`, `origin: ${spec.origin}`,
      `session:`, spec.session.header ? `  header: ${spec.session.header}` : `  cookie: ${spec.session.cookie}`,
      `entries:`, ...spec.entries.map((e) => `  - ${e}`), `bypass:`, ...spec.bypass.map((b) => `  - ${b}`),
      `mode: ${spec.mode}`, `on_jev_unavailable: ${spec.on_jev_unavailable}`];
    const a = spec.advanced || {};
    if (Object.keys(a).length) {
      lines.push('advanced:');
      if (a.jev_timeout_ms) lines.push(`  jev_timeout_ms: ${a.jev_timeout_ms}`);
      if (a.secret_fields) lines.push(`  secret_fields: [${a.secret_fields.join(', ')}]`);
      if (a.synonyms) a.synonyms.forEach((p) => lines.push(`  synonyms:\n    - [${p[0]}, ${p[1]}]`));
    }
    return lines.join('\n');
  }

  // ===================== boot =====================
  M.SYSTEM.params.site_overridable.secret_fields = M.SYSTEM.params.site_overridable.secret_fields;
  window.addEventListener('hashchange', render);
  document.addEventListener('keydown', (e) => {
    const typing = /INPUT|TEXTAREA/.test(document.activeElement.tagName);
    if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); return; }
    if (typing) return;
    if (e.key === '?') { toast('快捷键：⌘K 命令面板 · / 筛选 · g+字母 跳转 · j/k 浏览'); }
    if (e.key === 'g') { window._g = true; setTimeout(() => (window._g = false), 800); return; }
    if (window._g) { const m = { o: '#/', r: '#/requests', s: '#/sessions', j: '#/jev', c: '#/sites', y: '#/system' }[e.key]; if (m) go(m); window._g = false; }
  });

  // topbar wiring
  $('#site-select').onchange = (e) => { state.site = e.target.value; render(); };
  $('#search-box').onclick = openPalette;
  $('#nav-toggle').onclick = () => $('#app').classList.toggle('nav-collapsed');
  $('#theme-toggle').onclick = () => {
    const cur = document.documentElement.getAttribute('data-theme');
    const nextT = cur === 'dark' ? 'light' : 'dark';
    document.documentElement.setAttribute('data-theme', nextT);
  };
  document.querySelectorAll('.nav-item').forEach((b) => { b.onclick = () => go(b.dataset.href); });

  render();
})();
