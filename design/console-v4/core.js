// Xshield v4 console prototype: shared helpers, vocabulary, router, dialogs, status lights.
// Vanilla JS, no build step. All record text is rendered through esc()/safeText();
// nothing from the mock data is inserted as HTML. Sample times are shown in UTC+8.
'use strict';
(function () {
  const M = window.MOCK;
  const X = window.X = { M, routes: [], pageKeys: {}, dialogs: [], bootAt: Date.now(), scroll: {}, recent: [] };
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  X.$ = $; X.$$ = $$;

  // ---------------------------------------------------------------- escaping
  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  }
  // Control, zero-width and bidi code points are shown as visible \uXXXX (docs/06 6.5.5).
  // Listed as numbers so this source never contains an invisible character itself.
  const HIDDEN_RANGES = [[0x0000, 0x001f], [0x007f, 0x007f], [0x200b, 0x200f], [0x2060, 0x2060], [0xfeff, 0xfeff], [0x202a, 0x202e], [0x2066, 0x2069]];
  const uesc = (cp) => String.fromCharCode(92) + 'u' + cp.toString(16).padStart(4, '0');
  const HIDDEN = new RegExp('[' + HIDDEN_RANGES.map(([a, b]) => (a === b ? uesc(a) : uesc(a) + '-' + uesc(b))).join('') + ']', 'g');
  function safeText(s) { return esc(s).replace(HIDDEN, (c) => `<span class="escw">${esc(uesc(c.codePointAt(0)))}</span>`); }
  // Builds one element from an HTML string. A string with several top-level nodes is wrapped in a
  // display:contents box so no sibling is silently dropped (X.multiRoot lists such call sites for tests).
  function h(html) {
    const t = document.createElement('template'); t.innerHTML = html.trim();
    if (t.content.childNodes.length > 1) {
      const w = document.createElement('div'); w.className = 'ctn'; w.appendChild(t.content);
      (X.multiRoot = X.multiRoot || []).push(((new Error()).stack || '').split('\n').slice(2, 4).join(' <- '));
      return w;
    }
    return t.content.firstElementChild;
  }
  function mid(s, max) { s = String(s); return s.length <= max ? s : s.slice(0, Math.ceil((max - 1) * 0.6)) + '…' + s.slice(-Math.floor((max - 1) * 0.4)); }
  Object.assign(X, { esc, safeText, h, mid, uesc });

  // ---------------------------------------------------------------- formatting
  const TZ = 8 * 3600000; // sample data is shown in UTC+8, matching the examples in docs/06
  const z = (v, w = 2) => String(v).padStart(w, '0');
  function parts(ms) { const d = new Date(ms + TZ); return { y: d.getUTCFullYear(), mo: d.getUTCMonth() + 1, d: d.getUTCDate(), h: d.getUTCHours(), mi: d.getUTCMinutes(), s: d.getUTCSeconds(), ms: d.getUTCMilliseconds() }; }
  X.fmtTime = (ms, withDate) => { const p = parts(ms); const t = `${z(p.h)}:${z(p.mi)}:${z(p.s)}.${z(p.ms, 3)}`; return withDate ? `${p.mo}-${z(p.d)} ${t}` : t; };
  X.fmtHM = (ms) => { const p = parts(ms); return `${z(p.h)}:${z(p.mi)}`; };
  X.fmtHMS = (ms) => { const p = parts(ms); return `${z(p.h)}:${z(p.mi)}:${z(p.s)}`; };
  X.fmtFull = (ms) => { const p = parts(ms); return `${p.y}-${z(p.mo)}-${z(p.d)} ${z(p.h)}:${z(p.mi)}:${z(p.s)}.${z(p.ms, 3)}`; };
  X.fmtUtc = (ms) => new Date(ms).toISOString().replace('T', ' ').replace('Z', '');
  X.now = () => M.NOW + (Date.now() - X.bootAt);
  X.dur = (ms) => { const s = Math.round(ms / 1000); if (s < 60) return `${s} 秒`; if (s < 3600) return `${Math.floor(s / 60)} 分${s % 60 ? ` ${s % 60} 秒` : ''}`; const m = Math.round(s / 60); if (m < 1440) return `${Math.floor(m / 60)} 小时${m % 60 ? ` ${m % 60} 分` : ''}`; return `${Math.floor(m / 1440)} 天${Math.floor((m % 1440) / 60) ? ` ${Math.floor((m % 1440) / 60)} 小时` : ''}`; };
  X.rel = (ms) => { const s = Math.max(0, Math.round((X.now() - ms) / 1000)); if (s < 60) return `${s} 秒前`; if (s < 3600) return `${Math.round(s / 60)} 分钟前`; if (s < 86400) return `${Math.round(s / 3600)} 小时前`; return `${Math.round(s / 86400)} 天前`; };
  X.n = (x) => (x == null ? '—' : Number(x).toLocaleString('en-US'));
  X.bytes = (b) => { if (b < 1024) return `${b} B`; if (b < 1048576) return `${(b / 1024).toFixed(1)} KiB`; if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MiB`; return `${(b / 1073741824).toFixed(2)} GiB`; };
  X.pct = (p) => (p == null ? '—' : `${Math.round(p * 100)}%`);
  X.argmax = M.argmax;

  // ---------------------------------------------------------------- vocabulary (docs/06 6.6)
  X.DP = {
    bypass: { name: '绕过', g: '→', tip: '命中绕过规则，不判定，直接转发' },
    fast_allow: { name: '快速放行', g: '»', tip: '需核验的值都已核验，没有调用 Jev' },
    cached_allow: { name: '缓存放行', g: '↺', tip: '复用缓存时长内 Jev 对同一请求的放行' },
    jev_allow: { name: 'Jev 通过', g: '✦', tip: 'Jev 判定访问有依据、内容无攻击' },
    jev_deny: { name: 'Jev 拒绝', g: '✦', tip: 'Jev 判定越权或攻击；观察模式下网关的结论是“本应拦截”' },
    jev_unavailable: { name: 'Jev 不可用', g: '∅', tip: 'Jev 超时、出错、调用达到上限或答不上来，按站点设置处理' },
    no_session: { name: '无会话', g: '⊘', tip: '没有会话凭证，路径也不是入口' },
    body_not_inspectable: { name: '请求体不可判定', g: '⊟', tip: '请求体超过 48 KiB 或没有 Content-Length，返回 413' },
    unknown_site: { name: '未知站点', g: '⊗', tip: 'Host 不属于任何站点，返回 404' },
  };
  X.OUT = { allowed: ['放行', '○', '转发给源站'], blocked: ['拦截', '■', '网关返回 401 / 403 / 404 / 413，没有转发'], would_block: ['本应拦截', '▲', '观察模式下本应拦截，照常转发'], unjudged: ['未经判定', '◆', 'Jev 不可用且站点设置为放行，没有判定就转发'] };
  X.FAIL = {
    JEV_TIMEOUT: ['超时', '超过所用超时（站点设置或默认值）仍未返回'],
    JEV_RATE_LIMITED: ['服务限流', '模型服务返回 429'],
    JEV_TRANSPORT: ['连接失败', '连接、TLS 或协议错误'],
    JEV_HTTP_ERROR: ['服务出错', '模型服务返回非 200 状态'],
    JEV_RESPONSE_TOO_LARGE: ['响应过大', '响应超过 64 KiB'],
    JEV_RESPONSE_INVALID: ['响应无效', '响应结构不符合约定'],
    JEV_UNKNOWN: ['答不上来', '最高项是 UNKNOWN 或两项并列'],
    JEV_STATE_TOO_LARGE: ['上下文过大', '裁剪后仍超过 8 KiB，没有调用'],
    JEV_CALL_LIMIT: ['达到上限', '会话或地址每分钟调用次数用完，没有调用'],
  };
  X.failName = (c) => (X.FAIL[c] ? X.FAIL[c][0] : c);
  X.ACCESS = { ALLOW: '有依据', DENY: '越权', UNKNOWN: '不确定' };
  X.ATTACK = { BENIGN: '无攻击', ATTACK: '攻击', UNKNOWN: '不确定' };
  X.CONCL = { allow: '通过', deny: '拒绝', unknown: '无法判定' };
  X.ROUTE_N = { gateway: '经 AI Gateway', direct: '直连 TypeSafe', custom: '自定义地址' };
  X.KIND = { route: '路由词', reference: '引用', input: '输入' };
  X.SKIP = { status: '非 2xx', content_type: '类型不是 JSON 或 HTML', compressed: '响应被压缩', too_large: '超过 1 MiB', head: 'HEAD 请求', not_forwarded: '请求没有转发' };
  X.SUGG = { entry_candidate: '登记入口', bypass_candidate: '加入绕过', upload_candidate: '上传接口加入绕过', raise_jev_timeout: '调大 Jev 超时', raise_call_limit: '调大调用上限', secret_field_candidate: '追加脱敏词', hot_would_block: '本应拦截集中' };
  X.HINT = {
    verified: { g: '✓', cls: 'ok', text: '已核验', tip: '网关已用响应核验过这是同类对象' },
    input: { g: '–', cls: 'neutral', text: '输入内容，不需要见过', tip: '' },
    route: { g: '–', cls: 'neutral', text: '路由词', tip: '' },
    seen: { g: '!', cls: 'warn', text: '见过，但不是同类对象', tip: '这个值在会话里出现过，但网关没能核验它是同类对象' },
    never: { g: '✕', cls: 'err', text: '从未见过', tip: '这个值在这个会话的响应里从未出现过' },
  };
  X.valueHint = (v) => (v.verified ? 'verified' : v.kind === 'input' ? 'input' : v.kind === 'route' ? 'route' : v.seen ? 'seen' : 'never');

  X.dpBadge = (dp) => { const v = X.DP[dp] || { name: dp, g: '·', tip: '' }; return `<span class="badge" title="${esc(dp)}：${esc(v.tip)}"><span class="g" aria-hidden="true">${v.g}</span>${esc(v.name)}</span>`; };
  X.outPill = (o) => { const v = X.OUT[o] || [o, '·', '']; return `<span class="pill ${o}" title="${esc(o)}：${esc(v[2])}"><span class="g ${o}" aria-hidden="true">${v[1]}</span>${esc(v[0])}</span>`; };
  X.jevCell = (j) => {
    if (!j) return '<span class="dim">—</span>';
    if (j.failure) return `<span class="muted" title="${esc(j.failure)}">${esc(X.failName(j.failure))}</span>`;
    const lead = j.attack === 'ATTACK' ? `攻击 ${X.pct(j.confidence)}` : j.access === 'DENY' ? `越权 ${X.pct(j.confidence)}` : j.access === 'UNKNOWN' || j.attack === 'UNKNOWN' ? `不确定 ${X.pct(j.confidence)}` : `放行 ${X.pct(j.confidence)}`;
    return `<span title="置信度 = 两个回答中最高项概率的较小值">${esc(lead)}${j.confidence < 0.7 ? ' <span class="lowconf" title="置信度低于 70%">低</span>' : ''}</span>`;
  };
  X.idCell = (id) => `<span class="idcell" title="${esc(id)}">…${esc(id.slice(-8))}</span>`;
  X.shortSess = (s) => (s ? s.slice(0, 8) : '—');

  // ---------------------------------------------------------------- sites + rollout (in-memory only)
  X.sites = JSON.parse(JSON.stringify(M.SITES));
  X.site = (name) => X.sites.find((s) => s.name === name);
  X.loaded = {}; // site -> edge -> loaded version
  X.sites.forEach((s) => { X.loaded[s.name] = {}; M.SYSTEM.edges.forEach((e) => { X.loaded[s.name][e.edge] = e.sites[s.name] ? e.sites[s.name].version : 0; }); });
  X.stuckEdge = null; // demo: an online edge that never loads new versions
  X.BEHIND_MS = 6000; // docs say 30 s; the prototype shortens it so the amber state can be demonstrated
  function setLoaded(site, edge, v) {
    X.loaded[site][edge] = v;
    const e = M.SYSTEM.edges.find((x) => x.edge === edge); if (e) e.sites[site] = { version: v };
    X.refreshRollout();
  }
  X.rolloutOf = (s) => {
    const edges = M.SYSTEM.edges.map((e) => ({ edge: e.edge, online: e.online, version: X.loaded[s.name][e.edge] }));
    const on = edges.filter((e) => e.online);
    return { version: s.version, edges_online: on.length, edges_loaded: on.filter((e) => e.version >= s.version).length, edges };
  };
  X.rolloutHtml = (s) => {
    const ro = X.rolloutOf(s); const off = ro.edges.filter((e) => !e.online);
    const offTxt = off.length ? ` · ${off.map((e) => `${esc(e.edge)} 离线（${e.version ? `停在 v${e.version}` : '没有加载过'}）`).join('、')}` : '';
    if (!ro.edges_online) return `<span class="ro warn">◌ v${s.version} 已保存 · 没有在线的网关，上线后加载</span>`;
    if (ro.edges_loaded === ro.edges_online) return `<span class="ro ok"><span class="dot ok" aria-hidden="true"></span>v${s.version} · ${ro.edges_loaded}/${ro.edges_online} 个网关已生效${offTxt}</span>`;
    const behind = ro.edges.filter((e) => e.online && e.version < s.version);
    const late = X.now() - s.saved_at > X.BEHIND_MS;
    return `<span class="ro ${late ? 'warn' : 'pending'}">◌ v${s.version} · ${ro.edges_loaded}/${ro.edges_online} 个网关已加载${late ? ` · ${behind.map((e) => `${esc(e.edge)} 停在 v${e.version}`).join('、')}` : ' · 等待网关加载…'}${offTxt}</span>`;
  };
  X.refreshRollout = () => {
    $$('[data-rollout]').forEach((el) => { const s = X.site(el.dataset.rollout); if (s) el.innerHTML = X.rolloutHtml(s); });
    X.renderLights();
  };
  // A saved version reaches each online edge after a short delay (the real console polls /rollout every second).
  X.simulateRollout = (s, stuck) => {
    X.stuckEdge = stuck || null;
    const online = M.SYSTEM.edges.filter((e) => e.online);
    online.forEach((e, i) => {
      if (stuck && e.edge === stuck) return;
      setTimeout(() => { setLoaded(s.name, e.edge, s.version); if (X.rolloutOf(s).edges_loaded === X.rolloutOf(s).edges_online) X.toast(`● ${s.name} v${s.version} 已生效（${online.length} 个网关，${(1.1 + i * 1.2).toFixed(1)} 秒）`); }, 1100 + i * 1200);
    });
    if (stuck) setTimeout(() => X.refreshRollout(), X.BEHIND_MS + 200);
  };

  // ---------------------------------------------------------------- status lights (docs/07 7.9.13)
  // A log gap counts both rows dropped from a full queue and rows lost to failed writes (docs/07 7.7.4).
  X.gapLost = (g) => (g.dropped || 0) + (g.write_errors || 0);
  X.gapCause = (g) => (g.dropped && g.write_errors ? '队列满、写入失败' : g.write_errors ? '写入失败' : '队列满');
  // Evidence for a site; a site created in this session has none yet.
  X.evidence = (name) => M.EVIDENCE[name] || {
    window_hours: 24, jev: { p50_ms: 0, p95_ms: 0, p99_ms: 0, timeouts: 0, calls: 0, timeout_ms_used: M.SYSTEM.params.site_overridable.jev_timeout_ms },
    call_limit: { session_peak: 0, address_peak: 0, session_hits: 0, address_hits: 0 }, cache: { cached_allows: 0 }, histogram: new Array(30).fill(0),
  };
  X.computeStatus = () => {
    const now = X.now(); const edges = M.SYSTEM.edges; const on = edges.filter((e) => e.online); const problems = [];
    edges.filter((e) => !e.online).forEach((e) => problems.push({ kind: 'edge_offline', level: 'warn', text: `${e.edge} 已离线 ${Math.max(1, Math.round((now - e.seen_at) / 60000))} 分钟（最后心跳 ${X.fmtHMS(e.seen_at)}）`, href: '#/system?tab=edges', act: '查看系统' }));
    X.sites.forEach((s) => {
      const ro = X.rolloutOf(s); const behind = ro.edges.filter((e) => e.online && e.version < s.version);
      if (behind.length && now - s.saved_at > X.BEHIND_MS) problems.push({ kind: 'version_behind', level: 'serious', text: `${s.name} v${s.version} 保存后仍有 ${behind.length}/${ro.edges_online} 个网关没加载（${behind.map((e) => `${e.edge} 停在 v${e.version}`).join('、')}）`, href: '#/system?tab=edges', act: '查看系统' });
    });
    edges.forEach((e) => (e.gaps || []).forEach((g) => {
      if (X.gapLost(g) > 0 && now - g.to_ms < 15 * 60000) problems.push({ kind: 'log_gap', level: 'serious', text: `${e.edge} 在 ${X.fmtHM(g.from_ms)}–${X.fmtHM(g.to_ms)} 有 ${X.gapLost(g)} 条判定记录未写入（${X.gapCause(g)}），这段时间的请求可能查不到`, href: `#/requests?since=${g.from_ms}&until=${g.to_ms}&scope=all`, act: '查看缺口' });
    }));
    edges.forEach((e) => { if (e.online && e.queue / M.SYSTEM.params.fixed.queue_capacity > 0.8) problems.push({ kind: 'queue_pressure', level: 'warn', text: `${e.edge} 发送队列超过 80%`, href: '#/system?tab=edges', act: '查看系统' }); });
    const order = { serious: 0, warn: 1, info: 2 }; problems.sort((a, b) => order[a.level] - order[b.level]);
    const light = !on.length ? 'down' : problems.length ? 'warn' : 'ok';
    return { light, edges_online: on.length, edges_total: edges.length, problems, jev: M.JEV_STATUS };
  };
  X.renderLights = () => {
    const st = X.computeStatus(); X.status = st;
    const gw = $('#light-gw'); const jv = $('#light-jev'); if (!gw || !jv) return;
    const label = st.light === 'ok' ? `网关 ${st.edges_online}/${st.edges_total} 在线` : st.light === 'warn' ? `网关 ${st.edges_online}/${st.edges_total} 在线 · ${st.problems.length} 个问题` : '网关 无在线实例';
    gw.innerHTML = `<span class="dot ${st.light === 'ok' ? 'ok' : st.light === 'warn' ? 'warn' : 'down'}" aria-hidden="true"></span><span class="lt">${esc(label)}</span>`;
    gw.setAttribute('aria-label', label);
    const j = st.jev; const jl = { ok: ['ok', 'Jev 正常'], idle: ['idle', 'Jev 空闲'], degraded: ['warn', 'Jev 降级'], down: ['down', 'Jev 不可用'] }[j.health];
    jv.innerHTML = `<span class="dot ${jl[0]}" aria-hidden="true"></span><span class="lt">${jl[1]}</span>`; jv.setAttribute('aria-label', jl[1]);
  };
  X.openGatewayPopover = (anchor) => {
    const st = X.computeStatus();
    const box = h('<div class="pop-body"></div>');
    box.appendChild(h(`<div class="pop-title">网关 ${st.edges_online}/${st.edges_total} 在线 · ${st.problems.length ? `${st.problems.length} 个问题` : '没有问题'}</div>`));
    if (!st.problems.length) box.appendChild(h('<div class="muted">一切正常。只有现在存在的问题会让灯变色；更早的日志缺口在系统页的缺口列表里。</div>'));
    st.problems.forEach((p) => {
      const g = p.level === 'serious' ? '<span class="lvl-serious" aria-label="严重">■</span>' : '<span class="lvl-warn" aria-label="警告">▲</span>';
      const r = h(`<div class="pop-row"><span class="pg">${g}</span><span class="pm">${esc(p.text)}</span><a href="${esc(p.href)}">${esc(p.act)}</a></div>`);
      r.querySelector('a').onclick = () => X.closePopover();
      box.appendChild(r);
    });
    box.appendChild(h('<div class="pop-foot dim">每 15 秒读取 /api/status</div>'));
    X.popover(anchor, box, { right: true });
  };
  X.openJevPopover = (anchor) => {
    const j = M.JEV_STATUS; const box = h('<div class="pop-body"></div>');
    const lbl = { ok: '正常', idle: '空闲', degraded: '降级', down: '不可用' }[j.health];
    box.appendChild(h(`<div class="pop-title">Jev ${lbl}</div>`));
    box.appendChild(h(`<div class="muted" style="line-height:1.7">最近 ${j.window_minutes} 分钟 ${j.calls} 次调用，${j.ok === j.calls ? '全部成功' : `${j.calls - j.ok} 次失败`}<br>p50 ${j.p50_ms} ms · p95 ${j.p95_ms} ms<br>最后一次失败 ${X.fmtHMS(Date.parse(j.last_failure.at))}（${esc(X.failName(j.last_failure.failure))}，${esc(j.last_failure.site)}）</div>`));
    const a = h('<div class="pop-foot"><a href="#/jev">查看 Jev 调用</a></div>'); a.querySelector('a').onclick = () => X.closePopover();
    box.appendChild(a); X.popover(anchor, box, { right: true });
  };

  // ---------------------------------------------------------------- toast, copy, popover, dialog
  X.toast = (msg) => { const t = h(`<div class="toast">${esc(msg)}</div>`); $('#toasts').appendChild(t); setTimeout(() => t.remove(), 3200); };
  // Clipboard writes can be refused inside a sandboxed frame; say so instead of claiming success.
  X.copy = (text, msg) => {
    const ok = () => X.toast(msg || '已复制');
    const fail = () => X.toast('浏览器不允许自动复制，请手动选中后复制');
    const legacy = () => {
      const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0'; document.body.appendChild(ta); ta.select();
      let good = false; try { good = document.execCommand('copy'); } catch (e) { good = false; } ta.remove(); good ? ok() : fail();
    };
    if (navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(text).then(ok, legacy); else legacy();
  };
  X.btn = (label, fn, cls) => { const b = h(`<button type="button" class="btn ${cls || ''}">${esc(label)}</button>`); if (fn) b.onclick = fn; return b; };
  X.closePopover = () => { if (X._pop) { X._pop.close(); X._pop = null; } };
  X.popover = (anchor, content, opts = {}) => {
    X.closePopover();
    const pop = h('<div class="popover" role="dialog"></div>'); pop.appendChild(content); document.body.appendChild(pop);
    const r = anchor.getBoundingClientRect(); const w = pop.offsetWidth;
    let left = opts.right ? r.right - w : r.left; left = Math.max(8, Math.min(left, innerWidth - w - 8));
    let top = r.bottom + 6; if (top + pop.offsetHeight > innerHeight - 8) top = Math.max(8, r.top - pop.offsetHeight - 6);
    pop.style.left = `${left}px`; pop.style.top = `${top}px`;
    const onDoc = (e) => { if (!pop.contains(e.target) && !anchor.contains(e.target)) close(); };
    const onKey = (e) => { if (e.key === 'Escape') { e.stopPropagation(); close(); anchor.focus && anchor.focus(); } };
    function close() { pop.remove(); document.removeEventListener('mousedown', onDoc, true); document.removeEventListener('keydown', onKey, true); X._pop = null; }
    setTimeout(() => { document.addEventListener('mousedown', onDoc, true); document.addEventListener('keydown', onKey, true); });
    X._pop = { close }; return close;
  };
  X.dialog = (title, bodyEl, footEls, opts = {}) => {
    const prev = document.activeElement;
    const ov = h('<div class="overlay"></div>');
    const d = h(`<div class="dialog ${opts.wide ? 'wide' : ''}" role="dialog" aria-modal="true" aria-label="${esc(title)}"><div class="d-head"><span>${esc(title)}</span><button type="button" class="closex" aria-label="关闭">×</button></div><div class="d-body"></div><div class="d-foot"></div></div>`);
    d.querySelector('.d-body').appendChild(bodyEl);
    (footEls || []).forEach((f) => d.querySelector('.d-foot').appendChild(f));
    if (!(footEls || []).length) d.querySelector('.d-foot').remove();
    ov.appendChild(d); document.body.appendChild(ov);
    const api = { el: d, overlay: ov, close };
    function onKey(e) {
      if (X.dialogs[X.dialogs.length - 1] !== api) return;
      if (e.key === 'Escape') { e.stopPropagation(); e.preventDefault(); close(); }
      else if (e.key === 'Tab') {
        const f = $$('button, input, select, textarea, a[href]', d).filter((x) => !x.disabled && x.offsetParent !== null);
        if (!f.length) return; const first = f[0]; const last = f[f.length - 1];
        if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); } else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
      }
    }
    function close() { ov.remove(); document.removeEventListener('keydown', onKey, true); X.dialogs = X.dialogs.filter((x) => x !== api); if (prev && prev.focus) prev.focus(); if (opts.onClose) opts.onClose(); }
    d.querySelector('.closex').onclick = close;
    ov.addEventListener('mousedown', (e) => { if (e.target === ov) close(); });
    document.addEventListener('keydown', onKey, true);
    X.dialogs.push(api);
    const first = $('input:not([disabled]), textarea, select, .d-foot .primary', d) || d.querySelector('.closex'); first.focus();
    return api;
  };

  // ---------------------------------------------------------------- router
  X.parseHash = () => {
    const raw = (location.hash || '#/').slice(1); const i = raw.indexOf('?');
    return { parts: (i < 0 ? raw : raw.slice(0, i)).split('/').filter(Boolean).map(decodeURIComponent), q: new URLSearchParams(i < 0 ? '' : raw.slice(i + 1)) };
  };
  X.go = (hash) => { if (location.hash === hash) X.render(); else location.hash = hash; };
  X.hashWith = (patch, base) => {
    const { parts, q } = base || X.parseHash(); const nq = new URLSearchParams(q.toString());
    Object.keys(patch).forEach((k) => { if (patch[k] == null || patch[k] === '') nq.delete(k); else nq.set(k, patch[k]); });
    const qs = nq.toString(); return `#/${parts.map(encodeURIComponent).join('/')}${qs ? `?${qs}` : ''}`;
  };
  X.setQuery = (patch, replace) => { const next = X.hashWith(patch); if (replace) history.replaceState(null, '', next); else X.go(next); };
  X.route = (match, render) => X.routes.push({ match, render });
  X.pageHead = (title, sub, actions) => {
    const el = h(`<div class="page-head"><h1>${esc(title)}</h1><div class="sub">${esc(sub || '')}</div><div class="actions"></div></div>`);
    (actions || []).forEach((a) => el.querySelector('.actions').appendChild(a)); return el;
  };
  X.scopeLabel = () => (X.state.site === 'all' ? '全部站点' : X.state.site);
  X.state = { site: 'all' };
  X.render = () => {
    const page = $('#page'); const { parts, q } = X.parseHash(); const key = parts[0] || 'overview';
    // docs/06 6.2.2: the site scope lives in the URL (`site`, default all sites) and persists across pages.
    const urlSite = q.get('site');
    if (urlSite && (urlSite === 'all' || X.sites.some((s) => s.name === urlSite))) X.state.site = urlSite;
    else if (!urlSite && X.state.site !== 'all') { try { history.replaceState(null, '', X.hashWith({ site: X.state.site })); } catch (e) { /* sandboxed preview: keep the scope in memory only */ } }
    if (X.routeKey === 'requests' && !X.parseHashPrev) X.scroll.requests = page.scrollTop;
    X.closePopover();
    $$('.nav-item[data-route]').forEach((b) => b.classList.toggle('active', b.dataset.route === key));
    const prevKey = X.routeKey; const prevDetail = X.routeDetail;
    X.routeKey = key; X.routeDetail = parts.length > 1;
    X.pageKeys = {}; X.saveShortcut = null; X.pageCleanup && X.pageCleanup(); X.pageCleanup = null;
    page.innerHTML = '';
    const r = X.routes.find((x) => x.match(parts));
    try {
      if (r) r.render(page, parts, q);
      else page.appendChild(h('<div class="empty"><div class="big">页面不存在</div><div class="dim">检查地址，或从左侧导航进入。</div></div>'));
    } catch (e) { page.appendChild(h(`<div class="empty"><div class="big">渲染出错（原型）</div><div class="dim">${esc(e.message)}</div></div>`)); console.error(e); }
    page.scrollTop = (key === 'requests' && !parts[1] && prevKey === 'requests' && prevDetail) || (key === 'requests' && !parts[1] && X.restoreScroll) ? (X.scroll.requests || 0) : 0;
    X.restoreScroll = false;
    if (key === 'requests' && parts[1]) X.rememberRecent('request', parts[1]);
    document.title = `${{ overview: '总览', requests: '请求追溯', sessions: '会话', jev: 'Jev 调用', sites: '站点', system: '系统' }[key] || 'Xshield'} · Xshield 控制台原型`;
  };
  X.rememberRecent = (kind, id) => {
    const title = kind === 'request' ? (M.RECORD_BY_ID[id] ? `${M.RECORD_BY_ID[id].method} ${M.RECORD_BY_ID[id].path}` : id.slice(-8)) : id;
    const href = kind === 'request' ? `#/requests/${id}` : kind === 'session' ? `#/sessions/${id}` : `#/sites/${id}`;
    X.recent = X.recent.filter((r) => r.href !== href); X.recent.unshift({ kind, title, href }); X.recent = X.recent.slice(0, 10);
  };

  // ---------------------------------------------------------------- explain (docs/06 6.4.4)
  const short = (s, n2 = 24) => (String(s).length > n2 ? String(s).slice(0, n2 - 1) + '…' : String(s));
  X.explainParts = (r) => {
    const t = r.trace || {}; const j = r.jevFull; const vals = t.values || [];
    const site = X.site(r.site) || { spec: { advanced: {} } };
    let reason = '';
    switch (r.decision_path) {
      case 'bypass': reason = `命中绕过规则 ${t.bypass}，没有判定，直接转发。`; break;
      case 'unknown_site': reason = `Host ${r.host} 不属于任何站点。`; break;
      case 'body_not_inspectable': reason = '请求体超过 48 KiB 判定上限或没有 Content-Length，无法判定。需要上传大文件的接口可以加入绕过，但绕过后不做越权判定。'; break;
      case 'no_session': reason = `请求没有会话凭证（${site.spec.session && site.spec.session.cookie ? 'Cookie' : '请求头'} ${site.spec.session ? (site.spec.session.cookie || site.spec.session.header) : ''}），路径也不是入口。`; break;
      case 'fast_allow': { const nv = vals.filter((v) => !v.inert).length; reason = nv ? `${nv} 个需核验的值都已核验，没有调用 Jev。` : '请求里没有需要核验的值，没有调用 Jev。'; break; }
      case 'cached_allow': { const src = t.cache_source && M.RECORD_BY_ID[t.cache_source]; const mins = src ? Math.max(1, Math.round((r.at_millis - src.at_millis) / 60000)) : '?'; reason = `同一会话 ${mins} 分钟前的相同请求已由 Jev 放行（${src ? `${src.method} ${src.path}` : '来源已过保留期'}），在缓存时长 ${(site.spec.advanced || {}).allow_cache_minutes == null ? 10 : site.spec.advanced.allow_cache_minutes} 分钟内直接复用。`; break; }
      case 'jev_allow': { const need = vals.filter((v) => !v.inert && !v.verified); reason = `${need.length} 个值未核验（${need.map((v) => v.key || v.at).join('、')}），Jev 判定访问有依据（ALLOW ${X.pct(j.access.ALLOW)}）、内容无攻击（BENIGN ${X.pct(j.attack.BENIGN)}）。`; break; }
      case 'jev_deny':
        if (j && j.attack.ATTACK > j.attack.BENIGN) { const v = vals.find((x) => x.kind === 'input' && !x.redacted) || {}; reason = `Jev 判定为攻击（ATTACK ${X.pct(j.attack.ATTACK)}）：${v.at || '请求'} 的值含 “${short(v.value || '')}”。`; }
        else {
          const v = vals.find((x) => x.seen && !x.verified) || vals.find((x) => x.kind === 'reference' && !x.seen) || {}; const s0 = (v.sources || [])[0];
          reason = `Jev 判定越权（DENY ${X.pct(j.access.DENY)}）：${v.at || '某个值'} 里的 ${short(v.value || '')} 在这个会话里${s0 ? `没有以同类对象出现过，只以 ${s0.field} 出现在 ${s0.request} 的响应里` : '从未出现过'}。`;
        }
        break;
      case 'jev_unavailable':
        if (j && j.failure === 'JEV_TIMEOUT') reason = `Jev 调用超时（${j.timeout_ms} ms，${j.timeout_ms === M.SYSTEM.params.site_overridable.jev_timeout_ms ? '默认值' : '站点设置'}）。`;
        else if (j && j.failure === 'JEV_CALL_LIMIT') reason = `本${r.context === 'address' ? '地址' : '会话'}每分钟 Jev 调用已达上限 ${r.context === 'address' ? 30 : 60} 次，没有调用 Jev。`;
        else reason = `Jev 不可用（${j ? X.failName(j.failure) : '未知'}）。`;
        break;
      default: reason = '';
    }
    let act = '';
    if (r.outcome === 'blocked') act = `返回 ${r.status}。`;
    else if (r.outcome === 'would_block') act = '站点处于观察模式，请求照常转发。';
    else if (r.outcome === 'unjudged') act = '站点设置为 Jev 不可用时放行，这个请求没有经过判定。';
    return { reason, act };
  };
  X.explain = (r) => { const e = X.explainParts(r); return `${e.reason}${e.act ? ` ${e.act}` : ''}`; };
  // What the gateway did with Jev's answer (kept apart from Jev's own conclusion).
  X.gatewayEffect = (r) => ({
    blocked: `网关已拦截，返回 ${r.status}`, would_block: '本站点在观察模式：本应拦截，请求已照常转发',
    unjudged: 'Jev 不可用，按站点设置放行（未经判定）', allowed: '网关放行，请求已转发',
  }[r.outcome]);

  // ---------------------------------------------------------------- YAML subset, validation, rules, diffs
  const TOP_KEYS = ['name', 'hosts', 'origin', 'session', 'entries', 'bypass', 'mode', 'on_jev_unavailable', 'advanced'];
  const ADV_KEYS = ['jev_timeout_ms', 'session_calls_per_minute', 'address_calls_per_minute', 'allow_cache_minutes', 'secret_fields', 'synonyms'];
  X.ADV_KEYS = ADV_KEYS;
  X.specToYaml = (spec) => {
    const L = [`name: ${spec.name}`, `hosts: [${spec.hosts.join(', ')}]`, `origin: ${spec.origin}`, 'session:', spec.session.header ? `  header: ${spec.session.header}` : `  cookie: ${spec.session.cookie}`];
    L.push('entries:'); spec.entries.forEach((e) => L.push(`  - ${e}`));
    if (spec.bypass.length) { L.push('bypass:'); spec.bypass.forEach((e) => L.push(`  - ${e}`)); } else L.push('bypass: []');
    L.push(`mode: ${spec.mode}`, `on_jev_unavailable: ${spec.on_jev_unavailable}`);
    const a = spec.advanced || {}; const ks = ADV_KEYS.filter((k) => a[k] != null && (!Array.isArray(a[k]) || a[k].length));
    if (ks.length) {
      L.push('advanced:');
      ks.forEach((k) => {
        if (k === 'secret_fields') L.push(`  secret_fields: [${a[k].join(', ')}]`);
        else if (k === 'synonyms') { L.push('  synonyms:'); a[k].forEach((p) => L.push(`    - [${p[0]}, ${p[1]}]`)); } else L.push(`  ${k}: ${a[k]}`);
      });
    }
    return `${L.join('\n')}\n`;
  };
  // Returns {spec} or {error:{line,msg}}. Handles exactly the shapes specToYaml produces, plus comments.
  X.parseYaml = (text) => {
    const lines = text.split('\n').map((raw, i) => ({ raw: raw.replace(/\s+#.*$/, '').replace(/\s+$/, ''), i: i + 1 })).filter((l) => l.raw.trim() && !l.raw.trim().startsWith('#'));
    let pos = 0; const ind = (s) => s.match(/^ */)[0].length;
    const fail = (l, msg) => { throw { line: l.i, msg }; };
    const scalar = (s, l) => {
      s = s.trim();
      if (s.startsWith('[')) { if (!s.endsWith(']')) fail(l, '列表缺少右方括号 ]'); const inner = s.slice(1, -1).trim(); return inner ? inner.split(',').map((x) => scalar(x, l)) : []; }
      if (/^-?\d+$/.test(s)) return Number(s);
      return s.replace(/^["']|["']$/g, '');
    };
    function block(indent, allowed, path) {
      const first = lines[pos];
      if (first.raw.trim().startsWith('- ')) {
        const arr = [];
        while (pos < lines.length && ind(lines[pos].raw) === indent && lines[pos].raw.trim().startsWith('- ')) { arr.push(scalar(lines[pos].raw.trim().slice(2), lines[pos])); pos += 1; }
        return arr;
      }
      const obj = {};
      while (pos < lines.length && ind(lines[pos].raw) === indent) {
        const l = lines[pos]; const m = l.raw.trim().match(/^([A-Za-z_][\w-]*):\s*(.*)$/);
        if (!m) fail(l, '这一行不是“键: 值”的格式');
        if (allowed && !allowed.includes(m[1])) fail(l, `不认识的字段 ${m[1]}${path ? `（在 ${path} 下）` : ''}`);
        if (m[1] in obj) fail(l, `字段 ${m[1]} 重复`);
        pos += 1;
        if (m[2] === '') obj[m[1]] = pos < lines.length && ind(lines[pos].raw) > indent ? block(ind(lines[pos].raw), m[1] === 'advanced' ? ADV_KEYS : m[1] === 'session' ? ['cookie', 'header'] : null, m[1]) : null;
        else obj[m[1]] = scalar(m[2], l);
      }
      if (pos < lines.length && ind(lines[pos].raw) > indent) fail(lines[pos], '缩进与上一级不一致');
      return obj;
    }
    try {
      if (!lines.length) return { error: { line: 1, msg: '内容为空' } };
      const obj = block(ind(lines[0].raw), TOP_KEYS, '');
      if (pos < lines.length) fail(lines[pos], '缩进与上一级不一致');
      const spec = { name: obj.name || '', hosts: obj.hosts || [], origin: obj.origin || '', session: obj.session || {}, entries: obj.entries || [], bypass: obj.bypass || [], mode: obj.mode || 'observe', on_jev_unavailable: obj.on_jev_unavailable || 'deny', advanced: obj.advanced || {} };
      if (spec.advanced.synonyms) spec.advanced.synonyms = spec.advanced.synonyms.map((p) => (Array.isArray(p) ? p : String(p).split(/\s*,\s*/)));
      if (spec.advanced.secret_fields && !Array.isArray(spec.advanced.secret_fields)) spec.advanced.secret_fields = [String(spec.advanced.secret_fields)];
      return { spec };
    } catch (e) { if (e && e.line) return { error: e }; throw e; }
  };
  // These mirror crates/xshield-core/src/context/config.rs (valid_host, valid_origin, valid_token, PathPattern::parse).
  const hostOk = (x) => x.length > 0 && x.length <= 253 && /^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$/i.test(x) && !x.includes('..');
  const originOk = (o) => { const m = /^https?:\/\/([^:/]*)(?::(\d*))?$/.exec(o || ''); return !!m && hostOk(m[1]) && (m[2] == null || (m[2].length >= 1 && m[2].length <= 5)); };
  const tokenOk = (t) => /^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,64}$/.test(t || '');
  const pathOk = (p) => p.length <= 256 && p.startsWith('/') && !/[?#\\\s\x00-\x1f\x7f]/.test(p) && !p.slice(0, -1).includes('*') && !p.split('/').some((seg) => seg === '.' || seg === '..');
  X.validateSpec = (spec) => {
    const errors = []; const warnings = []; const add = (g, f, msg) => errors.push({ group: g, field: f, msg });
    if (!/^[a-z0-9_-]{1,64}$/.test(spec.name || '')) add('basic', 'name', '站点名只能用小写字母、数字、-、_，最长 64 个字符');
    if (!spec.hosts.length || spec.hosts.length > 16 || spec.hosts.some((x) => !hostOk(x))) add('basic', 'hosts', 'Host 不能为空，最多 16 个，每个必须是有效的主机名（不带端口）');
    if (!originOk(spec.origin)) add('basic', 'origin', '源站地址必须是 http://主机[:端口] 或 https://主机[:端口]，不带路径');
    if (!['observe', 'enforce'].includes(spec.mode)) add('mode', 'mode', '模式只能是 observe（观察）或 enforce（拦截）');
    if (!['allow', 'deny'].includes(spec.on_jev_unavailable)) add('mode', 'on_jev_unavailable', 'Jev 不可用时只能是 allow（放行）或 deny（拒绝）');
    const sess = spec.session || {}; if ((!sess.cookie && !sess.header) || (sess.cookie && sess.header) || !tokenOk(sess.cookie || sess.header)) add('session', 'session', '会话凭证需要一个有效的 Cookie 名或请求头名（字母、数字和 !#$%&\'*+-.^_`|~，最长 64）');
    if (!spec.entries.length || spec.entries.length > 64 || spec.entries.some((p) => !pathOk(p))) add('entries', 'entries', '入口至少一条、最多 64 条；每条以 / 开头，* 只能在末尾，不能含查询串、. 或 .. 段');
    if (spec.bypass.length > 64 || spec.bypass.some((p) => !pathOk(p))) add('bypass', 'bypass', '绕过最多 64 条，规则格式同入口');
    const a = spec.advanced || {}; const range = (k, lo, hi, label) => { if (a[k] != null && (!Number.isInteger(a[k]) || a[k] < lo || a[k] > hi)) add('advanced', k, `${label}需在 ${lo}–${hi} 之间`); };
    range('jev_timeout_ms', 100, 30000, 'Jev 超时（ms）'); range('session_calls_per_minute', 1, 600, '会话调用上限'); range('address_calls_per_minute', 1, 600, '地址调用上限'); range('allow_cache_minutes', 0, 60, '放行缓存时长（分钟）');
    (a.secret_fields || []).forEach((w) => { if (!/^[a-z0-9_-]{3,32}$/.test(w)) add('advanced', 'secret_fields', `脱敏词 ${w} 需为 3–32 个字符的小写字母、数字、_ 或 -`); });
    if ((a.secret_fields || []).length > 32) add('advanced', 'secret_fields', '追加脱敏词最多 32 个');
    (a.synonyms || []).forEach((p) => { if (p.length !== 2 || p.some((w) => !/^[a-z]{3,24}$/.test(w)) || p[0] === p[1]) add('advanced', 'synonyms', `同义词 ${p.join(' ↔ ')} 需为两个不同的 3–24 位小写字母词`); });
    if (spec.entries.some((p) => p === '/*' || /^\/[^/]*\/\*$/.test(p) && p.split('/').length <= 3 && p.endsWith('/*') && p.length <= 6)) warnings.push({ group: 'entries', msg: '前缀入口会放大无会话可达的范围' });
    return { errors, warnings };
  };
  // Mirrors PathPattern: odd spellings never match any entry or bypass rule.
  X.oddPath = (path) => /;|\/\/|%2e|%2f|%5c/i.test(path) || path.split('/').some((s) => s === '.' || s === '..');
  X.matchRule = (rule, path) => !X.oddPath(path) && (rule.endsWith('/*') ? path.startsWith(rule.slice(0, -1)) : rule === path);
  X.diffLines = (aText, bText) => {
    const a = aText.split('\n'); const b = bText.split('\n'); const dp = Array.from({ length: a.length + 1 }, () => new Int16Array(b.length + 1));
    for (let i = a.length - 1; i >= 0; i--) for (let j = b.length - 1; j >= 0; j--) dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    const out = []; let i = 0; let j = 0;
    while (i < a.length && j < b.length) { if (a[i] === b[j]) { out.push({ t: 'ctx', s: a[i] }); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) out.push({ t: 'del', s: a[i++] }); else out.push({ t: 'add', s: b[j++] }); }
    while (i < a.length) out.push({ t: 'del', s: a[i++] }); while (j < b.length) out.push({ t: 'add', s: b[j++] });
    return out;
  };
  X.diffView = (aText, bText) => {
    const rows = X.diffLines(aText, bText); const box = h('<div class="diff"></div>'); let any = false;
    rows.forEach((r, k) => {
      const near = rows.slice(Math.max(0, k - 1), k + 2).some((x) => x.t !== 'ctx');
      if (r.t === 'ctx' && !near) return;
      any = any || r.t !== 'ctx';
      box.appendChild(h(`<div class="line ${r.t}"><span class="sign">${r.t === 'add' ? '+' : r.t === 'del' ? '−' : ' '}</span>${esc(r.s)}</div>`));
    });
    if (!any) box.appendChild(h('<div class="line">没有差异</div>'));
    return box;
  };
  const list = (arr) => arr.join('、');
  X.diffSpec = (a, b) => {
    const out = []; const eq = (x, y) => JSON.stringify(x) === JSON.stringify(y);
    const arrDiff = (label, x, y) => { x.filter((v) => !y.includes(v)).forEach((v) => out.push({ label, kind: 'del', text: `− ${v}` })); y.filter((v) => !x.includes(v)).forEach((v) => out.push({ label, kind: 'add', text: `＋ ${v}` })); };
    if (a.origin !== b.origin) out.push({ label: '源站', text: `${a.origin} → ${b.origin}` });
    arrDiff('Host', a.hosts, b.hosts); arrDiff('入口', a.entries, b.entries); arrDiff('绕过', a.bypass, b.bypass);
    if (!eq(a.session, b.session)) out.push({ label: '会话凭证', kind: 'session', text: `${a.session.header ? `请求头 ${a.session.header}` : `Cookie ${a.session.cookie}`} → ${b.session.header ? `请求头 ${b.session.header}` : `Cookie ${b.session.cookie}`}` });
    if (a.on_jev_unavailable !== b.on_jev_unavailable) out.push({ label: 'Jev 不可用时', text: `${a.on_jev_unavailable === 'deny' ? '拒绝' : '放行'} → ${b.on_jev_unavailable === 'deny' ? '拒绝' : '放行'}` });
    if (a.mode !== b.mode) out.push({ label: '模式', text: `${a.mode === 'observe' ? '观察' : '拦截'} → ${b.mode === 'observe' ? '观察' : '拦截'}` });
    const A = a.advanced || {}; const B = b.advanced || {}; const NAMES = { jev_timeout_ms: 'Jev 超时', session_calls_per_minute: '会话调用上限', address_calls_per_minute: '地址调用上限', allow_cache_minutes: '放行缓存时长' };
    const UNIT = { jev_timeout_ms: ' ms', session_calls_per_minute: ' 次/分钟', address_calls_per_minute: ' 次/分钟', allow_cache_minutes: ' 分钟' };
    Object.keys(NAMES).forEach((k) => { if (A[k] !== B[k]) out.push({ label: NAMES[k], adv: k, text: `${A[k] == null ? '默认' : A[k] + UNIT[k]} → ${B[k] == null ? '默认' : B[k] + UNIT[k]}` }); });
    arrDiff('追加脱敏词', A.secret_fields || [], B.secret_fields || []);
    const sy = (p) => p.join(' ↔ '); arrDiff('同义词', (A.synonyms || []).map(sy), (B.synonyms || []).map(sy));
    return out;
  };
  X.list = list;

  // ---------------------------------------------------------------- charts (inline SVG, series colours from docs/06 6.5.4)
  X.stackedChart = (data) => {
    const W = 640; const H = 190; const pad = 28; const max = Math.max(...data.map((d) => d.fast + d.jev + d.no_session)); const bw = (W - pad * 2) / data.length; let bars = ''; let grid = '';
    [0.5, 1].forEach((f) => { const y = H - pad - f * (H - pad * 2); grid += `<line x1="${pad}" y1="${y}" x2="${W - pad}" y2="${y}" stroke="var(--grid)"/><text class="axislabel" x="${pad - 4}" y="${y + 3}" text-anchor="end">${Math.round(max * f)}</text>`; });
    data.forEach((d, i) => {
      const x = pad + i * bw + 2; const w = Math.min(bw - 4, 24); let y = H - pad;
      [['no_session', 'var(--s3)', '无会话'], ['jev', 'var(--s2)', 'Jev 判定'], ['fast', 'var(--s1)', '免调用放行']].forEach(([k, c, nm], si) => {
        const hgt = (d[k] / max) * (H - pad * 2); y -= hgt;
        bars += `<rect x="${x}" y="${y}" width="${w}" height="${Math.max(hgt - 2, 0)}" rx="${si === 2 ? 3 : 0}" fill="${c}"><title>${String(i).padStart(2, '0')}:00  ${nm} ${d[k]}</title></rect>`;
      });
    });
    return h(`<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="每小时请求堆叠柱，三组：免调用放行、Jev 判定、无会话">${grid}<line x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}" stroke="var(--axis)"/>${bars}<text class="axislabel" x="${pad}" y="${H - 8}">00:00</text><text class="axislabel" x="${W / 2}" y="${H - 8}" text-anchor="middle">12:00</text><text class="axislabel" x="${W - pad}" y="${H - 8}" text-anchor="end">现在</text></svg>`);
  };
  // buckets: counts per `step` units; marks: [{at, label}] positions in the same unit; xlabel(i) for ticks
  X.histogram = (buckets, o = {}) => {
    const W = 380; const H = 132; const pad = 22; const max = Math.max(...buckets, 1); const bw = (W - pad * 2) / buckets.length; let bars = ''; let marks = '';
    buckets.forEach((b, i) => { const hgt = (b / max) * (H - pad * 2 - 6); bars += `<rect x="${pad + i * bw + 1}" y="${H - pad - hgt}" width="${Math.max(bw - 2, 1)}" height="${hgt}" rx="2" fill="${o.color || 'var(--s1)'}"><title>${o.tip ? o.tip(i, b) : b}</title></rect>`; });
    (o.marks || []).forEach((m, k) => { const mx = pad + (m.at / buckets.length) * (W - pad * 2); marks += `<line x1="${mx}" y1="${pad - 8}" x2="${mx}" y2="${H - pad}" stroke="var(--ink-2)" stroke-width="1"${m.dash ? ' stroke-dasharray="3 3"' : ''}/><text class="axislabel" x="${mx + (m.left ? -4 : 4)}" y="${pad - 2 + k * 11}" text-anchor="${m.left ? 'end' : 'start'}">${esc(m.label)}</text>`; });
    const ticks = (o.ticks || []).map((t) => `<text class="axislabel" x="${pad + (t.at / buckets.length) * (W - pad * 2)}" y="${H - 6}" text-anchor="middle">${esc(t.label)}</text>`).join('');
    return h(`<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="${esc(o.label || '直方图')}"><line x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}" stroke="var(--axis)"/>${bars}${marks}${ticks}</svg>`);
  };
  X.spark = (vals, w = 96, hgt = 24, color = 'var(--s1)') => {
    const max = Math.max(...vals, 1); const step = w / (vals.length - 1 || 1);
    const pts = vals.map((v, i) => `${(i * step).toFixed(1)},${(hgt - 2 - (v / max) * (hgt - 4)).toFixed(1)}`).join(' ');
    return h(`<svg class="spark" width="${w}" height="${hgt}" viewBox="0 0 ${w} ${hgt}" aria-hidden="true"><polyline points="${pts}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/></svg>`);
  };
  // A card with an optional "以表格查看" switch (docs/06 6.5.4).
  X.chartCard = (title, chartEl, tableRows, cols) => {
    const card = h(`<div class="card"><div class="card-head"><h2>${esc(title)}</h2><button type="button" class="linkbtn">以表格查看</button></div><div class="cc-body"></div></div>`);
    const body = card.querySelector('.cc-body'); body.appendChild(chartEl);
    let table = false; const sw = card.querySelector('.linkbtn');
    sw.onclick = () => {
      table = !table; body.innerHTML = ''; sw.textContent = table ? '以图表查看' : '以表格查看';
      if (!table) { body.appendChild(chartEl); return; }
      const t = h(`<div class="tablewrap short"><table class="data"><thead><tr>${cols.map((c) => `<th>${esc(c)}</th>`).join('')}</tr></thead><tbody>${tableRows.map((r) => `<tr>${r.map((c) => `<td class="tnum">${esc(c)}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
      body.appendChild(t);
    };
    return card;
  };

  // ---------------------------------------------------------------- JSON helpers used by several views
  X.jsonPathCopy = (path) => X.copy(path, `已复制路径 ${path}`);
  X.safeParse = (s) => { try { return JSON.parse(s); } catch (e) { return null; } };
})();
