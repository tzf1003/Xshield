// Jev context viewer (docs/06 6.4.5), JSON tree, in-view search, and the Jev calls page (6.4.6).
'use strict';
(function () {
  const X = window.X; const M = X.M; const { $, $$, h, esc, safeText, n, pct, bytes } = X; const go = (hash) => X.go(hash);
  const TRIM = [null, '为满足 8 KiB 上限，最近访问从 10 条减到 3 条', '为满足 8 KiB 上限，最近访问全部去掉', '为满足 8 KiB 上限，最近访问去掉且每个值的来源只留 1 个', '为满足 8 KiB 上限，值的长度上限从 512 降到 128 字符'];
  const copyIcon = (text, label) => { const b = h(`<button type="button" class="iconbtn" aria-label="${esc(label)}" title="${esc(label)}">⧉</button>`); b.onclick = (e) => { e.stopPropagation(); X.copy(text, `已复制${label.replace(/^复制/, '')}`); }; return b; };

  // ---------------------------------------------------------------- in-view search
  X.highlight = (root, term) => {
    $$('mark.hit', root).forEach((m) => { const p = m.parentNode; p.replaceChild(document.createTextNode(m.textContent), m); p.normalize(); });
    if (!term) return [];
    const lower = term.toLowerCase(); const out = []; const nodes = [];
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, { acceptNode: (nd) => (nd.parentElement && nd.parentElement.closest('button, input, textarea, select') ? NodeFilter.FILTER_REJECT : nd.nodeValue.toLowerCase().includes(lower) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP) });
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach((nd) => {
      const text = nd.nodeValue; const lt = text.toLowerCase(); const frag = document.createDocumentFragment(); let i = 0; let k;
      while ((k = lt.indexOf(lower, i)) >= 0) {
        frag.appendChild(document.createTextNode(text.slice(i, k))); const m = document.createElement('mark'); m.className = 'hit'; m.textContent = text.slice(k, k + term.length); frag.appendChild(m); out.push(m); i = k + term.length;
      }
      frag.appendChild(document.createTextNode(text.slice(i))); nd.parentNode.replaceChild(frag, nd);
    });
    return out;
  };
  function reveal(el, root) {
    let p = el.parentElement;
    while (p && p !== root) {
      if (p.hasAttribute('hidden')) p.removeAttribute('hidden');
      if (p.classList.contains('folded')) p.classList.remove('folded');
      if (p.classList.contains('jt-node')) p.classList.add('open');
      p = p.parentElement;
    }
  }
  // returns {run(term), next(), prev(), count()} bound to a container
  function searcher(root, onCount) {
    let marks = []; let cur = -1;
    const show = () => {
      marks.forEach((m) => m.classList.remove('cur'));
      if (cur >= 0 && marks[cur]) { const m = marks[cur]; reveal(m, root); m.classList.add('cur'); m.scrollIntoView({ block: 'center', behavior: 'auto' }); }
      onCount(marks.length ? `${cur + 1} / ${marks.length}` : '');
    };
    return {
      run(term) { marks = X.highlight(root, term); marks.forEach((m) => reveal(m, root)); cur = marks.length ? 0 : -1; if (term && !marks.length) onCount('无匹配'); else show(); },
      next() { if (!marks.length) return; cur = (cur + 1) % marks.length; show(); },
      prev() { if (!marks.length) return; cur = (cur - 1 + marks.length) % marks.length; show(); },
    };
  }

  // ---------------------------------------------------------------- JSON tree (collapsible, copy path)
  X.jsonTree = (data, o = {}) => {
    const open = o.open || []; const el = h('<div class="jtree" role="tree"></div>');
    const isOpen = (path) => path === '' || open.some((p) => p === path || p.startsWith(`${path}.`) || p.startsWith(`${path}[`));
    const keyEl = (k, path) => {
      const s = h(`<span class="jt-key" title="点击复制路径 ${esc(path)}" role="button" tabindex="0">${typeof k === 'number' ? '' : `"${safeText(k)}"`}</span>`);
      if (typeof k === 'number') s.textContent = `${k}`; s.onclick = (e) => { e.stopPropagation(); X.jsonPathCopy(path); }; s.onkeydown = (e) => { if (e.key === 'Enter') s.onclick(e); }; return s;
    };
    function prim(v) {
      if (v === null) return '<span class="jt-null">null</span>';
      if (typeof v === 'number') return `<span class="jt-num">${v}</span>`;
      if (typeof v === 'boolean') return `<span class="jt-bool">${v}</span>`;
      const s = String(v);
      if (s.length > 180) return `<span class="jt-str jt-long" data-full="1">"${safeText(s.slice(0, 160))}<span class="dim">… 共 ${s.length} 字符</span>"</span>`;
      return `<span class="jt-str">"${safeText(s)}"</span>`;
    }
    function build(v, key, path, depth, last) {
      const line = h('<div class="jt-line"></div>');
      const comma = last ? '' : ',';
      if (v !== null && typeof v === 'object') {
        const isArr = Array.isArray(v); const keys = isArr ? v.map((_, i) => i) : Object.keys(v);
        const node = h(`<div class="jt-node ${isOpen(path) ? 'open' : ''}"></div>`); const head = h('<div class="jt-line jt-head"></div>');
        const tog = h(`<button type="button" class="jt-tog" aria-label="展开或折叠" aria-expanded="${isOpen(path)}">▸</button>`);
        head.appendChild(tog); if (key !== null) { head.appendChild(keyEl(key, path)); head.appendChild(document.createTextNode(': ')); }
        head.appendChild(h(`<span class="jt-br">${isArr ? '[' : '{'}</span>`)); head.appendChild(h(`<span class="jt-sum dim">${keys.length ? ` ${keys.length} ${isArr ? '项' : '个键'} ` : ''}</span>`)); head.appendChild(h(`<span class="jt-br jt-closed">${isArr ? ']' : '}'}${comma}</span>`));
        const kids = h('<div class="jt-children"></div>');
        keys.forEach((k, i) => kids.appendChild(build(v[k], isArr ? i : k, isArr ? `${path}[${k}]` : (path ? `${path}.${k}` : k), depth + 1, i === keys.length - 1)));
        const end = h(`<div class="jt-line jt-end"><span class="jt-br">${isArr ? ']' : '}'}${comma}</span></div>`);
        node.appendChild(head); node.appendChild(kids); node.appendChild(end);
        const toggle = () => { const on = node.classList.toggle('open'); tog.setAttribute('aria-expanded', String(on)); };
        tog.onclick = toggle; head.ondblclick = toggle;
        return node;
      }
      line.appendChild(h('<span class="jt-sp"></span>')); if (key !== null) { line.appendChild(keyEl(key, path)); line.appendChild(document.createTextNode(': ')); }
      const val = h(`<span class="jt-val">${prim(v)}</span>`); const lg = val.querySelector('.jt-long');
      if (lg) { lg.title = '点击展开全文'; lg.style.cursor = 'pointer'; lg.onclick = () => { lg.classList.remove('jt-long'); lg.innerHTML = `"${safeText(String(v))}"`; }; }
      line.appendChild(val); if (comma) line.appendChild(document.createTextNode(comma)); return line;
    }
    el.appendChild(build(data, null, '', 0, true));
    const all = () => $$('.jt-node', el);
    const setAll = (on) => all().forEach((nd, i) => { if (i === 0 && !on) return; nd.classList.toggle('open', on); const t = nd.querySelector(':scope > .jt-head > .jt-tog'); if (t) t.setAttribute('aria-expanded', String(nd.classList.contains('open'))); });
    return {
      el, expandAll: () => setAll(true), collapseAll: () => setAll(false),
      search(term) { const ms = X.highlight(el, term); ms.forEach((m) => reveal(m, el)); return ms.length; },
    };
  };

  // ---------------------------------------------------------------- shared pieces
  const bar = (label, o, passKey, failKey) => {
    const a = o[passKey] || 0; const b = o[failKey] || 0; const u = o.UNKNOWN || 0; const top = X.argmax(o);
    const seg = (cls, p, key) => `<div class="seg ${cls}" style="flex:${Math.max(p, 0.004)}" title="${key} ${(p * 100).toFixed(1)}%（原始值 ${p}）">${p >= 0.22 ? `${key} ${Math.round(p * 100)}%` : ''}</div>`;
    const concl = passKey === 'ALLOW' ? X.ACCESS[top] : X.ATTACK[top];
    return `<div class="qrow"><div class="ql">${esc(label)}</div><div class="answerbar" role="img" aria-label="${esc(`${passKey} ${pct(a)}，${failKey} ${pct(b)}，UNKNOWN ${pct(u)}`)}">${seg('pass', a, passKey)}${seg('fail', b, failKey)}${seg('unk', u, 'UNKNOWN')}</div>
      <div class="qc">→ ${esc(concl)}<span class="dim small"> ${top} ${pct(o[top])}</span></div></div>`;
  };
  X.miniAnswer = (j) => {
    if (j.failure) return h(`<div class="minians"><div class="notice">Jev ${esc(X.failName(j.failure))}${j.http_status ? `（HTTP ${j.http_status}）` : ''}</div></div>`);
    const mb = (label, o, pk, fk) => { const t = X.argmax(o); return `<div class="mrow"><span class="ml">${label}</span><span class="answerbar slim">${['pass', 'fail', 'unk'].map((c, i) => `<span class="seg ${c}" style="flex:${Math.max(o[[pk, fk, 'UNKNOWN'][i]], 0.004)}"></span>`).join('')}</span><span class="mc">${esc(pk === 'ALLOW' ? X.ACCESS[t] : X.ATTACK[t])} ${pct(o[t])}</span></div>`; };
    return h(`<div class="minians">${mb('访问', j.access, 'ALLOW', 'DENY')}${mb('攻击', j.attack, 'BENIGN', 'ATTACK')}</div>`);
  };
  const meter = (frac, warn) => `<span class="meter ${warn ? 'warn' : ''}" aria-hidden="true"><i style="width:${Math.max(2, Math.min(100, Math.round(frac * 100)))}%"></i></span>`;

  function answerCard(r) {
    const j = r.jevFull; const card = h('<div class="card answer"><h2>Jev 回答</h2></div>'); const site = X.site(r.site);
    if (j.failure) {
      const noCall = j.failure === 'JEV_CALL_LIMIT' || j.failure === 'JEV_STATE_TOO_LARGE'; const desc = X.FAIL[j.failure];
      const handling = r.outcome === 'unjudged' ? '站点设置“Jev 不可用时：放行”，请求未经判定就转发了' : `站点设置“Jev 不可用时：拒绝”，网关${r.outcome === 'blocked' ? `返回 ${r.status}` : '按观察模式转发'}`;
      card.appendChild(h(`<div class="failcard"><div class="fhead"><span class="fcode mono">${esc(j.failure)}</span><b>${esc(desc[0])}</b></div><div class="muted">${esc(desc[1])}${noCall ? '。<b>这次没有发出调用。</b>' : ''}</div>
        <div class="kv"><div class="k">HTTP 状态</div><div>${j.http_status == null ? '—（没有收到响应）' : j.http_status}</div><div class="k">耗时</div><div class="tnum">${noCall ? '—' : `${j.millis} ms / 超时 ${j.timeout_ms} ms（${j.timeout_ms === M.SYSTEM.params.site_overridable.jev_timeout_ms ? '默认' : '站点设置'}）`}</div><div class="k">怎么处理的</div><div>${esc(handling)} ${X.outPill(r.outcome)}</div></div>
        ${noCall ? `<a class="btn sm" href="#/sites/${esc(r.site)}?tab=config&group=advanced">${j.failure === 'JEV_CALL_LIMIT' ? '查看调用上限' : '查看高级判定参数'}</a>` : ''}</div>`));
      if (j.failure === 'JEV_TIMEOUT') card.appendChild(h(`<div class="dim small" style="margin-top:8px">${site ? `本站点 24 小时 p99 ${X.evidence(site.name).jev.p99_ms} ms，超时设置 ${j.timeout_ms} ms。` : ''}可以在“相关”栏用“调整 Jev 超时…”按证据改值。</div>`));
      return card;
    }
    const top = { a: X.argmax(j.access), t: X.argmax(j.attack) }; const conf = r.jev.confidence;
    card.appendChild(h(`<div class="abars">${bar('访问有依据吗', j.access, 'ALLOW', 'DENY')}${bar('内容是攻击吗', j.attack, 'BENIGN', 'ATTACK')}</div>`));
    const why = j.conclusion === 'deny' ? (top.a === 'DENY' ? 'access = DENY' : 'attack = ATTACK') : j.conclusion === 'allow' ? 'access = ALLOW，attack = BENIGN' : 'UNKNOWN';
    card.appendChild(h(`<div class="concl"><div><span class="muted">Jev 结论：</span><b>${esc(X.CONCL[j.conclusion])}</b><span class="dim">（${esc(why)}）</span> · 置信度 ${pct(conf)} ${conf < 0.7 ? '<span class="lowconf" title="两个回答的最高项概率，取较小值；低于 70%">置信度低</span>' : ''}</div>
      <div class="geff">${X.outPill(r.outcome)} <span class="muted">${esc(X.gatewayEffect(r))}</span></div></div>`));
    const cur = j.prompt === M.PROMPT_NOW; let resp = null; try { resp = JSON.parse(j.response); } catch (e) { /* ignore */ }
    card.appendChild(h(`<div class="jmeta dim">${esc(j.model)}${resp ? `（响应 ${esc(resp.model)}）` : ''} · ${esc(X.ROUTE_N[j.route])} · 指令 <a href="${esc(X.hashWith({ tab: 'jev', jev_view: 'prompt' }))}" class="mono">${esc(j.prompt)}</a>${cur ? '' : ' <span class="oldp" title="这次调用的指令不是网关当前版本">旧版指令</span>'}${j.usage ? ` · 用量 输入 ${n(j.usage.input_tokens)} / 输出 ${n(j.usage.output_tokens)} token` : ''}</div>`));
    const frac = j.millis / j.timeout_ms; const sb = M.utf8(j.state); const sf = sb / 8192;
    card.appendChild(h(`<div class="meters"><div class="mrowx"><span class="mk">耗时</span><span class="tnum">${j.millis} ms</span>${meter(frac, frac >= 0.8)}<span class="dim small">超时 ${j.timeout_ms} ms（${j.timeout_ms === M.SYSTEM.params.site_overridable.jev_timeout_ms ? '默认' : '站点设置'}）${frac >= 0.8 ? ' · 接近超时' : ''}</span></div>
      <div class="mrowx"><span class="mk">state</span><span class="tnum" title="完整请求体 ${j.request_bytes} 字节">${(sb / 1024).toFixed(1)} / 8 KiB</span>${meter(sf, sf >= 0.8)}<span class="dim small">裁剪 ${j.trim} 级${j.trim ? `：${esc(TRIM[j.trim])}` : ''}</span></div></div>`));
    return card;
  }

  // ---------------------------------------------------------------- views
  function alignInfo(r, state) {
    const tv = (r.trace.values || []).filter((v) => !v.inert); const sv = state.request.values; let ok = tv.length === sv.length;
    if (ok) sv.forEach((v, i) => {
      const src = tv[i].sources || []; const seen = v.seen_as || [];
      // A trimmed trace may keep fewer sources than state sent; then only the common prefix is compared.
      if (v.at !== tv[i].at || (seen.length > src.length && !r.trace.trimmed) || seen.slice(0, src.length).some((label, k) => label !== `${src[k].field} @ ${src[k].request}`)) ok = false;
    });
    return { ok, tv };
  }
  function structuredView(r, state, q) {
    const j = r.jevFull; const al = alignInfo(r, state); const wrap = h('<div class="structured"></div>');
    if (!al.ok) wrap.appendChild(h('<div class="notice" style="grid-column:1/-1">无法与追溯信息对齐（值的个数、位置或来源数不一致），下面只显示 state 的内容，没有判读提示和来源链接。</div>'));
    // ---- left: request values
    const left = h('<div class="card vcol"></div>'); const vals = state.request.values;
    const hints = vals.map((v, i) => (al.ok ? X.valueHint(al.tv[i]) : (v.verified ? 'verified' : v.kind === 'input' ? 'input' : v.kind === 'route' ? 'route' : (v.seen_as || []).length ? 'seen' : 'never')));
    const bad = hints.filter((x) => x === 'seen' || x === 'never').length;
    left.appendChild(h(`<div class="vc-title"><h2>本次请求 <span class="mono">${esc(state.request.method)} ${esc(state.request.path)}</span></h2><div class="dim small">发给 Jev ${vals.length} 个值，其中 ${bad} 个缺少佐证${state.request.truncated ? ' · 请求值被截断' : ''}</div></div>`));
    const hl = q.get('hl'); const okIdx = hints.map((x, i) => i).filter((i) => !['seen', 'never'].includes(hints[i])); const groupOk = vals.length > 8 && okIdx.length > 2;
    let group = null;
    vals.forEach((v, i) => {
      const hint = X.HINT[hints[i]]; const warn = hints[i] === 'seen' || hints[i] === 'never'; const redacted = v.value === '<redacted>';
      const card = h(`<div class="vcard ${hint.cls} ${warn ? '' : 'folded'} ${hl != null && String(i) === hl ? 'flash' : ''}" id="v${i}"><div class="vc-head"><span class="mono vi">#${i}</span><span class="mono at">${esc(v.at)}</span><span class="kind">${esc(X.KIND[v.kind] || v.kind)}</span>
        <span class="mono val">${redacted ? '已脱敏' : safeText(v.value)}</span><span class="hint ${hint.cls}" title="${esc(hint.tip)}">${hint.g} ${esc(hint.text)}</span></div><div class="vc-src"></div></div>`);
      card.querySelector('.vc-head').appendChild(copyIcon(redacted ? '<redacted>' : v.value, '复制值'));
      const srcBox = card.querySelector('.vc-src'); const seen = v.seen_as || [];
      if (seen.length) {
        srcBox.appendChild(h(`<span class="srclead">${hints[i] === 'verified' ? '已核验，见过' : '只见过'}</span>`));
        seen.forEach((s, k) => {
          const rid = al.ok ? (al.tv[i].sources[k] || {}).request_id : null; const rec = rid && M.RECORD_BY_ID[rid];
          const chip = h(rid ? `<a class="srcchip" href="#/requests/${esc(rid)}" title="${rec ? esc(`${rec.method} ${rec.path} · ${X.fmtHMS(rec.at_millis)}`) : '来源请求已过保留期'}">${safeText(s)} ↗</a>` : `<span class="srcchip off" title="${al.ok ? '这条来源没有记录请求 ID' : '无法与追溯信息对齐'}">${safeText(s)}</span>`);
          srcBox.appendChild(chip); if (rid) srcBox.appendChild(copyIcon(rid, '复制来源请求 ID'));
        });
      } else if (hints[i] === 'never') srcBox.appendChild(h('<span class="dim small">这个值在这个会话里没有出现过（seen_as 为空）</span>'));
      else if (hints[i] === 'input' || hints[i] === 'route') srcBox.appendChild(h('<span class="dim small">不需要见过</span>'));
      card.querySelector('.vc-head').onclick = (e) => { if (!e.target.closest('button, a')) card.classList.toggle('folded'); };
      if (groupOk && !warn) {
        if (!group) { group = h('<div class="vgroup" hidden></div>'); const tgl = h(`<button type="button" class="linkbtn vtoggle">另有 ${okIdx.length} 个值无异常 · 展开</button>`); tgl.onclick = () => { const hidden = group.hasAttribute('hidden'); if (hidden) group.removeAttribute('hidden'); else group.setAttribute('hidden', ''); tgl.textContent = hidden ? `${okIdx.length} 个无异常的值 · 收起` : `另有 ${okIdx.length} 个值无异常 · 展开`; }; left.appendChild(tgl); left.appendChild(group); }
        group.appendChild(card);
      } else left.appendChild(card);
    });
    if (!vals.length) left.appendChild(h('<div class="dim">这次发给 Jev 的请求里没有需要核验的值</div>'));
    wrap.appendChild(left);
    // ---- right: session
    const right = h('<div class="card scol"><h2>会话</h2></div>'); const sess = state.session; const ts = r.trace.session || {};
    right.appendChild(h(`<div class="kv"><div class="k">入口</div><div>${state.entry.matched ? `命中${r.trace.entry ? ` <span class="mono">${esc(r.trace.entry)}</span>` : ''}` : '未命中'}</div><div class="k">会话年龄</div><div>${sess.age_seconds} 秒（${X.dur(sess.age_seconds * 1000)}）</div><div class="k">已见值</div><div>${ts.known_values != null ? n(ts.known_values) : '—'}</div></div>`));
    right.appendChild(h('<div class="sect">经过的入口</div>'));
    if (sess.entries_passed.length) sess.entries_passed.forEach((p) => {
      const ent = ((ts.entries_passed) || []).find((e) => e.path === p); const row = h(`<div class="r-item">${ent && al.ok !== undefined ? `<a class="mono" href="#/requests/${esc(ent.request_id)}">${esc(p)} ↗</a>` : `<span class="mono">${esc(p)}</span>`}${ent ? `<span class="dim small"> 首次 ${X.fmtHMS(ent.at_millis)}</span>` : ''}</div>`); right.appendChild(row);
    }); else right.appendChild(h('<div class="dim small">还没有经过入口</div>'));
    right.appendChild(h(`<div class="sect">最近访问 ${state.recent.length} 条（新 → 旧）</div>`));
    const trRecent = ts.recent || []; const off = trRecent.length - state.recent.length;
    if (!state.recent.length) right.appendChild(h(`<div class="dim small">${j.trim >= 2 ? '裁剪后没有保留最近访问' : '没有最近访问'}</div>`));
    state.recent.map((x, k) => ({ x, ref: off >= 0 ? trRecent[off + k] : null })).reverse().forEach(({ x, ref }) => {
      const okRef = ref && ref.method === x.method && ref.path === x.path;
      right.appendChild(h(`<div class="r-item mono">${okRef ? `<a href="#/requests/${esc(ref.request_id)}">${esc(x.method)} ${esc(x.path)} ↗</a>` : `${esc(x.method)} ${esc(x.path)}`} <span class="dim small">${x.status}</span></div>`));
    });
    wrap.appendChild(right);
    if (hl != null) setTimeout(() => { const t = $(`#v${CSS.escape(hl)}`, wrap); if (t) { t.classList.remove('folded'); t.scrollIntoView({ block: 'center' }); setTimeout(() => t.classList.remove('flash'), 2200); } }, 40);
    return wrap;
  }
  const docOf = (r, which) => {
    const j = r.jevFull;
    if (which === 'body') return { text: M.buildBody(j.model, j.state, M.PROMPTS[j.prompt].questions), note: '完整请求体（还原值，键的顺序可能与实际发出的不同；不含密钥和请求头）', compact: true };
    if (which === 'response') return { text: j.response, note: j.response ? '模型服务的原始响应' : '超时或连接失败，没有响应', compact: true };
    return { text: j.state, note: '网关实际发出的 state（紧凑 JSON，逐字节）', compact: true };
  };
  function jsonView(r, q, srch) {
    const which = q.get('jev_doc') || 'state'; const d = docOf(r, which); const wrap = h('<div class="card jsonv"></div>');
    wrap.appendChild(docBar(which, d, true));
    if (!d.text) { wrap.appendChild(h('<div class="empty">没有响应</div>')); return wrap; }
    let parsed; try { parsed = JSON.parse(d.text); } catch (e) { parsed = undefined; }
    if (parsed === undefined) { wrap.appendChild(h(`<div class="notice">这份内容不是合法的 JSON（例如 JEV_RESPONSE_INVALID 时保存下来的原始响应）。下面原样显示，逐字节内容也可以在“原文”视图里看。</div>`)); const pre = h('<pre class="rawpre" style="padding:8px 12px;white-space:pre-wrap;word-break:break-all"></pre>'); pre.textContent = d.text; wrap.appendChild(pre); return wrap; }
    const tree = X.jsonTree(parsed, { open: which === 'state' ? ['request'] : which === 'body' ? ['state.request'] : ['answers'] });
    const bar2 = h('<div class="toolrow"><button type="button" class="linkbtn" id="ex">全部展开</button><button type="button" class="linkbtn" id="co">全部折叠</button><span class="dim small">点击键名复制路径，例如 request.values[0].seen_as</span></div>');
    $('#ex', bar2).onclick = tree.expandAll; $('#co', bar2).onclick = tree.collapseAll; wrap.appendChild(bar2); wrap.appendChild(tree.el); srch.rebind(tree.el);
    return wrap;
  }
  function docBar(which, d, tree) {
    const bar2 = h(`<div class="docbar"><div class="seg2" role="group" aria-label="看哪一份">${[['state', 'state'], ['body', '完整请求体'], ['response', '原始响应']].map(([k, l]) => `<button type="button" class="seg2b ${which === k ? 'active' : ''}" data-k="${k}">${l}</button>`).join('')}</div><span class="dim small">${esc(d.note)} · ${d.text ? bytes(M.utf8(d.text)) : '—'}</span></div>`);
    $$('.seg2b', bar2).forEach((b) => { b.onclick = () => X.setQuery({ tab: 'jev', jev_view: tree ? 'json' : 'raw', jev_doc: b.dataset.k === 'state' ? null : b.dataset.k }); });
    return bar2;
  }
  function rawViewJev(r, q, srch) {
    const which = q.get('jev_doc') || 'state'; const d = docOf(r, which); const fmt = q.get('fmt') === 'pretty'; const wrapOn = q.get('wrap') !== '0';
    const wrap = h('<div class="card rawv"></div>'); wrap.appendChild(docBar(which, d, false));
    const tools = h(`<div class="toolrow"><label class="check"><input type="checkbox" id="pretty" ${fmt ? 'checked' : ''}> 格式化显示</label><label class="check"><input type="checkbox" id="wrapb" ${wrapOn ? 'checked' : ''}> 自动换行</label><span class="sp"></span><button type="button" class="linkbtn" id="rc">复制此份</button></div>`);
    wrap.appendChild(tools);
    $('#pretty', tools).onchange = (e) => X.setQuery({ fmt: e.target.checked ? 'pretty' : null }, false); $('#wrapb', tools).onchange = (e) => X.setQuery({ wrap: e.target.checked ? null : '0' }, false);
    $('#rc', tools).onclick = () => X.copy(d.text || '', '已复制');
    if (!d.text) { wrap.appendChild(h('<div class="empty">没有响应</div>')); return wrap; }
    let text = d.text; if (fmt) { try { text = JSON.stringify(JSON.parse(d.text), null, 2); } catch (e) { /* keep */ } }
    const lines = text.split('\n'); const pre = h(`<div class="rawpre ${wrapOn ? 'wrapped' : ''}" tabindex="0" aria-label="${esc(d.note)}"></div>`);
    lines.forEach((ln, i) => pre.appendChild(h(`<div class="rl"><span class="ln" aria-hidden="true">${i + 1}</span><span class="lt">${safeText(ln) || ' '}</span></div>`)));
    wrap.appendChild(pre);
    if (!fmt) wrap.appendChild(h('<div class="dim small" style="margin-top:6px">紧凑原文只有一行；勾选“格式化显示”按层级换行并显示行号。</div>'));
    srch.rebind(pre); return wrap;
  }
  function promptView(r, q) {
    const j = r.jevFull; const p = M.PROMPTS[j.prompt]; const cur = M.PROMPTS[M.PROMPT_NOW]; const wrap = h('<div class="card promptv"></div>');
    const used = M.RECORDS.filter((x) => x.jevFull && x.jevFull.prompt === j.prompt).length;
    if (j.prompt !== M.PROMPT_NOW) {
      const nb = h(`<div class="notice">这次调用用的是旧版指令（当前 <span class="mono">${esc(M.PROMPT_NOW)}</span>）。 <button type="button" class="linkbtn" id="pd">${q.get('pdiff') ? '隐藏差异' : '显示与当前版本的逐行差异（P1）'}</button></div>`);
      $('#pd', nb).onclick = () => X.setQuery({ pdiff: q.get('pdiff') ? null : '1' }); wrap.appendChild(nb);
    }
    wrap.appendChild(h(`<div class="dim small" style="margin:6px 0 10px">指令版本 <span class="mono">${esc(p.id)}</span> · 首次出现 ${esc(p.first_seen.replace('T', ' ').replace('Z', ' UTC'))} · 样例数据里有 ${used} 次调用用了它。指令 id 是 jq_ 加上两个问题（含选项说明）紧凑 JSON 的 SHA-256 前缀。</div>`));
    const sent = (t) => t.replace(/\. (?=[A-Z])/g, '.\n');
    ['access', 'attack'].forEach((k) => {
      const qn = p.questions[k]; const choices = Object.keys(qn.criteria);
      const sec = h(`<div class="sec"><h3>${k === 'access' ? 'access · 访问有依据吗' : 'attack · 内容是攻击吗'}</h3><div class="instr">${esc(qn.instructions)}</div><div class="choices">${choices.map((c) => `<div class="choice"><span class="mono">${esc(c)}</span><span class="muted">${esc(qn.criteria[c])}</span></div>`).join('')}</div></div>`);
      wrap.appendChild(sec);
      if (q.get('pdiff') && j.prompt !== M.PROMPT_NOW) {
        const d = X.diffView(sent(qn.instructions), sent(cur.questions[k].instructions)); wrap.appendChild(h(`<div class="dim small" style="margin:8px 0 4px">${k} 的差异（旧 → 当前）</div>`)); wrap.appendChild(d);
      }
    });
    wrap.appendChild(h('<div class="dim small" style="margin-top:8px">发给模型的是 questions（上面的说明和选项）加 state；模型回答的 probabilities 就是上方分段条的来源。</div>'));
    return wrap;
  }

  // ---------------------------------------------------------------- Jev tab
  X.jevTab = (r, q) => {
    const wrap = h('<div class="jevtab"></div>');
    if (!r.jevFull) {
      const why = { fast_allow: '需核验的值都已核验，快速放行，没有调用 Jev。', cached_allow: '复用了缓存时长内 Jev 对同一请求的放行。', bypass: '命中绕过规则，没有判定。', no_session: '没有会话凭证，也不是入口，没有调用 Jev。', body_not_inspectable: '请求体不可判定，没有调用 Jev。', unknown_site: 'Host 不属于任何站点。' }[r.decision_path] || '没有调用 Jev。';
      wrap.appendChild(h(`<div class="card"><div class="empty"><div class="big">未调用 Jev</div><div class="dim">${esc(why)}</div></div></div>`)); return wrap;
    }
    const j = r.jevFull; wrap.appendChild(answerCard(r));
    if (j.failure && (j.failure === 'JEV_CALL_LIMIT' || j.failure === 'JEV_STATE_TOO_LARGE')) return wrap;
    const view = q.get('jev_view') || 'structured'; const state = X.safeParse(j.state);
    const body = h('<div class="jevbody"></div>'); const countEl = h('<span class="searchcount dim small" aria-live="polite"></span>');
    const srch = { root: body, s: null, rebind(root) { this.root = root; this.s = searcher(root, (t) => { countEl.textContent = t; }); if (input.value) this.s.run(input.value); } };
    const viewTabs = h('<div class="tabs sub" role="tablist"></div>');
    [['structured', '结构化'], ['json', 'JSON'], ['raw', '原文'], ['prompt', '指令']].forEach(([k, lbl]) => {
      const b = h(`<button type="button" class="tab ${view === k ? 'active' : ''}" role="tab" aria-selected="${view === k}">${lbl}</button>`); b.onclick = () => X.setQuery({ tab: 'jev', jev_view: k === 'structured' ? null : k, jev_doc: null }); viewTabs.appendChild(b);
    });
    const input = h('<input type="search" class="vsearch" placeholder="在上下文中搜索  ⏎ 下一处" aria-label="在当前视图中搜索">');
    const tools = h('<div class="vtools"></div>'); tools.appendChild(input); tools.appendChild(countEl);
    const cs = h('<button type="button" class="linkbtn">复制 state</button>'); cs.onclick = () => X.copy(j.state, '已复制 state（原文）');
    const cb = h('<button type="button" class="linkbtn">复制完整请求体</button>'); cb.onclick = () => X.copy(docOf(r, 'body').text, '已复制完整请求体（还原值，不含密钥和请求头）');
    tools.appendChild(h('<span class="sp"></span>')); tools.appendChild(cs); tools.appendChild(cb);
    const bar2 = h('<div class="viewbar"></div>'); bar2.appendChild(viewTabs); bar2.appendChild(tools); wrap.appendChild(bar2);
    if (!state) { wrap.appendChild(h('<div class="notice">没有 state 可显示</div>')); return wrap; }
    let el;
    if (view === 'structured') { el = structuredView(r, state, q); srch.rebind(el); }
    else if (view === 'json') el = jsonView(r, q, srch);
    else if (view === 'raw') el = rawViewJev(r, q, srch);
    else { el = promptView(r, q); srch.rebind(el); }
    body.appendChild(el); wrap.appendChild(body);
    input.oninput = () => srch.s && srch.s.run(input.value);
    input.onkeydown = (e) => { if (e.key === 'Enter') { e.preventDefault(); if (e.shiftKey) srch.s.prev(); else srch.s.next(); } else if (e.key === 'Escape') { input.value = ''; srch.s.run(''); input.blur(); e.stopPropagation(); } };
    const order = ['structured', 'json', 'raw', 'prompt'];
    X.pageKeys.v = () => X.setQuery({ tab: 'jev', jev_view: order[(order.indexOf(view) + 1) % 4] === 'structured' ? null : order[(order.indexOf(view) + 1) % 4], jev_doc: null });
    X.pageKeys['/'] = (e) => { e.preventDefault(); input.focus(); };
    return wrap;
  };

  // ---------------------------------------------------------------- Jev calls page
  X.route((p) => p[0] === 'jev', (page, parts, q) => {
    page.appendChild(X.pageHead('Jev 调用', `${X.scopeLabel()} · 最近 24 小时`));
    const js = M.JEV_STATUS; const names = X.state.site === 'all' ? X.sites.map((st) => st.name) : [X.state.site]; const ev = names.map((nm) => X.evidence(nm));
    const row = h('<div class="grid jev-grid" style="margin-bottom:16px"></div>');
    const hl = { ok: '正常', idle: '空闲', degraded: '降级', down: '不可用' }[js.health];
    row.appendChild(h(`<div class="card"><h2>健康</h2><div class="healthline"><span class="dot ${js.health === 'ok' ? 'ok' : js.health}" aria-hidden="true"></span><b>${hl}</b> · 最近 ${js.window_minutes} 分钟 ${js.calls} 次，全部成功</div>
      <div class="muted" style="margin-top:6px;font-size:13px;line-height:1.7">p50 ${js.p50_ms} ms · p95 ${js.p95_ms} ms<br>${esc(js.config.model)} · ${esc(X.ROUTE_N[js.config.route])}<br>默认超时 ${js.config.default_timeout_ms} ms · 指令 <span class="mono">${esc(js.config.prompt)}</span><br>最后一次失败 ${X.fmtHMS(Date.parse(js.last_failure.at))} ${esc(X.failName(js.last_failure.failure))}（${esc(js.last_failure.site)}）</div></div>`));
    const merged = []; ev.forEach((e) => e.histogram.forEach((c, i) => { merged[i] = (merged[i] || 0) + c; }));
    const marks = [{ at: js.config.default_timeout_ms / 100, label: `默认 ${js.config.default_timeout_ms / 1000} s`, left: true }];
    names.forEach((nm) => { const t = X.evidence(nm).jev.timeout_ms_used; if (t !== js.config.default_timeout_ms) marks.push({ at: t / 100, label: `${nm} ${t / 1000} s`, dash: true, left: true }); });
    const latency = X.histogram(merged, { marks, ticks: [0, 10, 20, 30].filter((t) => t <= merged.length).map((t) => ({ at: t, label: t === 0 ? '0' : `${t / 10} s` })), label: '耗时分布，100 毫秒一档', tip: (i, c) => `${i * 100}–${i * 100 + 100} ms：${c} 次` });
    row.appendChild(X.chartCard('耗时分布（100 ms 一档）', latency, merged.map((c, i) => [`${i * 100}–${i * 100 + 100} ms`, c]), ['区间', '调用数']));
    const conf = [2, 1, 1, 3, 6, 11, 22, 60, 140, 232]; const low = conf.slice(0, 7).reduce((a, b) => a + b, 0);
    row.appendChild(X.chartCard(`置信度分布（低于 70%：${low} 次）`, X.histogram(conf, { marks: [{ at: 7, label: '70%' }], ticks: [{ at: 0, label: '0' }, { at: 5, label: '0.5' }, { at: 10, label: '1.0' }], color: 'var(--s2)', label: '置信度分布，0.1 一档', tip: (i, c) => `${(i / 10).toFixed(1)}–${((i + 1) / 10).toFixed(1)}：${c} 次` }), conf.map((c, i) => [`${(i / 10).toFixed(1)}–${((i + 1) / 10).toFixed(1)}`, c]), ['区间', '调用数']));
    page.appendChild(row);

    const all = M.RECORDS.filter((r) => r.jev && (X.state.site === 'all' || r.site === X.state.site));
    const p95Of = (r) => X.evidence(r.site).jev.p95_ms;
    const CH = [['', '全部', () => true], ['deny', '拒绝', (r) => r.jevFull.conclusion === 'deny'], ['allow', '通过', (r) => r.jevFull.conclusion === 'allow'], ['fail', '失败', (r) => !!r.jev.failure], ['low', '置信度低', (r) => r.jev.confidence != null && r.jev.confidence < 0.7], ['slow', '慢于 p95', (r) => !r.jev.failure && r.jev.ms > p95Of(r)], ['trim', '裁剪过', (r) => r.jevFull.trim > 0]];
    const chip = q.get('chip') || ''; const dsl = X.parseDsl(q.get('q') || '');
    const chips = h('<div class="chips" role="group"></div>');
    CH.forEach(([k, l, f]) => { const c = h(`<button type="button" class="chip ${chip === k ? 'active' : ''}" aria-pressed="${chip === k}">${l} <span class="n">${all.filter(f).length}</span></button>`); c.onclick = () => X.setQuery({ chip: k }); chips.appendChild(c); });
    page.appendChild(chips);
    const fb = h(`<div class="filterbar"><div class="dsl">⌕ <input type="text" value="${esc(q.get('q') || '')}" placeholder="access:DENY  conf<0.7  failure:JEV_TIMEOUT  path:/rest/*" aria-label="筛选条件"></div></div>`);
    fb.querySelector('input').onkeydown = (e) => { if (e.key === 'Enter') X.setQuery({ q: e.target.value.trim() }); }; page.appendChild(fb);
    if (dsl.errors.length) page.appendChild(h(`<div class="dslerr" role="alert">${dsl.errors.map((e) => `<span class="mono">${esc(e.tok)}</span> ${esc(e.msg)}`).join('；')}</div>`));
    const f = (CH.find((c) => c[0] === chip) || CH[0])[2];
    const rows = all.filter(f).filter((r) => dsl.conds.every((c) => X.condMatch(r, c)));
    const tbl = h('<div class="tablewrap"><table class="data"><thead><tr><th>时间</th><th>站点</th><th>请求</th><th>Jev 结论</th><th>访问</th><th>攻击</th><th>置信度</th><th>耗时 / 超时</th><th>裁剪</th><th>网关结论</th></tr></thead><tbody></tbody></table></div>');
    rows.forEach((r) => {
      const j = r.jevFull; const a = j.failure ? null : X.argmax(j.access); const t = j.failure ? null : X.argmax(j.attack);
      const tr = h(`<table><tbody><tr data-id="${esc(r.request_id)}"><td class="tnum">${X.fmtTime(r.at_millis)}</td><td>${esc(r.site)}</td><td class="mono path">${esc(r.method)} ${esc(r.path)}</td>
        <td>${j.failure ? `<span class="muted">${esc(X.failName(j.failure))}</span>` : `${esc(X.CONCL[j.conclusion])}`}</td><td>${a ? `${a} ${pct(j.access[a])}` : '—'}</td><td>${t ? `${t} ${pct(j.attack[t])}` : '—'}</td>
        <td class="tnum">${r.jev.confidence != null ? `${pct(r.jev.confidence)}${r.jev.confidence < 0.7 ? ' <span class="lowconf">低</span>' : ''}` : '—'}</td><td class="tnum">${j.failure && j.millis === 0 ? '—' : `${j.millis} / ${j.timeout_ms}`}</td><td class="tnum">${j.failure && !j.state ? '—' : j.trim}</td><td>${X.outPill(r.outcome)}</td></tr></tbody></table>`).querySelector('tr');
      tr.onclick = () => go(`#/requests/${r.request_id}?tab=jev`); $('tbody', tbl).appendChild(tr);
    });
    if (!rows.length) tbl.innerHTML = '<div class="empty"><div class="big">没有匹配的 Jev 调用</div><div class="dim">换一个快捷筛选，或清除条件。</div></div>';
    page.appendChild(tbl);
    page.appendChild(h(`<div class="dim small tfoot">共 ${rows.length} 条；原型只含 ${all.length} 条 Jev 样例记录，上方的分布图用示意数据。点击行打开请求详情的 Jev 标签。</div>`));
  });
})();
