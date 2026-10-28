// The local guard, served by privometry timeline --web. It reads the read-only API
// (/api/events, /api/summary, /api/sessions, /api/view/<name>) and builds
// every view with DOM calls: commands, paths and file contents are
// untrusted, so text is only ever set with textContent.
'use strict';

(function () {
  var AGENTS = { claude_code: 'Claude Code', cursor: 'Cursor', codex_cli: 'Codex' };
  var LABELS = { allow: 'Allowed', auto: 'Auto-approved', ask: 'Asked', deny: 'Blocked', prompt: 'Query detected', config: 'Config changed', alert: 'Alert', failmode: 'Fail mode', inventory: 'Inventory', finding: 'Finding' };
  var KINDS = { shell_exec: 'Shell command', file_read: 'File read', file_write: 'File write', file_delete: 'File delete', mcp_call: 'MCP call', network_fetch: 'Network fetch', web_search: 'Web search', subagent_spawn: 'Subagent' };
  var VIEWS = ['timeline', 'sessions', 'scan', 'policy', 'device'];
  var TITLES = { timeline: 'Timeline', sessions: 'Sessions', scan: 'Scan', policy: 'Policy', device: 'Device' };
  var POLL_MS = 2000, SUMMARY_MS = 10000;

  var state = {
    view: 'timeline', live: true,
    show: 'all', search: '', rows: [], open: null, json: {}, more: false, maxSeq: 0, loading: false, loaded: false,
    summary: null, agents: null, scan: null, policy: null, device: null, sessions: null
  };
  var $ = function (id) { return document.getElementById(id); };

  /* ---------- DOM helpers ---------- */
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === null || v === undefined || v === false) return;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else el.setAttribute(k, v === true ? '' : v);
    });
    (kids || []).forEach(function (c) { if (c !== null && c !== undefined && c !== false) el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return el;
  }
  var SVG = 'http://www.w3.org/2000/svg';
  function svg(tag, attrs, kids) {
    var el = document.createElementNS(SVG, tag);
    Object.keys(attrs || {}).forEach(function (k) { el.setAttribute(k, attrs[k]); });
    (kids || []).forEach(function (c) { el.appendChild(c); });
    return el;
  }
  // Icons from the prototype, as data rather than markup.
  var ICONS = {
    alert: [['path', { d: 'M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z' }], ['line', { x1: 12, y1: 9, x2: 12, y2: 13 }], ['line', { x1: 12, y1: 17, x2: 12.01, y2: 17 }]],
    check: [['polyline', { points: '20 6 9 17 4 12' }]],
    x: [['line', { x1: 18, y1: 6, x2: 6, y2: 18 }], ['line', { x1: 6, y1: 6, x2: 18, y2: 18 }]],
    refresh: [['polyline', { points: '23 4 23 10 17 10' }], ['polyline', { points: '1 20 1 14 7 14' }], ['path', { d: 'M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15' }]],
    file: [['path', { d: 'M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z' }], ['polyline', { points: '14 2 14 8 20 8' }]],
    octagon: [['polygon', { points: '7.86 2 16.14 2 22 7.86 22 16.14 16.14 22 7.86 22 2 16.14 2 7.86 7.86 2' }], ['line', { x1: 15, y1: 9, x2: 9, y2: 15 }], ['line', { x1: 9, y1: 9, x2: 15, y2: 15 }]],
    minus: [['line', { x1: 5, y1: 12, x2: 19, y2: 12 }]]
  };
  function icon(name, size) {
    size = size || 16;
    return svg('svg', { class: 'ic', width: size, height: size, viewBox: '0 0 24 24', fill: 'none', stroke: 'currentColor', 'stroke-width': 2, 'stroke-linecap': 'round', 'stroke-linejoin': 'round', 'aria-hidden': 'true' },
      (ICONS[name] || []).map(function (p) { return svg(p[0], p[1]); }));
  }
  // Verdict glyphs, the same shapes as the prototype and the cloud console.
  function glyph(k) {
    var s;
    if (k === 'ask') s = svg('path', { d: 'M6 .8 L11.2 6 L6 11.2 L.8 6 Z', fill: 'var(--ask-glyph)' });
    else if (k === 'deny' || k === 'alert' || k === 'finding') s = svg('rect', { x: 1.5, y: 1.5, width: 9, height: 9, rx: 1.5, fill: 'var(--block-glyph)' });
    else if (k === 'would') s = svg('circle', { cx: 6, cy: 6, r: 4.4, fill: 'none', stroke: 'var(--ask-glyph)', 'stroke-width': 1.6, 'stroke-dasharray': '2 1.6' });
    else s = svg('circle', { cx: 6, cy: 6, r: 4.3, fill: 'none', stroke: 'var(--faint)', 'stroke-width': 1.6 });
    return svg('svg', { class: 'ic', width: 12, height: 12, viewBox: '0 0 12 12', 'aria-hidden': 'true' }, [s]);
  }
  function pill(text, cls, dot) { return h('span', { class: 'pill' + (cls ? ' ' + cls : '') }, [dot ? h('span', { class: 'dot' + (dot === 'off' ? ' off' : '') }) : null, text]); }

  /* ---------- formatting ---------- */
  function agentName(a) { return AGENTS[a] || a || ''; }
  function fmt(n) { return Number(n || 0).toLocaleString(); }
  function plural(n, w, many) { return fmt(n) + ' ' + (n === 1 ? w : (many || w + 's')); }
  function clock(iso) {
    return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
  }
  // dayName labels the divider above each day's rows.
  function dayName(iso) {
    var d = new Date(iso), today = new Date(), y = new Date();
    y.setDate(today.getDate() - 1);
    if (d.toDateString() === today.toDateString()) return 'Today';
    if (d.toDateString() === y.toDateString()) return 'Yesterday';
    return d.toLocaleDateString([], { weekday: 'short', month: 'short', day: 'numeric' });
  }
  function ago(iso) {
    if (!iso) return 'never';
    var s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
    if (s < 45) return 'just now';
    if (s < 3600) return Math.round(s / 60) + ' min ago';
    if (s < 86400) return Math.round(s / 3600) + ' h ago';
    return Math.round(s / 86400) + ' d ago';
  }
  function bytes(n) { return n > 1 << 20 ? (n / (1 << 20)).toFixed(1) + ' MB' : Math.max(1, Math.round(n / 1024)) + ' KB'; }
  function layerOf(ruleID) {
    if (!ruleID) return '';
    if (ruleID.indexOf('privometry/') === 0) return 'built-in pack ' + ruleID.split(':')[0];
    return 'policy ' + ruleID.split(':')[0];
  }

  /* ---------- data ---------- */
  // ended is set when the server no longer accepts this page (it was
  // restarted with a new link): polling stops and the page says so once.
  var ended = false;
  function get(path) {
    if (ended) return Promise.reject(new Error('auth'));
    return fetch(path, { credentials: 'same-origin', cache: 'no-store' }).then(function (res) {
      if (res.status === 401) { sessionEnded(); throw new Error('auth'); }
      if (!res.ok) return res.text().then(function (t) { throw new Error(t || res.statusText); });
      return res.json();
    });
  }
  function sessionEnded() {
    if (ended) return;
    ended = true;
    var main = $('main');
    main.insertBefore(failNote(new Error('auth')), main.firstChild);
  }
  function failNote(err) {
    return h('div', { class: 'l-banner', role: 'alert' }, [icon('alert', 18), h('span', { text: err.message === 'auth'
      ? 'This page’s session ended. Run privometry timeline --web again and open the new link.'
      : 'Could not load this page: ' + err.message + '. Is privometry timeline --web still running?' })]);
  }

  /* ---------- shell ---------- */
  function guarded() { return (state.agents || []).filter(function (a) { return a.state === 'installed'; }); }
  // guardPill is the one-line protection state, shown in the sidebar and on the timeline's header.
  function guardPill() {
    var d = state.summary && state.summary.daemon;
    if (!state.summary) return null;
    if (d && !d.running) return pill('privometryd not running', 'block');
    if (state.agents && guarded().length === 0) return pill('No agent is hooked', 'ask');
    if (!state.agents) return null;
    var n = guarded().length;
    return pill('Guarding ' + (n === 1 ? guarded()[0].name : n + ' agents'), 'ok', true);
  }
  function renderStatus() {
    var s = $('status');
    s.textContent = '';
    if (!state.summary) return;
    var p = guardPill();
    if (p) s.appendChild(p);
    if (state.summary.host) { $('host').textContent = state.summary.host; $('crumb-host').textContent = state.summary.host; $('tile').textContent = state.summary.host.slice(0, 1); }
    if (state.summary.user) { $('user').textContent = state.summary.user; $('avatar').textContent = state.summary.user.slice(0, 2); }
  }
  function setView(v, focus) {
    if (VIEWS.indexOf(v) < 0) v = 'timeline';
    state.view = v;
    document.querySelectorAll('#nav button').forEach(function (b) {
      if (b.dataset.view === v) b.setAttribute('aria-current', 'page'); else b.removeAttribute('aria-current');
    });
    $('crumb-view').textContent = TITLES[v];
    document.title = TITLES[v] + ' · Privometry local guard';
    $('shell').classList.remove('menu-open');
    render();
    if (focus) { $('scroller').scrollTop = 0; $('main').focus({ preventScroll: true }); }
  }
  function render() {
    var main = $('main');
    main.textContent = '';
    ({ timeline: viewTimeline, sessions: viewSessions, scan: viewScan, policy: viewPolicy, device: viewDevice })[state.view](main);
  }
  function section(title, body, aside) {
    return h('section', {}, [h('div', { class: 'sec-h' }, [h('h2', { text: title }), aside || null]), body]);
  }
  // pageHead is the console's page header: title with a state badge, a lede, and an action on the right.
  function pageHead(title, lede, badge, action) {
    return h('div', { class: 'page-head' }, [
      h('div', { class: 'ph-text' }, [h('div', { class: 'title-state' }, [h('h1', { class: 'page-title', text: title }), badge || null]), lede ? h('p', { class: 'lede', text: lede }) : null]),
      action || null]);
  }
  function loading(text) { return h('div', { class: 'panel' }, [h('div', { class: 'empty', text: text })]); }

  /* ---------- timeline ---------- */
  function label(r) {
    if (r.outcome === 'would') return r.label.indexOf('DENY') >= 0 ? 'Would block' : 'Would ask';
    if (r.outcome === 'deny' && r.type === 'fail_mode') return 'Blocked offline';
    return LABELS[r.outcome] || r.label;
  }
  function isExc(r) { return ['ask', 'deny', 'alert', 'would', 'finding'].indexOf(r.outcome) >= 0; }
  function explain(r) {
    if (r.message && r.outcome !== 'auto') return r.message;
    switch (r.outcome) {
      case 'auto': return 'Privometry rated this ' + (r.risk === 'none' ? 'no' : r.risk || 'low') + ' risk and approved it without interrupting you.';
      case 'allow': return r.rules && r.rules.length ? 'Allowed by the rule ' + r.rules[0] + '.' : 'Allowed.';
      case 'ask': return 'Privometry asked you before this ran' + (r.why ? ': ' + r.why : '') + '.';
      case 'would': return 'A rule in monitor mode matched, so the action ran. It would have been ' + (label(r) === 'Would block' ? 'blocked' : 'asked') + '.';
      case 'config': return 'An agent’s config or memory file changed: ' + r.why + '.';
      case 'prompt': return 'Codex received a user query. Privometry stored only a keyed fingerprint and character count, not the query text.';
      case 'finding': return 'A content detector found ' + r.why + '. The excerpt masks credentials and shows hidden characters; it stays on this machine.';
      case 'alert': return r.why === 'hook_removed' ? 'Privometry’s hook was removed from this agent’s config, so its actions are no longer checked. Run privometry guard install to put it back.' : 'Privometry’s hook in this agent’s config was changed: ' + r.why + '.';
      case 'failmode': case 'deny':
        if (r.type === 'fail_mode') return 'privometryd did not answer in time, so the hook decided alone: ' + r.why + '.';
    }
    return r.why || '';
  }
  function trRow(r) {
    var open = state.open === r.id;
    var frag = document.createDocumentFragment();
    frag.appendChild(h('button', { type: 'button', class: 'tr' + (isExc(r) ? ' exc' : '') + (r.fresh ? ' is-new' : ''), 'data-id': r.id, 'aria-expanded': String(open) }, [
      h('span', { class: 'time num', text: clock(r.at) }), glyph(r.outcome),
      h('span', { class: 'agent', text: agentName(r.agent) }),
      h('span', { class: 'what', title: r.what }, [r.kind_label ? h('span', { class: 'kind kind-' + r.kind_label.toLowerCase(), text: r.kind_label }) : null,
        h('span', { class: 'what-text', text: r.what || r.tool || '(no target)' })]),
      h('span', { class: 'lab v ' + r.outcome, text: label(r) })
    ]));
    r.fresh = false;
    if (!open) return frag;
    var mcp = r.event && r.event.mcp;
    var ctx = r.kind === 'mcp_call' && mcp ? 'MCP call to server ' + mcp.server_name + ', tool ' + mcp.tool + (r.tool ? ' (the agent calls it ' + r.tool + ')' : '') + (r.repo ? ', in ' + r.repo : '')
      : r.kind ? (KINDS[r.kind] || r.kind) + (r.tool ? ' (' + r.tool + ' tool)' : '') + (r.repo ? ' in ' + r.repo : '') : '';
    if (r.latency_ms != null) ctx += (ctx ? ', d' : 'D') + 'ecided in ' + (Math.round(r.latency_ms * 10) / 10) + ' ms on this machine.';
    else if (ctx) ctx += '.';
    if (r.untrusted) ctx += ' The session had read untrusted content first.';
    var d = r.event && r.event.decision;
    if (d && d.native_verdict && d.native_verdict !== d.verdict) ctx += ' ' + agentName(r.agent) + ' cannot ' + (d.verdict === 'ask' ? 'ask you' : d.verdict) + ', so it received ' + (d.native_verdict === 'deny' ? 'a block' : d.native_verdict) + '.';
    frag.appendChild(h('div', { class: 'why' }, [
      h('p', { text: explain(r) }),
      r.what ? h('p', { class: 'full', text: r.what }) : null,
      r.rules && r.rules.length ? h('p', { class: 'ctx' }, ['Rule ', h('span', { class: 'mono', text: r.rules.join(', ') }), ' from ' + layerOf(r.rules[0]) + '.']) : null,
      ctx ? h('p', { class: 'ctx', text: ctx }) : null,
      h('button', { type: 'button', class: 'btn-text', 'data-json': r.id, 'aria-expanded': String(!!state.json[r.id]), text: state.json[r.id] ? 'Hide the stored event' : 'Show the stored event' }),
      state.json[r.id] ? h('pre', { class: 'json', text: JSON.stringify(r.event, null, 2) }) : null
    ]));
    return frag;
  }
  function traceBody() {
    var t = $('trace');
    if (!t) return;
    var active = document.activeElement && document.activeElement.dataset ? document.activeElement : null;
    var focusID = active && (active.dataset.id || active.dataset.json), wasJSON = active && active.dataset.json;
    t.textContent = '';
    if (!state.rows.length) {
      var filtered = state.show !== 'all' || state.search;
      t.appendChild(h('div', { class: 'empty' }, filtered
        ? [h('strong', { text: 'No matching actions' }), 'Clear the search to see everything.']
        : [h('strong', { text: 'Nothing yet' }), 'Once an agent with Privometry’s hook runs a tool, it appears here.']));
    } else {
      var day = '';
      state.rows.forEach(function (r) {
        var dn = dayName(r.at);
        if (dn !== day) { day = dn; t.appendChild(h('div', { class: 'day', role: 'separator', text: dn })); }
        t.appendChild(trRow(r));
      });
    }
    t.setAttribute('aria-busy', 'false');
    var older = $('older'); if (older) older.hidden = !state.more;
    if (focusID) {
      var el = t.querySelector(wasJSON ? '[data-json="' + CSS.escape(focusID) + '"]' : '[data-id="' + CSS.escape(focusID) + '"]');
      if (el) el.focus({ preventScroll: true });
    }
  }
  function banner() {
    var d = state.summary && state.summary.daemon;
    if (d && !d.running) return h('div', { class: 'l-banner', role: 'status' }, [icon('octagon', 18), h('span', {}, [h('strong', { text: 'privometryd is not running.' }),
      ' Agent hooks apply fail modes only: catastrophic actions are blocked, secrets and exfiltration ask, everything else gets no opinion. Run privometry daemon install to start it.'])]);
    if (d && d.outdated) return h('div', { class: 'l-banner ask', role: 'status' }, [icon('alert', 18), h('span', { text: 'privometryd is older than this CLI. Run privometry daemon restart to update it.' })]);
    var missing = (state.agents || []).filter(function (a) { return a.state !== 'installed' && a.state !== 'unsupported'; });
    if (missing.length) return h('div', { class: 'l-banner ask', role: 'status' }, [icon('alert', 18), h('span', { text: missing.map(function (a) { return a.name; }).join(', ') + (missing.length === 1 ? ' is' : ' are') + ' not hooked, so its actions are not checked. Run privometry guard install.' })]);
    return null;
  }
  function agentChips() {
    var calls = {};
    ((state.summary && state.summary.agents) || []).forEach(function (a) { calls[a.agent] = a; });
    return h('div', { class: 'agents', id: 'agents', 'aria-label': 'Coding agents' }, (state.agents || []).map(function (a) {
      var on = a.state === 'installed', c = calls[a.agent];
      var note = !on ? 'not hooked' : a.trust_required && !c ? 'waiting for /hooks trust' : c ? plural(c.calls, 'decision') + ', last ' + ago(c.last_call) : 'no calls yet';
      return h('div', { class: 'agent-chip' + (on ? '' : ' off') }, [h('span', { class: 'dot' + (on && c ? '' : ' off') }), a.name, h('small', { class: 'num', text: note })]);
    }));
  }
  function timelineHead() {
    var badge = h('span', { class: 'badge-slot', id: 'guard' }, [guardPill()]);
    return pageHead('Timeline', 'Every action your coding agents took on this machine, and what Privometry decided.', badge);
  }
  function metric(label, tone, value, caption) {
    return h('div', { class: 'metric' }, [h('div', { class: 'metric-head' }, [h('span', { class: 'mdot ' + tone }), label]), h('strong', { class: 'num', text: value }), h('small', { text: caption })]);
  }
  function metrics() {
    var s = state.summary, t = s && s.tally;
    if (!t || s.empty || !t.actions) return h('div', { class: 'metrics', id: 'metrics', hidden: true });
    var ms = t.avg_latency_ms ? Math.max(1, Math.round(t.avg_latency_ms)) + ' ms' : '-';
    return h('div', { class: 'metrics', id: 'metrics' }, [
      metric('Approved', 'ok', fmt(t.actions - t.asked - t.blocked), 'without interrupting you'),
      metric('Asked', 'ask', fmt(t.asked), 'waited for your answer'),
      metric('Blocked', 'block', fmt(t.blocked), 'stopped before running'),
      metric('Decision time', 'brand', ms, 'on average, offline')]);
  }
  function tally() {
    var p = h('p', { class: 'tally', id: 'tally', 'aria-live': 'polite' });
    var s = state.summary;
    if (!s) return p;
    var t = s.tally;
    if (s.empty || !t.actions) { p.textContent = s.empty ? 'Privometry has not recorded anything on this machine yet.' : 'No agent actions today yet. Decisions work offline and never leave this machine.'; return p; }
    p.hidden = true; // the metric cards say it
    return p;
  }
  function viewTimeline(main) {
    main.appendChild(timelineHead());
    var b = banner(); if (b) main.appendChild(b);
    main.appendChild(metrics());
    main.appendChild(tally());
    main.appendChild(agentChips());
    var q = h('input', { class: 'input', id: 'q', type: 'search', placeholder: 'Search commands, files or rules', autocomplete: 'off', spellcheck: 'false', value: state.search });
    var chips = h('div', { class: 'chips', role: 'group', 'aria-label': 'Show' }, [['all', 'Everything'], ['exc', 'Asks and blocks'], ['ask', 'Asked', 'ask'], ['deny', 'Blocked', 'deny']].map(function (c) {
      return h('button', { type: 'button', class: 'chip', 'data-show': c[0], 'aria-pressed': String(state.show === c[0]) }, [c[2] ? glyph(c[2]) : null, c[1]]);
    }));
    main.appendChild(h('div', { class: 'trace-tools' }, [
      h('div', { class: 'search' }, [h('label', { class: 'sr-only', for: 'q', text: 'Search the timeline' }), q]), chips,
      h('span', { class: 'hint' }, [h('span', { class: 'kbd', text: 'j' }), h('span', { class: 'kbd', text: 'k' }), ' move ', h('span', { class: 'kbd', text: 'Enter' }), ' why ', h('span', { class: 'kbd', text: '/' }), ' search'])
    ]));
    main.appendChild(h('div', { class: 'panel', id: 'trace', 'aria-busy': 'true' }));
    main.appendChild(h('div', { class: 'more' }, [h('button', { type: 'button', class: 'btn', id: 'older', hidden: true, text: 'Show older actions' })]));
    main.appendChild(h('p', { class: 'note', text: 'Full commands stay on this machine. Nothing is uploaded: this device is not connected to an organization.' }));
    var timer;
    q.addEventListener('input', function () { clearTimeout(timer); timer = setTimeout(function () { state.search = q.value.trim(); load(); }, 200); });
    if (state.loaded) traceBody(); else load();
  }

  var gen = 0;
  function params(extra) {
    var p = new URLSearchParams();
    if (state.show !== 'all') p.set('show', state.show);
    if (state.search) p.set('search', state.search);
    Object.keys(extra || {}).forEach(function (k) { p.set(k, extra[k]); });
    return p.toString();
  }
  function load() {
    var mine = ++gen;
    var t = $('trace'); if (t) t.setAttribute('aria-busy', 'true');
    return get('/api/events?' + params()).then(function (d) {
      if (mine !== gen) return;
      state.rows = d.rows; state.more = d.more; state.loaded = true;
      state.maxSeq = d.rows.length ? d.rows[0].seq : state.maxSeq;
      traceBody();
    }).catch(function (err) { var t = $('trace'); if (t) { t.textContent = ''; t.appendChild(failNote(err)); } });
  }
  function older() {
    if (!state.rows.length || state.loading) return;
    state.loading = true;
    var mine = gen;
    get('/api/events?' + params({ before_seq: state.rows[state.rows.length - 1].seq })).then(function (d) {
      if (mine !== gen) return;
      state.rows = state.rows.concat(d.rows); state.more = d.more;
      traceBody();
    }).catch(function () {}).then(function () { state.loading = false; });
  }
  function poll() {
    if (document.hidden || !state.live || !state.loaded) return;
    var mine = gen;
    get('/api/events?' + params({ after_seq: state.maxSeq, limit: 500 })).then(function (d) {
      if (mine !== gen || !d.rows.length) return;
      var fresh = d.rows.reverse();
      fresh.forEach(function (r) { r.fresh = true; });
      state.rows = fresh.concat(state.rows);
      state.maxSeq = state.rows[0].seq;
      if (state.view === 'timeline') traceBody();
    }).catch(function () {});
  }

  /* ---------- sessions ---------- */
  function viewSessions(main) {
    main.appendChild(pageHead('Sessions', 'Each agent session Privometry has seen on this machine, most recently active first. A session that read untrusted content asks before uploads; one that read injected instructions cannot edit memory files.'));
    var panel = h('div', { class: 'panel rows', id: 'sessions' });
    main.appendChild(panel);
    function fill() {
      panel.textContent = '';
      var list = state.sessions || [];
      if (!list.length) { panel.appendChild(h('div', { class: 'empty' }, [h('strong', { text: 'No sessions yet' }), 'Sessions appear once a hooked agent submits a query or runs a tool.'])); return; }
      list.forEach(function (s) {
        var active = !s.ended && Date.now() - new Date(s.last_event_at).getTime() < 15 * 60 * 1000;
        var flags = [];
        if (s.injection_seen) flags.push(pill('Read injected instructions', 'block'));
        if (s.untrusted_input_seen) flags.push(pill('Read untrusted content', 'ask'));
        if (s.findings) flags.push(pill(plural(s.findings, 'finding'), 'block'));
        panel.appendChild(h('div', { class: 'row' }, [
          h('div', { class: 'grow' }, [
            h('div', { class: 't' }, [agentName(s.agent) + ' ', h('span', { class: 'muted', text: 'in' }), ' ', h('span', { class: 'mono', text: s.repo || 'a folder outside git' })]),
            h('small', { class: 'num', text: 'Started ' + ago(s.started_at) + ', last activity ' + ago(s.last_event_at) + '. ' + plural(s.prompts || 0, 'query', 'queries') + ', ' + plural(s.actions, 'action') + ', ' + fmt(s.asked) + ' asked, ' + fmt(s.blocked) + ' blocked.' }),
            flags.length ? h('div', { class: 'flags' }, flags) : null
          ]),
          active ? pill('Active', 'ok', true) : pill(s.ended ? 'Ended' : 'Idle')
        ]));
      });
    }
    if (state.sessions) fill(); else panel.appendChild(h('div', { class: 'empty', text: 'Loading…' }));
    get('/api/sessions').then(function (d) { state.sessions = d; if (state.view === 'sessions') fill(); }).catch(function (e) { panel.textContent = ''; panel.appendChild(failNote(e)); });
  }

  /* ---------- scan ---------- */
  function hookPill(s) {
    return { installed: pill('Hooked', 'ok'), partial: pill('Partly hooked', 'ask'), stale: pill('Hook out of date', 'ask'), missing: pill('Not hooked', 'block'), unsupported: pill('Not supported yet') }[s] || pill(s);
  }
  function sevPill(s) { return pill(s, s === 'critical' || s === 'high' ? 'block' : s === 'medium' ? 'ask' : ''); }
  function viewScan(main) {
    var btn = h('button', { type: 'button', class: 'btn btn-ink', id: 'scan-now' }, [icon('refresh', 15), h('span', { text: 'Scan now' })]);
    var head = pageHead('Scan', 'Coding agents, MCP servers, hooks and memory files on this machine, and anything worth fixing.', null, btn);
    var lede = head.querySelector('.lede'), badge = head.querySelector('.title-state');
    main.appendChild(head);
    var body = h('div', { class: 'stack', id: 'scan-body' });
    main.appendChild(body);
    function fill() {
      body.textContent = '';
      var s = state.scan;
      lede.textContent = 'Last scan ' + ago(s.scanned_at) + '. Privometry also watches agents’ config and memory files for changes, and checks every action as it happens.';
      var fixes = (s.findings || []).map(function (f) {
        return h('div', { class: 'row' }, [h('span', { class: 'sev ' + f.severity }, [icon('alert', 18)]), h('div', { class: 'grow' }, [
          h('div', { class: 't', text: f.message }), h('small', { text: (f.path ? f.path + (f.line ? ':' + f.line : '') + '. ' : '') + 'Fix: ' + f.fix })]), sevPill(f.severity)]);
      }).concat((s.content_findings || []).map(function (f) {
        return h('div', { class: 'row' }, [h('span', { class: 'sev ' + f.severity }, [icon('alert', 18)]), h('div', { class: 'grow' }, [
          h('div', { class: 't', text: f.title + ' in ' + f.path + (f.line ? ':' + f.line : '') }), h('small', { class: 'mono', text: f.excerpt }), h('small', { text: f.detector })]), sevPill(f.severity)]);
      }));
      var count = $('scan-count');
      count.hidden = !fixes.length; count.textContent = String(fixes.length);
      if (badge.childNodes.length > 1) badge.lastChild.remove();
      badge.appendChild(fixes.length ? pill(plural(fixes.length, 'thing') + ' to fix', 'ask') : pill('All clear', 'ok'));
      body.appendChild(section('Worth fixing', h('div', { class: 'panel rows' }, fixes.length ? fixes : [h('div', { class: 'row' }, [h('span', { class: 'ok-i' }, [icon('check', 18)]),
        h('div', { class: 'grow' }, [h('div', { class: 't', text: 'Nothing worth fixing' }), h('small', { text: 'No risky settings, and nothing found in memory files, skills or configs.' })])])])));
      body.appendChild(section('Coding agents', h('div', { class: 'panel rows' }, (s.agents || []).map(function (a) {
        var configs = (a.configs || []).filter(function (c) { return (c.holds || []).indexOf('skills') < 0; }).map(function (c) { return c.path; });
        return h('div', { class: 'row' }, [h('div', { class: 'grow' }, [
          h('div', { class: 't', text: a.name + (a.version ? ' ' + a.version : '') }),
          configs.length ? h('small', { class: 'mono', text: configs.slice(0, 3).join(', ') + (configs.length > 3 ? ', …' : '') }) : null,
          h('small', { text: [plural((a.mcp_servers || []).length, 'MCP server'), plural((a.skills || []).length, 'skill'), plural((a.memory_files || []).length, 'memory file')].join(', ') + (a.version_note ? '. ' + a.version_note : '') })
        ]), hookPill(a.hook)]);
      }))));
      var servers = [];
      (s.agents || []).forEach(function (a) { (a.mcp_servers || []).forEach(function (m) { servers.push({ a: a, m: m }); }); });
      body.appendChild(section('MCP servers', h('div', { class: 'panel rows' }, servers.length ? servers.map(function (x) {
        var m = x.m;
        return h('div', { class: 'row' }, [h('div', { class: 'grow' }, [h('div', { class: 't mono', text: m.name }),
          (m.transport === 'http' ? m.url : m.command) ? h('small', { class: 'mono', text: m.transport === 'http' ? m.url : m.command }) : null,
          h('small', { text: x.a.name + ', ' + m.tier + ' tier, in ' + m.path })]),
          m.pinned === false ? pill('Not pinned', 'ask') : m.pinned ? pill('Pinned', 'ok') : null]);
      }) : [h('div', { class: 'empty', text: 'No MCP servers configured.' })])));
      var memory = [];
      (s.agents || []).forEach(function (a) { (a.memory_files || []).forEach(function (m) { memory.push({ a: a, m: m }); }); });
      var shown = memory.slice(0, 12);
      var rows = shown.map(function (x) {
        return h('div', { class: 'row' }, [h('span', { class: 'muted' }, [icon('file', 16)]), h('div', { class: 'grow' }, [h('div', { class: 't mono', text: x.m.path }),
          h('small', { text: x.a.name + ', ' + x.m.tier + ' ' + x.m.kind })])]);
      });
      if (memory.length > shown.length) rows.push(h('div', { class: 'row' }, [h('small', { class: 'muted', text: 'and ' + plural(memory.length - shown.length, 'more file') + '. privometry scan --format json lists them all.' })]));
      body.appendChild(section('Memory and instruction files', h('div', { class: 'panel rows' }, rows.length ? rows : [h('div', { class: 'empty', text: 'No memory or instruction files found.' })]),
        h('span', { class: 'aside muted', text: plural(memory.length, 'file') })));
    }
    function run(fresh) {
      btn.disabled = true; btn.lastChild.textContent = 'Scanning…';
      get('/api/view/scan' + (fresh ? '?fresh=1' : '')).then(function (d) { state.scan = d; if (state.view === 'scan') fill(); })
        .catch(function (e) { body.textContent = ''; body.appendChild(failNote(e)); })
        .then(function () { btn.disabled = false; btn.lastChild.textContent = 'Scan now'; });
    }
    btn.addEventListener('click', function () { run(true); });
    if (state.scan) fill(); else body.appendChild(loading('Scanning this machine…'));
    run(false);
  }

  /* ---------- policy ---------- */
  function showFile(title, text) {
    var layer = $('layer');
    var close = h('button', { type: 'button', class: 'x', 'aria-label': 'Close' }, [icon('x', 18)]);
    var overlay = h('div', { class: 'overlay', role: 'dialog', 'aria-modal': 'true', 'aria-label': title }, [h('div', { class: 'modal' }, [
      h('div', { class: 'modal-head' }, [h('h2', { class: 'mono', text: title }), close]), h('div', { class: 'modal-body' }, [h('pre', { class: 'json', text: text })])])]);
    function done() { layer.textContent = ''; document.removeEventListener('keydown', esc); }
    function esc(e) { if (e.key === 'Escape') done(); }
    overlay.addEventListener('click', function (e) { if (e.target === overlay) done(); });
    close.addEventListener('click', done);
    document.addEventListener('keydown', esc);
    layer.textContent = '';
    layer.appendChild(overlay);
    close.focus();
  }
  var LAYER_NAMES = { builtin: 'Built-in', user: 'Yours', repo: 'Repo', org: 'Organization' };
  function viewPolicy(main) {
    main.appendChild(pageHead('Policy', 'Rules from these sources apply together. When they disagree, the strictest verdict wins: block beats ask, and ask beats allow.'));
    var body = h('div', { class: 'stack' });
    main.appendChild(body);
    function fill() {
      body.textContent = '';
      var p = state.policy;
      var builtin = p.packs.reduce(function (n, x) { return n + x.Rules; }, 0);
      var userBtn = p.user.text ? h('button', { type: 'button', class: 'btn btn-sm', text: 'View file' }) : null;
      if (userBtn) userBtn.addEventListener('click', function () { showFile(p.user.path, p.user.text); });
      if (p.problems && p.problems.length) body.appendChild(h('div', { class: 'l-banner ask', role: 'status' }, [icon('alert', 18), h('span', { text: p.problems.join(' ') })]));
      body.appendChild(h('div', { class: 'panel rows layers' }, [
        h('div', { class: 'row off' }, [h('div', { class: 'grow' }, [h('div', { class: 't', text: 'Organization policy' }), h('small', { text: 'Not connected. Privometry Team adds a signed organization policy, with locked rules lower layers cannot loosen.' })]), h('span', { class: 'layer-tag', text: 'From your organization' })]),
        h('div', { class: 'row' }, [h('div', { class: 'grow' }, [h('div', { class: 't', text: 'Repo policy' }), h('small', { text: '.privometry/policy.yaml in a repo, applied while an agent works in that repo.' })]), h('span', { class: 'layer-tag', text: 'Committed with the repo' })]),
        h('div', { class: 'row' }, [h('div', { class: 'grow' }, [h('div', { class: 't', text: 'Your overrides' }), h('small', { text: p.user.text ? p.user.path + ', ' + plural(p.user.rules, 'rule') + '. You can tighten built-in rules here, and loosen the ones marked overridable.' : 'No ' + p.user.path + ' yet. Write one to allow tools you trust or to tighten rules.' })]), h('span', { class: 'layer-tag', text: 'On this machine' }), userBtn]),
        h('div', { class: 'row' }, [h('div', { class: 'grow' }, [h('div', { class: 't', text: 'Built-in packs' }), h('small', { text: p.packs.map(function (x) { return x.ID + ' ' + x.Version; }).join(', ') + '. ' + plural(builtin, 'rule') + '.' })]), h('span', { class: 'layer-tag', text: 'Shipped with Privometry' })])
      ]));
      var fm = p.fail_modes || {};
      var closed = Object.keys(fm).filter(function (k) { return fm[k] === 'closed'; }).sort(), ask = Object.keys(fm).filter(function (k) { return fm[k] === 'ask'; }).sort();
      var failText = (closed.length ? closed.join(', ').replace(/_/g, ' ') + ' actions are blocked' : 'Nothing is blocked') + (ask.length ? '; ' + ask.join(' and ').replace(/_/g, ' ') + ' ask' : '') + '; everything else gets no opinion, so the agent’s own prompt applies';
      var kv = p.unmatched === 'auto'
        ? [['No or low risk', 'Approved without asking, and logged here'], ['Medium risk or higher', 'You’re asked, with the reason']]
        : [['Any action', p.unmatched === 'allow' ? 'Allowed and logged' : 'You’re asked, with the reason']];
      kv.push(['Privometry can’t decide in time', failText]);
      body.appendChild(section('When no rule matches', h('div', { class: 'panel' }, [h('dl', { class: 'kv' }, kv.reduce(function (a, x) { a.push(h('dt', { text: x[0] }), h('dd', { text: x[1] })); return a; }, []))])));
      var order = { deny: 0, ask: 1, allow: 2 };
      var rules = p.rules.slice().sort(function (a, b) { return (order[a.verdict] - order[b.verdict]) || a.id.localeCompare(b.id); });
      body.appendChild(section('Rules in effect', h('div', { class: 'panel rows' }, rules.map(function (r) {
        return h('div', { class: 'rule-row' }, [glyph(r.verdict), h('div', {}, [h('div', { class: 'id', text: r.id }), h('div', { class: 'meta', text: (r.message || r.category) + (r.mode === 'monitor' ? ' (monitor mode)' : '') })]),
          h('span', { class: 'layer-tag', text: LAYER_NAMES[r.layer] || r.layer })]);
      })), h('span', { class: 'aside muted', text: plural(rules.length, 'rule') })));
    }
    if (state.policy) fill(); else body.appendChild(loading('Loading…'));
    get('/api/view/policy').then(function (d) { state.policy = d; if (state.view === 'policy') fill(); }).catch(function (e) { body.textContent = ''; body.appendChild(failNote(e)); });
  }

  /* ---------- device ---------- */
  var CHECK_ICON = { ok: ['check', 'ok-i'], warn: ['alert', 'sev medium'], fail: ['x', 'sev high'], skip: ['minus', 'muted'] };
  function viewDevice(main) {
    main.appendChild(pageHead('Device', 'This machine, what Privometry keeps here, and whether protection is working.', pill('Local only', '', 'off')));
    var body = h('div', { class: 'stack' });
    main.appendChild(body);
    function fill() {
      body.textContent = '';
      var d = state.device;
      var kv = [['Machine', d.host], ['User', d.user], ['System', d.os + ' ' + d.arch], ['Device ID', d.device_id || 'Assigned when privometryd first runs'], ['Sensor', d.version],
        ['privometryd', d.daemon ? 'Running since ' + ago(d.daemon.started_at) + ' (pid ' + d.daemon.pid + ')' : 'Not running'], ['Organization', 'Not connected. Privometry Free keeps everything on this machine.']];
      var device = h('section', {}, [h('div', { class: 'sec-h' }, [h('h2', { text: 'This device' })]),
        h('div', { class: 'panel' }, [h('dl', { class: 'kv' }, kv.reduce(function (a, x) { a.push(h('dt', { text: x[0] }), h('dd', { class: x[0] === 'Device ID' ? 'mono' : null, text: x[1] || '-' })); return a; }, []))])]);
      var local = h('section', {}, [h('div', { class: 'sec-h' }, [h('h2', { text: 'Local data' })]), h('div', { class: 'panel rows' }, [
        h('div', { class: 'setting' }, [h('span', { text: 'What the timeline stores' }), h('p', { text: 'Commands and paths after secrets, personal paths, and other sensitive values are redacted.' })]),
        h('div', { class: 'setting' }, [h('span', { text: 'Keep history for' }), h('p', { text: d.retention_days + ' days. Stored in ' + d.data_dir + '/privometry.db' + (d.db_bytes ? ' (' + bytes(d.db_bytes) + ')' : '') + ', readable only by you.' })]),
        h('div', { class: 'setting' }, [h('span', { text: 'Diagnostics' }), h('p', {}, ['Run ', h('span', { class: 'mono', text: 'privometry doctor --bundle' }), ' for a zip to share. It has no full commands, and secrets are removed.'])])
      ])]);
      body.appendChild(h('div', { class: 'two' }, [device, local]));
      var checks = d.checks || [];
      var fails = checks.filter(function (c) { return c.status === 'fail'; }).length, warns = checks.filter(function (c) { return c.status === 'warn'; }).length;
      var summary = fails ? pill(plural(fails, 'problem'), 'block') : warns ? pill(plural(warns, 'warning'), 'ask') : pill('Protecting this machine', 'ok', true);
      body.appendChild(section('Health', h('div', { class: 'panel rows' }, checks.map(function (c) {
        var ic = CHECK_ICON[c.status] || CHECK_ICON.skip;
        return h('div', { class: 'row' }, [h('span', { class: ic[1] }, [icon(ic[0], 18)]), h('div', { class: 'grow' }, [h('div', { class: 't', text: c.title }), h('small', { text: c.detail }), c.fix ? h('small', { text: 'Fix: ' + c.fix }) : null])]);
      })), h('span', { class: 'aside' }, [summary])));
    }
    if (state.device) fill(); else body.appendChild(loading('Checking this machine…'));
    get('/api/view/device').then(function (d) { state.device = d; if (state.view === 'device') fill(); }).catch(function (e) { body.textContent = ''; body.appendChild(failNote(e)); });
  }

  /* ---------- header data ---------- */
  function refreshHeader() {
    Promise.all([get('/api/summary'), get('/api/view/agents')]).then(function (r) {
      state.summary = r[0]; state.agents = r[1];
      renderStatus();
      if (state.view !== 'timeline') return;
      var main = $('main');
      var oldB = main.querySelector(':scope > .l-banner'), b = banner();
      if (oldB && b) oldB.replaceWith(b); else if (oldB) oldB.remove(); else if (b) main.querySelector('.page-head').after(b);
      var g = $('guard'); if (g) { g.textContent = ''; var p = guardPill(); if (p) g.appendChild(p); }
      var m = $('metrics'); if (m) m.replaceWith(metrics());
      var a = $('agents'); if (a) a.replaceWith(agentChips());
      var t = $('tally'); if (t) t.replaceWith(tally());
    }).catch(function () {});
  }

  /* ---------- events ---------- */
  $('nav').addEventListener('click', function (e) {
    var b = e.target.closest('button[data-view]');
    if (!b) return;
    if (location.hash.slice(1) === b.dataset.view) setView(b.dataset.view, true); else location.hash = b.dataset.view;
  });
  window.addEventListener('hashchange', function () { setView(location.hash.slice(1), true); });
  $('main').addEventListener('click', function (e) {
    var j = e.target.closest('[data-json]');
    if (j) { var id = j.dataset.json; state.json[id] = !state.json[id]; traceBody(); return; }
    var c = e.target.closest('.chip[data-show]');
    if (c) {
      state.show = c.dataset.show;
      document.querySelectorAll('.chip[data-show]').forEach(function (o) { o.setAttribute('aria-pressed', String(o === c)); });
      load(); return;
    }
    if (e.target.closest('#older')) { older(); return; }
    var row = e.target.closest('.tr');
    if (row) { state.open = state.open === row.dataset.id ? null : row.dataset.id; traceBody(); }
  });
  $('live').addEventListener('click', function () {
    state.live = !state.live;
    var b = $('live');
    b.setAttribute('aria-pressed', String(state.live));
    b.firstChild.className = 'dot' + (state.live ? '' : ' off');
    b.lastChild.textContent = state.live ? 'Live' : 'Paused';
    if (state.live) poll();
  });
  function resolvedTheme() {
    var t = document.documentElement.getAttribute('data-theme');
    if (t === 'light' || t === 'dark') return t;
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  function themeButtons() {
    var t = resolvedTheme();
    document.querySelectorAll('.theme-seg button').forEach(function (b) { b.setAttribute('aria-pressed', String(b.dataset.theme === t)); });
  }
  document.querySelectorAll('.theme-seg button').forEach(function (b) {
    b.addEventListener('click', function () {
      document.documentElement.setAttribute('data-theme', b.dataset.theme);
      try { localStorage.setItem('privometry-theme', b.dataset.theme); } catch (e) { /* storage blocked: the choice lasts for this page */ }
      themeButtons();
    });
  });
  try { var saved = localStorage.getItem('privometry-theme'); if (saved === 'light' || saved === 'dark') document.documentElement.setAttribute('data-theme', saved); } catch (e) { /* ignore */ }
  themeButtons();
  $('menu').addEventListener('click', function () { $('shell').classList.add('menu-open'); });
  $('scrim').addEventListener('click', function () { $('shell').classList.remove('menu-open'); });
  document.addEventListener('keydown', function (e) {
    if (e.metaKey || e.ctrlKey || e.altKey || state.view !== 'timeline' || $('layer').firstChild) return;
    var inField = /^(INPUT|SELECT|TEXTAREA)$/.test(document.activeElement.tagName);
    if (e.key === '/' && !inField) { e.preventDefault(); var q = $('q'); if (q) q.focus(); return; }
    if (e.key === 'Escape' && inField) { document.activeElement.blur(); return; }
    if (inField || (e.key !== 'j' && e.key !== 'k')) return;
    var rows = Array.prototype.slice.call(document.querySelectorAll('.tr'));
    if (!rows.length) return;
    var i = rows.indexOf(document.activeElement);
    rows[e.key === 'j' ? Math.min(rows.length - 1, i + 1) : Math.max(0, i < 0 ? 0 : i - 1)].focus();
    e.preventDefault();
  });
  document.addEventListener('visibilitychange', function () { if (!document.hidden) { poll(); refreshHeader(); } });

  setView(location.hash.slice(1) || 'timeline', false);
  refreshHeader();
  setInterval(poll, POLL_MS);
  setInterval(refreshHeader, SUMMARY_MS);
})();
