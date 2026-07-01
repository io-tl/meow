/* ==========================================================================
   Meow — Mobile SPA controller
   One page, client-side routing, covers the full datastore REST API.
   Auth (X-API-Key) is injected transparently by auth.js.
   ========================================================================== */
(function () {
  'use strict';

  const PAGE_SIZE = 25;
  const CHART_COLORS = ['#4a9eff', '#00d4ff', '#a78bfa', '#34d399', '#fbbf24', '#f87171', '#f472b6', '#10b981', '#8b5cf6', '#3d8bfd'];

  // ------------------------------------------------------------------ helpers
  const $ = (id) => document.getElementById(id);
  const $$ = (sel, root) => Array.from((root || document).querySelectorAll(sel));

  function esc(t) {
    if (t === null || t === undefined) return '';
    const d = document.createElement('div');
    d.textContent = String(t);
    return d.innerHTML;
  }
  function fmtNum(n) { return (Number(n) || 0).toLocaleString('en-US'); }
  function parseJSON(v) {
    if (v == null) return null;
    if (typeof v === 'object') return v;
    try { return JSON.parse(v); } catch (e) { return null; }
  }
  function cloudClass(p) {
    if (!p) return 'other';
    const l = String(p).toLowerCase();
    if (l.includes('aws') || l.includes('amazon')) return 'aws';
    if (l.includes('gcp') || l.includes('google')) return 'gcp';
    if (l.includes('azure') || l.includes('microsoft')) return 'azure';
    return 'other';
  }
  function flag(cc) {
    if (!cc) return '';
    const c = String(cc).toLowerCase();
    return `<img src="https://flagcdn.com/16x12/${c}.png" alt="${esc(cc)}" onerror="this.style.display='none'">`;
  }
  function fmtDate(unix) {
    if (!unix) return '';
    const d = new Date(Number(unix) * 1000);
    if (isNaN(d.getTime())) return '';
    return d.toISOString().slice(0, 10);
  }
  function timeAgo(sec) {
    if (sec < 0) sec = 0;
    if (sec < 60) return sec + 's';
    if (sec < 3600) return Math.floor(sec / 60) + 'm';
    if (sec < 86400) return Math.floor(sec / 3600) + 'h';
    return Math.floor(sec / 86400) + 'd';
  }
  function fmtUptime(s) {
    if (!s || s <= 0) return '-';
    if (s < 60) return s + 's';
    if (s < 3600) return Math.floor(s / 60) + 'm';
    const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60);
    return h + 'h' + m + 'm';
  }
  function fmtBytes(n) {
    n = Number(n) || 0;
    const u = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i === 0 ? n : n.toFixed(1)) + ' ' + u[i];
  }
  async function fetchJSON(url, opts) {
    const r = await fetch(url, opts);
    let data = null;
    try { data = await r.json(); } catch (e) { /* ignore */ }
    if (!r.ok) {
      const err = new Error((data && data.error) || ('HTTP ' + r.status));
      err.status = r.status;
      err.data = data;
      throw err;
    }
    return data || {};
  }

  let toastTimer = null;
  function toast(msg, type) {
    const t = $('toast');
    if (!t) return;
    t.textContent = msg;
    t.className = 'toast show' + (type ? ' ' + type : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.className = 'toast'; }, 3500);
  }

  // sheet <-> backdrop pairs
  const SHEETS = {
    'detail-sheet': 'detail-backdrop',
    'help-sheet': 'help-backdrop',
    'menu-sheet': 'menu-backdrop',
  };
  function openSheet(id) {
    const bd = SHEETS[id];
    $(id) && $(id).classList.add('show');
    bd && $(bd) && $(bd).classList.add('show');
  }
  function closeSheet(id) {
    const bd = SHEETS[id];
    $(id) && $(id).classList.remove('show');
    bd && $(bd) && $(bd).classList.remove('show');
  }
  function openDrawer() { $('filter-drawer').classList.add('show'); $('drawer-backdrop').classList.add('show'); }
  function closeDrawer() { $('filter-drawer').classList.remove('show'); $('drawer-backdrop').classList.remove('show'); }

  function apiKey() { try { return localStorage.getItem('meow_api_key') || ''; } catch (e) { return ''; } }

  // shared detail sheet
  function showDetail(title, html) {
    $('detail-title').textContent = title;
    $('detail-body').innerHTML = html;
    openSheet('detail-sheet');
  }
  function detailLoading(title) {
    showDetail(title, '<div class="list-loading"><div class="pull-spinner"></div></div>');
  }

  // ------------------------------------------------------ shared port helpers
  function isGhost(s) { return !s.service && !s.fingerprint_data && !s.banner && !s.product; }
  function portTags(services) {
    const seen = new Map();
    (services || []).forEach((s) => {
      if (!seen.has(s.port) || (!isGhost(s) && isGhost(seen.get(s.port)))) seen.set(s.port, s);
    });
    const identified = [], ghost = [];
    Array.from(seen.values()).sort((a, b) => a.port - b.port).forEach((s) => {
      (isGhost(s) ? ghost : identified).push(s);
    });
    const tags = [];
    identified.slice(0, 5).forEach((s) => tags.push(`<span class="port-tag identified">${s.port}</span>`));
    if (identified.length > 5) tags.push(`<span class="port-tag more">+${identified.length - 5}</span>`);
    if (ghost.length) tags.push(`<span class="port-tag ghost">+${ghost.length}</span>`);
    return tags.join('');
  }

  // ============================================================ HOST DETAIL
  async function openHostDetail(ip) {
    detailLoading(ip);
    try {
      const h = await fetchJSON('/api/hosts/' + encodeURIComponent(ip));
      showDetail(ip, renderHostDetail(h));
    } catch (e) {
      showDetail(ip, `<div class="empty"><p>${esc(e.message || 'Failed to load')}</p></div>`);
    }
  }
  function kvRow(k, v) { return `<span class="d-label">${esc(k)}</span><span class="d-value">${esc(v)}</span>`; }

  function renderHostDetail(h) {
    let html = '';
    // Location / network
    const loc = [];
    if (h.country_code) loc.push(kvRow('Country', h.country_code + (h.city ? ' / ' + h.city : '')));
    if (h.asn) loc.push(kvRow('ASN', 'AS' + h.asn));
    if (h.as_org) loc.push(kvRow('Org', h.as_org));
    if (h.cloud_provider) loc.push(kvRow('Cloud', h.cloud_provider + (h.cloud_region ? ' / ' + h.cloud_region : '')));
    if (h.cloud_type) loc.push(kvRow('Cloud type', h.cloud_type));
    if (h.last_scan) loc.push(kvRow('Last scan', fmtDate(h.last_scan)));
    if (loc.length) html += `<div class="d-section"><h4>Network</h4><div class="d-grid">${loc.join('')}</div></div>`;

    // Domains
    const domains = h.domains || [];
    if (domains.length) {
      html += `<div class="d-section"><h4>Domains <span class="pill">${domains.length}</span></h4><div class="tags-wrap">`;
      html += domains.slice(0, 20).map((d) => `<span class="tag">${esc(d.domain || d)}</span>`).join('');
      if (domains.length > 20) html += `<span class="tag muted">+${domains.length - 20}</span>`;
      html += '</div></div>';
    }

    // Certificates
    const certs = h.certificates || [];
    if (certs.length) {
      html += `<div class="d-section"><h4>Certificates <span class="pill">${certs.length}</span></h4>`;
      html += certs.map((c) => `
        <div class="d-svc"><div class="d-svc-head">
          <span class="d-svc-title">${esc(c.subject_cn || c.fingerprint_sha256.slice(0, 16))}</span>
          <span class="d-svc-info">${c.not_after ? 'exp ' + fmtDate(c.not_after) : ''}</span>
        </div></div>`).join('');
      html += '</div>';
    }

    // Services
    const services = h.services || [];
    if (services.length) {
      html += `<div class="d-section"><h4>Services <span class="pill">${services.length}</span></h4>`;
      html += services.sort((a, b) => a.port - b.port).map(renderServiceBlock).join('');
      html += '</div>';
    }
    if (!html) html = '<div class="empty"><p>No details available</p></div>';
    return html;
  }

  function renderServiceBlock(s) {
    const title = s.port + (s.service && s.service !== 'open' ? '/' + s.service : '');
    const info = [s.product, s.version].filter(Boolean).join(' ');
    let body = '';
    const rows = [];
    if (info) rows.push(kvRow('Product', info));
    if (s.banner) rows.push(kvRow('Banner', s.banner.slice(0, 200)));
    if (s.cms) rows.push(kvRow('CMS', s.cms));
    if (s.framework) rows.push(kvRow('Framework', s.framework));
    if (s.webserver) rows.push(kvRow('Webserver', s.webserver));
    if (rows.length) body += `<div class="d-grid">${rows.join('')}</div>`;

    // technologies
    const techs = parseJSON(s.technologies);
    if (Array.isArray(techs) && techs.length) {
      const names = techs.map((t) => (typeof t === 'string' ? t : t && t.name)).filter(Boolean);
      if (names.length) body += `<div class="tech-row">${names.slice(0, 12).map((n) => `<span class="tag">${esc(n)}</span>`).join('')}</div>`;
    }
    // enrichment scalar summary
    const ed = parseJSON(s.enrichment_data);
    if (ed && typeof ed === 'object') {
      const entries = Object.entries(ed).filter(([, v]) => v !== null && v !== '' && typeof v !== 'object').slice(0, 8);
      if (entries.length) body += `<div class="d-grid" style="margin-top:8px">${entries.map(([k, v]) => kvRow(k, String(v))).join('')}</div>`;
    }
    // SNI enrichments (per-domain)
    (s.enrichments || []).forEach((en) => {
      const parts = [];
      if (en.title) parts.push('"' + en.title + '"');
      if (en.server) parts.push(en.server);
      if (en.status_code) parts.push(en.status_code);
      if (parts.length) body += `<div class="kv-json">${esc((en.domain || 'IP') + ' — ' + parts.join(' · '))}</div>`;
    });

    return `<div class="d-svc"><div class="d-svc-head${body ? ' open' : ''}">
        <span class="d-svc-title">${esc(title)}</span>
        <span class="d-svc-info">${esc(info)}</span>
      </div>${body ? `<div class="d-svc-body">${body}</div>` : ''}</div>`;
  }

  // ============================================================ EXPORT SHEET
  function showExport(type, params) {
    const build = (fmt) => {
      const p = new URLSearchParams(params || {});
      p.set('format', fmt);
      p.set('type', type);
      if (!p.has('limit')) p.set('limit', '5000');
      const k = apiKey();
      if (k) p.set('key', k);
      return '/api/export?' + p.toString();
    };
    const icon = '<svg width="18" height="18" viewBox="0 0 24 24" fill="none"><path d="M12 3v12m0 0l-4-4m4 4l4-4M4 17v2a2 2 0 002 2h12a2 2 0 002-2v-2" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>';
    const btn = (fmt, label) => `<button class="menu-item" data-fmt="${fmt}">${icon}<span>${esc(label)}</span></button>`;
    showDetail('Export ' + type, `<div class="menu-list" style="padding:0">${btn('json', 'JSON')}${btn('csv', 'CSV')}${btn('txt', 'Plain text (one per line)')}</div>`);
    // Attach handlers (avoid inline JS with interpolated data)
    $$('#detail-body .menu-item[data-fmt]').forEach((el) => el.addEventListener('click', () => window.open(build(el.dataset.fmt), '_blank')));
  }

  // ================================================================= ROUTER
  const VIEWS = ['dashboard', 'explore', 'query', 'scan', 'status'];
  const LABELS = { dashboard: 'Dashboard', explore: 'Explore', query: 'MeowQL Query', scan: 'Scan', status: 'System Status' };
  const inited = {};
  let currentView = null;

  function route() {
    let hash = (location.hash || '#dashboard').slice(1);
    let view = hash.split('/')[0];
    if (!VIEWS.includes(view)) view = 'dashboard';
    show(view);
  }

  function show(view) {
    currentView = view;
    VIEWS.forEach((v) => { const el = $('view-' + v); if (el) el.hidden = v !== view; });
    $$('.nav-tab').forEach((t) => t.classList.toggle('active', t.dataset.view === view));
    $('view-label').textContent = LABELS[view] || '';
    $('app-main').scrollTo(0, 0);
    if (!inited[view]) { inited[view] = true; Controllers[view].init(); }
    else if (Controllers[view].onShow) Controllers[view].onShow();
  }

  // ============================================================ CONTROLLERS
  const Controllers = {};

  /* ---------------------------------------------------------- DASHBOARD --- */
  Controllers.dashboard = {
    charts: {},
    init() {
      this.load();
    },
    onShow() { /* keep cached; pull-to-refresh reloads */ },
    async load() {
      try {
        const [stats, dstats] = await Promise.all([
          fetchJSON('/api/stats/dashboard'),
          fetchJSON('/api/domains/stats').catch(() => ({})),
        ]);
        this.cards(stats, dstats);
      } catch (e) { /* ignore */ }
      this.charts_countries();
      this.charts_services();
      this.charts_ports();
      this.charts_tech();
      this.products();
    },
    cards(s, d) {
      const items = [
        { cls: 'c1', label: 'Hosts', val: s.total_hosts, icon: '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/><path d="M12 7v5l3 3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>' },
        { cls: 'c2', label: 'Services', val: s.total_services, icon: '<rect x="3" y="9" width="18" height="10" rx="2" stroke="currentColor" stroke-width="2"/><path d="M8 9V7a4 4 0 018 0v2" stroke="currentColor" stroke-width="2"/>' },
        { cls: 'c3', label: 'Certificates', val: s.total_certificates, icon: '<path d="M12 2l8 5v9c0 3.9-3.6 7-8 7s-8-3.1-8-7V7l8-5z" stroke="currentColor" stroke-width="2"/><path d="M9 12l2 2 4-4" stroke="currentColor" stroke-width="2"/>' },
        { cls: 'c4', label: 'Domains', val: (d && d.total_domains) || 0, icon: '<circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/><path d="M3 12h18M12 3c2.5 3 2.5 15 0 18M12 3c-2.5 3-2.5 15 0 18" stroke="currentColor" stroke-width="2"/>' },
      ];
      $('dash-cards').innerHTML = items.map((it) => `
        <div class="stat-card ${it.cls}">
          <div class="stat-icon"><svg width="18" height="18" viewBox="0 0 24 24" fill="none">${it.icon}</svg></div>
          <div class="stat-value">${fmtNum(it.val)}</div>
          <div class="stat-label">${it.label}</div>
        </div>`).join('');
    },
    baseOpts(extra) {
      return Object.assign({ responsive: true, maintainAspectRatio: false, animation: { duration: 400 } }, extra);
    },
    legendRight() {
      return { legend: { position: 'right', labels: { color: '#a8b3cf', padding: 8, font: { size: 11 }, boxWidth: 12, boxHeight: 12 } } };
    },
    axes() {
      return {
        y: { beginAtZero: true, grid: { color: '#2a3550', drawBorder: false }, ticks: { color: '#a8b3cf', font: { size: 10 } } },
        x: { grid: { display: false }, ticks: { color: '#a8b3cf', font: { size: 10 } } },
      };
    },
    draw(key, cid, cfg) {
      const cv = $(cid); if (!cv || typeof Chart === 'undefined') return;
      if (this.charts[key]) this.charts[key].destroy();
      this.charts[key] = new Chart(cv.getContext('2d'), cfg);
    },
    async charts_countries() {
      try {
        const d = await fetchJSON('/api/stats/countries');
        const c = (d.countries || []).slice(0, 6);
        this.draw('countries', 'chart-countries', {
          type: 'doughnut',
          data: { labels: c.map((x) => x.name || x.code), datasets: [{ data: c.map((x) => x.host_count), backgroundColor: CHART_COLORS, borderWidth: 0 }] },
          options: this.baseOpts({ cutout: '58%', plugins: this.legendRight() }),
        });
      } catch (e) { /* ignore */ }
    },
    async charts_services() {
      try {
        const d = await fetchJSON('/api/stats/services');
        const s = (d.services || []).slice(0, 8);
        this.draw('services', 'chart-services', {
          type: 'bar',
          data: { labels: s.map((x) => x.service), datasets: [{ data: s.map((x) => x.count), backgroundColor: '#4a9eff', borderRadius: 4 }] },
          options: this.baseOpts({ indexAxis: 'y', plugins: { legend: { display: false } }, scales: { x: { beginAtZero: true, grid: { color: '#2a3550', drawBorder: false }, ticks: { color: '#a8b3cf', font: { size: 10 } } }, y: { grid: { display: false }, ticks: { color: '#a8b3cf', font: { size: 11 } } } } }),
        });
      } catch (e) { /* ignore */ }
    },
    async charts_ports() {
      try {
        const d = await fetchJSON('/api/facets');
        const p = (d.ports || []).slice(0, 8);
        this.draw('ports', 'chart-ports', {
          type: 'bar',
          data: { labels: p.map((x) => x.value), datasets: [{ data: p.map((x) => x.count), backgroundColor: p.map((_, i) => CHART_COLORS[i % CHART_COLORS.length]), borderRadius: 4 }] },
          options: this.baseOpts({ plugins: { legend: { display: false } }, scales: this.axes() }),
        });
      } catch (e) { /* ignore */ }
    },
    async charts_tech() {
      try {
        const d = await fetchJSON('/api/stats/technologies');
        const t = (d.technologies || []).slice(0, 8);
        this.draw('tech', 'chart-tech', {
          type: 'doughnut',
          data: { labels: t.map((x) => x.technology), datasets: [{ data: t.map((x) => x.count), backgroundColor: CHART_COLORS, borderWidth: 0 }] },
          options: this.baseOpts({ cutout: '58%', plugins: this.legendRight() }),
        });
      } catch (e) { /* ignore */ }
    },
    async products() {
      try {
        const d = await fetchJSON('/api/stats/products');
        const p = (d.products || []).slice(0, 8);
        if (!p.length) { $('dash-products').innerHTML = '<div class="empty" style="padding:20px"><p>No products yet</p></div>'; return; }
        const max = Math.max.apply(null, p.map((x) => x.count));
        $('dash-products').innerHTML = p.map((x) => `
          <div class="rank-row">
            <span class="rank-name">${esc(x.product)}</span>
            <span class="rank-bar"><i style="width:${max ? Math.round(x.count / max * 100) : 0}%"></i></span>
            <span class="rank-val">${fmtNum(x.count)}</span>
          </div>`).join('');
      } catch (e) { /* ignore */ }
    },
    refresh() { this.load(); },
  };

  /* ------------------------------------------------------------- EXPLORE --- */
  Controllers.explore = {
    pane: 'hosts',
    init() {
      $$('#explore-seg .seg').forEach((b) => b.addEventListener('click', () => this.switch(b.dataset.pane)));
      Panes.hosts.init();
      Panes.services.init();
      Panes.certs.init();
      Panes.domains.init();
      Panes.hosts.load();
    },
    switch(p) {
      if (p === this.pane) return;
      this.pane = p;
      $$('#explore-seg .seg').forEach((b) => b.classList.toggle('active', b.dataset.pane === p));
      ['hosts', 'services', 'certs', 'domains'].forEach((n) => { $('pane-' + n).hidden = n !== p; });
      $('app-main').scrollTo(0, 0);
      Panes[p].ensure();
    },
    refresh() { Panes[this.pane].load(); },
  };

  const Panes = {};

  // ---- shared pager wiring
  function wirePager(prefix, ctrl) {
    $(prefix + '-prev').addEventListener('click', () => { if (ctrl.page > 1) { ctrl.page--; ctrl.load(); scrollTop(); } });
    $(prefix + '-next').addEventListener('click', () => { if (ctrl.page < ctrl.totalPages) { ctrl.page++; ctrl.load(); scrollTop(); } });
  }
  function scrollTop() { $('app-main').scrollTo({ top: 0, behavior: 'smooth' }); }
  function wireSearch(inputId, clearId, onChange) {
    const input = $(inputId), clear = $(clearId);
    let timer = null;
    input.addEventListener('input', () => {
      clear.hidden = !input.value;
      clearTimeout(timer);
      timer = setTimeout(() => onChange(input.value.trim()), 400);
    });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { clearTimeout(timer); onChange(input.value.trim()); input.blur(); }
    });
    clear.addEventListener('click', () => { input.value = ''; clear.hidden = true; onChange(''); });
  }

  /* ---- HOSTS pane ---- */
  Panes.hosts = {
    page: 1, totalPages: 1, total: 0, q: '', filters: {}, loaded: false, facetsLoaded: false,
    init() {
      wireSearch('hosts-search', 'hosts-clear', (v) => { this.q = v; this.page = 1; this.load(); this.chips(); });
      wirePager('hosts', this);
      $('hosts-filter-btn').addEventListener('click', () => { this.loadFacets(); openDrawer(); });
      $('hosts-export-btn').addEventListener('click', () => showExport('hosts', this.params()));
      $('hosts-chips-clear').addEventListener('click', () => this.clearFilters());
      $('flt-apply').addEventListener('click', () => this.applyFilters());
      $('flt-clear').addEventListener('click', () => this.clearFilters());
    },
    ensure() { if (!this.loaded) this.load(); },
    params() {
      const p = {};
      if (this.q) p.q = this.q;
      Object.entries(this.filters).forEach(([k, v]) => { if (v) p[k] = v; });
      return p;
    },
    applyFilters() {
      this.filters = {};
      const g = (id) => ($(id).value || '').trim();
      const country = g('flt-country'); if (country) this.filters.country = country.toUpperCase();
      const port = g('flt-port'); if (port) this.filters.port = port.split(',')[0].trim();
      const service = g('flt-service'); if (service) this.filters.service = service;
      const tech = g('flt-tech'); if (tech) this.filters.technology = tech;
      const cloud = g('flt-cloud'); if (cloud) this.filters.cloud = cloud;
      const asn = g('flt-asn'); if (asn) this.filters.asn = asn.replace(/^AS/i, '');
      if ($('flt-verified').checked) this.filters.verified = 'true';
      this.page = 1; this.load(); this.chips(); closeDrawer();
      $('hosts-filter-btn').classList.toggle('on', Object.keys(this.filters).length > 0);
    },
    clearFilters() {
      ['flt-country', 'flt-port', 'flt-service', 'flt-tech', 'flt-cloud', 'flt-asn'].forEach((id) => { if ($(id)) $(id).value = ''; });
      $('flt-verified').checked = false;
      this.filters = {}; this.page = 1; this.load(); this.chips();
      $('hosts-filter-btn').classList.remove('on');
    },
    chips() {
      const chips = [];
      const add = (k, v) => chips.push(`<span class="chip"><span class="k">${k}:</span> <span class="v">${esc(v)}</span></span>`);
      if (this.q) add('q', this.q);
      Object.entries(this.filters).forEach(([k, v]) => add(k, v));
      const row = $('hosts-chips');
      if (chips.length) { $('hosts-chips-scroll').innerHTML = chips.join(''); row.hidden = false; }
      else row.hidden = true;
    },
    async loadFacets() {
      if (this.facetsLoaded) return;
      try {
        const d = await fetchJSON('/api/facets');
        const sel = $('flt-country');
        (d.countries || []).forEach((c) => {
          const o = document.createElement('option');
          o.value = c.value; o.textContent = c.value.toUpperCase() + ' (' + fmtNum(c.count) + ')';
          sel.appendChild(o);
        });
        $('flt-port-facets').innerHTML = (d.ports || []).slice(0, 14).map((p) =>
          `<div class="facet-chip" data-port="${p.value}"><span class="facet-name">${p.value}</span><span class="facet-count">${fmtNum(p.count)}</span></div>`).join('');
        $$('#flt-port-facets .facet-chip').forEach((el) => el.addEventListener('click', () => { $('flt-port').value = el.dataset.port; this.applyFilters(); }));
        this.facetsLoaded = true;
      } catch (e) { /* ignore */ }
    },
    async load() {
      this.loaded = true;
      $('hosts-loading').hidden = false; $('hosts-empty').hidden = true;
      try {
        const p = new URLSearchParams(Object.assign({ page: this.page, limit: PAGE_SIZE }, this.params()));
        const d = await fetchJSON('/api/hosts?' + p.toString());
        this.total = d.total || 0;
        this.totalPages = Math.max(1, Math.ceil(this.total / PAGE_SIZE));
        $('hosts-count').textContent = fmtNum(this.total);
        this.render(d.hosts || []);
        this.pager();
      } catch (e) {
        $('hosts-list').innerHTML = '';
        $('hosts-empty').hidden = false;
        $('hosts-empty').querySelector('p').textContent = e.message || 'Error';
      } finally { $('hosts-loading').hidden = true; }
    },
    render(hosts) {
      if (!hosts.length) { $('hosts-list').innerHTML = ''; $('hosts-empty').hidden = false; $('hosts-pager').hidden = true; return; }
      $('hosts-empty').hidden = true;
      $('hosts-list').innerHTML = hosts.map((h) => {
        const cloud = h.cloud_provider ? `<span class="cloud-badge ${cloudClass(h.cloud_provider)}">${esc(h.cloud_provider)}</span>` : '';
        const org = h.as_org ? `<span class="card-sub">${h.asn ? 'AS' + h.asn + ' ' : ''}${esc(h.as_org)}</span>` : '';
        return `<div class="card-row" data-ip="${esc(h.ip)}">
          <div class="card-top"><span class="card-ip">${esc(h.ip)}</span><span class="card-loc">${flag(h.country_code)} ${esc(h.country_code || '')}</span></div>
          <div class="card-ports">${portTags(h.services)}</div>
          ${org}
          ${cloud ? `<div class="card-meta">${cloud}</div>` : ''}
        </div>`;
      }).join('');
      $$('#hosts-list .card-row').forEach((el) => el.addEventListener('click', () => openHostDetail(el.dataset.ip)));
    },
    pager() {
      $('hosts-pager').hidden = this.total <= PAGE_SIZE;
      $('hosts-prev').disabled = this.page <= 1;
      $('hosts-next').disabled = this.page >= this.totalPages;
      $('hosts-pageinfo').textContent = this.page + ' / ' + this.totalPages;
    },
  };

  /* ---- SERVICES pane ---- */
  Panes.services = {
    page: 1, q: '', filter: '', loaded: false, quickLoaded: false, hasNext: false,
    init() {
      wireSearch('services-search', 'services-clear', (v) => { this.q = v; this.page = 1; this.load(); });
      $('services-export-btn').addEventListener('click', () => showExport('services', this.params()));
      $('services-prev').addEventListener('click', () => { if (this.page > 1) { this.page--; this.load(); scrollTop(); } });
      $('services-next').addEventListener('click', () => { if (this.hasNext) { this.page++; this.load(); scrollTop(); } });
    },
    ensure() { if (!this.loaded) { this.loadQuick(); this.load(); } },
    params() {
      const p = {};
      if (this.q) p.q = this.q;
      if (this.filter) p.service = this.filter;
      return p;
    },
    async loadQuick() {
      if (this.quickLoaded) return;
      try {
        const d = await fetchJSON('/api/facets');
        const svc = (d.services || []).slice(0, 12);
        $('services-quick').innerHTML = svc.map((s) =>
          `<button class="qchip" data-svc="${esc(s.value)}">${esc(s.value)}<span class="cnt">${fmtNum(s.count)}</span></button>`).join('');
        $$('#services-quick .qchip').forEach((el) => el.addEventListener('click', () => {
          const v = el.dataset.svc;
          this.filter = (this.filter === v) ? '' : v;
          $$('#services-quick .qchip').forEach((c) => c.classList.toggle('active', c.dataset.svc === this.filter));
          this.page = 1; this.load();
        }));
        this.quickLoaded = true;
      } catch (e) { /* ignore */ }
    },
    async load() {
      this.loaded = true;
      $('services-loading').hidden = false; $('services-empty').hidden = true;
      try {
        const p = new URLSearchParams(Object.assign({ page: this.page, limit: PAGE_SIZE }, this.params()));
        const d = await fetchJSON('/api/services?' + p.toString());
        const list = d.services || [];
        this.hasNext = list.length >= PAGE_SIZE;
        this.render(list);
      } catch (e) {
        $('services-list').innerHTML = ''; $('services-empty').hidden = false;
        $('services-empty').querySelector('p').textContent = e.message || 'Error';
      } finally { $('services-loading').hidden = true; }
    },
    render(list) {
      if (!list.length) { $('services-list').innerHTML = ''; $('services-empty').hidden = false; $('services-pager').hidden = true; return; }
      $('services-empty').hidden = true;
      $('services-list').innerHTML = list.map((s) => {
        const product = [s.product, s.version].filter(Boolean).join(' ');
        const cloud = s.cloud_provider ? `<span class="cloud-badge ${cloudClass(s.cloud_provider)}">${esc(s.cloud_provider)}</span>` : '';
        const st = s.enrichment_status ? `<span class="tag muted">${esc(s.enrichment_status)}</span>` : '';
        return `<div class="card-row" data-ip="${esc(s.ip)}">
          <div class="card-top"><span class="card-ip">${esc(s.ip)}:${s.port}</span><span class="card-loc">${flag(s.country_code)} ${esc(s.country_code || '')}</span></div>
          <div class="card-meta"><span class="svc-name">${esc(s.service || 'open')}</span>${product ? `<span class="svc-product">${esc(product)}</span>` : ''}${cloud}${st}</div>
          ${s.banner ? `<div class="card-sub">${esc(s.banner.slice(0, 80))}</div>` : ''}
        </div>`;
      }).join('');
      $$('#services-list .card-row').forEach((el) => el.addEventListener('click', () => openHostDetail(el.dataset.ip)));
      $('services-pager').hidden = !(this.page > 1 || this.hasNext);
      $('services-prev').disabled = this.page <= 1;
      $('services-next').disabled = !this.hasNext;
      $('services-pageinfo').textContent = String(this.page);
    },
  };

  /* ---- CERTS pane ---- */
  Panes.certs = {
    page: 1, totalPages: 1, total: 0, q: '', loaded: false,
    init() {
      wireSearch('certs-search', 'certs-clear', (v) => { this.q = v; this.page = 1; this.load(); });
      $('certs-export-btn').addEventListener('click', () => showExport('certificates', this.q ? { q: this.q } : {}));
      wirePager('certs', this);
    },
    ensure() { if (!this.loaded) this.load(); },
    async load() {
      this.loaded = true;
      $('certs-loading').hidden = false; $('certs-empty').hidden = true;
      try {
        const p = new URLSearchParams({ page: this.page, limit: PAGE_SIZE });
        if (this.q) p.set('q', this.q);
        const d = await fetchJSON('/api/certificates?' + p.toString());
        this.total = d.total || 0;
        this.totalPages = d.total_pages || 1;
        $('certs-count').textContent = fmtNum(this.total);
        this.render(d.certificates || []);
      } catch (e) {
        $('certs-list').innerHTML = ''; $('certs-empty').hidden = false;
        $('certs-empty').querySelector('p').textContent = e.message || 'Error';
      } finally { $('certs-loading').hidden = true; }
    },
    render(certs) {
      if (!certs.length) { $('certs-list').innerHTML = ''; $('certs-empty').hidden = false; $('certs-pager').hidden = true; return; }
      $('certs-empty').hidden = true;
      const now = Date.now() / 1000;
      $('certs-list').innerHTML = certs.map((c) => {
        const cn = c.subject_cn || '(no CN)';
        const issuer = c.issuer_cn || c.issuer_org || '';
        const badges = [];
        if (c.not_after) {
          if (c.not_after < now) badges.push('<span class="tag err">expired</span>');
          else if (c.not_after < now + 30 * 86400) badges.push('<span class="tag warn">expiring</span>');
          else badges.push(`<span class="tag ok">valid</span>`);
        }
        if (c.is_self_signed) badges.push('<span class="tag muted">self-signed</span>');
        if (c.is_ca) badges.push('<span class="tag">CA</span>');
        const algo = [c.public_key_algorithm, c.public_key_bits ? c.public_key_bits + 'b' : ''].filter(Boolean).join(' ');
        return `<div class="card-row" data-fp="${esc(c.fingerprint_sha256 || '')}">
          <div class="card-top"><span class="card-ip">${esc(cn)}</span><span class="card-loc"><span class="pill">${fmtNum(c.host_count)} hosts</span></span></div>
          ${issuer ? `<div class="card-sub">issuer: ${esc(issuer)}</div>` : ''}
          <div class="card-meta">${badges.join('')}${algo ? `<span class="tag muted">${esc(algo)}</span>` : ''}${c.not_after ? `<span class="svc-product">exp ${fmtDate(c.not_after)}</span>` : ''}</div>
        </div>`;
      }).join('');
      $$('#certs-list .card-row').forEach((el) => el.addEventListener('click', () => openCertDetail(el.dataset.fp)));
      $('certs-pager').hidden = this.total <= PAGE_SIZE;
      $('certs-prev').disabled = this.page <= 1;
      $('certs-next').disabled = this.page >= this.totalPages;
      $('certs-pageinfo').textContent = this.page + ' / ' + this.totalPages;
    },
  };

  async function openCertDetail(fp) {
    if (!fp) return;
    detailLoading('Certificate');
    try {
      const [cert, hostsResp] = await Promise.all([
        fetchJSON('/api/certificates/' + encodeURIComponent(fp)),
        fetchJSON('/api/certificates/' + encodeURIComponent(fp) + '/hosts').catch(() => ({ hosts: [] })),
      ]);
      $('detail-title').textContent = cert.subject_cn || 'Certificate';
      let html = '';
      const rows = [];
      if (cert.subject_cn) rows.push(kvRow('Subject CN', cert.subject_cn));
      if (cert.subject_org) rows.push(kvRow('Subject Org', cert.subject_org));
      if (cert.issuer_cn) rows.push(kvRow('Issuer CN', cert.issuer_cn));
      if (cert.issuer_org) rows.push(kvRow('Issuer Org', cert.issuer_org));
      if (cert.not_before) rows.push(kvRow('Not before', fmtDate(cert.not_before)));
      if (cert.not_after) rows.push(kvRow('Not after', fmtDate(cert.not_after)));
      if (cert.public_key_algorithm) rows.push(kvRow('Key', [cert.public_key_algorithm, cert.public_key_bits ? cert.public_key_bits + 'b' : ''].filter(Boolean).join(' ')));
      if (cert.signature_algorithm) rows.push(kvRow('Sig algo', cert.signature_algorithm));
      if (cert.serial_number) rows.push(kvRow('Serial', cert.serial_number));
      rows.push(kvRow('Self-signed', cert.is_self_signed ? 'yes' : 'no'));
      rows.push(kvRow('CA', cert.is_ca ? 'yes' : 'no'));
      if (cert.fingerprint_sha256) rows.push(kvRow('SHA-256', cert.fingerprint_sha256));
      html += `<div class="d-section"><h4>Certificate</h4><div class="d-grid">${rows.join('')}</div></div>`;

      // SANs
      const names = (hostsResp.names || cert.names || '').split(/[,\s]+/).filter(Boolean);
      if (names.length) {
        html += `<div class="d-section"><h4>SANs <span class="pill">${names.length}</span></h4><div class="tags-wrap">`;
        html += names.slice(0, 40).map((n) => `<span class="tag">${esc(n)}</span>`).join('');
        if (names.length > 40) html += `<span class="tag muted">+${names.length - 40}</span>`;
        html += '</div></div>';
      }

      // Hosts using this cert
      const hosts = hostsResp.hosts || [];
      if (hosts.length) {
        html += `<div class="d-section"><h4>Hosts <span class="pill">${hostsResp.count || hosts.length}</span></h4>`;
        html += hosts.slice(0, 50).map((h) => `
          <div class="d-svc"><div class="d-svc-head" data-ip="${esc(h.ip)}">
            <span class="d-svc-title">${esc(h.ip)}:${h.port}</span>
            <span class="d-svc-info">${flag(h.country_code)} ${esc(h.as_org || h.country_code || '')}</span>
          </div></div>`).join('');
        html += '</div>';
      }
      $('detail-body').innerHTML = html;
      $$('#detail-body .d-svc-head[data-ip]').forEach((el) => el.addEventListener('click', () => openHostDetail(el.dataset.ip)));
    } catch (e) {
      $('detail-body').innerHTML = `<div class="empty"><p>${esc(e.message || 'Failed to load')}</p></div>`;
    }
  }

  /* ---- DOMAINS pane ---- */
  Panes.domains = {
    page: 1, totalPages: 1, total: 0, q: '', loaded: false, statsLoaded: false,
    init() {
      wireSearch('domains-search', 'domains-clear', (v) => { this.q = v; this.page = 1; this.load(); });
      $('domains-export-btn').addEventListener('click', () => showExport('domains', this.q ? { q: this.q } : {}));
      wirePager('domains', this);
    },
    ensure() { if (!this.loaded) { this.loadStats(); this.load(); } },
    async loadStats() {
      if (this.statsLoaded) return;
      try {
        const d = await fetchJSON('/api/domains/stats');
        $('domains-stats').innerHTML = [
          ['Domains', d.total_domains], ['HTTP', d.http_domains], ['Endpoints', d.total_endpoints], ['Unique IPs', d.unique_ips],
        ].map(([l, v]) => `<div class="ss"><div class="ss-v">${fmtNum(v)}</div><div class="ss-l">${l}</div></div>`).join('');
        this.statsLoaded = true;
      } catch (e) { /* ignore */ }
    },
    async load() {
      this.loaded = true;
      $('domains-loading').hidden = false; $('domains-empty').hidden = true;
      try {
        const p = new URLSearchParams({ page: this.page, limit: PAGE_SIZE });
        if (this.q) p.set('q', this.q);
        const d = await fetchJSON('/api/domains?' + p.toString());
        this.total = d.total || 0;
        this.totalPages = d.total_pages || 1;
        $('domains-count').textContent = fmtNum(this.total);
        this.render(d.domains || []);
      } catch (e) {
        $('domains-list').innerHTML = ''; $('domains-empty').hidden = false;
        $('domains-empty').querySelector('p').textContent = e.message || 'Error';
      } finally { $('domains-loading').hidden = true; }
    },
    render(list) {
      if (!list.length) { $('domains-list').innerHTML = ''; $('domains-empty').hidden = false; $('domains-pager').hidden = true; return; }
      $('domains-empty').hidden = true;
      $('domains-list').innerHTML = list.map((d) => {
        const protos = (d.protocols || '').split(',').filter(Boolean).slice(0, 4).map((p) => `<span class="tag muted">${esc(p)}</span>`).join('');
        const sample = d.sample_title || d.sample_server || '';
        return `<div class="card-row" data-domain="${esc(d.domain)}">
          <div class="card-top"><span class="card-ip">${esc(d.domain)}</span><span class="card-loc"><span class="pill">${fmtNum(d.services_count)} svc</span></span></div>
          ${sample ? `<div class="card-sub">${esc(sample)}</div>` : ''}
          <div class="card-meta">${protos}${d.ip_count ? `<span class="tag">${fmtNum(d.ip_count)} IPs</span>` : ''}${d.sample_status_code ? `<span class="tag muted">HTTP ${d.sample_status_code}</span>` : ''}</div>
        </div>`;
      }).join('');
      $$('#domains-list .card-row').forEach((el) => el.addEventListener('click', () => openDomainDetail(el.dataset.domain)));
      $('domains-pager').hidden = this.total <= PAGE_SIZE;
      $('domains-prev').disabled = this.page <= 1;
      $('domains-next').disabled = this.page >= this.totalPages;
      $('domains-pageinfo').textContent = this.page + ' / ' + this.totalPages;
    },
  };

  async function openDomainDetail(domain) {
    detailLoading(domain);
    try {
      const d = await fetchJSON('/api/domains/' + encodeURIComponent(domain) + '/services?limit=100');
      const svcs = d.services || [];
      let html = `<div class="d-section"><h4>Services <span class="pill">${d.total || svcs.length}</span></h4>`;
      if (!svcs.length) html += '<div class="empty"><p>No services</p></div>';
      else html += svcs.map((s) => {
        const rows = [];
        if (s.protocol) rows.push(kvRow('Protocol', s.protocol + (s.version ? ' ' + s.version : '')));
        if (s.status_code) rows.push(kvRow('Status', s.status_code));
        if (s.title) rows.push(kvRow('Title', s.title));
        if (s.server) rows.push(kvRow('Server', s.server));
        if (s.redirect_url) rows.push(kvRow('Redirect', s.redirect_url));
        if (s.as_org) rows.push(kvRow('Org', s.as_org));
        const canPreview = s.status_code && s.content_length;
        return `<div class="d-svc"><div class="d-svc-head open" data-ip="${esc(s.ip)}">
            <span class="d-svc-title">${esc(s.ip)}:${s.port}</span>
            <span class="d-svc-info">${flag(s.country_code)} ${esc(s.country_code || '')}</span>
          </div><div class="d-svc-body">
            ${rows.length ? `<div class="d-grid">${rows.join('')}</div>` : ''}
            ${canPreview ? `<button class="mini-btn" style="margin-top:8px" data-body="${esc(s.ip)}|${s.port}|${esc(domain)}">View body</button>` : ''}
          </div></div>`;
      }).join('');
      html += '</div>';
      $('detail-title').textContent = domain;
      $('detail-body').innerHTML = html;
      $$('#detail-body .d-svc-head[data-ip]').forEach((el) => el.addEventListener('click', (ev) => { if (ev.target.closest('.mini-btn')) return; openHostDetail(el.dataset.ip); }));
      $$('#detail-body .mini-btn[data-body]').forEach((el) => el.addEventListener('click', () => {
        const [ip, port, dom] = el.dataset.body.split('|');
        openBodyPreview(ip, port, dom);
      }));
    } catch (e) {
      $('detail-body').innerHTML = `<div class="empty"><p>${esc(e.message || 'Failed to load')}</p></div>`;
    }
  }

  async function openBodyPreview(ip, port, domain) {
    detailLoading(ip + ':' + port);
    try {
      const p = new URLSearchParams({ ip, port });
      if (domain) p.set('domain', domain);
      const r = await fetch('/api/body?' + p.toString());
      const html = await r.text();
      if (!r.ok) { showDetail(ip + ':' + port, `<div class="empty"><p>${esc(html || 'No body')}</p></div>`); return; }
      const frame = document.createElement('iframe');
      frame.className = 'body-frame';
      frame.setAttribute('sandbox', '');
      frame.srcdoc = html;
      $('detail-title').textContent = (domain || ip) + ':' + port;
      $('detail-body').innerHTML = '';
      $('detail-body').appendChild(frame);
    } catch (e) {
      showDetail(ip + ':' + port, `<div class="empty"><p>${esc(e.message || 'Error')}</p></div>`);
    }
  }

  /* --------------------------------------------------------------- QUERY --- */
  Controllers.query = {
    page: 1, totalPages: 1, total: 0, q: '', matched: [], lastMs: 0,
    history: [], fieldCache: null, fieldReady: false, valueCache: {}, ghost: '', acItems: [], acTimer: null,
    init() {
      this.loadHistory();
      this.prefetch();
      const input = $('query-input');
      input.addEventListener('keydown', (e) => this.onKey(e));
      input.addEventListener('input', () => this.onInput());
      input.addEventListener('focus', () => { if (!input.value.trim()) this.emptyAC(); });
      input.addEventListener('blur', () => setTimeout(() => { this.hideAC(); this.clearGhost(); }, 200));
      input.addEventListener('scroll', () => { $('query-ghost').scrollLeft = input.scrollLeft; });
      $('query-go').addEventListener('click', () => { this.hideAC(); this.clearGhost(); this.search(input.value.trim()); });
      $('query-help-btn').addEventListener('click', () => { this.renderHelp(); openSheet('help-sheet'); });
      $('help-close').addEventListener('click', () => closeSheet('help-sheet'));
      $$('.ex-chip').forEach((el) => el.addEventListener('click', () => { input.value = el.dataset.query; this.search(el.dataset.query); }));
      $('query-prev').addEventListener('click', () => { if (this.page > 1) { this.page--; this.fetch(); scrollTop(); } });
      $('query-next').addEventListener('click', () => { if (this.page < this.totalPages) { this.page++; this.fetch(); scrollTop(); } });
      this.checkURL();
    },
    async prefetch() {
      try { const d = await fetchJSON('/api/autocomplete?prefix='); if (d.suggestions) { this.fieldCache = d.suggestions; this.fieldReady = true; } } catch (e) { /* */ }
    },
    onInput() {
      const v = $('query-input').value;
      this.updateGhost(v);
      clearTimeout(this.acTimer);
      this.acTimer = setTimeout(() => { if (!v.trim()) { this.emptyAC(); return; } this.updateAC(v); }, 120);
    },
    onKey(e) {
      const dd = $('ac-dropdown'); const vis = dd.classList.contains('show'); const input = $('query-input');
      if (e.key === 'Enter') { e.preventDefault(); this.hideAC(); this.clearGhost(); this.search(input.value.trim()); input.blur(); return; }
      if (e.key === 'Tab') {
        if (this.ghost) { e.preventDefault(); this.acceptGhost(); return; }
        if (vis && this.acItems.length) { e.preventDefault(); this.selectAC(0); return; }
      }
      if (e.key === 'ArrowRight' && this.ghost && input.selectionStart === input.value.length) { e.preventDefault(); this.acceptGhost(); }
    },
    parseToken(val) {
      let start = 0, inQ = false;
      for (let i = 0; i < val.length; i++) { if (val[i] === '"') inQ = !inQ; if (val[i] === ' ' && !inQ) start = i + 1; }
      const token = val.substring(start);
      if (['and', 'or', 'not'].includes(token.toLowerCase())) return { mode: 'keyword', prefix: token, tokenStart: start };
      const op = token.match(/^-?([a-zA-Z_][a-zA-Z0-9_.]*)([:=!><*~]{1,2})(.*)/);
      if (op) return { mode: 'value', field: op[1], op: op[2], prefix: op[3].replace(/^"/, ''), tokenStart: start };
      const neg = token.startsWith('-');
      return { mode: 'field', prefix: token.replace(/^-/, ''), tokenStart: start + (neg ? 1 : 0) };
    },
    updateGhost(val) {
      if (!val || !this.fieldReady) { this.clearGhost(); return; }
      const p = this.parseToken(val); let comp = '';
      if (p.mode === 'field' && p.prefix.length >= 1) comp = this.fieldComp(p.prefix);
      else if (p.mode === 'value' && p.field && p.prefix === '') { const c = this.valueCache[p.field]; if (c && c.length) comp = c[0].value.includes(' ') ? `"${c[0].value}"` : c[0].value; }
      else if (p.mode === 'value' && p.field && p.prefix.length >= 1) { const c = this.valueCache[p.field]; if (c) { const pf = p.prefix.toLowerCase(); const m = c.find((v) => v.value.toLowerCase().startsWith(pf) && v.value.toLowerCase() !== pf); if (m) comp = m.value.substring(p.prefix.length); } }
      if (comp) { this.ghost = comp; $('query-ghost').innerHTML = `<span style="visibility:hidden">${esc(val)}</span><span class="ghost-completion">${esc(comp)}</span>`; }
      else this.clearGhost();
    },
    fieldComp(prefix) {
      if (!this.fieldCache) return '';
      const pf = prefix.toLowerCase();
      const exact = this.fieldCache.find((s) => s.field === prefix || s.field === pf);
      if (exact && exact.type === 'field') return ':';
      const m = this.fieldCache.filter((s) => s.field.toLowerCase().startsWith(pf) && s.field.toLowerCase() !== pf)
        .sort((a, b) => (a.type === 'field' ? -1 : 1) - (b.type === 'field' ? -1 : 1) || a.field.length - b.field.length);
      if (m.length) { const b = m[0]; return b.field.substring(prefix.length) + (b.type === 'field' ? ':' : ''); }
      return '';
    },
    clearGhost() { this.ghost = ''; $('query-ghost').innerHTML = ''; },
    acceptGhost() {
      const input = $('query-input'); if (!this.ghost) return;
      input.value += this.ghost; this.clearGhost(); input.focus();
      if (input.value.endsWith(':')) setTimeout(() => this.onInput(), 30); else this.onInput();
    },
    async updateAC(val) {
      const p = this.parseToken(val);
      if (p.mode === 'keyword') { this.hideAC(); return; }
      try {
        const url = (p.mode === 'value' && p.field)
          ? `/api/autocomplete?field=${encodeURIComponent(p.field)}&prefix=${encodeURIComponent(p.prefix)}`
          : `/api/autocomplete?prefix=${encodeURIComponent(p.prefix)}`;
        const d = await fetchJSON(url); const items = [];
        if (p.mode === 'field' && d.suggestions) {
          d.suggestions.filter((s) => s.type === 'field').forEach((s) => items.push({ type: 'field', label: s.field, detail: s.description, value: s.field + ':', tokenStart: p.tokenStart }));
          d.suggestions.filter((s) => s.type === 'prefix').forEach((s) => items.push({ type: 'prefix', label: s.field, detail: s.description, value: s.field, tokenStart: p.tokenStart }));
        } else if (p.mode === 'value' && d.values) {
          this.valueCache[p.field] = d.values;
          d.values.forEach((v) => items.push({ type: 'value', label: v.value, detail: fmtNum(v.count), value: p.field + ':' + (v.value.includes(' ') ? `"${v.value}"` : v.value), tokenStart: p.tokenStart }));
          this.updateGhost(val);
        }
        this.acItems = items;
        this.renderAC(items, p.mode === 'field' ? 'Fields' : 'Values for ' + p.field);
      } catch (e) { this.hideAC(); }
    },
    emptyAC() {
      const dd = $('ac-dropdown'); this.acItems = [];
      const hasHist = this.history.length > 0;
      if (hasHist) this.history.slice(0, 6).forEach((q) => this.acItems.push({ type: 'history', label: q, value: q, full: true, tokenStart: 0 }));
      const fields = ['port', 'service', 'ip', 'country', 'product', 'http.title', 'cloud', 'org', 'tls.cert.cn', 'banner', 'domain', 'protocol'];
      fields.forEach((f) => this.acItems.push({ type: 'field', label: f, value: f + ':', tokenStart: 0 }));
      let html = '';
      if (hasHist) {
        html += `<div class="ac-group-header"><span class="ac-group" style="padding:0">Recent</span><button class="ac-clear-btn" onmousedown="event.preventDefault();window.__meowClearHist()">Clear</button></div>`;
        this.acItems.filter((i) => i.type === 'history').forEach((it, i) => { html += `<div class="ac-item" onmousedown="window.__meowSelAC(${i})"><span class="ac-item-label">${esc(it.label)}</span></div>`; });
      }
      html += `<div class="ac-group">Fields</div><div class="ac-fields-grid">`;
      this.acItems.filter((i) => i.type === 'field').forEach((it) => { const idx = this.acItems.indexOf(it); html += `<div class="ac-field-chip" onmousedown="window.__meowSelAC(${idx})">${esc(it.label)}</div>`; });
      html += `</div>`;
      dd.innerHTML = html; dd.classList.add('show');
    },
    renderAC(items, label) {
      const dd = $('ac-dropdown'); if (!items.length) { this.hideAC(); return; }
      let html = `<div class="ac-group">${esc(label)}</div>`;
      items.forEach((it, i) => { html += `<div class="ac-item" onmousedown="window.__meowSelAC(${i})"><span class="ac-item-label">${esc(it.label)}</span>${it.detail ? `<span class="ac-item-detail">${esc(it.detail)}</span>` : ''}</div>`; });
      dd.innerHTML = html; dd.classList.add('show');
    },
    selectAC(i) {
      const it = this.acItems[i]; if (!it) return; const input = $('query-input');
      if (it.full) { input.value = it.value; this.clearGhost(); this.hideAC(); this.search(it.value); return; }
      input.value = input.value.substring(0, it.tokenStart) + it.value; this.clearGhost(); this.hideAC(); input.focus();
      if (it.type === 'field') setTimeout(() => this.onInput(), 30);
    },
    hideAC() { $('ac-dropdown').classList.remove('show'); },
    loadHistory() { try { this.history = JSON.parse(localStorage.getItem('meowql-history') || '[]'); } catch (e) { this.history = []; } },
    addHistory(q) { this.history = this.history.filter((x) => x !== q); this.history.unshift(q); if (this.history.length > 20) this.history = this.history.slice(0, 20); localStorage.setItem('meowql-history', JSON.stringify(this.history)); },
    clearHistory() { this.history = []; localStorage.removeItem('meowql-history'); this.emptyAC(); },
    async search(q) {
      if (!q) return;
      this.q = q; this.page = 1; this.addHistory(q); this.updateURL();
      $('query-error').hidden = true; this.hideAC(); this.clearGhost();
      await this.fetch();
    },
    async fetch() {
      const t0 = performance.now();
      $('query-welcome').style.display = 'none';
      try {
        const p = new URLSearchParams({ q: this.q, limit: PAGE_SIZE, page: this.page });
        const d = await fetchJSON('/api/search/services?' + p.toString());
        this.lastMs = Math.round(performance.now() - t0);
        this.total = d.total || 0; this.totalPages = Math.max(1, Math.ceil(this.total / PAGE_SIZE));
        this.matched = d.matched_fields || [];
        this.render(d.services || []);
        this.stats(); this.pager();
      } catch (e) {
        $('query-error').hidden = false; $('query-error-msg').textContent = e.message || 'Search failed';
        $('query-list').innerHTML = ''; $('query-stats').hidden = true; $('query-pager').hidden = true;
      }
    },
    render(list) {
      if (!list.length) { $('query-list').innerHTML = '<div class="empty"><p>No services found</p></div>'; return; }
      const matched = this.matched.length ? `<div class="matched-tags">${this.matched.map((f) => `<span class="matched-tag">${esc(f)}</span>`).join('')}</div>` : '';
      $('query-list').innerHTML = list.map((s) => {
        const product = [s.product, s.version].filter(Boolean).join('/');
        const cloud = s.cloud_provider ? `<span class="cloud-badge ${cloudClass(s.cloud_provider)}">${esc(s.cloud_provider)}</span>` : '';
        const http = [];
        if (s.http_title) http.push('"' + s.http_title + '"');
        if (s.http_server) http.push(s.http_server);
        const techs = parseJSON(s.http_technologies);
        let techHtml = '';
        if (Array.isArray(techs) && techs.length) { const names = techs.map((t) => (typeof t === 'string' ? t : t && t.name)).filter(Boolean); if (names.length) techHtml = `<div class="tech-row">${names.slice(0, 6).map((n) => `<span class="tag">${esc(n)}</span>`).join('')}</div>`; }
        return `<div class="card-row" data-ip="${esc(s.ip)}">
          <div class="card-top"><span class="card-ip">${esc(s.ip)}:${s.port}</span><span class="card-loc">${flag(s.country_code)} ${esc(s.country_code || '')}</span></div>
          <div class="card-meta"><span class="svc-name">${esc(s.service || 'open')}</span>${product ? `<span class="svc-product">${esc(product)}</span>` : ''}${cloud}</div>
          ${http.length ? `<div class="card-sub">${esc(http.join(' — '))}</div>` : ''}
          ${techHtml}${matched}
        </div>`;
      }).join('');
      $$('#query-list .card-row').forEach((el) => el.addEventListener('click', () => openHostDetail(el.dataset.ip)));
    },
    stats() {
      $('query-stats').hidden = false;
      $('query-stats-text').innerHTML = `<strong>${fmtNum(this.total)}</strong> services · <code>${esc(this.q)}</code>`;
      $('query-stats-time').textContent = this.lastMs + 'ms';
    },
    pager() {
      $('query-pager').hidden = this.total <= PAGE_SIZE;
      $('query-prev').disabled = this.page <= 1;
      $('query-next').disabled = this.page >= this.totalPages;
      $('query-pageinfo').textContent = this.page + ' / ' + this.totalPages;
    },
    updateURL() {
      const u = new URL(location); u.hash = 'query';
      u.searchParams.set('q', this.q);
      history.replaceState({}, '', u);
    },
    checkURL() {
      const q = new URLSearchParams(location.search).get('q');
      if (q) { $('query-input').value = q; this.search(q); }
    },
    renderHelp() {
      const ops = [['field:value', 'contains (LIKE)'], ['field="exact"', 'exact match'], ['field!=value', 'not equal'], ['field>10 field<100', 'numeric compare'], ['field:*', 'field exists'], ['field:{a,b,c}', 'set / IN'], ['a and b · a b', 'AND (space = AND)'], ['a or b', 'OR'], ['not a · -field:v', 'negation'], ['(a or b) and c', 'grouping'], ['ip:10.0.0.0/24', 'CIDR']];
      const fields = [['port', 'service', 'product', 'version', 'banner'], ['ip', 'country', 'city', 'org', 'asn', 'cloud'], ['http.title', 'http.server', 'http.status', 'tech', 'framework'], ['tls.cert.cn', 'tls.cert.issuer', 'tls.jarm', 'domain', 'protocol']];
      $('help-body').innerHTML = `
        <div class="help-block"><h4>Operators</h4>${ops.map(([c, d]) => `<div class="help-row"><code>${esc(c)}</code><span>${esc(d)}</span></div>`).join('')}</div>
        <div class="help-block"><h4>Common fields</h4><div class="tags-wrap">${fields.flat().map((f) => `<span class="tag muted">${esc(f)}</span>`).join('')}</div></div>
        <div class="help-block"><h4>JSON fields</h4><div class="help-row"><code>enrichment.*</code><span>services.enrichment_data</span></div><div class="help-row"><code>fingerprint.*</code><span>services.fingerprint_data</span></div><div class="help-row"><code>http.headers.*</code><span>response headers</span></div></div>`;
    },
    refresh() { if (this.q) this.fetch(); },
  };
  window.__meowSelAC = (i) => Controllers.query.selectAC(i);
  window.__meowClearHist = () => Controllers.query.clearHistory();

  /* ---------------------------------------------------------------- SCAN --- */
  const PORT_PRESETS = {
    top20: '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
    top50: '21,22,23,25,26,53,80,81,110,111,113,135,139,143,179,199,443,445,465,514,515,548,554,587,646,993,995,1025,1026,1027,1433,1720,1723,2000,2001,3306,3389,5060,5666,5900,6001,8000,8008,8080,8443,8888,10000,32768,49152,49154',
    top100: '7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157',
  };
  Controllers.scan = {
    scanners: [], timerNodes: null, timerFeed: null,
    init() {
      $('scan-form').addEventListener('submit', (e) => { e.preventDefault(); this.submit(); });
      $$('.preset').forEach((b) => b.addEventListener('click', () => {
        const p = b.dataset.preset; const input = $('scan-ports');
        $$('.preset').forEach((x) => x.classList.remove('active'));
        if (p === 'clear') { input.value = ''; input.focus(); return; }
        if (PORT_PRESETS[p]) { input.value = PORT_PRESETS[p]; b.classList.add('active'); }
      }));
      $('scan-ports').addEventListener('input', () => $$('.preset').forEach((x) => x.classList.remove('active')));
      $('dns-go').addEventListener('click', () => this.dns());
      $('dns-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); this.dns(); } });
      this.loadScanners(); this.loadFeed();
      this.startPolling();
    },
    onShow() { this.loadScanners(); this.loadFeed(); this.startPolling(); },
    startPolling() {
      this.stopPolling();
      this.timerNodes = setInterval(() => { if (currentView === 'scan') this.loadScanners(); }, 5000);
      this.timerFeed = setInterval(() => { if (currentView === 'scan') this.loadFeed(); }, 3000);
    },
    stopPolling() { clearInterval(this.timerNodes); clearInterval(this.timerFeed); },
    async loadScanners() {
      try { const d = await fetchJSON('/api/scanners'); this.scanners = d.scanners || []; this.renderScanners(); } catch (e) { /* */ }
    },
    renderScanners() {
      const has = this.scanners.length > 0;
      $('scan-node-count').textContent = this.scanners.length + ' node' + (this.scanners.length !== 1 ? 's' : '');
      $('scan-empty').hidden = has;
      $('scanner-chips').hidden = !has;
      $('scan-form-card').classList.toggle('disabled', !has);
      $('scan-submit').disabled = !has;
      if (!has) { $('scanner-chips').innerHTML = ''; return; }
      $('scanner-chips').innerHTML = this.scanners.map((n) => {
        const cls = n.status === 'scanning' ? 'scanning' : 'idle';
        const id = n.node_id.length > 18 ? n.node_id.slice(0, 18) + '…' : n.node_id;
        return `<div class="scanner-chip"><span class="sc-dot ${cls}"></span><span class="sc-id">${esc(id)}</span><span class="sc-status ${cls}">${cls}</span><span class="sc-uptime">${fmtUptime(n.uptime_sec)}</span></div>`;
      }).join('');
    },
    async submit() {
      const target = $('scan-target').value.trim(), ports = $('scan-ports').value.trim(), rate = $('scan-rate').value.trim();
      if (!target) { toast('Target is required', 'error'); return; }
      if (!ports) { toast('Ports are required', 'error'); return; }
      const body = { target, ports }; if (rate && parseInt(rate, 10) > 0) body.rate_limit = parseInt(rate, 10);
      $('scan-submit').disabled = true;
      try {
        const d = await fetchJSON('/api/scan', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
        toast('Scan submitted: ' + (d.request_id || '').slice(0, 8) + '…', 'success');
        $('scan-target').value = '';
      } catch (e) { toast(e.message || 'Failed to submit', 'error'); }
      finally { $('scan-submit').disabled = this.scanners.length === 0; }
    },
    async loadFeed() {
      try { const d = await fetchJSON('/api/events/recent'); this.renderFeed(d.events || []); } catch (e) { /* */ }
    },
    renderFeed(events) {
      const list = $('feed-list');
      if (!events.length) { list.innerHTML = `<div class="feed-empty"><svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M2 12h4l3-9 6 18 3-9h4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span>No recent events</span></div>`; $('feed-count').textContent = ''; return; }
      $('feed-count').textContent = events.length + ' events';
      const now = Math.floor(Date.now() / 1000);
      list.innerHTML = events.map((e) => {
        const label = e.type === 'open' ? 'OPEN' : e.type === 'fingerprinted' ? 'FP' : 'ENR';
        return `<div class="feed-row"><span class="feed-type ${esc(e.type)}">${label}</span><span class="feed-target">${esc(e.ip)}:${e.port}</span><span class="feed-svc">${esc(e.service || e.product || '')}</span><span class="feed-ago">${timeAgo(now - e.at)}</span></div>`;
      }).join('');
    },
    async dns() {
      const q = $('dns-input').value.trim(); const box = $('dns-results');
      if (!q) return;
      box.innerHTML = '<div class="dns-msg">Resolving…</div>';
      try {
        const d = await fetchJSON('/api/tools/dns?q=' + encodeURIComponent(q));
        const rows = [];
        const row = (type, val, act, suffix) => `<div class="dns-row"><span class="dns-type">${type}</span><span class="dns-value${act ? ' act' : ''}" ${act ? `data-q="${esc(val)}"` : ''}>${esc(val)}</span>${suffix ? `<span class="dns-suffix">${esc(suffix)}</span>` : ''}</div>`;
        (d.a || []).forEach((ip) => rows.push(row('A', ip, true)));
        (d.aaaa || []).forEach((ip) => rows.push(row('AAAA', ip, true)));
        if (d.cname) rows.push(row('CNAME', d.cname, true));
        (d.ptr || []).forEach((n) => rows.push(row('PTR', n, true)));
        (d.mx || []).forEach((mx) => rows.push(row('MX', mx.host, true, 'pref ' + mx.pref)));
        (d.ns || []).forEach((n) => rows.push(row('NS', n, true)));
        (d.txt || []).forEach((t) => rows.push(row('TXT', t, false)));
        box.innerHTML = rows.length ? rows.join('') : '<div class="dns-msg">No records found</div>';
        $$('#dns-results .dns-value.act').forEach((el) => el.addEventListener('click', () => { $('dns-input').value = el.dataset.q; this.dns(); }));
      } catch (e) { box.innerHTML = `<div class="dns-msg err">${esc(e.message || 'Lookup failed')}</div>`; }
    },
    refresh() { this.loadScanners(); this.loadFeed(); },
  };

  /* -------------------------------------------------------------- STATUS --- */
  Controllers.status = {
    timer: null,
    init() { this.load(); this.timer = setInterval(() => { if (currentView === 'status') this.load(); }, 5000); },
    onShow() { this.load(); },
    async load() {
      try {
        const [dbg, sc] = await Promise.all([fetchJSON('/api/debug/stats'), fetchJSON('/api/scanners').catch(() => ({ scanners: [] }))]);
        this.render(dbg, sc.scanners || []);
      } catch (e) {
        $('status-body').innerHTML = `<div class="empty"><p>${esc(e.message || 'Failed to load')}</p></div>`;
      }
    },
    render(d, scanners) {
      const db = d.database || {}; const en = db.enrichment || {}; const nats = d.nats || null;
      const total = (en.enriched || 0) + (en.pending || 0) + (en.failed || 0) + (en.skipped || 0);
      const pct = (v) => (total ? (v / total * 100).toFixed(1) : 0) + '%';
      let html = '';

      // KPIs
      html += `<div class="status-grid">
        <div class="kpi"><div class="kpi-val">${fmtNum(db.hosts)}</div><div class="kpi-label">Hosts</div></div>
        <div class="kpi"><div class="kpi-val">${fmtNum(db.services)}</div><div class="kpi-label">Services</div></div>
        <div class="kpi"><div class="kpi-val">${fmtNum(db.certificates)}</div><div class="kpi-label">Certificates</div></div>
        <div class="kpi"><div class="kpi-val">${fmtNum(scanners.length)}</div><div class="kpi-label">Scanners</div></div>
      </div>`;

      // Enrichment
      html += `<div class="mini-card"><div class="mini-head"><h3>Enrichment</h3><span class="pill">${fmtNum(total)}</span></div>
        <div class="enrich-bar">
          <div class="enrich-seg enriched" style="width:${pct(en.enriched)}"></div>
          <div class="enrich-seg pending" style="width:${pct(en.pending)}"></div>
          <div class="enrich-seg failed" style="width:${pct(en.failed)}"></div>
          <div class="enrich-seg skipped" style="width:${pct(en.skipped)}"></div>
        </div>
        <div class="enrich-legend">
          <span class="legend-item"><span class="legend-dot enriched"></span>Enriched <b>${fmtNum(en.enriched)}</b></span>
          <span class="legend-item"><span class="legend-dot pending"></span>Pending <b>${fmtNum(en.pending)}</b></span>
          <span class="legend-item"><span class="legend-dot failed"></span>Failed <b>${fmtNum(en.failed)}</b></span>
          <span class="legend-item"><span class="legend-dot skipped"></span>Skipped <b>${fmtNum(en.skipped)}</b></span>
        </div></div>`;

      // NATS
      if (nats) {
        const on = nats.connected;
        html += `<div class="mini-card"><div class="mini-head"><h3>NATS</h3>
          <span class="conn-badge"><span class="conn-dot ${on ? 'on' : 'off'}"></span>${on ? 'connected' : 'offline'}</span></div>`;
        const line = (k, v) => `<div class="status-line"><span class="sl-k">${k}</span><span class="sl-v">${esc(v)}</span></div>`;
        html += line('URL', nats.url || '-');
        html += line('Status', nats.status || '-');
        html += line('Messages', fmtNum(nats.in_msgs) + ' in · ' + fmtNum(nats.out_msgs) + ' out');
        html += line('Data', fmtBytes(nats.in_bytes) + ' in · ' + fmtBytes(nats.out_bytes) + ' out');
        html += line('Reconnects', fmtNum(nats.reconnects));
        if (nats.total_connections != null) html += line('Connections', fmtNum(nats.total_connections));
        html += '</div>';

        const clients = nats.clients || [];
        if (clients.length) {
          html += `<div class="mini-card"><div class="mini-head"><h3>Clients</h3><span class="pill">${clients.length}</span></div>`;
          html += clients.map((c) => `<div class="status-line"><span class="sl-k">${esc(c.name || 'client')}</span><span class="sl-v">${esc(c.ip || '')}:${c.port || ''} · ${fmtNum(c.subscriptions)} subs</span></div>`).join('');
          html += '</div>';
        }
      }

      // Top services
      const top = db.top_services || [];
      if (top.length) {
        const max = Math.max.apply(null, top.map((t) => t.count));
        html += `<div class="mini-card"><div class="mini-head"><h3>Top Services</h3></div><div class="rank-list">`;
        html += top.slice(0, 10).map((t) => `<div class="rank-row"><span class="rank-name">${esc(t.type)}</span><span class="rank-bar"><i style="width:${max ? Math.round(t.count / max * 100) : 0}%"></i></span><span class="rank-val">${fmtNum(t.count)}</span></div>`).join('');
        html += '</div></div>';
      }

      $('status-body').innerHTML = html;
    },
    refresh() { this.load(); },
  };

  // ================================================================== BOOT
  function clock() {
    const now = new Date();
    $('last-update').textContent = now.toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', hour12: false });
  }

  function setupPullToRefresh() {
    const main = $('app-main'); const ind = $('pull-indicator');
    let startY = 0, pulling = false, armed = false;
    main.addEventListener('touchstart', (e) => { if (main.scrollTop <= 0) { startY = e.touches[0].clientY; pulling = true; armed = false; } }, { passive: true });
    main.addEventListener('touchmove', (e) => {
      if (!pulling) return;
      const diff = e.touches[0].clientY - startY;
      if (diff > 65 && main.scrollTop <= 0) { ind.classList.add('visible'); armed = true; }
      else if (diff < 20) { ind.classList.remove('visible'); armed = false; }
    }, { passive: true });
    main.addEventListener('touchend', () => {
      if (!pulling) return; pulling = false;
      if (armed) {
        const c = Controllers[currentView];
        if (c && c.refresh) c.refresh();
        clock();
        setTimeout(() => ind.classList.remove('visible'), 700);
      } else ind.classList.remove('visible');
    }, { passive: true });
  }

  function setupMenu() {
    $('menu-btn').addEventListener('click', () => { $('menu-about').textContent = 'Meow Datastore · mobile'; openSheet('menu-sheet'); });
    $('menu-refresh').addEventListener('click', () => { closeSheet('menu-sheet'); const c = Controllers[currentView]; if (c && c.refresh) c.refresh(); clock(); toast('Refreshed'); });
    $('menu-apikey').addEventListener('click', () => {
      closeSheet('menu-sheet');
      const cur = apiKey();
      const val = window.prompt('API key (leave empty to clear):', cur);
      if (val === null) return;
      if (val.trim()) { localStorage.setItem('meow_api_key', val.trim()); toast('API key saved', 'success'); }
      else { localStorage.removeItem('meow_api_key'); toast('API key cleared'); }
      const c = Controllers[currentView]; if (c && c.refresh) c.refresh();
    });
  }

  function setupOverlayDismiss() {
    // backdrops close their sheets
    Object.entries(SHEETS).forEach(([sheet, bd]) => { $(bd).addEventListener('click', () => closeSheet(sheet)); });
    $('detail-close').addEventListener('click', () => closeSheet('detail-sheet'));
    $('drawer-backdrop').addEventListener('click', closeDrawer);
    $('drawer-close').addEventListener('click', closeDrawer);
  }

  function boot() {
    window.addEventListener('hashchange', route);
    setupPullToRefresh();
    setupMenu();
    setupOverlayDismiss();
    clock();
    setInterval(clock, 60000);
    route();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
