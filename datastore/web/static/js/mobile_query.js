// Mobile Query Page
class MobileQuery {
  constructor() {
    this.currentPage = 1;
    this.pageSize = 25;
    this.totalResults = 0;
    this.currentQuery = '';
    this.matchedFields = [];
    this.lastSearchTime = 0;
    this.queryHistory = [];
    this.acItems = [];
    this.acSelectedIndex = -1;
    this.acTimer = null;

    // Ghost text / inline completion
    this.ghostText = '';
    this.fieldCache = null;
    this.fieldCacheReady = false;
    this.valueCache = {};

    this.init();
  }

  init() {
    this.loadHistory();
    this.prefetchFields();
    this.bindEvents();
    this.checkURL();
  }

  async prefetchFields() {
    try {
      const resp = await fetch('/api/autocomplete?prefix=');
      const data = await resp.json();
      if (data.suggestions) {
        this.fieldCache = data.suggestions;
        this.fieldCacheReady = true;
      }
    } catch (e) { /* silent */ }
  }

  bindEvents() {
    const input = document.getElementById('query-input');
    const goBtn = document.getElementById('query-go');

    // Search
    if (input) {
      input.addEventListener('keydown', (e) => this.onKeydown(e));
      input.addEventListener('input', () => this.onInputChange());
      input.addEventListener('focus', () => {
        if (!input.value.trim()) this.showEmptyStateAC();
      });
      input.addEventListener('blur', () => {
        setTimeout(() => { this.hideAC(); this.clearGhost(); }, 200);
      });
      input.addEventListener('scroll', () => {
        const ghost = document.getElementById('query-ghost');
        if (ghost) ghost.scrollLeft = input.scrollLeft;
      });
    }
    if (goBtn) goBtn.addEventListener('click', () => { this.hideAC(); this.clearGhost(); this.search(input?.value.trim() || ''); });

    // Example chips
    document.querySelectorAll('[data-query]').forEach(el => {
      el.addEventListener('click', () => {
        const q = el.dataset.query;
        if (q) { if (input) input.value = q; this.closeHelp(); this.search(q); }
      });
    });

    // Help
    document.getElementById('help-btn')?.addEventListener('click', () => this.openHelp());
    document.getElementById('help-backdrop')?.addEventListener('click', () => this.closeHelp());
    document.getElementById('help-close')?.addEventListener('click', () => this.closeHelp());

    // Help tabs
    document.querySelectorAll('.help-tab').forEach(tab => {
      tab.addEventListener('click', () => {
        document.querySelectorAll('.help-tab').forEach(t => t.classList.toggle('active', t === tab));
        document.querySelectorAll('.help-panel').forEach(p => p.classList.toggle('active', p.dataset.tab === tab.dataset.tab));
      });
    });

    // Pagination
    document.getElementById('prev-page')?.addEventListener('click', () => this.prevPage());
    document.getElementById('next-page')?.addEventListener('click', () => this.nextPage());

    // Detail sheet
    document.getElementById('detail-backdrop')?.addEventListener('click', () => this.closeDetail());
    document.getElementById('sheet-close')?.addEventListener('click', () => this.closeDetail());
  }

  // ===== Input handlers =====
  onInputChange() {
    const input = document.getElementById('query-input');
    if (!input) return;
    const value = input.value;

    this.updateGhostText(value);

    clearTimeout(this.acTimer);
    this.acTimer = setTimeout(() => {
      if (!value.trim()) { this.showEmptyStateAC(); return; }
      this.updateAC(value);
    }, 120);
  }

  onKeydown(e) {
    const dd = document.getElementById('ac-dropdown');
    const isVisible = dd && dd.classList.contains('show');
    const input = document.getElementById('query-input');

    if (e.key === 'Enter') {
      e.preventDefault();
      this.hideAC();
      this.clearGhost();
      this.search(input?.value.trim() || '');
      input?.blur();
      return;
    }

    if (e.key === 'Escape') {
      if (this.ghostText || isVisible) {
        e.preventDefault();
        this.clearGhost();
        this.hideAC();
        return;
      }
      if (input) { input.value = ''; input.blur(); }
      this.clearGhost();
      return;
    }

    // Tab: accept ghost text or dropdown selection
    if (e.key === 'Tab') {
      if (this.ghostText) {
        e.preventDefault();
        this.acceptGhostText();
        return;
      }
      if (isVisible && this.acItems.length > 0) {
        e.preventDefault();
        this.selectAC(0);
        return;
      }
      return;
    }

    // Right arrow: accept ghost at end of input
    if (e.key === 'ArrowRight' && this.ghostText) {
      if (input && input.selectionStart === input.value.length) {
        e.preventDefault();
        this.acceptGhostText();
        return;
      }
    }
  }

  // ===== Ghost Text =====
  updateGhostText(value) {
    if (!value || !this.fieldCacheReady) { this.clearGhost(); return; }

    const parsed = this.parseToken(value);
    let completion = '';

    if (parsed.mode === 'field' && parsed.prefix.length >= 1) {
      completion = this.findFieldCompletion(parsed.prefix);
    } else if (parsed.mode === 'value' && parsed.field && parsed.prefix === '') {
      const cached = this.valueCache[parsed.field];
      if (cached && cached.length > 0) {
        const topVal = cached[0].value;
        completion = topVal.includes(' ') ? `"${topVal}"` : topVal;
      }
    } else if (parsed.mode === 'value' && parsed.field && parsed.prefix.length >= 1) {
      const cached = this.valueCache[parsed.field];
      if (cached) {
        const pfx = parsed.prefix.toLowerCase();
        const match = cached.find(v => v.value.toLowerCase().startsWith(pfx) && v.value.toLowerCase() !== pfx);
        if (match) completion = match.value.substring(parsed.prefix.length);
      }
    }

    if (completion) {
      this.ghostText = completion;
      this.renderGhostText(value, completion);
    } else {
      this.clearGhost();
    }
  }

  findFieldCompletion(prefix) {
    if (!this.fieldCache) return '';
    const pfx = prefix.toLowerCase();

    const exact = this.fieldCache.find(s => s.field === prefix || s.field === pfx);
    if (exact && exact.type === 'field') return ':';

    const matches = this.fieldCache
      .filter(s => s.field.toLowerCase().startsWith(pfx) && s.field.toLowerCase() !== pfx)
      .sort((a, b) => {
        if (a.type === 'field' && b.type !== 'field') return -1;
        if (a.type !== 'field' && b.type === 'field') return 1;
        return a.field.length - b.field.length;
      });

    if (matches.length > 0) {
      const best = matches[0];
      const suffix = best.field.substring(prefix.length);
      return best.type === 'field' ? suffix + ':' : suffix;
    }
    return '';
  }

  renderGhostText(typed, completion) {
    const ghost = document.getElementById('query-ghost');
    const tabHint = document.getElementById('query-tab-hint');
    if (!ghost) return;
    ghost.innerHTML = `<span style="visibility:hidden">${this.esc(typed)}</span><span class="ghost-completion">${this.esc(completion)}</span>`;
    if (tabHint) tabHint.classList.add('show');
  }

  clearGhost() {
    this.ghostText = '';
    const ghost = document.getElementById('query-ghost');
    const tabHint = document.getElementById('query-tab-hint');
    if (ghost) ghost.innerHTML = '';
    if (tabHint) tabHint.classList.remove('show');
  }

  acceptGhostText() {
    const input = document.getElementById('query-input');
    if (!input || !this.ghostText) return;
    input.value += this.ghostText;
    this.clearGhost();
    input.focus();
    if (input.value.endsWith(':')) {
      setTimeout(() => this.onInputChange(), 30);
    } else {
      this.onInputChange();
    }
  }

  // ===== Search =====
  async search(query) {
    if (!query) return;
    this.currentQuery = query;
    this.currentPage = 1;
    this.addHistory(query);
    this.updateURL(query);
    this.hideError();
    this.hideAC();
    this.clearGhost();

    await this.fetchResults();
  }

  async fetchResults() {
    const startTime = performance.now();

    try {
      const params = new URLSearchParams({
        q: this.currentQuery,
        limit: this.pageSize,
        page: this.currentPage
      });

      const response = await fetch(`/api/search/services?${params}`);
      const data = await response.json();

      if (!response.ok) {
        this.showError(data.error || 'Search failed');
        return;
      }

      this.lastSearchTime = Math.round(performance.now() - startTime);
      this.totalResults = data.total || 0;
      this.matchedFields = data.matched_fields || [];

      this.renderResults(data.services || []);
      this.updateStats();
      this.updatePagination();
    } catch (e) {
      this.showError('Network error: ' + e.message);
    }
  }

  // ===== Render =====
  renderResults(services) {
    document.getElementById('query-empty').style.display = 'none';
    const results = document.getElementById('query-results');
    const list = document.getElementById('results-list');
    results.style.display = 'block';

    if (!services.length) {
      list.innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted)">No services found</div>';
      return;
    }

    list.innerHTML = services.map(svc => this.renderCard(svc)).join('');
  }

  renderCard(svc) {
    const ip = this.esc(svc.ip);
    const port = svc.port;
    const service = svc.service || 'open';
    const product = [svc.product, svc.version].filter(Boolean).join('/');

    const flag = svc.country_code
      ? `<img src="https://flagcdn.com/16x12/${svc.country_code.toLowerCase()}.png" alt="${svc.country_code}" onerror="this.style.display='none'" style="border-radius:2px;box-shadow:0 1px 2px rgba(0,0,0,0.2)">`
      : '';
    const cc = svc.country_code || '';

    const cloudCls = this.cloudClass(svc.cloud_provider);
    const cloud = svc.cloud_provider ? `<span class="cloud-badge ${cloudCls}">${this.esc(svc.cloud_provider)}</span>` : '';

    // HTTP info
    let httpHtml = '';
    const httpParts = [];
    if (svc.http_title) httpParts.push(`"${this.esc(svc.http_title)}"`);
    if (svc.http_server) httpParts.push(this.esc(svc.http_server));
    if (httpParts.length) httpHtml = `<div class="svc-http-info">${httpParts.join(' - ')}</div>`;

    // Techs
    let techHtml = '';
    if (svc.http_technologies) {
      try {
        const techs = JSON.parse(svc.http_technologies);
        if (Array.isArray(techs) && techs.length) {
          const names = techs.map(t => typeof t === 'string' ? t : t?.name).filter(Boolean);
          if (names.length) techHtml = `<div class="svc-techs">${names.slice(0, 6).map(t => `<span class="tech-tag">${this.esc(t)}</span>`).join('')}</div>`;
        }
      } catch (e) { /* ignore */ }
    }

    // Matched fields
    let matchedHtml = '';
    if (this.matchedFields.length) {
      matchedHtml = '<div class="matched-tags">' + this.matchedFields.map(f => `<span class="matched-tag">${this.esc(f)}</span>`).join('') + '</div>';
    }

    const bodyContent = httpHtml || techHtml || matchedHtml;

    return `
      <div class="svc-card" onclick="mobileQuery.openDetail('${ip}')">
        <div class="svc-header">
          <div class="svc-header-top">
            <span class="svc-endpoint">${ip}:${port}</span>
            <span class="svc-location">${flag} ${cc}</span>
          </div>
          <div class="svc-header-meta">
            <span class="svc-service-name">${this.esc(service)}</span>
            ${product ? `<span class="svc-product">${this.esc(product)}</span>` : ''}
            ${cloud}
          </div>
        </div>
        ${bodyContent ? `<div class="svc-body">${httpHtml}${techHtml}${matchedHtml}</div>` : ''}
      </div>
    `;
  }

  updateStats() {
    const stats = document.getElementById('query-stats');
    const text = document.getElementById('stats-text');
    const time = document.getElementById('stats-time');

    stats.style.display = 'flex';
    text.innerHTML = `<strong>${this.totalResults.toLocaleString()}</strong> services for <code>${this.esc(this.currentQuery)}</code>`;
    time.textContent = `${this.lastSearchTime}ms`;
  }

  // ===== Pagination =====
  updatePagination() {
    const tp = Math.max(1, Math.ceil(this.totalResults / this.pageSize));
    const el = document.getElementById('pagination');
    el.style.display = this.totalResults > this.pageSize ? 'flex' : 'none';
    document.getElementById('prev-page').disabled = this.currentPage <= 1;
    document.getElementById('next-page').disabled = this.currentPage >= tp;
    document.getElementById('page-info').textContent = `${this.currentPage} / ${tp}`;
  }

  prevPage() { if (this.currentPage > 1) { this.currentPage--; this.fetchResults(); this.updateURL(this.currentQuery); this.scrollTop(); } }
  nextPage() { const tp = Math.ceil(this.totalResults / this.pageSize); if (this.currentPage < tp) { this.currentPage++; this.fetchResults(); this.updateURL(this.currentQuery); this.scrollTop(); } }
  scrollTop() { document.getElementById('query-content')?.scrollTo(0, 0); }

  // ===== Error =====
  showError(msg) {
    const el = document.getElementById('query-error');
    const msgEl = document.getElementById('query-error-msg');
    el.classList.add('show');
    msgEl.textContent = msg;
    document.getElementById('query-results').style.display = 'none';
    document.getElementById('query-stats').style.display = 'none';
    document.getElementById('pagination').style.display = 'none';
  }

  hideError() { document.getElementById('query-error')?.classList.remove('show'); }

  // ===== Help =====
  openHelp() {
    document.getElementById('help-sheet')?.classList.add('show');
    document.getElementById('help-backdrop')?.classList.add('show');
  }

  closeHelp() {
    document.getElementById('help-sheet')?.classList.remove('show');
    document.getElementById('help-backdrop')?.classList.remove('show');
  }

  // ===== Autocomplete =====
  async updateAC(value) {
    if (!value.trim()) { this.showEmptyStateAC(); return; }

    const parsed = this.parseToken(value);
    if (parsed.mode === 'keyword') { this.hideAC(); return; }

    try {
      let url;
      if (parsed.mode === 'value' && parsed.field) {
        url = `/api/autocomplete?field=${encodeURIComponent(parsed.field)}&prefix=${encodeURIComponent(parsed.prefix)}`;
      } else {
        url = `/api/autocomplete?prefix=${encodeURIComponent(parsed.prefix)}`;
      }

      const resp = await fetch(url);
      const data = await resp.json();
      const items = [];

      if (parsed.mode === 'field' && data.suggestions) {
        data.suggestions.filter(s => s.type === 'field').sort((a, b) => {
          const pfx = (parsed.prefix || '').toLowerCase();
          const aS = a.field.toLowerCase().startsWith(pfx) ? 0 : 1;
          const bS = b.field.toLowerCase().startsWith(pfx) ? 0 : 1;
          if (aS !== bS) return aS - bS;
          return a.field.length - b.field.length || a.field.localeCompare(b.field);
        }).forEach(s => items.push({
          type: 'field', label: s.field, detail: s.description, value: s.field + ':', tokenStart: parsed.tokenStart
        }));
        data.suggestions.filter(s => s.type === 'prefix').forEach(s => items.push({
          type: 'prefix', label: s.field, detail: s.description, value: s.field, tokenStart: parsed.tokenStart
        }));
      } else if (parsed.mode === 'value' && data.values) {
        this.valueCache[parsed.field] = data.values;
        data.values.forEach(v => items.push({
          type: 'value', label: v.value, detail: `${v.count.toLocaleString()}`,
          value: parsed.field + ':' + (v.value.includes(' ') ? `"${v.value}"` : v.value), tokenStart: parsed.tokenStart
        }));
        this.updateGhostText(value);
      }

      this.acItems = items;
      this.renderAC(items, parsed.mode === 'field' ? 'Fields' : `Values for ${parsed.field}`);
    } catch (e) { this.hideAC(); }
  }

  parseToken(val) {
    let start = 0;
    let inQuote = false;
    for (let i = 0; i < val.length; i++) {
      if (val[i] === '"') inQuote = !inQuote;
      if (val[i] === ' ' && !inQuote) start = i + 1;
    }
    const token = val.substring(start);

    const lower = token.toLowerCase();
    if (['and', 'or', 'not', 'and ', 'or ', 'not '].includes(lower)) {
      return { mode: 'keyword', prefix: token, tokenStart: start };
    }

    const opMatch = token.match(/^-?([a-zA-Z_][a-zA-Z0-9_.]*)([:=!><*~]{1,2})(.*)/);
    if (opMatch) {
      return { mode: 'value', field: opMatch[1], op: opMatch[2], prefix: opMatch[3].replace(/^"/, ''), tokenStart: start };
    }

    const clean = token.replace(/^-/, '');
    const neg = token.startsWith('-');
    return { mode: 'field', prefix: clean, tokenStart: start + (neg ? 1 : 0), negated: neg };
  }

  // ===== Empty state dropdown (history + fields) =====
  showEmptyStateAC() {
    const dd = document.getElementById('ac-dropdown');
    if (!dd) return;

    const hasHistory = this.queryHistory.length > 0;
    this.acItems = [];

    if (hasHistory) {
      this.queryHistory.slice(0, 6).forEach(q => {
        this.acItems.push({ type: 'history', label: q, detail: '', value: q, tokenStart: 0, full: true });
      });
    }

    const popularFields = [
      { field: 'port', desc: 'Port number' },
      { field: 'service', desc: 'Service name' },
      { field: 'ip', desc: 'IP address / CIDR' },
      { field: 'country', desc: 'Country code' },
      { field: 'product', desc: 'Product name' },
      { field: 'http.title', desc: 'Page title' },
      { field: 'cloud', desc: 'Cloud provider' },
      { field: 'org', desc: 'AS organization' },
      { field: 'tls.cert.cn', desc: 'Certificate CN' },
      { field: 'banner', desc: 'Service banner' },
      { field: 'domain', desc: 'Associated domain' },
      { field: 'http.server', desc: 'HTTP Server header' },
    ];

    popularFields.forEach(f => {
      this.acItems.push({ type: 'field', label: f.field, detail: f.desc, value: f.field + ':', tokenStart: 0 });
    });

    this.renderEmptyStateAC(hasHistory);
  }

  renderEmptyStateAC(hasHistory) {
    const dd = document.getElementById('ac-dropdown');
    if (!dd) return;

    let html = '';

    if (hasHistory) {
      html += `<div class="ac-group-header">
        <span class="ac-group">Recent</span>
        <button class="ac-clear-btn" onmousedown="event.preventDefault(); mobileQuery.clearHistory()">Clear</button>
      </div>`;
      const historyItems = this.acItems.filter(i => i.type === 'history');
      historyItems.forEach((item, i) => {
        html += `<div class="ac-item" onmousedown="mobileQuery.selectAC(${i})">
          <span class="ac-item-label">${this.esc(item.label)}</span>
        </div>`;
      });
    }

    const fieldStartIdx = this.acItems.findIndex(i => i.type === 'field');
    if (fieldStartIdx >= 0) {
      html += `<div class="ac-group-header"><span class="ac-group">Fields</span></div>`;
      html += `<div class="ac-fields-grid">`;
      this.acItems.filter(i => i.type === 'field').forEach(item => {
        const idx = this.acItems.indexOf(item);
        html += `<div class="ac-field-chip" onmousedown="mobileQuery.selectAC(${idx})" title="${this.esc(item.detail)}">
          ${this.esc(item.label)}
        </div>`;
      });
      html += `</div>`;
    }

    if (!html) { this.hideAC(); return; }
    dd.innerHTML = html;
    dd.classList.add('show');
  }

  clearHistory() {
    this.queryHistory = [];
    localStorage.removeItem('meowql-history');
    this.showEmptyStateAC();
  }

  renderAC(items, label) {
    const dd = document.getElementById('ac-dropdown');
    if (!items.length) { this.hideAC(); return; }

    let html = `<div class="ac-group">${this.esc(label)}</div>`;
    items.forEach((item, i) => {
      const labelHtml = this.highlightACMatch(item);
      html += `<div class="ac-item" onmousedown="mobileQuery.selectAC(${i})">
        <span class="ac-item-label">${labelHtml}</span>
        ${item.detail ? `<span class="ac-item-detail">${this.esc(item.detail)}</span>` : ''}
      </div>`;
    });
    dd.innerHTML = html;
    dd.classList.add('show');
  }

  highlightACMatch(item) {
    if (item.type === 'history') return this.esc(item.label);
    const input = document.getElementById('query-input');
    if (!input) return this.esc(item.label);
    const parsed = this.parseToken(input.value);
    const prefix = parsed.prefix || '';
    if (prefix && item.label.toLowerCase().startsWith(prefix.toLowerCase())) {
      const matched = item.label.substring(0, prefix.length);
      const rest = item.label.substring(prefix.length);
      return `<span class="ac-match">${this.esc(matched)}</span>${this.esc(rest)}`;
    }
    return this.esc(item.label);
  }

  selectAC(index) {
    const item = this.acItems[index];
    if (!item) return;
    const input = document.getElementById('query-input');

    if (item.full) {
      input.value = item.value;
      this.clearGhost();
      this.hideAC();
      this.search(item.value);
      return;
    }

    input.value = input.value.substring(0, item.tokenStart) + item.value;
    this.clearGhost();
    this.hideAC();
    input.focus();

    if (item.type === 'field') {
      setTimeout(() => this.onInputChange(), 30);
    }
  }

  hideAC() { document.getElementById('ac-dropdown')?.classList.remove('show'); }

  // ===== History =====
  loadHistory() { try { this.queryHistory = JSON.parse(localStorage.getItem('meowql-history') || '[]'); } catch { this.queryHistory = []; } }
  addHistory(q) {
    this.queryHistory = this.queryHistory.filter(x => x !== q);
    this.queryHistory.unshift(q);
    if (this.queryHistory.length > 20) this.queryHistory = this.queryHistory.slice(0, 20);
    localStorage.setItem('meowql-history', JSON.stringify(this.queryHistory));
  }

  // ===== Host Detail Sheet =====
  async openDetail(ip) {
    document.getElementById('detail-ip').textContent = ip;
    document.getElementById('sheet-body').innerHTML = '<div style="display:flex;justify-content:center;padding:24px"><div class="pull-spinner"></div></div>';
    document.getElementById('detail-sheet')?.classList.add('show');
    document.getElementById('detail-backdrop')?.classList.add('show');

    try {
      const response = await fetch(`/api/hosts/${ip}`);
      const host = await response.json();
      this.renderDetail(host);
    } catch (e) {
      document.getElementById('sheet-body').innerHTML = '<div style="text-align:center;padding:40px;color:var(--text-muted)">Failed to load details</div>';
    }
  }

  closeDetail() {
    document.getElementById('detail-sheet')?.classList.remove('show');
    document.getElementById('detail-backdrop')?.classList.remove('show');
  }

  renderDetail(host) {
    const body = document.getElementById('sheet-body');
    let html = '';

    // Location
    html += '<div class="detail-section"><h4>Location</h4><div class="detail-grid">';
    if (host.country_code) html += `<span class="detail-label">Country</span><span class="detail-value">${this.esc(host.country_code)}${host.city ? ' / ' + this.esc(host.city) : ''}</span>`;
    if (host.asn) html += `<span class="detail-label">ASN</span><span class="detail-value">AS${host.asn}</span>`;
    if (host.as_org) html += `<span class="detail-label">Org</span><span class="detail-value">${this.esc(host.as_org)}</span>`;
    if (host.cloud_provider) html += `<span class="detail-label">Cloud</span><span class="detail-value">${this.esc(host.cloud_provider)}${host.cloud_region ? ' / ' + this.esc(host.cloud_region) : ''}</span>`;
    if (host.timezone) html += `<span class="detail-label">Timezone</span><span class="detail-value">${this.esc(host.timezone)}</span>`;
    html += '</div></div>';

    // Domains
    const domains = host.domains || [];
    if (domains.length > 0) {
      html += '<div class="detail-section"><h4>Domains</h4><div class="sheet-domains">';
      html += domains.slice(0, 10).map(d => `<span class="domain-tag">${this.esc(d.domain || d)}</span>`).join('');
      if (domains.length > 10) html += `<span class="domain-tag" style="color:var(--text-muted);background:var(--bg-tertiary);border-color:var(--border-primary)">+${domains.length - 10}</span>`;
      html += '</div></div>';
    }

    // Services
    const services = host.services || [];
    if (services.length > 0) {
      html += '<div class="detail-section"><h4>Services</h4>';
      html += services.map(s => {
        const title = s.port + (s.service && s.service !== 'open' ? '/' + s.service : '');
        const info = [s.product, s.version].filter(Boolean).join(' ');
        let bodyHtml = '';

        if (info) bodyHtml += `<div class="detail-grid"><span class="detail-label">Product</span><span class="detail-value">${this.esc(info)}</span></div>`;

        if (s.enrichment_data) {
          try {
            const ed = typeof s.enrichment_data === 'string' ? JSON.parse(s.enrichment_data) : s.enrichment_data;
            const entries = Object.entries(ed).filter(([k, v]) => v !== null && v !== '' && typeof v !== 'object').slice(0, 6);
            if (entries.length > 0) {
              bodyHtml += '<div class="detail-grid" style="margin-top:6px">';
              entries.forEach(([k, v]) => {
                bodyHtml += `<span class="detail-label">${this.esc(k)}</span><span class="detail-value">${this.esc(String(v))}</span>`;
              });
              bodyHtml += '</div>';
            }
          } catch (e) { /* ignore */ }
        }

        return `
          <div class="sheet-service">
            <div class="sheet-service-header">
              <span class="sheet-service-title">${this.esc(title)}</span>
              <span class="sheet-service-info">${this.esc(info)}</span>
            </div>
            ${bodyHtml ? `<div class="sheet-service-body">${bodyHtml}</div>` : ''}
          </div>
        `;
      }).join('');
      html += '</div>';
    }

    body.innerHTML = html;
  }

  // ===== URL =====
  updateURL(q) {
    const url = new URL(window.location);
    url.searchParams.set('q', q);
    if (this.currentPage > 1) {
      url.searchParams.set('page', this.currentPage);
    } else {
      url.searchParams.delete('page');
    }
    history.replaceState({}, '', url);
  }

  checkURL() {
    const params = new URLSearchParams(window.location.search);
    const q = params.get('q');
    const page = parseInt(params.get('page'), 10);
    if (q) {
      document.getElementById('query-input').value = q;
      this.currentQuery = q;
      if (page > 1) this.currentPage = page;
      this.addHistory(q);
      this.hideError();
      this.fetchResults();
    }
  }

  // ===== Utils =====
  esc(text) { if (!text) return ''; const d = document.createElement('div'); d.textContent = text; return d.innerHTML; }
  cloudClass(p) {
    if (!p) return 'other';
    const l = p.toLowerCase();
    if (l.includes('aws') || l.includes('amazon')) return 'aws';
    if (l.includes('gcp') || l.includes('google')) return 'gcp';
    if (l.includes('azure') || l.includes('microsoft')) return 'azure';
    return 'other';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.mobileQuery = new MobileQuery();
});

