// Mobile Hosts Page
class MobileHosts {
  constructor() {
    this.currentPage = 1;
    this.pageSize = 25;
    this.totalResults = 0;
    this.currentQuery = '';
    this.currentFilters = {};
    this.searchTimer = null;
    this.init();
  }

  init() {
    this.bindEvents();
    this.checkURLParams();
    this.loadFacets();
    this.loadHosts();
  }

  bindEvents() {
    // Search
    const input = document.getElementById('search-input');
    const clear = document.getElementById('search-clear');
    if (input) {
      input.addEventListener('input', () => {
        clear.style.display = input.value ? 'flex' : 'none';
        clearTimeout(this.searchTimer);
        this.searchTimer = setTimeout(() => {
          if (input.value.length >= 2 || input.value.length === 0) {
            this.currentQuery = input.value.trim();
            this.currentPage = 1;
            this.loadHosts();
          }
        }, 400);
      });
      input.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
          clearTimeout(this.searchTimer);
          this.currentQuery = input.value.trim();
          this.currentPage = 1;
          this.loadHosts();
          input.blur();
        }
      });
    }
    if (clear) clear.addEventListener('click', () => { input.value = ''; clear.style.display = 'none'; this.currentQuery = ''; this.currentPage = 1; this.loadHosts(); });

    // Filter drawer
    const toggleBtn = document.getElementById('filter-toggle-btn');
    const backdrop = document.getElementById('filter-backdrop');
    const closeBtn = document.getElementById('drawer-close');
    const applyBtn = document.getElementById('btn-apply');
    const clearBtn = document.getElementById('btn-clear');

    if (toggleBtn) toggleBtn.addEventListener('click', () => this.openDrawer());
    if (backdrop) backdrop.addEventListener('click', () => this.closeDrawer());
    if (closeBtn) closeBtn.addEventListener('click', () => this.closeDrawer());
    if (applyBtn) applyBtn.addEventListener('click', () => { this.applyFilters(); this.closeDrawer(); });
    if (clearBtn) clearBtn.addEventListener('click', () => this.clearFilters());

    // Clear chips
    document.getElementById('clear-chips')?.addEventListener('click', () => this.clearFilters());

    // Pagination
    document.getElementById('prev-page')?.addEventListener('click', () => this.prevPage());
    document.getElementById('next-page')?.addEventListener('click', () => this.nextPage());

    // Detail sheet
    document.getElementById('detail-backdrop')?.addEventListener('click', () => this.closeDetail());
    document.getElementById('sheet-close')?.addEventListener('click', () => this.closeDetail());
  }

  checkURLParams() {
    const params = new URLSearchParams(window.location.search);
    const q = params.get('search') || '';
    if (q) {
      const input = document.getElementById('search-input');
      if (input) input.value = q;
      this.currentQuery = q;
    }
  }

  // ===== Drawer =====
  openDrawer() {
    document.getElementById('filter-drawer')?.classList.add('show');
    document.getElementById('filter-backdrop')?.classList.add('show');
  }

  closeDrawer() {
    document.getElementById('filter-drawer')?.classList.remove('show');
    document.getElementById('filter-backdrop')?.classList.remove('show');
  }

  applyFilters() {
    this.currentFilters = {};
    const country = document.getElementById('filter-country')?.value;
    const port = document.getElementById('filter-port')?.value.trim();
    const tech = document.getElementById('filter-technology')?.value.trim();
    const verified = document.getElementById('filter-verified')?.checked;

    if (country) this.currentFilters.country = country.toUpperCase();
    if (port) this.currentFilters.port = port.split(',')[0].trim();
    if (tech) this.currentFilters.technology = tech;
    if (verified) this.currentFilters.verified = 'true';

    this.currentPage = 1;
    this.loadHosts();
    this.updateChips();
    this.updateFilterBtn();
  }

  clearFilters() {
    document.getElementById('filter-country').value = '';
    document.getElementById('filter-port').value = '';
    document.getElementById('filter-technology').value = '';
    document.getElementById('filter-verified').checked = false;
    this.currentFilters = {};
    this.currentPage = 1;
    this.loadHosts();
    this.updateChips();
    this.updateFilterBtn();
  }

  updateChips() {
    const container = document.getElementById('active-chips');
    const scroll = document.getElementById('chips-scroll');
    const chips = [];

    if (this.currentQuery) chips.push(`<span class="filter-chip"><span class="chip-label">Search:</span> <span class="chip-value">${this.esc(this.currentQuery)}</span></span>`);
    if (this.currentFilters.country) chips.push(`<span class="filter-chip"><span class="chip-label">Country:</span> <span class="chip-value">${this.esc(this.currentFilters.country)}</span></span>`);
    if (this.currentFilters.port) chips.push(`<span class="filter-chip"><span class="chip-label">Port:</span> <span class="chip-value">${this.currentFilters.port}</span></span>`);
    if (this.currentFilters.technology) chips.push(`<span class="filter-chip"><span class="chip-label">Tech:</span> <span class="chip-value">${this.esc(this.currentFilters.technology)}</span></span>`);
    if (this.currentFilters.verified) chips.push(`<span class="filter-chip"><span class="chip-value">Verified only</span></span>`);

    if (chips.length > 0) {
      scroll.innerHTML = chips.join('');
      container.style.display = 'flex';
    } else {
      container.style.display = 'none';
    }
  }

  updateFilterBtn() {
    const btn = document.getElementById('filter-toggle-btn');
    if (btn) btn.classList.toggle('has-filters', Object.keys(this.currentFilters).length > 0);
  }

  // ===== Data Loading =====
  async loadFacets() {
    try {
      const response = await fetch('/api/facets');
      const data = await response.json();

      // Country dropdown
      const select = document.getElementById('filter-country');
      (data.countries || []).forEach(c => {
        const opt = document.createElement('option');
        opt.value = c.value.toLowerCase();
        opt.textContent = `${c.value.toUpperCase()} (${c.count.toLocaleString()})`;
        select.appendChild(opt);
      });

      // Port facets
      const portContainer = document.getElementById('port-facets');
      if (portContainer) {
        portContainer.innerHTML = (data.ports || []).slice(0, 12).map(p =>
          `<div class="facet-chip" onclick="mobileHosts.addPortFilter('${p.value}')"><span class="facet-name">${p.value}</span><span class="facet-count">${p.count.toLocaleString()}</span></div>`
        ).join('');
      }
    } catch (e) {
      console.error('Error loading facets:', e);
    }
  }

  addPortFilter(port) {
    document.getElementById('filter-port').value = port;
    this.applyFilters();
    this.closeDrawer();
  }

  async loadHosts() {
    document.getElementById('list-loading').style.display = 'flex';
    document.getElementById('list-empty').style.display = 'none';

    try {
      const params = new URLSearchParams({ page: this.currentPage, limit: this.pageSize });
      if (this.currentQuery) params.set('q', this.currentQuery);
      Object.entries(this.currentFilters).forEach(([k, v]) => { if (v) params.set(k, v); });

      const response = await fetch(`/api/hosts?${params}`);
      const data = await response.json();

      this.totalResults = data.total || 0;
      document.getElementById('results-count').textContent = this.totalResults.toLocaleString();

      this.renderHosts(data.hosts || []);
      this.updatePagination();
    } catch (e) {
      console.error('Error loading hosts:', e);
    } finally {
      document.getElementById('list-loading').style.display = 'none';
    }
  }

  renderHosts(hosts) {
    const container = document.getElementById('hosts-list');

    if (hosts.length === 0) {
      container.innerHTML = '';
      document.getElementById('list-empty').style.display = 'flex';
      return;
    }

    container.innerHTML = hosts.map(h => {
      const ip = this.esc(h.ip);
      const flag = h.country_code ? `<img src="https://flagcdn.com/16x12/${h.country_code.toLowerCase()}.png" alt="${h.country_code}" onerror="this.style.display='none'" style="border-radius:2px;box-shadow:0 1px 2px rgba(0,0,0,0.2)">` : '';
      const country = h.country_code || '';

      // Ports - separate identified from ghost
      const services = h.services || [];
      const portTags = this.generatePortTags(services);

      // Hostname
      const hostname = h.hostnames?.length ? `<div class="host-card-hostname">${this.esc(h.hostnames[0])}</div>` : '';

      // Cloud + Org
      const cloud = h.cloud_provider ? `<span class="cloud-badge ${this.cloudClass(h.cloud_provider)}">${this.esc(h.cloud_provider)}</span>` : '';
      const org = h.as_org ? `<span class="host-card-org">${h.asn ? 'AS' + h.asn + ' ' : ''}${this.esc(h.as_org)}</span>` : '';
      const meta = (cloud || org) ? `<div class="host-card-meta">${cloud}${org}</div>` : '';

      return `
        <div class="host-card" onclick="mobileHosts.openDetail('${ip}')">
          <div class="host-card-top">
            <span class="host-card-ip">${ip}</span>
            <span class="host-card-location">${flag} ${country}</span>
          </div>
          <div class="host-card-ports">${portTags}</div>
          ${hostname}
          ${meta}
        </div>
      `;
    }).join('');
  }

  // ===== Pagination =====
  updatePagination() {
    const totalPages = Math.max(1, Math.ceil(this.totalResults / this.pageSize));
    const container = document.getElementById('pagination');
    const prev = document.getElementById('prev-page');
    const next = document.getElementById('next-page');
    const info = document.getElementById('page-info');

    container.style.display = this.totalResults > this.pageSize ? 'flex' : 'none';
    if (prev) prev.disabled = this.currentPage <= 1;
    if (next) next.disabled = this.currentPage >= totalPages;
    if (info) info.textContent = `${this.currentPage} / ${totalPages}`;
  }

  prevPage() { if (this.currentPage > 1) { this.currentPage--; this.loadHosts(); this.scrollTop(); } }
  nextPage() { const tp = Math.ceil(this.totalResults / this.pageSize); if (this.currentPage < tp) { this.currentPage++; this.loadHosts(); this.scrollTop(); } }
  scrollTop() { document.getElementById('hosts-content')?.scrollTo(0, 0); }

  // ===== Detail Sheet =====
  async openDetail(ip) {
    document.getElementById('detail-ip').textContent = ip;
    document.getElementById('sheet-body').innerHTML = '<div class="list-loading" style="display:flex"><div class="pull-spinner"></div></div>';
    document.getElementById('detail-sheet')?.classList.add('show');
    document.getElementById('detail-backdrop')?.classList.add('show');

    try {
      const response = await fetch(`/api/hosts/${ip}`);
      const host = await response.json();
      this.renderDetail(host);
    } catch (e) {
      document.getElementById('sheet-body').innerHTML = '<div class="list-empty" style="display:flex"><p>Failed to load details</p></div>';
    }
  }

  closeDetail() {
    document.getElementById('detail-sheet')?.classList.remove('show');
    document.getElementById('detail-backdrop')?.classList.remove('show');
  }

  renderDetail(host) {
    const body = document.getElementById('sheet-body');
    let html = '';

    // Location info
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

        // Enrichment data summary
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

  // ===== Port Tags =====
  isGhostService(s) {
    return !s.service && !s.fingerprint_data && !s.banner && !s.product;
  }

  generatePortTags(services) {
    const identified = [];
    const ghost = [];

    // Deduplicate by port, prefer identified over ghost
    const seen = new Map();
    for (const s of services) {
      if (!seen.has(s.port) || (!this.isGhostService(s) && this.isGhostService(seen.get(s.port)))) {
        seen.set(s.port, s);
      }
    }

    for (const s of [...seen.values()].sort((a, b) => a.port - b.port)) {
      if (this.isGhostService(s)) {
        ghost.push(s);
      } else {
        identified.push(s);
      }
    }

    const tags = [];

    // Identified: green tags with port number only
    const show = identified.slice(0, 4);
    for (const s of show) {
      tags.push(`<span class="port-tag identified">${s.port}</span>`);
    }
    if (identified.length > 4) {
      tags.push(`<span class="port-tag more">+${identified.length - 4}</span>`);
    }

    // Ghost: single dashed tag with count
    if (ghost.length > 0) {
      tags.push(`<span class="port-tag ghost">+${ghost.length}</span>`);
    }

    return tags.join('');
  }

  // ===== Utilities =====
  esc(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }

  cloudClass(provider) {
    if (!provider) return 'other';
    const p = provider.toLowerCase();
    if (p.includes('aws') || p.includes('amazon')) return 'aws';
    if (p.includes('gcp') || p.includes('google')) return 'gcp';
    if (p.includes('azure') || p.includes('microsoft')) return 'azure';
    return 'other';
  }
}

document.addEventListener('DOMContentLoaded', () => {
  window.mobileHosts = new MobileHosts();
});

