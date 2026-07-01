// Certificates Page — server-side pagination.
// The list, counts and pagination come from /api/certificates (one page at a
// time, with the true total); the stat cards and issuer/algorithm facets come
// from /api/stats/certificates (whole-dataset aggregates). Nothing is capped
// client-side, so the header total and page count reflect the full database.
class CertificatesPage {
  constructor() {
    this.currentPage = 1;
    this.pageSize = 25;
    this.totalResults = 0;
    this.totalPages = 1;
    this.pageCertificates = [];       // certs currently rendered (for detail lookups)
    this.certCache = new Map();       // fingerprint -> decorated cert (page + fetched singles)
    // Filter state (source of truth; the DOM mirrors it for convenience).
    this.search = '';
    this.subject = '';
    this.issuer = '';
    this.status = '';
    this.algo = '';
    this.sortColumn = 'host_count';
    this.sortDirection = 'desc';
    this.searchTimeout = null;
    this.summaryTotal = 0;
    this.init();
  }

  init() {
    this.setupEventListeners();
    this.loadSummary();

    // Deep link: /certificates#<sha256> from a host page — search + open modal.
    const hash = window.location.hash.substring(1);
    if (hash) {
      const search = document.getElementById('main-search');
      if (search) search.value = hash;
      this.search = hash;
      this.loadCertificates().then(() => this.showCertificateDetails(hash));
    } else {
      this.loadCertificates();
    }
  }

  setupEventListeners() {
    const searchBtn = document.getElementById('search-btn');
    if (searchBtn) searchBtn.addEventListener('click', () => { this.search = this.val('main-search'); this.reload(); });

    const mainSearch = document.getElementById('main-search');
    if (mainSearch) {
      mainSearch.addEventListener('keypress', (e) => { if (e.key === 'Enter') { this.search = this.val('main-search'); this.reload(); } });
      mainSearch.addEventListener('input', () => this.debounced(() => { this.search = this.val('main-search'); this.reload(); }));
    }

    // Select filters trigger immediately.
    const statusEl = document.getElementById('status-filter');
    if (statusEl) statusEl.addEventListener('change', () => { this.status = statusEl.value; this.syncStatCards(); this.reload(); });
    const algoEl = document.getElementById('algo-filter');
    if (algoEl) algoEl.addEventListener('change', () => { this.algo = algoEl.value; this.reload(); });

    // Text filters debounce.
    ['subject-filter', 'issuer-filter'].forEach(id => {
      const el = document.getElementById(id);
      if (!el) return;
      const apply = () => { this.subject = this.val('subject-filter'); this.issuer = this.val('issuer-filter'); this.reload(); };
      el.addEventListener('change', apply);
      el.addEventListener('input', () => this.debounced(apply));
    });

    const clearBtn = document.getElementById('clear-filters');
    if (clearBtn) clearBtn.addEventListener('click', () => this.clearFilters());

    const exportJson = document.getElementById('export-json');
    if (exportJson) exportJson.addEventListener('click', () => this.exportCertificates('json'));
    const exportCsv = document.getElementById('export-csv');
    if (exportCsv) exportCsv.addEventListener('click', () => this.exportCertificates('csv'));

    // Sortable columns.
    document.querySelectorAll('.certificates-table th.sortable').forEach(th => {
      th.addEventListener('click', () => {
        const col = th.dataset.sort;
        if (this.sortColumn === col) {
          this.sortDirection = this.sortDirection === 'asc' ? 'desc' : 'asc';
        } else {
          this.sortColumn = col;
          this.sortDirection = col === 'not_after' ? 'asc' : 'desc';
        }
        this.reload();
      });
    });

    // Stat cards as quick status filters.
    document.querySelectorAll('.stat-card[data-filter]').forEach(card => {
      card.addEventListener('click', () => {
        const filter = card.dataset.filter;
        this.status = (this.status === filter) ? '' : filter;
        const statusFilter = document.getElementById('status-filter');
        if (statusFilter) statusFilter.value = this.status;
        this.syncStatCards();
        this.reload();
      });
    });

    document.addEventListener('keydown', (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
        e.preventDefault();
        document.getElementById('main-search')?.focus();
      }
      if (e.key === 'Escape') {
        this.closeCertModal();
        this.closeHostsModal();
      }
    });
  }

  val(id) { return (document.getElementById(id)?.value || '').trim(); }

  debounced(fn) {
    clearTimeout(this.searchTimeout);
    this.searchTimeout = setTimeout(fn, 400);
  }

  // reload resets to page 1 and refetches the current filter set.
  reload() {
    this.currentPage = 1;
    this.loadCertificates();
  }

  syncStatCards() {
    document.querySelectorAll('.stat-card[data-filter]').forEach(card => {
      card.classList.toggle('active-filter', card.dataset.filter === this.status && this.status !== '');
    });
  }

  clearFilters() {
    ['main-search', 'subject-filter', 'issuer-filter', 'status-filter', 'algo-filter'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.value = '';
    });
    this.search = this.subject = this.issuer = this.status = this.algo = '';
    document.querySelectorAll('.stat-card.active-filter').forEach(c => c.classList.remove('active-filter'));
    document.querySelectorAll('.facet-chip.active').forEach(c => c.classList.remove('active'));
    this.reload();
  }

  // decorate adds the computed fields the table/modal rely on.
  decorate(cert) {
    cert._sanNames = this.parseNames(cert.names);
    cert._sanCount = cert._sanNames.length;
    cert._status = this.computeStatus(cert);
    cert._algoLabel = this.formatAlgo(cert.public_key_algorithm, cert.public_key_bits);
    return cert;
  }

  async loadSummary() {
    try {
      const resp = await fetch('/api/stats/certificates');
      const s = await resp.json();
      this.summaryTotal = s.total || 0;
      this.animateNumber('valid-certs', s.valid || 0);
      this.animateNumber('expired-certs', s.expired || 0);
      this.animateNumber('selfsigned-certs', s.self_signed || 0);
      this.animateNumber('ca-certs', s.ca || 0);
      this.animateNumber('total-certs', s.total || 0);
      const topCount = document.getElementById('top-results-count');
      if (topCount) topCount.textContent = (s.total || 0).toLocaleString();
      this.renderIssuerFacets(s.top_issuers || []);
      this.renderAlgoFacets(s.top_algorithms || []);
    } catch (error) {
      console.error('Error loading certificate summary:', error);
    }
  }

  renderIssuerFacets(issuers) {
    const container = document.getElementById('facet-issuer-chips');
    if (!container) return;
    container.innerHTML = '';
    issuers.forEach(({ name, count }) => {
      const chip = this.facetChip(name, count, () => {
        const active = this.issuer === name;
        this.issuer = active ? '' : name;
        const el = document.getElementById('issuer-filter');
        if (el) el.value = this.issuer;
        container.querySelectorAll('.facet-chip.active').forEach(c => c.classList.remove('active'));
        if (!active) chip.classList.add('active');
        this.reload();
      });
      container.appendChild(chip);
    });
  }

  renderAlgoFacets(algos) {
    const container = document.getElementById('facet-algo-chips');
    if (!container) return;
    container.innerHTML = '';
    algos.forEach(({ name, algo, count }) => {
      const chip = this.facetChip(name, count, () => {
        const active = this.algo === algo;
        this.algo = active ? '' : algo;
        const el = document.getElementById('algo-filter');
        if (el) el.value = this.algo; // best-effort; state is authoritative
        container.querySelectorAll('.facet-chip.active').forEach(c => c.classList.remove('active'));
        if (!active) chip.classList.add('active');
        this.reload();
      });
      container.appendChild(chip);
    });
  }

  facetChip(label, count, onClick) {
    const chip = document.createElement('span');
    chip.className = 'facet-chip';
    chip.innerHTML = `${this.escapeHtml(this.truncate(String(label), 22))} <span class="facet-chip-count">${count}</span>`;
    chip.title = label;
    chip.addEventListener('click', onClick);
    return chip;
  }

  // buildParams assembles the shared filter/sort query string.
  buildParams(extra) {
    const params = new URLSearchParams({ sort: this.sortColumn, order: this.sortDirection, ...extra });
    if (this.search) params.set('q', this.search);
    if (this.subject) params.set('subject', this.subject);
    if (this.issuer) params.set('issuer', this.issuer);
    if (this.status) params.set('status', this.status);
    if (this.algo) params.set('algo', this.algo);
    return params;
  }

  async loadCertificates() {
    const params = this.buildParams({ page: this.currentPage, limit: this.pageSize });
    try {
      const response = await fetch(`/api/certificates?${params}`);
      const data = await response.json();
      this.pageCertificates = (data.certificates || []).map(cert => this.decorate(cert));
      this.pageCertificates.forEach(c => { if (c.fingerprint_sha256) this.certCache.set(c.fingerprint_sha256, c); });
      this.totalResults = data.total || 0;
      this.totalPages = data.total_pages || 1;
      this.currentPage = data.page || this.currentPage;
      this.renderCertificates(this.pageCertificates);
      this.updatePagination();
      this.updateSortHeaders();
      this.updateResultsCount();
    } catch (error) {
      console.error('Error loading certificates:', error);
      this.showError('Failed to load certificates');
    }
  }

  parseNames(namesJson) {
    if (!namesJson) return [];
    try {
      const parsed = JSON.parse(namesJson);
      return Array.isArray(parsed) ? parsed : [];
    } catch { return []; }
  }

  computeStatus(cert) {
    const now = Math.floor(Date.now() / 1000);
    if (cert.not_after && cert.not_after < now) return 'expired';
    if (cert.is_self_signed) return 'self-signed';
    if (cert.not_after) {
      const days = Math.floor((cert.not_after - now) / 86400);
      if (days <= 30) return 'expiring-soon';
    }
    return 'valid';
  }

  formatAlgo(algo, bits) {
    if (!algo) return '-';
    let label = algo;
    if (algo === 'RSA' || algo === 'rsa') label = 'RSA';
    else if (algo === 'ECDSA' || algo === 'ecdsa' || algo.includes('EC')) label = 'ECDSA';
    else if (algo === 'Ed25519' || algo === 'ed25519') label = 'Ed25519';
    if (bits) label += ` ${bits}`;
    return label;
  }

  updateSortHeaders() {
    document.querySelectorAll('.certificates-table th.sortable').forEach(th => {
      th.classList.remove('active', 'asc', 'desc');
      if (th.dataset.sort === this.sortColumn) {
        th.classList.add('active', this.sortDirection);
      }
    });
  }

  renderCertificates(certificates) {
    const tbody = document.getElementById('certificates-tbody');
    if (!tbody) return;
    tbody.innerHTML = '';

    if (certificates.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" class="loading-row">
        <div class="no-results">
          <div class="no-results-icon">
            <svg width="48" height="48" viewBox="0 0 24 24" fill="none" style="opacity:0.3">
              <path d="M12 2l8 5v9c0 3.866-3.582 7-8 7s-8-3.134-8-7V7l8-5z" stroke="currentColor" stroke-width="1.5"/>
              <path d="M12 11v4M12 8h.01" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            </svg>
          </div>
          <div class="no-results-text">No certificates found</div>
          <div class="no-results-subtext">Try adjusting your filters or search query</div>
        </div>
      </td></tr>`;
      return;
    }

    certificates.forEach(cert => {
      const fp = cert.fingerprint_sha256 || '';
      if (!fp) return;
      const row = document.createElement('tr');
      row.onclick = () => this.showCertificateDetails(fp);
      const now = Math.floor(Date.now() / 1000);
      const daysLeft = cert.not_after ? Math.floor((cert.not_after - now) / 86400) : null;
      const expiryDate = cert.not_after ? this.formatDate(cert.not_after) : '-';

      let expiryPct = 0, expiryClass = 'ok';
      if (cert.not_before && cert.not_after) {
        const total = cert.not_after - cert.not_before;
        const elapsed = now - cert.not_before;
        expiryPct = total > 0 ? Math.min(100, Math.max(0, (elapsed / total) * 100)) : 100;
      }
      if (daysLeft !== null) {
        if (daysLeft <= 0) expiryClass = 'danger';
        else if (daysLeft <= 30) expiryClass = 'warning';
      }

      const daysText = daysLeft === null ? '' :
        daysLeft < 0 ? `${Math.abs(daysLeft)}d ago` :
        daysLeft === 0 ? 'today' : `${daysLeft}d`;

      let badges = '';
      if (cert._status === 'expired') badges += '<span class="status-badge expired"><span class="status-dot"></span>expired</span>';
      else if (cert._status === 'self-signed') badges += '<span class="status-badge self-signed"><span class="status-dot"></span>self-signed</span>';
      else if (cert._status === 'expiring-soon') badges += '<span class="status-badge expiring-soon"><span class="status-dot"></span>expiring</span>';
      else badges += '<span class="status-badge valid"><span class="status-dot"></span>valid</span>';
      if (cert.is_ca) badges += '<span class="status-badge ca">CA</span>';

      row.innerHTML = `
        <td>
          <div class="cert-subject">
            <span class="cert-subject-cn" title="${this.escapeHtml(cert.subject_cn || 'Unknown')}">${this.escapeHtml(cert.subject_cn || 'Unknown')}</span>
            ${cert.subject_org ? `<span class="cert-subject-org" title="${this.escapeHtml(cert.subject_org)}">${this.escapeHtml(cert.subject_org)}</span>` : ''}
          </div>
        </td>
        <td><span class="cert-san-count" title="${cert._sanCount} Subject Alternative Names">${cert._sanCount}</span></td>
        <td>
          <span class="cert-issuer" title="${this.escapeHtml(cert.issuer_cn || 'Unknown')}">
            <span class="cert-issuer-link" onclick="event.stopPropagation(); certificatesPage.pivotSearch('issuer', '${this.escapeHtml(cert.issuer_cn || '')}')">${this.escapeHtml(cert.issuer_cn || 'Unknown')}</span>
          </span>
        </td>
        <td>
          <div class="cert-algo">
            <span class="cert-algo-name">${this.escapeHtml(cert.public_key_algorithm || '-')}</span>
            ${cert.public_key_bits ? `<span class="cert-algo-bits">${cert.public_key_bits} bits</span>` : ''}
          </div>
        </td>
        <td>
          <div class="cert-expiry">
            <span class="cert-expiry-date">${expiryDate}</span>
            <span class="cert-expiry-days ${expiryClass}">${daysText}</span>
            <div class="expiry-bar"><div class="expiry-bar-fill ${expiryClass}" style="width:${expiryPct}%"></div></div>
          </div>
        </td>
        <td><div class="status-badges">${badges}</div></td>
        <td><span class="host-count">${cert.host_count || 0}</span></td>`;
      tbody.appendChild(row);
    });
  }

  // Ensures a certificate is available client-side. Certs not on the current page
  // (e.g. a deep-linked fingerprint) are fetched individually and cached, so the
  // detail modal always resolves.
  async ensureCertificateLoaded(fingerprint) {
    let cert = this.certCache.get(fingerprint);
    if (cert) return cert;
    try {
      const resp = await fetch(`/api/certificates/${fingerprint}`);
      if (!resp.ok) return null;
      cert = await resp.json();
    } catch { return null; }
    if (!cert || !cert.fingerprint_sha256) return null;
    this.decorate(cert);
    cert._pemLoaded = true; // the detail endpoint already returns the PEM
    if (cert.host_count == null) cert.host_count = 0;
    this.certCache.set(fingerprint, cert);
    return cert;
  }

  async showCertificateDetails(fingerprint) {
    const cert = await this.ensureCertificateLoaded(fingerprint);
    if (!cert) return;

    // Load PEM on demand if not already cached
    if (!cert._pemLoaded) {
      try {
        const resp = await fetch(`/api/certificates/${fingerprint}`);
        if (resp.ok) {
          const detail = await resp.json();
          if (detail.pem) cert.pem = detail.pem;
          cert._pemLoaded = true;
        }
      } catch { /* PEM will just not be shown */ }
    }

    const modal = document.getElementById('cert-modal');
    const modalTitle = document.getElementById('cert-modal-title');
    const modalBadges = document.getElementById('cert-modal-badges');
    const modalBody = document.getElementById('cert-modal-body');

    modalTitle.textContent = cert.subject_cn || 'Unknown Certificate';

    let badgesHtml = '';
    if (cert._status === 'expired') badgesHtml += '<span class="status-badge expired"><span class="status-dot"></span>expired</span>';
    else if (cert._status === 'self-signed') badgesHtml += '<span class="status-badge self-signed"><span class="status-dot"></span>self-signed</span>';
    else if (cert._status === 'expiring-soon') badgesHtml += '<span class="status-badge expiring-soon"><span class="status-dot"></span>expiring soon</span>';
    else badgesHtml += '<span class="status-badge valid"><span class="status-dot"></span>valid</span>';
    if (cert.is_ca) badgesHtml += '<span class="status-badge ca">CA</span>';
    badgesHtml += `<span class="status-badge" style="background:var(--bg-tertiary);color:var(--text-secondary);border:1px solid var(--border-primary)">${cert._algoLabel}</span>`;
    modalBadges.innerHTML = badgesHtml;

    const now = Math.floor(Date.now() / 1000);
    const daysLeft = cert.not_after ? Math.floor((cert.not_after - now) / 86400) : null;

    let vPct = 0, vClass = 'ok';
    if (cert.not_before && cert.not_after) {
      const total = cert.not_after - cert.not_before;
      const elapsed = now - cert.not_before;
      vPct = total > 0 ? Math.min(100, Math.max(0, (elapsed / total) * 100)) : 100;
    }
    if (daysLeft !== null && daysLeft <= 0) vClass = 'danger';
    else if (daysLeft !== null && daysLeft <= 30) vClass = 'warning';

    const daysLabel = daysLeft === null ? 'Unknown' :
      daysLeft < 0 ? `Expired ${Math.abs(daysLeft)} days ago` :
      daysLeft === 0 ? 'Expires today' :
      daysLeft <= 30 ? `${daysLeft} days remaining` : `${daysLeft} days remaining`;

    const sanTags = cert._sanNames.map(name => {
      const isWild = name.startsWith('*.');
      return `<span class="san-tag ${isWild ? 'wildcard' : ''}" onclick="event.stopPropagation(); certificatesPage.pivotSearch('search', '${this.escapeHtml(name)}')" title="Search for ${this.escapeHtml(name)}">${this.escapeHtml(name)}</span>`;
    }).join('');

    let html = '';

    html += this.buildSection('identity', 'Identity', `
      <svg viewBox="0 0 24 24" fill="none"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" stroke="currentColor" stroke-width="2"/><circle cx="12" cy="7" r="4" stroke="currentColor" stroke-width="2"/></svg>
    `, `<table class="detail-table">
      ${this.detailRow('Subject CN', cert.subject_cn, true, true)}
      ${cert.subject_org ? this.detailRow('Organization', cert.subject_org) : ''}
      ${cert.subject_country ? this.detailRow('Country', cert.subject_country) : ''}
      ${this.detailRow('Issuer CN', cert.issuer_cn, true, false, 'issuer')}
      ${cert.issuer_org ? this.detailRow('Issuer Org', cert.issuer_org, false, false, 'issuer') : ''}
    </table>`);

    html += this.buildSection('validity', 'Validity', `
      <svg viewBox="0 0 24 24" fill="none"><circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/><path d="M12 6v6l4 2" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
    `, `<table class="detail-table">
      ${this.detailRow('Not Before', cert.not_before ? this.formatDateFull(cert.not_before) : 'Unknown')}
      ${this.detailRow('Not After', cert.not_after ? this.formatDateFull(cert.not_after) : 'Unknown')}
      <tr><td class="detail-key">Lifetime</td><td class="detail-value"><strong class="${vClass === 'danger' ? 'danger' : vClass === 'warning' ? 'warning' : ''}" style="color:var(--${vClass === 'ok' ? 'success' : vClass})">${daysLabel}</strong>
        <div class="validity-timeline">
          <div class="validity-bar"><div class="validity-bar-fill ${vClass}" style="width:${vPct}%"></div></div>
          <div class="validity-labels">
            <span>${cert.not_before ? this.formatDate(cert.not_before) : '?'}</span>
            <span>${cert.not_after ? this.formatDate(cert.not_after) : '?'}</span>
          </div>
        </div>
      </td></tr>
      ${cert.first_seen ? this.detailRow('First Seen', this.formatDateFull(cert.first_seen)) : ''}
      ${cert.last_seen ? this.detailRow('Last Seen', this.formatDateFull(cert.last_seen)) : ''}
    </table>`);

    html += this.buildSection('fingerprints', 'Fingerprints', `
      <svg viewBox="0 0 24 24" fill="none"><path d="M12 10V2M18.4 6.6L22 3M21.96 12.04H14M18.4 17.4L22 21M12 14V22M5.6 17.4L2 21M2.04 12.04H10M5.6 6.6L2 3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
    `, `<table class="detail-table">
      ${this.detailRow('SHA-256', cert.fingerprint_sha256, true)}
      ${cert.fingerprint_sha1 ? this.detailRow('SHA-1', cert.fingerprint_sha1, true) : ''}
      ${cert.fingerprint_md5 ? this.detailRow('MD5', cert.fingerprint_md5, true) : ''}
      ${cert.serial_number ? this.detailRow('Serial Number', cert.serial_number, true) : ''}
    </table>`);

    html += this.buildSection('crypto', 'Cryptography', `
      <svg viewBox="0 0 24 24" fill="none"><rect x="3" y="11" width="18" height="11" rx="2" stroke="currentColor" stroke-width="2"/><path d="M7 11V7a5 5 0 0110 0v4" stroke="currentColor" stroke-width="2"/></svg>
    `, `<table class="detail-table">
      ${this.detailRow('Public Key Algorithm', cert.public_key_algorithm || 'Unknown')}
      ${cert.public_key_bits ? this.detailRow('Key Size', cert.public_key_bits + ' bits') : ''}
      ${cert.signature_algorithm ? this.detailRow('Signature Algorithm', cert.signature_algorithm) : ''}
      ${this.detailRow('Self-Signed', cert.is_self_signed ? 'Yes' : 'No')}
      ${this.detailRow('CA Certificate', cert.is_ca ? 'Yes' : 'No')}
    </table>`);

    if (cert._sanNames.length > 0) {
      html += this.buildSection('sans', `Names (${cert._sanNames.length} SANs)`, `
        <svg viewBox="0 0 24 24" fill="none"><path d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zM4 12h16M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10A15.3 15.3 0 0112 2z" stroke="currentColor" stroke-width="2"/></svg>
      `, `<div class="san-tags">${sanTags}</div>`);
    }

    html += this.buildSection('hosts', `Hosts (${cert.host_count || 0})`, `
      <svg viewBox="0 0 24 24" fill="none"><rect x="2" y="2" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2"/><rect x="2" y="14" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2"/><circle cx="6" cy="6" r="1" fill="currentColor"/><circle cx="6" cy="18" r="1" fill="currentColor"/></svg>
    `, `<div id="detail-hosts-container" class="detail-hosts-list"><div style="padding:12px;color:var(--text-dim);text-align:center">Loading hosts...</div></div>`);

    if (cert.pem) {
      html += this.buildSection('pem', 'PEM Certificate', `
        <svg viewBox="0 0 24 24" fill="none"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" stroke="currentColor" stroke-width="2"/><polyline points="14,2 14,8 20,8" stroke="currentColor" stroke-width="2"/></svg>
      `, `<div class="pem-container">
        <div class="pem-actions">
          <button class="pem-btn" onclick="certificatesPage.copyToClipboard(\`${this.escapeBacktick(cert.pem)}\`, 'PEM copied')">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" stroke-width="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" stroke="currentColor" stroke-width="2"/></svg>
            Copy PEM
          </button>
          <button class="pem-btn" onclick="certificatesPage.downloadPEM('${this.escapeHtml(fingerprint)}', \`${this.escapeBacktick(cert.pem)}\`)">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4M7 10l5 5 5-5M12 15V3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
            Download .pem
          </button>
        </div>
        <textarea class="pem-textarea" readonly>${this.escapeHtml(cert.pem)}</textarea>
      </div>`);
    }

    modalBody.innerHTML = html;
    modal.style.display = 'flex';

    this.loadDetailHosts(fingerprint);

    modalBody.querySelectorAll('.cert-section-header').forEach(header => {
      header.addEventListener('click', () => {
        header.closest('.cert-section').classList.toggle('collapsed');
      });
    });
  }

  buildSection(id, title, iconSvg, content) {
    return `<div class="cert-section" id="section-${id}">
      <div class="cert-section-header">
        <span class="cert-section-icon">${iconSvg}</span>
        <span class="cert-section-title">${title}</span>
        <svg class="cert-section-chevron" viewBox="0 0 24 24" fill="none"><path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>
      </div>
      <div class="cert-section-body">${content}</div>
    </div>`;
  }

  detailRow(label, value, copyable = false, isMonospace = false, pivotType = null) {
    if (!value) return '';
    const mono = copyable || isMonospace ? ' mono' : '';
    let valueHtml;
    if (pivotType) {
      valueHtml = `<span class="pivot-link" onclick="event.stopPropagation(); certificatesPage.pivotSearch('${pivotType}', '${this.escapeHtml(value)}')">${this.escapeHtml(value)}</span>`;
    } else {
      valueHtml = this.escapeHtml(value.toString());
    }
    if (copyable) {
      return `<tr><td class="detail-key">${label}</td><td class="detail-value${mono}">
        <div class="detail-value-row">
          <span class="detail-value-text">${valueHtml}</span>
          <button class="copy-btn" onclick="event.stopPropagation(); certificatesPage.copyToClipboard('${this.escapeHtml(value)}', '${label} copied')" title="Copy ${label}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><rect x="9" y="9" width="13" height="13" rx="2" stroke="currentColor" stroke-width="2"/><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" stroke="currentColor" stroke-width="2"/></svg>
          </button>
        </div>
      </td></tr>`;
    }
    return `<tr><td class="detail-key">${label}</td><td class="detail-value${mono}">${valueHtml}</td></tr>`;
  }

  async loadDetailHosts(fingerprint) {
    const container = document.getElementById('detail-hosts-container');
    if (!container) return;
    try {
      const response = await fetch(`/api/certificates/${fingerprint}/hosts`);
      if (!response.ok) throw new Error('API error');
      const data = await response.json();
      if (!data.hosts || data.hosts.length === 0) {
        container.innerHTML = '<div style="padding:12px;color:var(--text-dim);text-align:center">No hosts found</div>';
        return;
      }
      container.innerHTML = data.hosts.map(host => `
        <div class="detail-host-item">
          <div class="detail-host-left">
            <a href="/hosts?search=${encodeURIComponent(host.ip)}" class="detail-host-ip" target="_blank" onclick="event.stopPropagation()">${host.ip}</a>
            <span class="detail-host-geo">${[host.country_code, host.city, host.as_org].filter(Boolean).join(' / ')}</span>
          </div>
          <span class="detail-host-port">:${host.port}</span>
        </div>
      `).join('');
    } catch {
      const cert = this.certCache.get(fingerprint);
      container.innerHTML = `<div style="padding:12px;color:var(--text-dim);text-align:center">${cert?.host_count || 0} hosts (details unavailable)</div>`;
    }
  }

  pivotSearch(type, value) {
    if (!value) return;
    if (type === 'issuer') {
      const el = document.getElementById('issuer-filter');
      if (el) el.value = value;
      this.issuer = value;
    } else if (type === 'search') {
      const el = document.getElementById('main-search');
      if (el) el.value = value;
      this.search = value;
    }
    this.closeCertModal();
    this.reload();
  }

  copyToClipboard(text, message) {
    const done = () => this.showToast(message || 'Copied!');
    const fallback = () => {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.position = 'fixed';
      ta.style.left = '-9999px';
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      done();
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done).catch(fallback);
    } else {
      fallback();
    }
  }

  downloadPEM(fingerprint, pem) {
    const blob = new Blob([pem], { type: 'application/x-pem-file' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `certificate_${fingerprint.substring(0, 16)}.pem`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  showToast(message) {
    const toast = document.getElementById('toast');
    const msg = document.getElementById('toast-message');
    if (!toast || !msg) return;
    msg.textContent = message;
    toast.style.display = 'flex';
    clearTimeout(this._toastTimeout);
    this._toastTimeout = setTimeout(() => { toast.style.display = 'none'; }, 2000);
  }

  closeCertModal() { document.getElementById('cert-modal').style.display = 'none'; }
  closeHostsModal() { const m = document.getElementById('hosts-modal'); if (m) m.style.display = 'none'; }

  // Export the full filtered result set (server-side), not just the current page.
  async exportCertificates(format) {
    let data = [];
    try {
      const params = this.buildParams({ page: 1, limit: 100000 });
      const resp = await fetch(`/api/certificates?${params}`);
      const json = await resp.json();
      data = (json.certificates || []).map(c => this.decorate(c));
    } catch {
      this.showToast('Export failed');
      return;
    }

    if (format === 'csv') {
      const headers = ['fingerprint_sha256','subject_cn','subject_org','issuer_cn','issuer_org','public_key_algorithm','public_key_bits','not_before','not_after','is_self_signed','is_ca','host_count','serial_number','names'];
      const rows = data.map(cert => headers.map(h => {
        let v = cert[h];
        if (h === 'not_before' || h === 'not_after') v = v ? new Date(v * 1000).toISOString() : '';
        if (typeof v === 'boolean') v = v ? '1' : '0';
        if (v === undefined || v === null) v = '';
        return `"${String(v).replace(/"/g, '""')}"`;
      }).join(','));
      const csv = [headers.join(','), ...rows].join('\n');
      this.downloadBlob(csv, `certificates_${this.dateStamp()}.csv`, 'text/csv');
    } else {
      const json = JSON.stringify(data.map(c => {
        const { _sanNames, _sanCount, _status, _algoLabel, _pemLoaded, ...rest } = c;
        return rest;
      }), null, 2);
      this.downloadBlob(json, `certificates_${this.dateStamp()}.json`, 'application/json');
    }
  }

  downloadBlob(content, filename, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  dateStamp() { return new Date().toISOString().split('T')[0]; }

  // Pagination
  updatePagination() {
    const totalPages = this.totalPages;
    const from = this.totalResults > 0 ? (this.currentPage - 1) * this.pageSize + 1 : 0;
    const to = Math.min(this.currentPage * this.pageSize, this.totalResults);
    this.setText('showing-from', from);
    this.setText('showing-to', to);
    this.setText('total-results', this.totalResults.toLocaleString());
    this.setText('current-page', this.currentPage);
    this.setText('total-pages', totalPages || 1);
    this.renderPaginationControls('pagination-top');
    this.renderPaginationControls('pagination-bottom');
  }

  setText(id, value) { const el = document.getElementById(id); if (el) el.textContent = value; }

  renderPaginationControls(containerId) {
    const container = document.getElementById(containerId);
    if (!container) return;
    const totalPages = this.totalPages;
    container.innerHTML = '';

    const prevBtn = document.createElement('button');
    prevBtn.className = 'pagination-btn';
    prevBtn.innerHTML = '&larr;';
    prevBtn.disabled = this.currentPage === 1;
    prevBtn.onclick = () => this.goToPage(this.currentPage - 1);
    container.appendChild(prevBtn);

    const maxBtns = 5;
    let startPage = Math.max(1, this.currentPage - Math.floor(maxBtns / 2));
    let endPage = Math.min(totalPages, startPage + maxBtns - 1);
    if (endPage - startPage < maxBtns - 1) startPage = Math.max(1, endPage - maxBtns + 1);

    if (startPage > 1) {
      this.addPageBtn(container, 1);
      if (startPage > 2) this.addDots(container);
    }
    for (let i = startPage; i <= endPage; i++) this.addPageBtn(container, i);
    if (endPage < totalPages) {
      if (endPage < totalPages - 1) this.addDots(container);
      this.addPageBtn(container, totalPages);
    }

    const nextBtn = document.createElement('button');
    nextBtn.className = 'pagination-btn';
    nextBtn.innerHTML = '&rarr;';
    nextBtn.disabled = this.currentPage >= totalPages || totalPages === 0;
    nextBtn.onclick = () => this.goToPage(this.currentPage + 1);
    container.appendChild(nextBtn);
  }

  addPageBtn(container, num) {
    const btn = document.createElement('button');
    btn.className = `pagination-btn ${num === this.currentPage ? 'active' : ''}`;
    btn.textContent = num;
    btn.onclick = () => this.goToPage(num);
    container.appendChild(btn);
  }

  addDots(container) {
    const s = document.createElement('span');
    s.textContent = '...';
    s.style.cssText = 'padding:0 6px;color:var(--text-muted)';
    container.appendChild(s);
  }

  goToPage(page) {
    if (page < 1 || page > this.totalPages || page === this.currentPage) return;
    this.currentPage = page;
    this.loadCertificates();
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }

  updateResultsCount() {
    const el = document.getElementById('results-count');
    if (el) el.textContent = this.totalResults.toLocaleString();
  }

  animateNumber(elementId, targetValue) {
    const el = document.getElementById(elementId);
    if (!el) return;
    const start = parseInt(el.textContent) || 0;
    const duration = 800;
    const t0 = performance.now();
    const tick = (now) => {
      const p = Math.min((now - t0) / duration, 1);
      const ease = 1 - Math.pow(1 - p, 3); // ease-out cubic
      el.textContent = Math.floor(start + (targetValue - start) * ease).toLocaleString();
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }

  showError(message) {
    const tbody = document.getElementById('certificates-tbody');
    if (tbody) tbody.innerHTML = `<tr><td colspan="7" class="loading-row">
      <div class="no-results">
        <div class="no-results-text">${message}</div>
      </div>
    </td></tr>`;
  }

  formatDate(ts) {
    if (!ts) return '-';
    return new Date(ts * 1000).toLocaleDateString('en-CA'); // YYYY-MM-DD
  }

  formatDateFull(ts) {
    if (!ts) return '-';
    return new Date(ts * 1000).toLocaleString('en-US', {
      year: 'numeric', month: 'short', day: 'numeric',
      hour: '2-digit', minute: '2-digit', timeZoneName: 'short'
    });
  }

  truncate(str, len) {
    return str.length > len ? str.substring(0, len) + '...' : str;
  }

  escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  escapeBacktick(str) {
    if (!str) return '';
    return String(str).replace(/\\/g, '\\\\').replace(/`/g, '\\`').replace(/\$/g, '\\$');
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  setTimeout(() => { window.certificatesPage = new CertificatesPage(); }, 100);
});
