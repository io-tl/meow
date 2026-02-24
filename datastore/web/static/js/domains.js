// DomainsPage — Domain Intelligence UI
class DomainsPage {
    constructor() {
        this.currentPage = 1;
        this.limit = 50;
        this.searchQuery = '';
        this.protocolFilter = '';
        this.statusCodeFilter = '';
        this.expandedDomains = {};  // domain -> { page, total, totalPages }
        this.debounceTimer = null;

        this.init();
    }

    init() {
        document.getElementById('main-search').addEventListener('input', () => this.onSearchInput());
        document.getElementById('main-search').addEventListener('keydown', (e) => {
            if (e.key === 'Enter') this.loadDomains();
        });
        document.getElementById('search-btn').addEventListener('click', () => this.loadDomains());
        document.getElementById('protocol-filter').addEventListener('change', () => this.onFilterChange());
        document.getElementById('status-code-filter').addEventListener('change', () => this.onFilterChange());
        document.getElementById('clear-filters').addEventListener('click', () => this.clearFilters());

        const exportBtn = document.getElementById('export-json');
        if (exportBtn) exportBtn.addEventListener('click', () => this.exportJSON());

        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closePreviewModal();
        });

        const modal = document.getElementById('preview-modal');
        if (modal) {
            modal.addEventListener('click', (e) => {
                if (e.target === modal) this.closePreviewModal();
            });
        }

        this.loadStats();
        this.loadDomains();
        this.hideLoading();
    }

    onSearchInput() {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => {
            this.currentPage = 1;
            this.loadDomains();
        }, 300);
    }

    onFilterChange() {
        this.currentPage = 1;
        this.loadDomains();
    }

    clearFilters() {
        document.getElementById('main-search').value = '';
        document.getElementById('protocol-filter').value = '';
        document.getElementById('status-code-filter').value = '';
        this.searchQuery = '';
        this.protocolFilter = '';
        this.statusCodeFilter = '';
        this.currentPage = 1;
        this.loadDomains();
    }

    async loadStats() {
        try {
            const resp = await fetch('/api/domains/stats');
            const data = await resp.json();
            document.getElementById('stat-domains').textContent = this.formatNumber(data.total_domains);
            document.getElementById('stat-endpoints').textContent = this.formatNumber(data.total_endpoints);
            document.getElementById('stat-http-domains').textContent = this.formatNumber(data.http_domains);
            document.getElementById('stat-unique-ips').textContent = this.formatNumber(data.unique_ips);
        } catch (e) {
            console.error('Failed to load domain stats:', e);
        }
    }

    async loadDomains() {
        this.searchQuery = document.getElementById('main-search').value.trim();
        this.protocolFilter = document.getElementById('protocol-filter').value;
        this.statusCodeFilter = document.getElementById('status-code-filter').value;

        const params = new URLSearchParams({ page: this.currentPage, limit: this.limit });
        if (this.searchQuery) params.set('q', this.searchQuery);
        if (this.protocolFilter) params.set('protocol', this.protocolFilter);
        if (this.statusCodeFilter) params.set('status_code', this.statusCodeFilter);

        try {
            const resp = await fetch(`/api/domains?${params}`);
            const data = await resp.json();
            this.renderDomains(data.domains || []);
            this.updatePagination(data.total || 0, data.page || 1, data.total_pages || 1);
            document.getElementById('top-results-count').textContent = this.formatNumber(data.total || 0);
        } catch (e) {
            console.error('Failed to load domains:', e);
        }
    }

    renderDomains(domains) {
        const container = document.getElementById('domain-cards');
        const emptyState = document.getElementById('empty-state');

        if (!domains || domains.length === 0) {
            container.innerHTML = '';
            emptyState.style.display = 'flex';
            return;
        }
        emptyState.style.display = 'none';
        container.innerHTML = domains.map(d => this.renderDomainCard(d)).join('');

        // Re-expand previously expanded domains
        for (const domain of Object.keys(this.expandedDomains)) {
            const card = container.querySelector(`[data-domain="${CSS.escape(domain)}"]`);
            if (card) {
                card.classList.add('expanded');
                this.loadServices(domain, card, this.expandedDomains[domain].page || 1);
            }
        }
    }

    renderDomainCard(d) {
        const protocols = (d.protocols || '').split(',').filter(Boolean);
        const protoBadges = protocols.map(p =>
            `<span class="domain-card-badge badge-protocol">${this.esc(p)}</span>`
        ).join('');

        const statusCode = d.sample_status_code;
        const statusBadge = statusCode ?
            `<span class="domain-card-badge badge-status status-${this.statusClass(statusCode)}">${statusCode}</span>` : '';

        const server = d.sample_server ?
            `<span class="domain-card-server" title="${this.esc(d.sample_server)}">${this.esc(d.sample_server)}</span>` : '';

        const count = d.services_count || 0;
        const timeAgo = d.last_seen ? this.timeAgo(d.last_seen) : '';

        return `<div class="domain-card" data-domain="${this.esc(d.domain)}">
            <div class="domain-card-header" onclick="domainsPage.toggleDomain('${this.esc(d.domain)}', this.parentElement)">
                <svg class="domain-card-icon" width="18" height="18" viewBox="0 0 24 24" fill="none">
                    <circle cx="12" cy="12" r="10" stroke="currentColor" stroke-width="2"/>
                    <path d="M2 12h20M12 2a15.3 15.3 0 014 10 15.3 15.3 0 01-4 10 15.3 15.3 0 01-4-10A15.3 15.3 0 0112 2z" stroke="currentColor" stroke-width="2"/>
                </svg>
                <span class="domain-card-name">${this.esc(d.domain)}</span>
                <div class="domain-card-meta">
                    ${protoBadges}
                    ${statusBadge}
                    ${server}
                    <span class="domain-card-count">${count} endpoint${count !== 1 ? 's' : ''}</span>
                    ${timeAgo ? `<span class="domain-card-time">${timeAgo}</span>` : ''}
                </div>
                <svg class="domain-card-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none">
                    <path d="M6 9l6 6 6-6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </div>
            <div class="domain-card-body">
                <div class="domain-split-layout">
                    <div class="domain-services-panel">
                        <div class="domain-card-loading">Loading services...</div>
                    </div>
                    <div class="domain-preview-panel">
                        <div class="domain-preview-placeholder">
                            <svg width="40" height="40" viewBox="0 0 24 24" fill="none" opacity="0.3">
                                <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="1.5"/>
                                <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.5"/>
                            </svg>
                            <span>Select a service to preview</span>
                        </div>
                    </div>
                </div>
            </div>
        </div>`;
    }

    async toggleDomain(domain, card) {
        const isExpanded = card.classList.contains('expanded');
        if (isExpanded) {
            card.classList.remove('expanded');
            // Clean up iframe
            const iframe = card.querySelector('.domain-preview-iframe');
            if (iframe) { iframe.removeAttribute('srcdoc'); iframe.src = 'about:blank'; }
            delete this.expandedDomains[domain];
        } else {
            card.classList.add('expanded');
            this.expandedDomains[domain] = { page: 1 };
            this.loadServices(domain, card, 1);
        }
    }

    async loadServices(domain, card, page) {
        const panel = card.querySelector('.domain-services-panel');
        if (!panel) return;

        panel.innerHTML = '<div class="domain-card-loading">Loading services...</div>';

        const state = this.expandedDomains[domain] || {};
        const hideEmpty = state.hideEmpty || false;
        let url = `/api/domains/${encodeURIComponent(domain)}/services?page=${page}&limit=25`;
        if (hideEmpty) url += '&hide_empty=1';

        try {
            const resp = await fetch(url);
            const data = await resp.json();

            this.expandedDomains[domain] = {
                ...state,
                page: data.page || 1,
                total: data.total || 0,
                totalPages: data.total_pages || 1
            };

            panel.innerHTML = this.renderServicesPanel(domain, data);
        } catch (e) {
            panel.innerHTML = '<div class="domain-card-loading">Failed to load services</div>';
        }
    }

    renderServicesPanel(domain, data) {
        const services = data.services || [];
        const state = this.expandedDomains[domain] || {};
        const hideEmpty = state.hideEmpty || false;
        const total = data.total || 0;
        const page = data.page || 1;
        const totalPages = data.total_pages || 1;

        let html = '';

        // Single toolbar: info + toggle + pagination
        html += this.renderSubToolbar(domain, total, page, totalPages, hideEmpty);

        if (services.length === 0) {
            html += `<div class="domain-card-loading">${hideEmpty ? 'No services with body' : 'No services found'}</div>`;
            return html;
        }

        // Service rows
        html += services.map(svc => this.renderServiceRow(domain, svc)).join('');

        // Footer pagination (only if more than 1 page)
        if (totalPages > 1) {
            html += this.renderSubToolbar(domain, total, page, totalPages, hideEmpty, true);
        }

        return html;
    }

    renderSubToolbar(domain, total, page, totalPages, hideEmpty, isFooter) {
        const from = total === 0 ? 0 : (page - 1) * 25 + 1;
        const to = Math.min(page * 25, total);
        const info = totalPages > 1 ? `${from}-${to} of ${total}` : `${total} service${total !== 1 ? 's' : ''}`;

        let paginationHtml = '';
        if (totalPages > 1) {
            paginationHtml = `<div class="sub-pagination-controls">
                <button class="sub-page-btn" ${page <= 1 ? 'disabled' : ''}
                    onclick="event.stopPropagation(); domainsPage.subGoToPage('${this.esc(domain)}', ${page - 1})">&larr;</button>
                <span class="sub-page-current">${page} / ${totalPages}</span>
                <button class="sub-page-btn" ${page >= totalPages ? 'disabled' : ''}
                    onclick="event.stopPropagation(); domainsPage.subGoToPage('${this.esc(domain)}', ${page + 1})">&rarr;</button>
            </div>`;
        }

        const toggleHtml = isFooter ? '' : `<label class="svc-toggle" onclick="event.stopPropagation()">
                <input type="checkbox" ${hideEmpty ? 'checked' : ''}
                    onchange="domainsPage.toggleHideEmpty('${this.esc(domain)}', this.checked)">
                <span class="svc-toggle-slider"></span>
                <span class="svc-toggle-label">With body only</span>
            </label>`;

        return `<div class="sub-pagination">
            <span class="sub-pagination-info">${info}</span>
            ${toggleHtml}
            ${paginationHtml}
        </div>`;
    }

    toggleHideEmpty(domain, checked) {
        const state = this.expandedDomains[domain];
        if (!state) return;
        state.hideEmpty = checked;
        state.page = 1;
        const card = document.querySelector(`[data-domain="${CSS.escape(domain)}"]`);
        if (card) this.loadServices(domain, card, 1);
    }

    renderServiceRow(domain, svc) {
        const endpoint = `${svc.ip}:${svc.port}`;
        const proto = svc.protocol ? `<span class="svc-protocol">${this.esc(svc.protocol)}</span>` : '';
        const status = svc.status_code ?
            `<span class="svc-status s-${this.statusClass(svc.status_code)}">${svc.status_code}</span>` : '';
        const server = svc.server ? `<span class="svc-server" title="${this.esc(svc.server)}">${this.esc(svc.server)}</span>` : '';

        let titleOrRedirect = '';
        if (svc.redirect_url) {
            titleOrRedirect = `<span class="svc-redirect">&rarr; ${this.esc(svc.redirect_url)}</span>`;
        } else if (svc.title) {
            titleOrRedirect = `<span class="svc-title" title="${this.esc(svc.title)}">${this.esc(svc.title)}</span>`;
        } else {
            titleOrRedirect = '<span class="svc-title"></span>';
        }

        const geo = svc.country_code ? `<span class="svc-geo">${this.esc(svc.country_code)}${svc.as_org ? ' / ' + this.esc(svc.as_org) : ''}</span>` : '';

        // Body size
        const isHTTP = svc.protocol === 'http' || svc.protocol === 'https';
        const bodySize = svc.content_length != null ? svc.content_length : -1;
        let bodySizeLabel = '';
        if (isHTTP) {
            if (bodySize > 0) {
                bodySizeLabel = `<span class="svc-body-size">${this.formatBytes(bodySize)}</span>`;
            } else {
                bodySizeLabel = `<span class="svc-body-size empty">0 B</span>`;
            }
        }

        // Action buttons
        let actionBtns = '<span class="svc-actions">';

        // Preview button: only for HTTP with body > 0
        if (isHTTP && bodySize > 0) {
            actionBtns += `<button class="svc-action-btn" onclick="event.stopPropagation(); domainsPage.showInlinePreview('${this.esc(svc.ip)}', ${svc.port}, '${this.esc(domain)}', this)" title="Preview page">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="2"/>
                    <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/>
                </svg>
            </button>`;
        } else if (isHTTP) {
            actionBtns += `<button class="svc-action-btn disabled" disabled title="No body available">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" opacity="0.3">
                    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="1.5"/>
                    <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="1.5"/>
                </svg>
            </button>`;
        }

        // Source button: only for HTTP with body > 0
        if (isHTTP && bodySize > 0) {
            actionBtns += `<button class="svc-action-btn" onclick="event.stopPropagation(); domainsPage.showInlineSource('${this.esc(svc.ip)}', ${svc.port}, '${this.esc(domain)}', this)" title="View source">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                    <polyline points="16 18 22 12 16 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    <polyline points="8 6 2 12 8 18" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                </svg>
            </button>`;
        }

        // Host link
        actionBtns += `<a class="svc-action-btn" href="/hosts?search=${encodeURIComponent(svc.ip)}" title="View host ${this.esc(svc.ip)}" onclick="event.stopPropagation()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none">
                <rect x="2" y="2" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2"/>
                <rect x="2" y="14" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2"/>
                <circle cx="6" cy="6" r="1" fill="currentColor"/>
                <circle cx="6" cy="18" r="1" fill="currentColor"/>
            </svg>
        </a>`;

        actionBtns += '</span>';

        return `<div class="domain-service-row" data-ip="${this.esc(svc.ip)}" data-port="${svc.port}">
            <span class="svc-endpoint">${this.esc(endpoint)}</span>
            ${proto}
            ${status}
            ${server}
            ${titleOrRedirect}
            ${bodySizeLabel}
            ${geo}
            ${actionBtns}
        </div>`;
    }

    subGoToPage(domain, page) {
        const card = document.querySelector(`[data-domain="${CSS.escape(domain)}"]`);
        if (!card) return;
        this.expandedDomains[domain].page = page;
        this.loadServices(domain, card, page);
    }

    async showInlinePreview(ip, port, domain, btn) {
        // Find the card and its preview panel
        let card;
        if (btn) {
            card = btn.closest('.domain-card');
        } else {
            card = document.querySelector(`[data-domain="${CSS.escape(domain)}"]`);
        }
        if (!card) return;
        const previewPanel = card.querySelector('.domain-preview-panel');
        if (!previewPanel) return;

        // Highlight active row
        if (btn && btn.closest('.domain-service-row')) {
            card.querySelectorAll('.domain-service-row.active').forEach(r => r.classList.remove('active'));
            btn.closest('.domain-service-row').classList.add('active');
        }

        // Show loading state with header buttons
        previewPanel.innerHTML = `<div class="domain-preview-header">
                <span class="preview-header-domain">${this.esc(domain)}</span>
                <span class="preview-header-endpoint">${this.esc(ip)}:${port}</span>
                <span class="preview-header-actions">
                    <button class="preview-header-btn" onclick="domainsPage.showInlineSource('${this.esc(ip)}', ${port}, '${this.esc(domain)}', null)" title="View source">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
                            <polyline points="16 18 22 12 16 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            <polyline points="8 6 2 12 8 18" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </button>
                    <a class="preview-header-btn" href="/hosts?search=${encodeURIComponent(ip)}" title="View host ${this.esc(ip)}">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
                            <rect x="2" y="2" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2"/>
                            <rect x="2" y="14" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2"/>
                            <circle cx="6" cy="6" r="1" fill="currentColor"/>
                            <circle cx="6" cy="18" r="1" fill="currentColor"/>
                        </svg>
                    </a>
                    <button class="preview-header-btn" onclick="domainsPage.showPreview('${this.esc(ip)}', ${port}, '${this.esc(domain)}')" title="Fullscreen">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
                            <path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </button>
                </span>
            </div>
            <div class="domain-preview-loading">Loading preview...</div>`;

        try {
            const resp = await fetch(`/api/body?ip=${encodeURIComponent(ip)}&port=${port}&domain=${encodeURIComponent(domain)}`);
            if (!resp.ok) {
                previewPanel.querySelector('.domain-preview-loading').outerHTML =
                    '<div class="domain-preview-placeholder"><span>No preview available</span></div>';
                return;
            }
            const html = await resp.text();
            previewPanel.querySelector('.domain-preview-loading').outerHTML =
                `<iframe sandbox="" srcdoc="${this.escAttr(html)}" class="domain-preview-iframe"></iframe>`;
        } catch (e) {
            previewPanel.querySelector('.domain-preview-loading').outerHTML =
                '<div class="domain-preview-placeholder"><span>Failed to load preview</span></div>';
        }
    }

    async showInlineSource(ip, port, domain, btn) {
        // Find the card's preview panel
        let card;
        if (btn) {
            card = btn.closest('.domain-card');
        } else {
            // Called from header — find via domain
            card = document.querySelector(`[data-domain="${CSS.escape(domain)}"]`);
        }
        if (!card) return;
        const previewPanel = card.querySelector('.domain-preview-panel');
        if (!previewPanel) return;

        // Highlight active row if btn is in a service row
        if (btn && btn.closest('.domain-service-row')) {
            card.querySelectorAll('.domain-service-row.active').forEach(r => r.classList.remove('active'));
            btn.closest('.domain-service-row').classList.add('active');
        }

        previewPanel.innerHTML = `<div class="domain-preview-header">
                <span class="preview-header-domain">${this.esc(domain)}</span>
                <span class="preview-header-endpoint">${this.esc(ip)}:${port} &mdash; source</span>
                <span class="preview-header-actions">
                    <button class="preview-header-btn active" title="Source view (active)">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
                            <polyline points="16 18 22 12 16 6" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                            <polyline points="8 6 2 12 8 18" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                        </svg>
                    </button>
                    <button class="preview-header-btn" onclick="domainsPage.showInlinePreview('${this.esc(ip)}', ${port}, '${this.esc(domain)}', null)" title="Preview page">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
                            <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" stroke="currentColor" stroke-width="2"/>
                            <circle cx="12" cy="12" r="3" stroke="currentColor" stroke-width="2"/>
                        </svg>
                    </button>
                    <a class="preview-header-btn" href="/hosts?search=${encodeURIComponent(ip)}" title="View host ${this.esc(ip)}">
                        <svg width="13" height="13" viewBox="0 0 24 24" fill="none">
                            <rect x="2" y="2" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2"/>
                            <rect x="2" y="14" width="20" height="8" rx="2" stroke="currentColor" stroke-width="2"/>
                            <circle cx="6" cy="6" r="1" fill="currentColor"/>
                            <circle cx="6" cy="18" r="1" fill="currentColor"/>
                        </svg>
                    </a>
                </span>
            </div>
            <div class="domain-preview-loading">Loading source...</div>`;

        try {
            const resp = await fetch(`/api/body?ip=${encodeURIComponent(ip)}&port=${port}&domain=${encodeURIComponent(domain)}`);
            if (!resp.ok) {
                previewPanel.querySelector('.domain-preview-loading').outerHTML =
                    '<div class="domain-preview-placeholder"><span>No source available</span></div>';
                return;
            }
            const html = await resp.text();
            const pre = document.createElement('pre');
            pre.className = 'domain-source-view';
            pre.textContent = html;
            previewPanel.querySelector('.domain-preview-loading').replaceWith(pre);
        } catch (e) {
            previewPanel.querySelector('.domain-preview-loading').outerHTML =
                '<div class="domain-preview-placeholder"><span>Failed to load source</span></div>';
        }
    }

    async showPreview(ip, port, domain) {
        const modal = document.getElementById('preview-modal');
        const iframe = document.getElementById('preview-iframe');
        const title = document.getElementById('preview-modal-title');
        const subtitle = document.getElementById('preview-modal-subtitle');

        title.textContent = domain;
        subtitle.textContent = `${ip}:${port}`;
        iframe.removeAttribute('srcdoc');
        modal.style.display = 'flex';

        try {
            const resp = await fetch(`/api/body?ip=${encodeURIComponent(ip)}&port=${port}&domain=${encodeURIComponent(domain)}`);
            if (!resp.ok) {
                iframe.srcdoc = '<html><body style="display:flex;align-items:center;justify-content:center;height:100%;margin:0;font-family:sans-serif;color:#666;"><p>No preview available</p></body></html>';
                return;
            }
            const html = await resp.text();
            iframe.srcdoc = html;
        } catch (e) {
            iframe.srcdoc = '<html><body style="display:flex;align-items:center;justify-content:center;height:100%;margin:0;font-family:sans-serif;color:#666;"><p>Failed to load preview</p></body></html>';
        }
    }

    closePreviewModal() {
        const modal = document.getElementById('preview-modal');
        const iframe = document.getElementById('preview-iframe');
        modal.style.display = 'none';
        iframe.removeAttribute('srcdoc');
        iframe.src = 'about:blank';
    }

    updatePagination(total, page, totalPages) {
        this.currentPage = page;
        this.totalResults = total;

        const from = total === 0 ? 0 : (page - 1) * this.limit + 1;
        const to = Math.min(page * this.limit, total);

        document.getElementById('showing-from').textContent = from;
        document.getElementById('showing-to').textContent = to;
        document.getElementById('total-results').textContent = this.formatNumber(total);
        document.getElementById('current-page').textContent = page;
        document.getElementById('total-pages').textContent = totalPages;

        this.renderPaginationControls('pagination-top', totalPages);
        this.renderPaginationControls('pagination-bottom', totalPages);
    }

    renderPaginationControls(containerId, totalPages) {
        const container = document.getElementById(containerId);
        if (!container) return;
        container.innerHTML = '';
        if (totalPages <= 1) return;

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
        nextBtn.disabled = this.currentPage >= totalPages;
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
        this.currentPage = page;
        this.loadDomains();
        window.scrollTo({ top: 0, behavior: 'smooth' });
    }

    exportJSON() {
        const params = new URLSearchParams({ limit: 10000 });
        if (this.searchQuery) params.set('q', this.searchQuery);
        if (this.protocolFilter) params.set('protocol', this.protocolFilter);
        if (this.statusCodeFilter) params.set('status_code', this.statusCodeFilter);
        const apiKey = localStorage.getItem('meow_api_key');
        if (apiKey) params.set('key', apiKey);
        window.open(`/api/domains?${params}`, '_blank');
    }

    // Helpers
    formatNumber(n) {
        if (n === undefined || n === null) return '-';
        return n.toLocaleString();
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB'];
        const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
        return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    statusClass(code) {
        if (code >= 200 && code < 300) return '2xx';
        if (code >= 300 && code < 400) return '3xx';
        if (code >= 400 && code < 500) return '4xx';
        if (code >= 500) return '5xx';
        return '';
    }

    timeAgo(ts) {
        const now = Math.floor(Date.now() / 1000);
        const diff = now - ts;
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
        return new Date(ts * 1000).toLocaleDateString();
    }

    esc(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = String(str);
        return div.innerHTML;
    }

    escAttr(str) {
        if (!str) return '';
        return str.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    hideLoading() {
        const overlay = document.getElementById('loading-overlay');
        if (overlay) overlay.style.display = 'none';
    }
}

// Initialize
const domainsPage = new DomainsPage();
