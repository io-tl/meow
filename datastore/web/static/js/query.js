// MeowQL Query Page - Service-Centric Cards
class MeowQueryPage {
    constructor() {
        this.currentPage = 1;
        this.pageSize = 50;
        this.totalResults = 0;
        this.currentQuery = '';
        this.matchedFields = [];
        this.queryHistory = [];
        this.lastSearchTime = 0;
        this.acSelectedIndex = -1;
        this.acItems = [];
        this.acDebounceTimer = null;

        // Ghost text / inline completion
        this.ghostText = '';           // The completion suffix to show
        this.fieldCache = null;        // Cached field names + descriptions
        this.fieldCacheReady = false;
        this.operatorList = [':', '=', '!=', '=~', '*=', '>', '<', '>=', '<='];
        this.valueCache = {};          // field -> [{value, count}]

        this.init();
    }

    init() {
        this.loadQueryHistory();
        this.prefetchFields();
        this.bindEvents();
        this.checkURLQuery();
    }

    // Prefetch all field names for instant local completion
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
        const input = document.getElementById('meowql-input');
        const searchBtn = document.getElementById('query-search-btn');
        const helpBtn = document.getElementById('query-help-btn');

        if (input) {
            input.addEventListener('keydown', (e) => this.onInputKeydown(e));
            input.addEventListener('input', () => this.onInputChange());
            input.addEventListener('focus', () => {
                if (!input.value.trim()) this.showHistorySuggestions();
            });
            input.addEventListener('blur', () => {
                setTimeout(() => {
                    this.hideAutocomplete();
                    this.clearGhost();
                }, 200);
            });
            // Sync ghost text position with input scroll
            input.addEventListener('scroll', () => {
                const ghost = document.getElementById('meowql-ghost');
                if (ghost) ghost.scrollLeft = input.scrollLeft;
            });
        }

        if (searchBtn) {
            searchBtn.addEventListener('click', () => {
                this.hideAutocomplete();
                this.search(input?.value.trim() || '');
            });
        }

        if (helpBtn) {
            helpBtn.addEventListener('click', () => this.openHelp());
        }

        // Global keyboard shortcuts
        document.addEventListener('keydown', (e) => {
            if (e.key === '/' && !e.ctrlKey && !e.metaKey && document.activeElement !== input) {
                e.preventDefault();
                input?.focus();
            }
            if (e.key === 'Escape') {
                this.closeHelp();
                this.closeJsonModal();
                this.closeHtmlModal();
            }
        });

        // Example query chips and help examples (data-query attributes)
        document.querySelectorAll('[data-query]').forEach(el => {
            el.addEventListener('click', () => {
                const query = el.dataset.query;
                if (query) this.insertExample(query);
            });
        });

        // Help tabs
        document.querySelectorAll('.help-tab[data-tab]').forEach(tab => {
            tab.addEventListener('click', () => this.switchHelpTab(tab.dataset.tab));
        });

        // Pagination
        document.getElementById('query-prev-page')?.addEventListener('click', () => this.previousPage());
        document.getElementById('query-next-page')?.addEventListener('click', () => this.nextPage());
    }

    // ==================== Search ====================

    async search(query) {
        if (!query) return;

        this.currentQuery = query;
        this.currentPage = 1;
        this.addToHistory(query);
        this.updateURL(query);
        this.hideError();
        this.hideAutocomplete();
        this.clearGhost();

        const input = document.getElementById('meowql-input');
        if (input) input.value = query;

        await this.searchServices();
    }

    async searchServices() {
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
                this.showError(data.error || 'Search failed', data.fields);
                return;
            }

            this.lastSearchTime = Math.round(performance.now() - startTime);
            this.totalResults = data.total || 0;
            this.matchedFields = data.matched_fields || [];

            this.renderServiceCards(data.services || [], this.matchedFields);
            this.updateTopBar();
            this.updatePagination(this.totalResults);
        } catch (error) {
            console.error('Search error:', error);
            this.showError('Network error: ' + error.message);
        }
    }

    // ==================== Render Service Cards ====================

    renderServiceCards(services, matchedFields) {
        // Show results sections
        document.querySelector('.query-results-stats')?.classList.add('show');
        document.querySelector('.query-results-wrapper')?.classList.add('show');
        document.querySelector('.query-empty-state')?.classList.add('hidden');

        // Update stats
        const statsEl = document.getElementById('query-stats-text');
        if (statsEl) {
            statsEl.innerHTML = `<strong>${this.totalResults.toLocaleString()}</strong> services found for <code>${this.escapeHtml(this.currentQuery)}</code>`;
        }

        const timeEl = document.getElementById('query-search-time');
        if (timeEl) {
            timeEl.textContent = `${this.lastSearchTime}ms`;
        }

        const container = document.getElementById('query-results-list');
        if (!container) return;

        if (!services || services.length === 0) {
            container.innerHTML = `<div style="text-align: center; padding: 40px; color: var(--text-muted);">No services found</div>`;
            return;
        }

        container.innerHTML = services.map((svc, index) => this.renderResultCard(svc, index, matchedFields)).join('');
    }

    renderResultCard(svc, index, matchedFields) {
        // Parse JSON blobs
        let enrichedData = null;
        let fingerprintData = null;

        if (svc.enrichment_data) {
            try { enrichedData = JSON.parse(svc.enrichment_data); }
            catch (e) { enrichedData = { raw: svc.enrichment_data }; }
        }
        if (svc.fingerprint_data) {
            try { fingerprintData = JSON.parse(svc.fingerprint_data); }
            catch (e) { fingerprintData = { raw: svc.fingerprint_data }; }
        }

        // Build host-like and service-like objects for renderSingleServiceCard
        const host = { ip: svc.ip };
        const service = {
            port: svc.port,
            service: svc.service,
            product: svc.product,
            version: svc.version,
            banner: svc.banner,
            enrichment_data: svc.enrichment_data,
            fingerprint_data: svc.fingerprint_data
        };

        // Build header bar
        const ip = this.escapeHtml(svc.ip);
        const port = svc.port;
        const serviceName = svc.service || 'open';
        const productVersion = [svc.product, svc.version].filter(Boolean).join('/');

        // Country
        const countryFlag = svc.country_code
            ? `<img src="https://flagcdn.com/16x12/${this.escapeHtml(svc.country_code.toLowerCase())}.png" alt="${this.escapeHtml(svc.country_code)}" onerror="this.style.display='none'" style="border-radius:2px;box-shadow:0 1px 2px rgba(0,0,0,0.2)">`
            : '';
        const countryCode = svc.country_code ? this.escapeHtml(svc.country_code) : '';

        // Cloud badge
        const cloudClass = this.getCloudClass(svc.cloud_provider);
        const cloudBadge = svc.cloud_provider
            ? `<span class="cloud-badge ${cloudClass}">${this.escapeHtml(svc.cloud_provider)}</span>`
            : '';

        // ASN / Org
        const asnOrg = svc.asn
            ? `<span class="service-result-asn">AS${svc.asn}${svc.as_org ? '/' + this.escapeHtml(svc.as_org) : ''}</span>`
            : (svc.as_org ? `<span class="service-result-asn">${this.escapeHtml(svc.as_org)}</span>` : '');

        // Matched field tags + resolved values
        const matchedEntries = (matchedFields || []).map(f => {
            const val = this.resolveMatchedValue(f, svc, enrichedData, fingerprintData);
            return { field: f, value: val };
        });
        const matchedTags = matchedEntries.map(e => {
            if (e.value !== null && e.value !== undefined && e.value !== '') {
                const display = typeof e.value === 'boolean' ? (e.value ? 'true' : 'false')
                    : Array.isArray(e.value) ? e.value.map(v => typeof v === 'object' && v !== null ? (v.name || JSON.stringify(v)) : String(v)).join(', ')
                    : (typeof e.value === 'object' ? JSON.stringify(e.value) : String(e.value));
                const truncated = display.length > 80 ? display.substring(0, 80) + '...' : display;
                return `<span class="matched-tag has-value" title="${this.escapeHtml(e.field)}=${this.escapeHtml(display)}"><span class="matched-tag-key">${this.escapeHtml(e.field)}</span><span class="matched-tag-val">${this.escapeHtml(truncated)}</span></span>`;
            }
            return `<span class="matched-tag">${this.escapeHtml(e.field)}</span>`;
        }).join('');

        // HTTP info line
        let httpInfoHtml = '';
        if (svc.http_title || svc.http_server) {
            const parts = [];
            if (svc.http_title) parts.push(`Title: "${this.escapeHtml(svc.http_title)}"`);
            if (svc.http_server) parts.push(`Server: ${this.escapeHtml(svc.http_server)}`);
            httpInfoHtml = `<div class="service-result-http-info">${parts.join('  ')}</div>`;
        }

        // Technologies from http_technologies
        let techTagsHtml = '';
        if (svc.http_technologies) {
            try {
                const techs = JSON.parse(svc.http_technologies);
                if (Array.isArray(techs) && techs.length > 0) {
                    const techNames = techs.map(t => typeof t === 'string' ? t : t?.name).filter(Boolean);
                    if (techNames.length > 0) {
                        techTagsHtml = `<div class="service-result-techs">${techNames.slice(0, 8).map(t => `<span class="tech-tag">${this.escapeHtml(t)}</span>`).join('')}</div>`;
                    }
                }
            } catch (e) { /* ignore */ }
        }

        // Inner card content (reusing existing renderSingleServiceCard)
        const innerCard = this.renderSingleServiceCard(host, service, index, enrichedData, fingerprintData, null);

        return `
            <div class="service-result-card">
                <div class="service-result-header">
                    <div class="service-result-header-left">
                        <a href="/hosts?search=${encodeURIComponent(svc.ip)}" target="_blank" class="host-link-icon" title="View host ${ip}" onclick="event.stopPropagation()">
                            <svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                                <rect x="2" y="3" width="20" height="14" rx="2" ry="2"></rect>
                                <line x1="8" y1="21" x2="16" y2="21"></line>
                                <line x1="12" y1="17" x2="12" y2="21"></line>
                            </svg>
                        </a>
                        <span class="service-result-endpoint">${ip}:${port}</span>
                        <span class="service-result-name">${this.escapeHtml(serviceName)}</span>
                        ${productVersion ? `<span class="service-result-product">${this.escapeHtml(productVersion)}</span>` : ''}
                    </div>
                    <div class="service-result-header-right">
                        ${countryFlag ? `<span class="service-result-country">${countryFlag} ${countryCode}</span>` : ''}
                        ${cloudBadge}
                        ${asnOrg}
                        ${matchedTags ? `<div class="matched-tags">${matchedTags}</div>` : ''}
                    </div>
                </div>
                <div class="service-result-body">
                    ${httpInfoHtml}
                    ${innerCard}
                    ${techTagsHtml}
                </div>
            </div>
        `;
    }

    // ==================== Pagination ====================

    updatePagination(total) {
        const totalPages = Math.max(1, Math.ceil(total / this.pageSize));
        const paginationEl = document.querySelector('.query-pagination');
        const prevBtn = document.getElementById('query-prev-page');
        const nextBtn = document.getElementById('query-next-page');
        const pageInfo = document.getElementById('query-page-info');

        if (total > this.pageSize) {
            paginationEl?.classList.add('show');
        } else {
            paginationEl?.classList.remove('show');
        }

        if (prevBtn) prevBtn.disabled = this.currentPage <= 1;
        if (nextBtn) nextBtn.disabled = this.currentPage >= totalPages;
        if (pageInfo) pageInfo.innerHTML = `Page <span>${this.currentPage}</span> of <span>${totalPages}</span>`;
    }

    async previousPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            await this.searchServices();
        }
    }

    async nextPage() {
        const totalPages = Math.ceil(this.totalResults / this.pageSize);
        if (this.currentPage < totalPages) {
            this.currentPage++;
            await this.searchServices();
        }
    }

    // ==================== Top Bar ====================

    updateTopBar() {
        const counter = document.getElementById('query-results-counter');
        const countEl = document.getElementById('query-top-count');
        const timeEl = document.getElementById('query-top-time');
        const exportBtns = document.getElementById('query-export-buttons');

        if (counter) counter.style.display = 'flex';
        if (countEl) countEl.textContent = this.totalResults.toLocaleString();
        if (timeEl) {
            timeEl.style.display = 'inline';
            timeEl.textContent = `${this.lastSearchTime}ms`;
        }
        if (exportBtns && this.totalResults > 0) exportBtns.style.display = 'flex';
    }

    // ==================== Error ====================

    showError(msg, fields) {
        const errorEl = document.getElementById('query-error');
        const msgEl = document.getElementById('query-error-msg');
        const fieldsEl = document.getElementById('query-error-fields');

        if (!errorEl) return;

        errorEl.classList.add('show');
        if (msgEl) msgEl.textContent = msg;

        if (fieldsEl && fields && fields.length > 0) {
            fieldsEl.innerHTML = fields.slice(0, 20).map(f =>
                `<span class="query-error-field" onclick="queryPage.insertFieldInQuery('${this.escapeHtml(f)}')">${this.escapeHtml(f)}</span>`
            ).join('');
            fieldsEl.style.display = 'flex';
        } else if (fieldsEl) {
            fieldsEl.style.display = 'none';
        }

        // Hide results
        document.querySelector('.query-results-stats')?.classList.remove('show');
        document.querySelector('.query-results-wrapper')?.classList.remove('show');
    }

    hideError() {
        document.getElementById('query-error')?.classList.remove('show');
    }

    insertFieldInQuery(field) {
        const input = document.getElementById('meowql-input');
        if (input) {
            input.value = field + ':';
            input.focus();
        }
    }

    // ==================== Autocomplete ====================

    onInputChange() {
        const input = document.getElementById('meowql-input');
        if (!input) return;
        const value = input.value;

        // Update ghost text immediately (synchronous, from local cache)
        this.updateGhostText(value);

        // Debounced dropdown suggestions
        clearTimeout(this.acDebounceTimer);
        this.acDebounceTimer = setTimeout(() => {
            if (!value.trim()) {
                this.showHistorySuggestions();
                return;
            }
            this.updateAutocomplete(value);
        }, 120);
    }

    onInputKeydown(e) {
        const dropdown = document.getElementById('autocomplete-dropdown');
        const isVisible = dropdown && dropdown.classList.contains('show');

        if (e.key === 'Enter') {
            e.preventDefault();
            if (isVisible && this.acSelectedIndex >= 0 && this.acItems[this.acSelectedIndex]) {
                this.selectAutocompleteItem(this.acItems[this.acSelectedIndex]);
            } else {
                this.hideAutocomplete();
                this.clearGhost();
                const input = document.getElementById('meowql-input');
                this.search(input?.value.trim() || '');
            }
            return;
        }

        if (e.key === 'Escape') {
            if (this.ghostText || isVisible) {
                e.preventDefault();
                e.stopPropagation();
                this.clearGhost();
                this.hideAutocomplete();
                return;
            }
            const input = document.getElementById('meowql-input');
            if (input) { input.value = ''; input.blur(); }
            this.clearGhost();
            return;
        }

        // Tab: accept ghost text or dropdown selection
        if (e.key === 'Tab') {
            // Priority 1: accept ghost text
            if (this.ghostText) {
                e.preventDefault();
                this.acceptGhostText();
                return;
            }
            // Priority 2: accept dropdown selection
            if (isVisible && this.acItems.length > 0) {
                e.preventDefault();
                const idx = this.acSelectedIndex >= 0 ? this.acSelectedIndex : 0;
                if (this.acItems[idx]) this.selectAutocompleteItem(this.acItems[idx]);
                return;
            }
            // Otherwise: let Tab do its default (move focus)
            return;
        }

        // Right arrow: accept ghost text if cursor is at end
        if (e.key === 'ArrowRight' && this.ghostText) {
            const input = document.getElementById('meowql-input');
            if (input && input.selectionStart === input.value.length) {
                e.preventDefault();
                this.acceptGhostText();
                return;
            }
        }

        if (isVisible) {
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                this.acSelectedIndex = Math.min(this.acSelectedIndex + 1, this.acItems.length - 1);
                this.highlightAcItem();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                this.acSelectedIndex = Math.max(this.acSelectedIndex - 1, -1);
                this.highlightAcItem();
            }
        }
    }

    parseCurrentToken(fullValue) {
        // Find the current token being typed (last space-separated segment)
        // But respect quoted strings and boolean operators
        let lastTokenStart = 0;
        let inQuote = false;
        for (let i = 0; i < fullValue.length; i++) {
            if (fullValue[i] === '"') inQuote = !inQuote;
            if (fullValue[i] === ' ' && !inQuote) lastTokenStart = i + 1;
        }
        const token = fullValue.substring(lastTokenStart);

        // Skip boolean keywords being typed
        const lowerToken = token.toLowerCase();
        if (['and', 'or', 'not', 'and ', 'or ', 'not '].includes(lowerToken)) {
            return { mode: 'keyword', prefix: token, tokenStart: lastTokenStart };
        }

        // Check for operator position: field<op>value (optionally with - prefix for negation)
        const opMatch = token.match(/^-?([a-zA-Z_][a-zA-Z0-9_.]*)([:=!><*~]{1,2})(.*)/);
        if (opMatch) {
            const field = opMatch[1];
            const op = opMatch[2];
            const valuePrefix = opMatch[3].replace(/^"/, '');
            return { mode: 'value', field, op, prefix: valuePrefix, tokenStart: lastTokenStart };
        }

        // Before any operator: we're typing a field name (or it's a negation prefix)
        const cleanToken = token.replace(/^-/, '');
        const negated = token.startsWith('-');
        return { mode: 'field', prefix: cleanToken, tokenStart: lastTokenStart + (negated ? 1 : 0), negated };
    }

    // ==================== Ghost Text (inline completion) ====================

    updateGhostText(value) {
        if (!value || !this.fieldCacheReady) {
            this.clearGhost();
            return;
        }

        const parsed = this.parseCurrentToken(value);
        let completion = '';

        if (parsed.mode === 'field' && parsed.prefix.length >= 1) {
            // Find best matching field name
            completion = this.findFieldCompletion(parsed.prefix);
        } else if (parsed.mode === 'value' && parsed.field && parsed.prefix === '') {
            // Just typed field:, suggest common values from cache
            const cached = this.valueCache[parsed.field];
            if (cached && cached.length > 0) {
                const topVal = cached[0].value;
                completion = topVal.includes(' ') ? `"${topVal}"` : topVal;
            }
        } else if (parsed.mode === 'value' && parsed.field && parsed.prefix.length >= 1) {
            // Typing a value, suggest from cache
            const cached = this.valueCache[parsed.field];
            if (cached) {
                const pfx = parsed.prefix.toLowerCase();
                const match = cached.find(v => v.value.toLowerCase().startsWith(pfx) && v.value.toLowerCase() !== pfx);
                if (match) {
                    completion = match.value.substring(parsed.prefix.length);
                    if (match.value.includes(' ')) {
                        // Need to wrap in quotes
                        completion = match.value.substring(parsed.prefix.length);
                    }
                }
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

        // Exact match -> suggest colon
        const exact = this.fieldCache.find(s => s.field === prefix || s.field === pfx);
        if (exact && exact.type === 'field') return ':';

        // Prefix match -> complete the field name + colon
        const matches = this.fieldCache
            .filter(s => s.field.toLowerCase().startsWith(pfx) && s.field.toLowerCase() !== pfx)
            .sort((a, b) => {
                // Prefer exact fields over prefixes
                if (a.type === 'field' && b.type !== 'field') return -1;
                if (a.type !== 'field' && b.type === 'field') return 1;
                // Shorter fields first
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
        const ghost = document.getElementById('meowql-ghost');
        const tabHint = document.getElementById('meowql-tab-hint');
        if (!ghost) return;

        // Render: invisible typed text + visible completion
        const escapedTyped = this.escapeHtml(typed);
        const escapedCompletion = this.escapeHtml(completion);
        ghost.innerHTML = `<span style="visibility:hidden">${escapedTyped}</span><span class="ghost-completion">${escapedCompletion}</span>`;

        if (tabHint) tabHint.classList.add('show');
    }

    clearGhost() {
        this.ghostText = '';
        const ghost = document.getElementById('meowql-ghost');
        const tabHint = document.getElementById('meowql-tab-hint');
        if (ghost) ghost.innerHTML = '';
        if (tabHint) tabHint.classList.remove('show');
    }

    acceptGhostText() {
        const input = document.getElementById('meowql-input');
        if (!input || !this.ghostText) return;

        input.value += this.ghostText;
        this.clearGhost();
        input.focus();

        // If we completed a field (ends with :), trigger value suggestions
        if (input.value.endsWith(':')) {
            setTimeout(() => this.onInputChange(), 30);
        } else {
            this.onInputChange();
        }
    }

    // ==================== Dropdown Autocomplete ====================

    async updateAutocomplete(value) {
        const parsed = this.parseCurrentToken(value);

        if (parsed.mode === 'keyword') {
            this.hideAutocomplete();
            return;
        }

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
                // Sort: exact prefix match first, then fields, then prefixes
                const fields = data.suggestions.filter(s => s.type === 'field').sort((a, b) => {
                    const pfx = (parsed.prefix || '').toLowerCase();
                    const aStarts = a.field.toLowerCase().startsWith(pfx) ? 0 : 1;
                    const bStarts = b.field.toLowerCase().startsWith(pfx) ? 0 : 1;
                    if (aStarts !== bStarts) return aStarts - bStarts;
                    return a.field.length - b.field.length || a.field.localeCompare(b.field);
                });
                const prefixes = data.suggestions.filter(s => s.type === 'prefix');

                fields.forEach(s => items.push({
                    type: 'field',
                    label: s.field,
                    detail: s.description,
                    value: s.field + ':',
                    tokenStart: parsed.tokenStart
                }));
                prefixes.forEach(s => items.push({
                    type: 'prefix',
                    label: s.field,
                    detail: s.description,
                    value: s.field,
                    tokenStart: parsed.tokenStart
                }));
            } else if (parsed.mode === 'value' && data.values) {
                // Cache values for ghost text
                this.valueCache[parsed.field] = data.values;

                data.values.forEach(v => items.push({
                    type: 'value',
                    label: v.value,
                    detail: `${v.count.toLocaleString()} results`,
                    value: parsed.field + ':' + (v.value.includes(' ') ? `"${v.value}"` : v.value),
                    tokenStart: parsed.tokenStart
                }));

                // After getting values, update ghost text
                this.updateGhostText(value);
            }

            this.acItems = items;
            this.acSelectedIndex = -1;
            this.renderAutocompleteDropdown(items, parsed.mode === 'field' ? 'Fields' : `Values for ${parsed.field}`);
        } catch (e) {
            this.hideAutocomplete();
        }
    }

    showHistorySuggestions() {
        const dropdown = document.getElementById('autocomplete-dropdown');
        if (!dropdown) return;

        const hasHistory = this.queryHistory.length > 0;

        // Build combined items: history + fields
        this.acItems = [];

        // History items
        if (hasHistory) {
            this.queryHistory.slice(0, 6).forEach(q => {
                this.acItems.push({
                    type: 'history',
                    label: q,
                    detail: '',
                    value: q,
                    tokenStart: 0,
                    fullReplace: true
                });
            });
        }

        // Popular fields
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
            this.acItems.push({
                type: 'field',
                label: f.field,
                detail: f.desc,
                value: f.field + ':',
                tokenStart: 0
            });
        });

        this.acSelectedIndex = -1;
        this.renderEmptyStateDropdown(hasHistory, popularFields);
    }

    renderEmptyStateDropdown(hasHistory, popularFields) {
        const dropdown = document.getElementById('autocomplete-dropdown');
        if (!dropdown) return;

        let html = '';

        // History section
        if (hasHistory) {
            html += `<div class="ac-group-header">
                <span class="ac-group-label">Recent</span>
                <button class="ac-clear-btn" onmousedown="event.preventDefault(); queryPage.clearHistory()">Clear</button>
            </div>`;
            const historyItems = this.acItems.filter(i => i.type === 'history');
            historyItems.forEach((item, i) => {
                html += `<div class="ac-item" data-index="${i}" onmousedown="queryPage.selectAutocompleteItem(queryPage.acItems[${i}])">
                    <span class="ac-icon">\u23F3</span>
                    <span class="ac-label">${this.escapeHtml(item.label)}</span>
                </div>`;
            });
        }

        // Fields section
        const fieldStartIdx = this.acItems.findIndex(i => i.type === 'field');
        if (fieldStartIdx >= 0) {
            html += `<div class="ac-group-header"><span class="ac-group-label">Fields</span></div>`;
            html += `<div class="ac-fields-grid">`;
            const fieldItems = this.acItems.filter(i => i.type === 'field');
            fieldItems.forEach((item) => {
                const idx = this.acItems.indexOf(item);
                html += `<div class="ac-field-chip" onmousedown="queryPage.selectAutocompleteItem(queryPage.acItems[${idx}])" title="${this.escapeHtml(item.detail)}">
                    <span class="ac-field-chip-name">${this.escapeHtml(item.label)}</span>
                </div>`;
            });
            html += `</div>`;
        }

        if (!html) {
            this.hideAutocomplete();
            return;
        }

        dropdown.innerHTML = html;
        dropdown.classList.add('show');
    }

    clearHistory() {
        this.queryHistory = [];
        localStorage.removeItem('meowql-history');
        // Re-render the dropdown without history
        this.showHistorySuggestions();
    }

    renderAutocompleteDropdown(items, groupLabel) {
        const dropdown = document.getElementById('autocomplete-dropdown');
        if (!dropdown || items.length === 0) {
            this.hideAutocomplete();
            return;
        }

        const icons = { history: '\u23F3', field: '\u25B8', prefix: '\u25B8', value: '\u2022', operator: '\u2261' };

        let html = `<div class="ac-group-label">${this.escapeHtml(groupLabel)}</div>`;
        items.forEach((item, i) => {
            // Highlight matching prefix in the label
            const label = this.highlightMatch(item.label, item);
            html += `<div class="ac-item${i === this.acSelectedIndex ? ' selected' : ''}" data-index="${i}" onmousedown="queryPage.selectAutocompleteItem(queryPage.acItems[${i}])">
                <span class="ac-icon">${icons[item.type] || '\u2022'}</span>
                <span class="ac-label">${label}</span>
                ${item.detail ? `<span class="ac-detail">${this.escapeHtml(item.detail)}</span>` : ''}
            </div>`;
        });

        dropdown.innerHTML = html;
        dropdown.classList.add('show');
    }

    highlightMatch(label, item) {
        if (item.type === 'history') return this.escapeHtml(label);

        // Find what the user typed for this token
        const input = document.getElementById('meowql-input');
        if (!input) return this.escapeHtml(label);

        const parsed = this.parseCurrentToken(input.value);
        const prefix = parsed.prefix || '';

        if (prefix && label.toLowerCase().startsWith(prefix.toLowerCase())) {
            const matched = label.substring(0, prefix.length);
            const rest = label.substring(prefix.length);
            return `<span class="ac-match">${this.escapeHtml(matched)}</span>${this.escapeHtml(rest)}`;
        }

        return this.escapeHtml(label);
    }

    highlightAcItem() {
        const dropdown = document.getElementById('autocomplete-dropdown');
        if (!dropdown) return;
        dropdown.querySelectorAll('.ac-item').forEach((el, i) => {
            el.classList.toggle('selected', i === this.acSelectedIndex);
        });
        // Scroll selected item into view
        const selected = dropdown.querySelector('.ac-item.selected');
        if (selected) selected.scrollIntoView({ block: 'nearest' });
    }

    selectAutocompleteItem(item) {
        const input = document.getElementById('meowql-input');
        if (!input || !item) return;

        if (item.fullReplace) {
            input.value = item.value;
            this.clearGhost();
            this.hideAutocomplete();
            this.search(item.value);
            return;
        }

        const before = input.value.substring(0, item.tokenStart);
        input.value = before + item.value;
        this.clearGhost();
        this.hideAutocomplete();
        input.focus();

        // If we just completed a field name (ends with :), trigger value autocompletion
        if (item.type === 'field') {
            setTimeout(() => this.onInputChange(), 30);
        }
    }

    hideAutocomplete() {
        const dropdown = document.getElementById('autocomplete-dropdown');
        if (dropdown) dropdown.classList.remove('show');
        this.acSelectedIndex = -1;
    }

    // ==================== Help Modal ====================

    openHelp() {
        let modal = document.getElementById('help-modal');
        if (modal) {
            modal.classList.add('show');
            document.body.style.overflow = 'hidden';
        }
    }

    closeHelp() {
        const modal = document.getElementById('help-modal');
        if (modal) {
            modal.classList.remove('show');
            document.body.style.overflow = '';
        }
    }

    switchHelpTab(tab) {
        document.querySelectorAll('.help-tab').forEach(t => {
            t.classList.toggle('active', t.dataset.tab === tab);
        });
        document.querySelectorAll('.help-tab-content').forEach(c => {
            c.classList.toggle('active', c.dataset.tab === tab);
        });
    }

    insertExample(query) {
        const input = document.getElementById('meowql-input');
        if (input) input.value = query;
        this.closeHelp();
        this.search(query);
    }

    // ==================== History ====================

    loadQueryHistory() {
        try {
            this.queryHistory = JSON.parse(localStorage.getItem('meowql-history') || '[]');
        } catch { this.queryHistory = []; }
    }

    addToHistory(query) {
        this.queryHistory = this.queryHistory.filter(q => q !== query);
        this.queryHistory.unshift(query);
        if (this.queryHistory.length > 20) this.queryHistory = this.queryHistory.slice(0, 20);
        localStorage.setItem('meowql-history', JSON.stringify(this.queryHistory));
    }

    // ==================== URL Deep Link ====================

    updateURL(query) {
        const url = new URL(window.location);
        url.searchParams.set('q', query);
        history.pushState({}, '', url);
    }

    checkURLQuery() {
        const params = new URLSearchParams(window.location.search);
        const q = params.get('q');
        if (q) {
            const input = document.getElementById('meowql-input');
            if (input) input.value = q;
            this.search(q);
        }
    }

    // ==================== Utility ====================

    resolveMatchedValue(field, svc, enrichedData, fingerprintData) {
        // Host fields
        if (field === 'ip') return svc.ip;
        if (field === 'country') return svc.country_code;
        if (field === 'city') return svc.city;
        if (field === 'cloud') return svc.cloud_provider;
        if (field === 'cloud.type') return null;
        if (field === 'org' || field === 'as_org') return svc.as_org;
        if (field === 'asn') return svc.asn;
        if (field === 'isp') return null;
        if (field === 'hostname') return null;
        if (field === 'domain') return null;

        // Service fields
        if (field === 'port') return svc.port;
        if (field === 'service') return svc.service;
        if (field === 'product') return svc.product;
        if (field === 'version') return svc.version;
        if (field === 'banner') return svc.banner ? '(present)' : null;
        if (field === 'banner_hash') return null;
        if (field === 'enrichment') return svc.enrichment_status;

        // HTTP fields
        if (field === 'http.title') return svc.http_title || enrichedData?.title;
        if (field === 'http.server') return svc.http_server || enrichedData?.server;
        if (field === 'http.status') return svc.http_status || enrichedData?.status_code;
        if (field === 'http.body') return enrichedData?.body ? '(present)' : null;
        if (field === 'http.favicon') return enrichedData?.favicon_md5;
        if (field === 'http.redirect') return enrichedData?.redirect_url || enrichedData?.location;
        if (field === 'http.headers') return enrichedData?.headers ? Object.keys(enrichedData.headers).join(', ') : null;
        if (field === 'tech') return svc.http_technologies ? '(see tags)' : null;
        if (field === 'framework') return enrichedData?.framework;

        // HTTP headers (dynamic: http.headers.X-Something)
        if (field.startsWith('http.headers.')) {
            const headerName = field.substring('http.headers.'.length);
            const headers = enrichedData?.headers;
            if (headers && typeof headers === 'object') {
                // Case-insensitive lookup
                for (const [k, v] of Object.entries(headers)) {
                    if (k.toLowerCase() === headerName.toLowerCase()) {
                        return Array.isArray(v) ? v.join(', ') : v;
                    }
                }
            }
            return null;
        }

        // Enrichment JSON (dynamic: enrichment.some.path)
        if (field.startsWith('enrichment.')) {
            return this.resolveJSONPath(enrichedData, field.substring('enrichment.'.length));
        }

        // Fingerprint JSON (dynamic: fingerprint.some.path)
        if (field.startsWith('fingerprint.')) {
            return this.resolveJSONPath(fingerprintData, field.substring('fingerprint.'.length));
        }

        // TLS fields (not in current API response)
        if (field.startsWith('tls.')) return null;

        return null;
    }

    resolveJSONPath(obj, path) {
        if (!obj || typeof obj !== 'object') return null;
        const parts = path.split('.');
        let current = obj;
        for (const part of parts) {
            if (current === null || current === undefined || typeof current !== 'object') return null;
            current = current[part];
        }
        if (current === null || current === undefined) return null;
        if (typeof current === 'object') {
            if (Array.isArray(current)) return current;
            return JSON.stringify(current);
        }
        return current;
    }

    getCloudClass(provider) {
        if (!provider) return '';
        const p = provider.toLowerCase();
        if (p.includes('aws') || p.includes('amazon')) return 'aws';
        if (p.includes('gcp') || p.includes('google')) return 'gcp';
        if (p.includes('azure') || p.includes('microsoft')) return 'azure';
        if (p.includes('digitalocean')) return 'do';
        return 'other';
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // ==================== Service Rendering (ported from hosts_search.js) ====================

    isBinaryString(str) {
        if (!str) return false;
        let nonPrintable = 0;
        for (let i = 0; i < Math.min(str.length, 500); i++) {
            const code = str.charCodeAt(i);
            if (code < 32 && code !== 9 && code !== 10 && code !== 13) nonPrintable++;
            else if (code > 126 && code < 160) nonPrintable++;
        }
        return nonPrintable > str.length * 0.1;
    }

    formatHexdump(str) {
        if (!str) return '';
        const lines = [];
        const bytes = new TextEncoder().encode(str);
        const bytesPerLine = 16;
        for (let offset = 0; offset < bytes.length && offset < 256; offset += bytesPerLine) {
            const chunk = bytes.slice(offset, offset + bytesPerLine);
            const offsetHex = offset.toString(16).padStart(8, '0');
            let hexPart = '';
            let asciiPart = '';
            for (let i = 0; i < bytesPerLine; i++) {
                if (i < chunk.length) {
                    hexPart += chunk[i].toString(16).padStart(2, '0') + ' ';
                    const charCode = chunk[i];
                    asciiPart += (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : '.';
                } else {
                    hexPart += '   ';
                    asciiPart += ' ';
                }
                if (i === 7) hexPart += ' ';
            }
            lines.push(`<span class="hex-offset">${offsetHex}</span>  <span class="hex-bytes">${hexPart}</span> <span class="hex-ascii">|${asciiPart}|</span>`);
        }
        if (bytes.length > 256) lines.push(`<span class="hex-truncated">... (${bytes.length - 256} more bytes)</span>`);
        return lines.join('\n');
    }

    formatBanner(banner) {
        if (!banner) return '';
        if (this.isBinaryString(banner)) return `<pre class="banner-text hexdump">${this.formatHexdump(banner)}</pre>`;
        return `<pre class="banner-text">${this.escapeHtml(banner)}</pre>`;
    }

    makeRow(label, value, isLong = false) {
        if (!value) return '';
        const displayValue = String(value);
        const longClass = isLong || displayValue.length > 60 ? ' long-value' : '';
        return `<div class="enrichment-row"><span class="enrichment-label">${this.escapeHtml(label)}</span><span class="enrichment-value${longClass}">${this.escapeHtml(displayValue)}</span></div>`;
    }

    makeInlineRow(label, value) {
        if (!value) return '';
        return `<div class="enrichment-row inline"><span class="enrichment-label">${this.escapeHtml(label)}</span><span class="enrichment-value">${this.escapeHtml(String(value))}</span></div>`;
    }

    makeBool(label, value, style = null) {
        const cls = style || (value ? 'true' : 'false');
        const text = value ? 'Yes' : 'No';
        return `<div class="enrichment-row inline"><span class="enrichment-label">${this.escapeHtml(label)}</span><span class="enrichment-bool ${cls}"><span class="indicator"></span>${text}</span></div>`;
    }

    makeTags(label, items, tagClass = '') {
        if (!items || !Array.isArray(items) || items.length === 0) return '';
        return `<div class="enrichment-row"><span class="enrichment-label">${this.escapeHtml(label)}</span><div class="enrichment-tags">${items.map(item => `<span class="enrichment-tag ${tagClass}">${this.escapeHtml(String(item))}</span>`).join('')}</div></div>`;
    }

    makeScreenshot(label, value) {
        if (!value || typeof value !== 'string') return '';
        const src = value.startsWith('data:') ? value : `data:image/png;base64,${value}`;
        return `<div class="enrichment-row"><span class="enrichment-label">${this.escapeHtml(label)}</span><a class="enrichment-screenshot" href="${this.escapeHtml(src)}" target="_blank" rel="noopener noreferrer"><img src="${this.escapeHtml(src)}" alt="${this.escapeHtml(label)}" loading="lazy"></a></div>`;
    }

    makeSection(title, rows) {
        if (!rows || rows.length === 0) return '';
        return `<div class="enrichment-section"><div class="enrichment-title">${title}</div><div class="enrichment-grid">${rows.join('')}</div></div>`;
    }

    parseArrayField(value) {
        if (!value) return null;
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') {
            try { const parsed = JSON.parse(value); return Array.isArray(parsed) ? parsed : [parsed]; }
            catch { return value.includes(',') ? value.split(',').map(s => s.trim()) : [value]; }
        }
        return null;
    }

    renderServiceSection(config, data, serviceName) {
        const rows = [];
        for (const field of config.fields) {
            if (field.condition && !field.condition(data)) continue;
            let value = field.getter ? field.getter(data) : data?.[field.key];
            if (field.parser) {
                if (field.parser === 'array') value = this.parseArrayField(value);
                else if (DATA_PARSERS[field.parser]) value = DATA_PARSERS[field.parser](value, data);
            }
            if (value === null || value === undefined) continue;
            let rendered = '';
            switch (field.type) {
                case 'row': rendered = this.makeRow(field.label, value, field.long); break;
                case 'inline': rendered = this.makeInlineRow(field.label, value); break;
                case 'bool':
                    if (typeof value !== 'undefined') {
                        const style = typeof field.style === 'function' ? field.style(value) : field.style;
                        rendered = this.makeBool(field.label, value, style);
                    }
                    break;
                case 'tags':
                    if (Array.isArray(value) && value.length > 0) rendered = this.makeTags(field.label, value, field.tagClass || '');
                    break;
                case 'custom':
                    if (field.renderer && this[field.renderer]) rendered = this[field.renderer](field, value, data);
                    break;
                case 'screenshot':
                    rendered = this.makeScreenshot(field.label, value);
                    break;
            }
            if (rendered) rows.push(rendered);
        }
        if (rows.length === 0) return '';
        const title = typeof config.title === 'function' ? config.title(data, serviceName) : config.title;
        return this.makeSection(title, rows);
    }

    renderSMBShares(field, shares, data) {
        if (!shares || !Array.isArray(shares) || shares.length === 0) return '';
        const shareItems = shares.map(share => `<div class="enrichment-list-item"><span class="item-name">${this.escapeHtml(share.name)}</span>${share.type ? `<span class="item-type">${this.escapeHtml(share.type)}</span>` : ''}${share.comment ? `<span class="item-comment">${this.escapeHtml(share.comment)}</span>` : ''}</div>`).join('');
        return `<div class="enrichment-row"><span class="enrichment-label">Shares</span><div class="enrichment-list">${shareItems}</div></div>`;
    }

    renderNFSExports(field, exports, data) {
        if (!exports || !Array.isArray(exports) || exports.length === 0) return '';
        const exportItems = exports.map(exp => `<div class="enrichment-list-item"><span class="item-name" style="font-family:'JetBrains Mono',monospace;font-size:11px;">${this.escapeHtml(exp.directory || 'unknown')}</span><span class="enrichment-tag info" style="font-size:10px;">${(exp.groups || []).length} client(s)</span></div>`).join('');
        return `<div class="enrichment-row"><span class="enrichment-label">NFS Exports (${exports.length})</span><div class="enrichment-list" style="max-height:200px;overflow-y:auto;">${exportItems}</div></div>`;
    }

    renderRPCServices(field, services, data) {
        if (!services || !Array.isArray(services) || services.length === 0) return '';
        const rpcItems = services.map(svc => `<div class="enrichment-list-item"><span class="item-name">${this.escapeHtml(svc.service || 'unknown')}</span><span class="item-type">${this.escapeHtml(String(svc.program || ''))}</span><span class="enrichment-tag info" style="font-size:10px">v${this.escapeHtml(String(svc.version || '?'))}</span></div>`).join('');
        return `<div class="enrichment-row"><span class="enrichment-label">Registered Programs (${services.length})</span><div class="enrichment-list" style="max-height:200px;overflow-y:auto;">${rpcItems}</div></div>`;
    }

    renderKeyValueMap(field, value, data) {
        if (!value || typeof value !== 'object') return '';
        const entries = Object.entries(value);
        if (entries.length === 0) return '';
        const items = entries.map(([k, v]) => `<div class="enrichment-list-item"><span class="item-name">${this.escapeHtml(k)}</span><span class="item-type">${this.escapeHtml(String(v))}</span></div>`).join('');
        return `<div class="enrichment-row"><span class="enrichment-label">${this.escapeHtml(field.label || 'Parameters')} (${entries.length})</span><div class="enrichment-list" style="max-height:200px;overflow-y:auto;">${items}</div></div>`;
    }

    renderTLSVersion(field, version, data) {
        if (!version) return '';
        if (typeof version === 'number') {
            const tlsVersionMap = { 769: 'TLS 1.0', 770: 'TLS 1.1', 771: 'TLS 1.2', 772: 'TLS 1.3' };
            return this.makeInlineRow('TLS Version', tlsVersionMap[version] || `0x${version.toString(16)}`);
        }
        return this.makeInlineRow('TLS Version', String(version));
    }

    renderCipherSuite(field, suite, data) {
        if (!suite) return '';
        if (typeof suite === 'number') {
            return this.makeInlineRow('Cipher Suite', `0x${suite.toString(16).toUpperCase()}`);
        }
        return this.makeInlineRow('Cipher Suite', String(suite));
    }

    renderEnrichmentData(data, fingerprintData, service) {
        if (!data && !fingerprintData) return '';
        const sections = [];
        const serviceName = service?.service?.toLowerCase() || '';
        for (const [key, config] of Object.entries(SERVICE_RENDERERS)) {
            if (config.match(serviceName, data)) {
                const section = this.renderServiceSection(config, data, serviceName);
                if (section) sections.push(section);
                break;
            }
        }
        sections.push(...this.renderGenericSections(data, fingerprintData));
        return `<div class="enrichment-data">${sections.join('')}</div>`;
    }

    renderGenericSections(data, fingerprintData) {
        const sections = [];
        if (data?.status_code || data?.response?.status_code) {
            const statusCode = data.status_code || data.response?.status_code;
            const statusLine = data.status_line || data.response?.status_line || '';
            sections.push(`<div class="enrichment-section"><div class="enrichment-title">HTTP Response</div><div class="enrichment-grid"><div class="enrichment-row inline"><span class="enrichment-label">Status</span><span class="enrichment-value status-${Math.floor(statusCode/100)}xx">${statusCode} ${this.escapeHtml(statusLine)}</span></div></div></div>`);
        }
        const headers = data?.headers || data?.response?.headers;
        if (headers && typeof headers === 'object') {
            const headerRows = [];
            for (const [key, value] of Object.entries(headers)) {
                const displayValue = Array.isArray(value) ? value.join(', ') : String(value);
                headerRows.push(this.makeRow(key, displayValue, displayValue.length > 80));
            }
            if (headerRows.length > 0) sections.push(this.makeSection('Headers', headerRows));
        }
        if (fingerprintData) {
            const fpRows = [];
            if (fingerprintData.jarm_fingerprint) fpRows.push(this.makeInlineRow('JARM', fingerprintData.jarm_fingerprint));
            if (fingerprintData.service) fpRows.push(this.makeInlineRow('Detected Service', fingerprintData.service));
            if (fingerprintData.product) fpRows.push(this.makeInlineRow('Product', fingerprintData.product));
            if (fingerprintData.version) fpRows.push(this.makeInlineRow('Version', fingerprintData.version));
            if (fpRows.length > 0) sections.push(this.makeSection('Fingerprint Info', fpRows));
        }
        return sections;
    }

    renderGenericObject(obj, depth = 0) {
        if (depth > 3) return '';
        const skipKeys = ['body', 'html', 'content', 'raw_body', 'response_body', 'raw', 'data', 'payload', 'script', 'source', 'text', 'message_body', 'enrichment_data', 'fingerprint_data', 'raw_response'];
        const rows = [];
        for (const [key, value] of Object.entries(obj)) {
            if (value === null || value === undefined) continue;
            if (skipKeys.some(sk => key.toLowerCase().includes(sk))) continue;
            if (typeof value === 'string' && value.length > 500) continue;
            const label = this.formatLabel(key);
            if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
                const dv = String(value);
                rows.push(`<div class="enrichment-row"><span class="enrichment-label">${this.escapeHtml(label)}</span><span class="enrichment-value${dv.length > 80 ? ' long-value' : ''}">${this.escapeHtml(dv)}</span></div>`);
            } else if (Array.isArray(value) && value.length > 0 && (typeof value[0] === 'string' || typeof value[0] === 'number')) {
                rows.push(`<div class="enrichment-row"><span class="enrichment-label">${this.escapeHtml(label)}</span><div class="enrichment-tags">${value.slice(0, 10).map(v => `<span class="enrichment-tag">${this.escapeHtml(String(v))}</span>`).join('')}</div></div>`);
            } else if (typeof value === 'object' && !Array.isArray(value)) {
                const nested = this.renderGenericObject(value, depth + 1);
                if (nested) rows.push(`<div class="enrichment-row"><span class="enrichment-label">${this.escapeHtml(label)}</span><div class="enrichment-grid" style="margin-left:8px;padding-left:8px;border-left:2px solid var(--border-primary);">${nested}</div></div>`);
            }
        }
        return rows.slice(0, 15).join('');
    }

    formatLabel(key) {
        return key.replace(/_/g, ' ').replace(/([a-z])([A-Z])/g, '$1 $2').replace(/\b\w/g, c => c.toUpperCase());
    }

    sanitizeId(str) {
        return String(str).replace(/[^a-zA-Z0-9_-]/g, '_');
    }

    renderSingleServiceCard(host, service, index, enrichedData, fingerprintData, domainOverride = null) {
        const serviceId = this.sanitizeId(`q-${service.service || 'open'}-${service.port}-${index}${domainOverride ? '-' + domainOverride.replace(/\./g, '_') : ''}`);
        const banner = service.banner || fingerprintData?.banner || null;
        const hasBanner = !!banner;
        const hasEnrichment = !!enrichedData;
        const hasFingerprint = !!fingerprintData;
        const hasAnyContent = hasBanner || hasEnrichment || hasFingerprint || service.product;

        if (!hasAnyContent) return '';

        const technologies = [];
        if (enrichedData?.technologies) enrichedData.technologies.forEach(t => { const name = typeof t === 'string' ? t : t?.name; if (name) technologies.push(name); });
        if (enrichedData?.server) technologies.push(enrichedData.server);
        if (fingerprintData?.product) technologies.push(fingerprintData.product);
        if (service.product && !domainOverride) technologies.push(service.product);

        const os = enrichedData?.os || fingerprintData?.os || '';
        const techTags = [...new Set(technologies)].slice(0, 5).map(tech => `<span class="tech-tag">${this.escapeHtml(String(tech))}</span>`).join('');
        const osTag = os ? `<span class="tech-tag os">${this.escapeHtml(os)}</span>` : '';
        const fingerprint = fingerprintData?.jarm_fingerprint || fingerprintData?.fingerprint || '';

        const showBannerTab = hasBanner;
        const showDetailsTab = hasEnrichment || hasFingerprint;
        const htmlBody = enrichedData?.body || '';
        const hasHtmlPreview = htmlBody && htmlBody.length > 0;
        const bannerActive = showBannerTab ? 'active' : '';
        const detailsActive = !showBannerTab && showDetailsTab ? 'active' : '';

        const jsonDataForModal = { ip: host.ip, service: service.service, port: service.port, product: service.product, version: service.version, banner: banner, fingerprint_data: fingerprintData, enrichment_data: enrichedData, domain: domainOverride };
        const jsonDataStr = JSON.stringify(jsonDataForModal).replace(/<\//g, '<\\/');

        return `
            <div class="service-item enhanced ${domainOverride ? 'domain-enrichment' : ''}">
                <script type="application/json" id="json-data-${serviceId}">${jsonDataStr}</script>
                <div class="service-header" style="padding: 6px 0;">
                    <div class="service-header-right" style="margin-left:auto;">
                        <div class="service-tabs">
                            ${showBannerTab ? `<button class="service-tab ${bannerActive}" onclick="queryPage.switchServiceTab('${serviceId}', 'banner')">BANNER</button>` : ''}
                            ${showDetailsTab ? `<button class="service-tab ${detailsActive}" onclick="queryPage.switchServiceTab('${serviceId}', 'details')">DETAILS</button>` : ''}
                            ${hasHtmlPreview ? `<button class="service-tab html-btn" onclick="queryPage.showHtmlModal('${serviceId}')" title="Preview HTML page">&lt;/&gt;</button>` : ''}
                            <button class="service-tab json-btn" onclick="queryPage.showJsonModal('${serviceId}')" title="View raw JSON">{ }</button>
                        </div>
                    </div>
                </div>
                <div class="service-content">
                    ${showBannerTab ? `<div id="${serviceId}-banner" class="service-tab-panel ${bannerActive}"><div class="tech-tags">${osTag}${techTags}</div>${fingerprint ? `<div class="fingerprint-tag">Fingerprint: <code>${this.escapeHtml(fingerprint)}</code></div>` : ''}${this.formatBanner(banner)}</div>` : ''}
                    ${showDetailsTab ? `<div id="${serviceId}-details" class="service-tab-panel ${detailsActive}">${this.renderEnrichmentData(enrichedData, fingerprintData, service)}</div>` : ''}
                </div>
            </div>
        `;
    }

    switchServiceTab(serviceId, tabName) {
        const bannerEl = document.getElementById(`${serviceId}-banner`);
        const detailsEl = document.getElementById(`${serviceId}-details`);
        const serviceElement = (bannerEl || detailsEl)?.closest('.service-item');
        if (!serviceElement) return;
        serviceElement.querySelectorAll('.service-tab').forEach(tab => tab.classList.remove('active'));
        serviceElement.querySelectorAll('.service-tab-panel').forEach(panel => panel.classList.remove('active'));
        const targetPanel = document.getElementById(`${serviceId}-${tabName}`);
        if (targetPanel) targetPanel.classList.add('active');
        serviceElement.querySelectorAll('.service-tab').forEach(tab => {
            if (tab.textContent.toLowerCase().includes(tabName.toLowerCase())) tab.classList.add('active');
        });
    }

    // ==================== JSON Modal ====================

    showJsonModal(serviceId) {
        const dataElement = document.getElementById(`json-data-${serviceId}`);
        if (!dataElement) return;
        const jsonData = JSON.parse(dataElement.textContent);
        const prettyJson = JSON.stringify(jsonData, null, 2);

        let modal = document.getElementById('json-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'json-modal';
            modal.className = 'json-modal';
            modal.innerHTML = `<div class="json-modal-backdrop"></div><div class="json-modal-content"><div class="json-modal-header"><h3>JSON Data</h3><div class="json-modal-actions"><button class="json-copy-btn" title="Copy to clipboard"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy</button><button class="json-close-btn" title="Close"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button></div></div><pre class="json-modal-body"><code></code></pre></div>`;
            document.body.appendChild(modal);
            modal.querySelector('.json-modal-backdrop').addEventListener('click', () => this.closeJsonModal());
            modal.querySelector('.json-close-btn').addEventListener('click', () => this.closeJsonModal());
            modal.querySelector('.json-copy-btn').addEventListener('click', () => this.copyJsonToClipboard());
        }
        modal.querySelector('code').textContent = prettyJson;
        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
    }

    closeJsonModal() {
        const modal = document.getElementById('json-modal');
        if (modal) { modal.classList.remove('show'); document.body.style.overflow = ''; }
    }

    copyToClipboard(text) {
        if (navigator.clipboard && window.isSecureContext) {
            return navigator.clipboard.writeText(text);
        }
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.left = '-9999px';
        document.body.appendChild(ta);
        ta.select();
        try {
            document.execCommand('copy');
        } catch (e) {
            document.body.removeChild(ta);
            return Promise.reject(e);
        }
        document.body.removeChild(ta);
        return Promise.resolve();
    }

    copyJsonToClipboard() {
        const modal = document.getElementById('json-modal');
        if (!modal) return;
        const code = modal.querySelector('code').textContent;
        const btn = modal.querySelector('.json-copy-btn');
        const orig = btn.innerHTML;
        this.copyToClipboard(code).then(() => {
            btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
            setTimeout(() => { btn.innerHTML = orig; }, 2000);
        }).catch(() => {
            btn.innerHTML = 'Failed';
            setTimeout(() => { btn.innerHTML = orig; }, 2000);
        });
    }

    // ==================== HTML Modal ====================

    showHtmlModal(serviceId) {
        const dataElement = document.getElementById(`json-data-${serviceId}`);
        if (!dataElement) return;
        const jsonData = JSON.parse(dataElement.textContent);
        const htmlBody = jsonData.enrichment_data?.body || '';
        if (!htmlBody) return;
        const ip = jsonData.ip || '';
        const port = jsonData.port || '';
        const domain = jsonData.domain || '';

        let modal = document.getElementById('html-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'html-modal';
            modal.className = 'html-modal';
            modal.innerHTML = `<div class="html-modal-backdrop"></div><div class="html-modal-content"><div class="html-modal-header"><h3>HTML Preview</h3><div class="html-modal-tabs"><button class="html-tab active" data-view="rendered">Rendered</button><button class="html-tab" data-view="source">Source</button></div><div class="html-modal-actions"><button class="html-copy-btn" title="Copy HTML source"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copy</button><button class="html-close-btn" title="Close"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button></div></div><div class="html-modal-body"><div class="html-view-rendered active"><iframe sandbox="" class="html-preview-iframe"></iframe></div><div class="html-view-source"><pre class="html-source-code"><code></code></pre></div></div></div>`;
            document.body.appendChild(modal);
            modal.querySelector('.html-modal-backdrop').addEventListener('click', () => this.closeHtmlModal());
            modal.querySelector('.html-close-btn').addEventListener('click', () => this.closeHtmlModal());
            modal.querySelector('.html-copy-btn').addEventListener('click', () => {
                const html = modal.dataset.rawHtml || '';
                const btn = modal.querySelector('.html-copy-btn');
                const orig = btn.innerHTML;
                this.copyToClipboard(html).then(() => {
                    btn.innerHTML = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"></polyline></svg> Copied!';
                    setTimeout(() => { btn.innerHTML = orig; }, 2000);
                }).catch(() => {
                    btn.innerHTML = 'Failed';
                    setTimeout(() => { btn.innerHTML = orig; }, 2000);
                });
            });
            modal.querySelectorAll('.html-tab').forEach(tab => {
                tab.addEventListener('click', (e) => {
                    const view = e.target.dataset.view;
                    modal.querySelectorAll('.html-tab').forEach(t => t.classList.remove('active'));
                    e.target.classList.add('active');
                    modal.querySelector('.html-view-rendered').classList.toggle('active', view === 'rendered');
                    modal.querySelector('.html-view-source').classList.toggle('active', view === 'source');
                });
            });
        }
        modal.querySelector('.html-source-code code').textContent = htmlBody;
        modal.dataset.rawHtml = htmlBody;
        const iframe = modal.querySelector('.html-preview-iframe');
        iframe.removeAttribute('srcdoc');

        modal.querySelectorAll('.html-tab').forEach(t => t.classList.remove('active'));
        modal.querySelector('.html-tab[data-view="rendered"]').classList.add('active');
        modal.querySelector('.html-view-rendered').classList.add('active');
        modal.querySelector('.html-view-source').classList.remove('active');

        modal.classList.add('show');
        document.body.style.overflow = 'hidden';

        const params = new URLSearchParams({ ip, port });
        if (domain) params.set('domain', domain);
        fetch(`/api/body?${params}`)
            .then(resp => { if (!resp.ok) throw new Error('No preview'); return resp.text(); })
            .then(safeHtml => { iframe.srcdoc = safeHtml; })
            .catch(() => { iframe.srcdoc = '<html><body style="display:flex;align-items:center;justify-content:center;height:100%;margin:0;font-family:sans-serif;color:#666;"><p>No preview available</p></body></html>'; });
    }

    closeHtmlModal() {
        const modal = document.getElementById('html-modal');
        if (modal) {
            modal.classList.remove('show');
            document.body.style.overflow = '';
            const iframe = modal.querySelector('.html-preview-iframe');
            if (iframe) { iframe.removeAttribute('srcdoc'); iframe.src = 'about:blank'; }
        }
    }

    // ==================== Export ====================

    async exportQuery(format) {
        if (!this.currentQuery) return;

        try {
            const params = new URLSearchParams({
                q: this.currentQuery,
                limit: 10000,
                page: 1
            });

            const response = await fetch(`/api/search/services?${params}`);
            const data = await response.json();

            if (!response.ok || !data.services || data.services.length === 0) return;

            const services = data.services;

            if (format === 'txt') {
                const txt = services.map(s => `${s.ip}:${s.port}`).join('\n');
                const blob = new Blob([txt + '\n'], { type: 'text/plain' });
                window.open(URL.createObjectURL(blob), '_blank');
            } else if (format === 'csv') {
                const headers = ['ip', 'port', 'service', 'product', 'version', 'country_code', 'as_org', 'cloud_provider'];
                const rows = services.map(s => headers.map(h => {
                    let v = s[h];
                    if (v === undefined || v === null) v = '';
                    return `"${String(v).replace(/"/g, '""')}"`;
                }).join(','));
                const csv = [headers.join(','), ...rows].join('\n');
                this.downloadBlob(csv, `query_${this.dateStamp()}.csv`, 'text/csv');
            } else {
                const json = JSON.stringify(services, null, 2);
                this.downloadBlob(json, `query_${this.dateStamp()}.json`, 'application/json');
            }
        } catch (error) {
            console.error('Export error:', error);
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
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.queryPage = new MeowQueryPage();
});
