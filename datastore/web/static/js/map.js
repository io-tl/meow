// Map Page JavaScript - Choropleth + Filters + Rankings
class MapPage {
    constructor() {
        this.map = null;
        this.geoJsonLayer = null;
        this.geoJsonData = null;
        this.countriesData = [];
        this.countryDataMap = {};
        this.selectedCountry = null;
        this.sortField = 'host_count';
        this.filters = { q: '', country: '', port: '', service: '', asn: '', cloud: '' };
        this.portDebounceTimer = null;
        this.init();
    }

    async init() {
        this.initMap();
        this.setupControls();
        this.setupFilterListeners();
        await Promise.all([
            this.loadGeoJSON(),
            this.loadFacets()
        ]);
        await this.loadMapData();
    }

    // ── Map Setup ──────────────────────────────────────────────

    initMap() {
        this.map = L.map('world-map', {
            center: [25, 0],
            zoom: 2,
            minZoom: 2,
            maxZoom: 10,
            worldCopyJump: true,
            zoomControl: false
        });

        // No tile layer: fully offline choropleth using GeoJSON only
    }

    setupControls() {
        const zoomIn = document.getElementById('zoom-in');
        const zoomOut = document.getElementById('zoom-out');
        const resetView = document.getElementById('reset-view');
        const fullscreen = document.getElementById('fullscreen');

        if (zoomIn) zoomIn.addEventListener('click', () => this.map.zoomIn());
        if (zoomOut) zoomOut.addEventListener('click', () => this.map.zoomOut());
        if (resetView) resetView.addEventListener('click', () => {
            this.map.setView([25, 0], 2);
            this.deselectCountry();
        });
        if (fullscreen) {
            fullscreen.addEventListener('click', () => {
                const el = document.querySelector('.map-content');
                if (el) {
                    el.classList.toggle('fullscreen');
                    setTimeout(() => this.map.invalidateSize(), 300);
                }
            });
        }

        // Close panel
        const closeBtn = document.getElementById('close-panel');
        if (closeBtn) closeBtn.addEventListener('click', () => this.closeCountryPanel());

        // Escape key
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') this.closeCountryPanel();
        });
    }

    // ── GeoJSON ────────────────────────────────────────────────

    async loadGeoJSON() {
        try {
            const resp = await fetch('/static/data/world.geojson');
            this.geoJsonData = await resp.json();
        } catch (err) {
            console.error('Failed to load GeoJSON:', err);
        }
    }

    // ── Facets ─────────────────────────────────────────────────

    async loadFacets() {
        try {
            const resp = await fetch('/api/facets');
            const data = await resp.json();

            this.populateSelect('filter-country', data.countries, v => v.value, v => `${v.value} (${v.count})`);
            this.populateSelect('filter-service', data.services, v => v.value, v => `${v.value} (${v.count})`);
            this.populateSelect('filter-asn', data.asns, v => String(v.value), v => `AS${v.value} ${v.label || ''} (${v.count})`);
            this.populateSelect('filter-cloud', data.cloud_providers, v => v.value, v => `${v.value} (${v.count})`);
        } catch (err) {
            console.error('Failed to load facets:', err);
        }
    }

    populateSelect(id, items, valueFn, labelFn) {
        const el = document.getElementById(id);
        if (!el || !items) return;
        const placeholder = el.options[0];
        el.innerHTML = '';
        el.appendChild(placeholder);
        items.forEach(item => {
            const opt = document.createElement('option');
            opt.value = valueFn(item);
            opt.textContent = labelFn(item);
            el.appendChild(opt);
        });
    }

    // ── Filter System ──────────────────────────────────────────

    setupFilterListeners() {
        // MeowQL search: Enter or button
        const searchInput = document.getElementById('meowql-search');
        const searchBtn = document.getElementById('search-btn');
        if (searchInput) {
            searchInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') this.applyFilters();
            });
        }
        if (searchBtn) searchBtn.addEventListener('click', () => this.applyFilters());

        // Selects: immediate
        ['filter-country', 'filter-service', 'filter-asn', 'filter-cloud'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.addEventListener('change', () => this.applyFilters());
        });

        // Port input: debounce
        const portInput = document.getElementById('filter-port');
        if (portInput) {
            portInput.addEventListener('input', () => {
                clearTimeout(this.portDebounceTimer);
                this.portDebounceTimer = setTimeout(() => this.applyFilters(), 400);
            });
            portInput.addEventListener('keydown', (e) => {
                if (e.key === 'Enter') {
                    clearTimeout(this.portDebounceTimer);
                    this.applyFilters();
                }
            });
        }

        // Clear
        const clearBtn = document.getElementById('clear-filters');
        if (clearBtn) clearBtn.addEventListener('click', () => this.clearFilters());

        // Sort
        const sortSelect = document.getElementById('sort-field');
        if (sortSelect) {
            sortSelect.addEventListener('change', (e) => {
                this.sortField = e.target.value;
                this.renderSidebar();
            });
        }
    }

    applyFilters() {
        this.filters.q = (document.getElementById('meowql-search')?.value || '').trim();
        this.filters.country = document.getElementById('filter-country')?.value || '';
        this.filters.port = (document.getElementById('filter-port')?.value || '').trim();
        this.filters.service = document.getElementById('filter-service')?.value || '';
        this.filters.asn = document.getElementById('filter-asn')?.value || '';
        this.filters.cloud = document.getElementById('filter-cloud')?.value || '';

        this.renderActiveFilters();
        this.loadMapData();
    }

    clearFilters() {
        this.filters = { q: '', country: '', port: '', service: '', asn: '', cloud: '' };
        const searchInput = document.getElementById('meowql-search');
        if (searchInput) searchInput.value = '';
        ['filter-country', 'filter-service', 'filter-asn', 'filter-cloud'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.value = '';
        });
        const portInput = document.getElementById('filter-port');
        if (portInput) portInput.value = '';

        this.renderActiveFilters();
        this.loadMapData();
    }

    renderActiveFilters() {
        const container = document.getElementById('active-filters');
        if (!container) return;

        const chips = [];
        const labels = { q: 'Query', country: 'Country', port: 'Port', service: 'Service', asn: 'ASN', cloud: 'Cloud' };

        for (const [key, val] of Object.entries(this.filters)) {
            if (!val) continue;
            chips.push(`<span class="active-chip" data-key="${key}">${labels[key]}: <strong>${this.escapeHtml(val)}</strong>
                <button class="chip-remove" data-key="${key}">&times;</button></span>`);
        }

        container.innerHTML = chips.join('');

        // Bind remove buttons
        container.querySelectorAll('.chip-remove').forEach(btn => {
            btn.addEventListener('click', (e) => {
                const key = e.target.dataset.key;
                this.filters[key] = '';
                // Also reset the corresponding input/select
                const elMap = { q: 'meowql-search', country: 'filter-country', port: 'filter-port', service: 'filter-service', asn: 'filter-asn', cloud: 'filter-cloud' };
                const el = document.getElementById(elMap[key]);
                if (el) el.value = '';
                this.renderActiveFilters();
                this.loadMapData();
            });
        });
    }

    buildQueryParams() {
        const params = new URLSearchParams();
        for (const [key, val] of Object.entries(this.filters)) {
            if (val) params.set(key, val);
        }
        return params.toString();
    }

    // ── Data Loading ───────────────────────────────────────────

    async loadMapData() {
        try {
            const qs = this.buildQueryParams();
            const url = '/api/geomap' + (qs ? '?' + qs : '');
            const resp = await fetch(url);
            const data = await resp.json();

            this.countriesData = data.countries || [];
            this.countryDataMap = {};
            this.countriesData.forEach(c => { this.countryDataMap[c.code] = c; });

            // Update topbar stats
            const totals = data.totals || {};
            this.animateNumber('total-hosts-map', totals.hosts || 0);
            this.animateNumber('total-countries-map', totals.countries || 0);
            this.animateNumber('total-asns-map', totals.asns || 0);
            this.animateNumber('total-ports-map', totals.ports || 0);

            this.renderChoropleth();
            this.renderSidebar();
            this.updateLegend();

            // Re-fetch country details if panel is open
            if (this.selectedCountry) {
                this.showCountryDetails(this.selectedCountry);
            }

        } catch (err) {
            console.error('Error loading map data:', err);
        }
    }

    // ── Choropleth Rendering ───────────────────────────────────

    getColor(value, max) {
        if (!value || value === 0) return '#111827';
        if (max <= 0) return '#111827';
        const t = Math.log10(value + 1) / Math.log10(max + 1);
        const hue = 210 - (t * 20);       // 210 → 190 (blue → cyan, subtle)
        const sat = 50 + (t * 20);         // 50% → 70%
        const light = 12 + (t * 22);       // 12% → 34% (stay dark)
        return `hsl(${hue}, ${sat}%, ${light}%)`;
    }

    renderChoropleth() {
        if (!this.geoJsonData) return;

        // Remove old layer
        if (this.geoJsonLayer) {
            this.map.removeLayer(this.geoJsonLayer);
            this.geoJsonLayer = null;
        }

        const maxCount = this.countriesData.reduce((m, c) => Math.max(m, c.host_count || 0), 0);

        this.geoJsonLayer = L.geoJSON(this.geoJsonData, {
            style: (feature) => {
                const code = feature.properties.ISO_A2;
                const d = this.countryDataMap[code];
                const count = d ? d.host_count : 0;
                return {
                    fillColor: this.getColor(count, maxCount),
                    weight: count > 0 ? 0.8 : 0.5,
                    opacity: 1,
                    color: count > 0 ? 'rgba(0, 212, 255, 0.2)' : 'rgba(255,255,255,0.12)',
                    fillOpacity: count > 0 ? 0.55 : 1,
                };
            },
            onEachFeature: (feature, layer) => {
                const code = feature.properties.ISO_A2;
                const d = this.countryDataMap[code];

                if (d && d.host_count > 0) {
                    layer.bindTooltip(
                        `<strong>${d.name || code}</strong><br>${(d.host_count || 0).toLocaleString()} hosts`,
                        { sticky: true, className: 'choropleth-tooltip' }
                    );
                }

                layer.on({
                    mouseover: (e) => {
                        if (!d || !d.host_count) return;
                        e.target.setStyle({
                            weight: 1.5,
                            color: '#00d4ff',
                            fillOpacity: 0.6,
                        });
                        e.target.bringToFront();
                    },
                    mouseout: (e) => {
                        if (this.selectedCountry !== code) {
                            this.geoJsonLayer.resetStyle(e.target);
                        }
                    },
                    click: (e) => {
                        if (!d || !d.host_count) return;
                        this.selectCountry(code, e.target);
                    }
                });
            }
        }).addTo(this.map);
    }

    updateLegend() {
        const max = this.countriesData.reduce((m, c) => Math.max(m, c.host_count || 0), 0);
        const legendMax = document.getElementById('legend-max');
        if (legendMax) legendMax.textContent = max > 0 ? max.toLocaleString() : '-';
    }

    // ── Country Selection ──────────────────────────────────────

    selectCountry(code, layer) {
        this.selectedCountry = code;

        // Highlight on map
        if (this.geoJsonLayer) this.geoJsonLayer.resetStyle();
        if (layer) {
            layer.setStyle({
                weight: 2.5,
                color: '#00d4ff',
                fillOpacity: 0.5,
            });
            layer.bringToFront();
        }

        // Zoom to country
        if (layer) {
            this.map.fitBounds(layer.getBounds(), { padding: [50, 50], maxZoom: 6 });
        }

        // Highlight sidebar row
        document.querySelectorAll('.ranking-row').forEach(r => r.classList.remove('active'));
        const row = document.querySelector(`.ranking-row[data-code="${code}"]`);
        if (row) {
            row.classList.add('active');
            row.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }

        this.showCountryDetails(code);
    }

    deselectCountry() {
        this.selectedCountry = null;
        if (this.geoJsonLayer) this.geoJsonLayer.resetStyle();
        document.querySelectorAll('.ranking-row').forEach(r => r.classList.remove('active'));
        this.closeCountryPanel();
    }

    // ── Country Details Panel ──────────────────────────────────

    async showCountryDetails(code) {
        const panel = document.getElementById('country-panel');
        if (!panel) return;

        const d = this.countryDataMap[code];
        document.getElementById('country-flag').textContent = this.countryFlag(code);
        document.getElementById('country-name').textContent = d?.name || code;

        // Show panel
        panel.classList.add('open');

        // Set summary stats from cached data
        document.getElementById('country-hosts').textContent = (d?.host_count || 0).toLocaleString();
        document.getElementById('country-ports').textContent = (d?.total_ports || 0).toLocaleString();
        document.getElementById('country-asns').textContent = (d?.unique_asns || 0).toLocaleString();
        document.getElementById('country-cloud').textContent = (d?.cloud_count || 0).toLocaleString();

        // Clear detail sections
        ['country-services', 'country-top-ports', 'country-top-asns', 'country-top-cloud', 'country-top-cities'].forEach(id => {
            const el = document.getElementById(id);
            if (el) el.innerHTML = '<div class="loading-bar"></div>';
        });

        // Fetch detailed data
        try {
            const qs = this.buildQueryParams();
            const url = `/api/geomap/country/${code}` + (qs ? '?' + qs : '');
            const resp = await fetch(url);
            const detail = await resp.json();

            // Update stats from detail response (more accurate)
            document.getElementById('country-hosts').textContent = (detail.host_count || 0).toLocaleString();
            document.getElementById('country-ports').textContent = (detail.total_ports || 0).toLocaleString();
            document.getElementById('country-asns').textContent = (detail.unique_asns || 0).toLocaleString();
            document.getElementById('country-cloud').textContent = (detail.cloud_count || 0).toLocaleString();

            this.renderBarList('country-services', detail.top_services, 'name');
            this.renderBarList('country-top-ports', detail.top_ports, 'port');
            this.renderBarList('country-top-asns', detail.top_asns, item => `AS${item.asn} ${item.as_org || ''}`);
            this.renderBarList('country-top-cloud', detail.top_cloud_providers, 'name');
            this.renderBarList('country-top-cities', detail.top_cities, 'name');

            // Browse link
            const link = document.getElementById('browse-hosts-link');
            const text = document.getElementById('browse-hosts-text');
            if (link) {
                const params = new URLSearchParams();
                params.set('country', code);
                // Forward all active filters
                if (this.filters.q) params.set('search', this.filters.q);
                if (this.filters.port) params.set('port', this.filters.port);
                if (this.filters.service) params.set('service', this.filters.service);
                if (this.filters.asn) params.set('asn', this.filters.asn);
                if (this.filters.cloud) params.set('cloud', this.filters.cloud);
                link.href = '/hosts?' + params.toString();
            }
            if (text) text.textContent = `Browse ${(detail.host_count || 0).toLocaleString()} hosts`;

        } catch (err) {
            console.error('Error loading country details:', err);
        }
    }

    renderBarList(containerId, items, labelKey) {
        const container = document.getElementById(containerId);
        if (!container) return;

        if (!items || items.length === 0) {
            container.innerHTML = '<div class="empty-list">No data</div>';
            return;
        }

        const max = items[0].count || 1;
        container.innerHTML = items.map(item => {
            const label = typeof labelKey === 'function' ? labelKey(item) : item[labelKey];
            const pct = Math.max(2, (item.count / max) * 100);
            return `<div class="bar-item">
                <div class="bar-label">${this.escapeHtml(String(label))}</div>
                <div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div>
                <div class="bar-count">${item.count.toLocaleString()}</div>
            </div>`;
        }).join('');
    }

    closeCountryPanel() {
        const panel = document.getElementById('country-panel');
        if (panel) panel.classList.remove('open');
        this.selectedCountry = null;
        if (this.geoJsonLayer) this.geoJsonLayer.resetStyle();
        document.querySelectorAll('.ranking-row').forEach(r => r.classList.remove('active'));
    }

    // ── Sidebar Rankings ───────────────────────────────────────

    renderSidebar() {
        const container = document.getElementById('country-rankings');
        if (!container) return;

        const sorted = [...this.countriesData].sort((a, b) => (b[this.sortField] || 0) - (a[this.sortField] || 0));
        const max = sorted.length > 0 ? (sorted[0][this.sortField] || 1) : 1;

        container.innerHTML = sorted.map((c, i) => {
            const val = c[this.sortField] || 0;
            const pct = Math.max(2, (val / max) * 100);
            const active = this.selectedCountry === c.code ? ' active' : '';
            return `<div class="ranking-row${active}" data-code="${c.code}">
                <span class="rank-num">${i + 1}</span>
                <span class="rank-flag">${this.countryFlag(c.code)}</span>
                <span class="rank-code">${c.code}</span>
                <div class="rank-bar-track"><div class="rank-bar-fill" style="width:${pct}%"></div></div>
                <span class="rank-value">${this.formatNum(val)}</span>
            </div>`;
        }).join('');

        // Click events
        container.querySelectorAll('.ranking-row').forEach(row => {
            row.addEventListener('click', () => {
                const code = row.dataset.code;
                // Find the GeoJSON layer for this country
                let targetLayer = null;
                if (this.geoJsonLayer) {
                    this.geoJsonLayer.eachLayer(layer => {
                        if (layer.feature?.properties?.ISO_A2 === code) {
                            targetLayer = layer;
                        }
                    });
                }
                this.selectCountry(code, targetLayer);
            });
        });
    }

    // ── Utilities ──────────────────────────────────────────────

    countryFlag(code) {
        if (!code || code.length !== 2) return '';
        return String.fromCodePoint(...code.toUpperCase().split('').map(c => c.charCodeAt(0) + 127397));
    }

    formatNum(n) {
        if (n >= 1000000) return (n / 1000000).toFixed(1) + 'M';
        if (n >= 1000) return (n / 1000).toFixed(1) + 'k';
        return String(n);
    }

    escapeHtml(str) {
        const d = document.createElement('div');
        d.textContent = str;
        return d.innerHTML;
    }

    animateNumber(elementId, targetValue) {
        const element = document.getElementById(elementId);
        if (!element) return;

        const startValue = parseInt(element.textContent.replace(/,/g, '')) || 0;
        const duration = 400;
        const startTime = performance.now();

        const animate = (currentTime) => {
            const elapsed = currentTime - startTime;
            const progress = Math.min(elapsed / duration, 1);
            const easeProgress = 1 - Math.pow(1 - progress, 3);
            const currentValue = Math.floor(startValue + (targetValue - startValue) * easeProgress);
            element.textContent = currentValue.toLocaleString();
            if (progress < 1) requestAnimationFrame(animate);
        };

        requestAnimationFrame(animate);
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.mapPage = new MapPage();
});
