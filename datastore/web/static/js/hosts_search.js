class MeowHostSearch {
    constructor() {
        this.currentPage = 1;
        this.pageSize = 50;
        this.totalResults = 0;
        this.totalPages = 1;
        this.currentQuery = '';
        this.currentFilters = {};
        this.selectedHost = null;
        this.hostDetailsCache = new Map();
        this.searchDebounceTimer = null;

        this.init();
    }

    init() {
        this.bindEvents();
        this.loadInitialData();
    }

    bindEvents() {
        // Filter chips
        document.querySelectorAll('.filter-chip').forEach(chip => {
            chip.addEventListener('click', (e) => {
                this.toggleFilterChip(e.currentTarget);
            });
        });

        // Pagination
        document.getElementById('prev-page')?.addEventListener('click', () => this.previousPage());
        document.getElementById('next-page')?.addEventListener('click', () => this.nextPage());

        // Live search with debounce
        const searchInput = document.getElementById('filter-search');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.debounceSearch(e.target.value);
            });
        }

        // Enter key submission for filter inputs
        const filterInputs = [
            'filter-search',
            'filter-country',
            'filter-port',
            'filter-technology'
        ];

        filterInputs.forEach(inputId => {
            const element = document.getElementById(inputId);
            if (element) {
                element.addEventListener('keypress', (e) => {
                    if (e.key === 'Enter') {
                        // Clear debounce timer and apply immediately
                        if (this.searchDebounceTimer) {
                            clearTimeout(this.searchDebounceTimer);
                            this.searchDebounceTimer = null;
                        }
                        this.applyAdvancedFilters();
                    }
                });
            }
        });

        // Close details panel on escape
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') {
                this.closeDetailsPanel();
            }
        });

        // Dropdown changes trigger immediate search
        ['filter-country'].forEach(id => {
            const element = document.getElementById(id);
            if (element) {
                element.addEventListener('change', () => this.applyAdvancedFilters());
            }
        });
    }

    debounceSearch(value) {
        if (this.searchDebounceTimer) {
            clearTimeout(this.searchDebounceTimer);
        }

        // Only trigger search after 400ms of no typing
        this.searchDebounceTimer = setTimeout(() => {
            if (value.length >= 2 || value.length === 0) {
                this.applyAdvancedFilters();
            }
        }, 400);
    }

    closeDetailsPanel() {
        const sidebar = document.getElementById('details-sidebar');
        if (sidebar) {
            sidebar.classList.remove('show');
            sidebar.innerHTML = `
                <div class="empty-state">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" opacity="0.3">
                        <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/>
                        <path d="M12 7v5l3 3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                    <h3>Select a Host</h3>
                    <p>Click on any host to view detailed information</p>
                </div>
            `;
        }
        // Remove active class from all host items
        document.querySelectorAll('.host-item.active').forEach(item => {
            item.classList.remove('active');
        });
    }

    async loadInitialData() {
        // Check URL params for deep-link search (e.g. /hosts?search=1.2.3.4)
        const urlParams = new URLSearchParams(window.location.search);
        const searchParam = urlParams.get('search') || '';
        if (searchParam) {
            const searchInput = document.getElementById('filter-search');
            if (searchInput) searchInput.value = searchParam;
            this.currentQuery = searchParam;
        }

        // Check URL params for filters (e.g. from map page "Browse hosts" link)
        const filterParams = ['country', 'port', 'service', 'asn', 'cloud'];
        filterParams.forEach(key => {
            const val = urlParams.get(key);
            if (val) this.currentFilters[key] = val;
        });

        await this.loadFacets();

        // Apply URL filter values to their corresponding UI elements
        filterParams.forEach(key => {
            const val = urlParams.get(key);
            if (!val) return;
            const elMap = { country: 'filter-country', port: 'filter-port', service: 'filter-service', asn: 'filter-asn', cloud: 'filter-cloud' };
            const el = document.getElementById(elMap[key]);
            if (el) el.value = val;
        });

        this.updateActiveFiltersChips();
        await this.loadHosts();

        // Auto-select first host when arriving via deep-link
        if (searchParam) {
            const firstItem = document.querySelector('.host-item');
            if (firstItem && firstItem.dataset.ip) {
                this.selectHost(firstItem.dataset.ip, firstItem);
            }
        }
    }

    async loadFacets() {
        try {
            const response = await fetch('/api/facets');
            const facets = await response.json();

            // Populate country dropdown for advanced filters
            this.populateCountryDropdown(facets.countries || []);

            // Render port facets only
            this.renderFacets('port-facets', facets.ports || []);
        } catch (error) {
            console.error('Error loading facets:', error);
        }
    }

    populateCountryDropdown(countries) {
        const select = document.getElementById('filter-country');
        if (!select) return;

        countries.forEach(country => {
            const option = document.createElement('option');
            const countryCode = country.value.toLowerCase();
            const countryName = this.getCountryName(countryCode);

            option.value = countryCode;
            option.textContent = `${countryName} (${country.count.toLocaleString()})`;
            select.appendChild(option);
        });
    }

    getCountryName(countryCode) {
        // Map of country codes to names
        const countryNames = {
            'af': 'Afghanistan',
            'al': 'Albania',
            'dz': 'Algeria',
            'as': 'American Samoa',
            'ad': 'Andorra',
            'ao': 'Angola',
            'ai': 'Anguilla',
            'aq': 'Antarctica',
            'ag': 'Antigua and Barbuda',
            'ar': 'Argentina',
            'am': 'Armenia',
            'aw': 'Aruba',
            'au': 'Australia',
            'at': 'Austria',
            'az': 'Azerbaijan',
            'bs': 'Bahamas',
            'bh': 'Bahrain',
            'bd': 'Bangladesh',
            'bb': 'Barbados',
            'by': 'Belarus',
            'be': 'Belgium',
            'bz': 'Belize',
            'bj': 'Benin',
            'bm': 'Bermuda',
            'bt': 'Bhutan',
            'bo': 'Bolivia',
            'bq': 'Bonaire, Sint Eustatius and Saba',
            'ba': 'Bosnia and Herzegovina',
            'bw': 'Botswana',
            'bv': 'Bouvet Island',
            'br': 'Brazil',
            'io': 'British Indian Ocean Territory',
            'bn': 'Brunei Darussalam',
            'bg': 'Bulgaria',
            'bf': 'Burkina Faso',
            'bi': 'Burundi',
            'cv': 'Cabo Verde',
            'kh': 'Cambodia',
            'cm': 'Cameroon',
            'ca': 'Canada',
            'ky': 'Cayman Islands',
            'cf': 'Central African Republic',
            'td': 'Chad',
            'cl': 'Chile',
            'cn': 'China',
            'cx': 'Christmas Island',
            'cc': 'Cocos (Keeling) Islands',
            'co': 'Colombia',
            'km': 'Comoros',
            'cg': 'Congo',
            'cd': 'Congo, Democratic Republic of the',
            'ck': 'Cook Islands',
            'cr': 'Costa Rica',
            'ci': 'Côte d\'Ivoire',
            'hr': 'Croatia',
            'cu': 'Cuba',
            'cw': 'Curaçao',
            'cy': 'Cyprus',
            'cz': 'Czechia',
            'dk': 'Denmark',
            'dj': 'Djibouti',
            'dm': 'Dominica',
            'do': 'Dominican Republic',
            'ec': 'Ecuador',
            'eg': 'Egypt',
            'sv': 'El Salvador',
            'gq': 'Equatorial Guinea',
            'er': 'Eritrea',
            'ee': 'Estonia',
            'sz': 'Eswatini',
            'et': 'Ethiopia',
            'fk': 'Falkland Islands (Malvinas)',
            'fo': 'Faroe Islands',
            'fj': 'Fiji',
            'fi': 'Finland',
            'fr': 'France',
            'gf': 'French Guiana',
            'pf': 'French Polynesia',
            'tf': 'French Southern Territories',
            'ga': 'Gabon',
            'gm': 'Gambia',
            'ge': 'Georgia',
            'de': 'Germany',
            'gh': 'Ghana',
            'gi': 'Gibraltar',
            'gr': 'Greece',
            'gl': 'Greenland',
            'gd': 'Grenada',
            'gp': 'Guadeloupe',
            'gu': 'Guam',
            'gt': 'Guatemala',
            'gg': 'Guernsey',
            'gn': 'Guinea',
            'gw': 'Guinea-Bissau',
            'gy': 'Guyana',
            'ht': 'Haiti',
            'hm': 'Heard Island and McDonald Islands',
            'va': 'Holy See',
            'hn': 'Honduras',
            'hk': 'Hong Kong',
            'hu': 'Hungary',
            'is': 'Iceland',
            'in': 'India',
            'id': 'Indonesia',
            'ir': 'Iran, Islamic Republic of',
            'iq': 'Iraq',
            'ie': 'Ireland',
            'im': 'Isle of Man',
            'il': 'Israel',
            'it': 'Italy',
            'jm': 'Jamaica',
            'jp': 'Japan',
            'je': 'Jersey',
            'jo': 'Jordan',
            'kz': 'Kazakhstan',
            'ke': 'Kenya',
            'ki': 'Kiribati',
            'kp': 'Korea, Democratic People\'s Republic of',
            'kr': 'Korea, Republic of',
            'kw': 'Kuwait',
            'kg': 'Kyrgyzstan',
            'la': 'Lao People\'s Democratic Republic',
            'lv': 'Latvia',
            'lb': 'Lebanon',
            'ls': 'Lesotho',
            'lr': 'Liberia',
            'ly': 'Libya',
            'li': 'Liechtenstein',
            'lt': 'Lithuania',
            'lu': 'Luxembourg',
            'mo': 'Macao',
            'mg': 'Madagascar',
            'mw': 'Malawi',
            'my': 'Malaysia',
            'mv': 'Maldives',
            'ml': 'Mali',
            'mt': 'Malta',
            'mh': 'Marshall Islands',
            'mq': 'Martinique',
            'mr': 'Mauritania',
            'mu': 'Mauritius',
            'yt': 'Mayotte',
            'mx': 'Mexico',
            'fm': 'Micronesia, Federated States of',
            'md': 'Moldova, Republic of',
            'mc': 'Monaco',
            'mn': 'Mongolia',
            'me': 'Montenegro',
            'ms': 'Montserrat',
            'ma': 'Morocco',
            'mz': 'Mozambique',
            'mm': 'Myanmar',
            'na': 'Namibia',
            'nr': 'Nauru',
            'np': 'Nepal',
            'nl': 'Netherlands',
            'nc': 'New Caledonia',
            'nz': 'New Zealand',
            'ni': 'Nicaragua',
            'ne': 'Niger',
            'ng': 'Nigeria',
            'nu': 'Niue',
            'nf': 'Norfolk Island',
            'mk': 'North Macedonia',
            'mp': 'Northern Mariana Islands',
            'no': 'Norway',
            'om': 'Oman',
            'pk': 'Pakistan',
            'pw': 'Palau',
            'ps': 'Palestine, State of',
            'pa': 'Panama',
            'pg': 'Papua New Guinea',
            'py': 'Paraguay',
            'pe': 'Peru',
            'ph': 'Philippines',
            'pn': 'Pitcairn',
            'pl': 'Poland',
            'pt': 'Portugal',
            'pr': 'Puerto Rico',
            'qa': 'Qatar',
            're': 'Réunion',
            'ro': 'Romania',
            'ru': 'Russian Federation',
            'rw': 'Rwanda',
            'bl': 'Saint Barthélemy',
            'sh': 'Saint Helena, Ascension and Tristan da Cunha',
            'kn': 'Saint Kitts and Nevis',
            'lc': 'Saint Lucia',
            'mf': 'Saint Martin (French part)',
            'pm': 'Saint Pierre and Miquelon',
            'vc': 'Saint Vincent and the Grenadines',
            'ws': 'Samoa',
            'sm': 'San Marino',
            'st': 'Sao Tome and Principe',
            'sa': 'Saudi Arabia',
            'sn': 'Senegal',
            'rs': 'Serbia',
            'sc': 'Seychelles',
            'sl': 'Sierra Leone',
            'sg': 'Singapore',
            'sx': 'Sint Maarten (Dutch part)',
            'sk': 'Slovakia',
            'si': 'Slovenia',
            'sb': 'Solomon Islands',
            'so': 'Somalia',
            'za': 'South Africa',
            'gs': 'South Georgia and the South Sandwich Islands',
            'ss': 'South Sudan',
            'es': 'Spain',
            'lk': 'Sri Lanka',
            'sd': 'Sudan',
            'sr': 'Suriname',
            'sj': 'Svalbard and Jan Mayen',
            'se': 'Sweden',
            'ch': 'Switzerland',
            'sy': 'Syrian Arab Republic',
            'tw': 'Taiwan, Province of China',
            'tj': 'Tajikistan',
            'tz': 'Tanzania, United Republic of',
            'th': 'Thailand',
            'tl': 'Timor-Leste',
            'tg': 'Togo',
            'tk': 'Tokelau',
            'to': 'Tonga',
            'tt': 'Trinidad and Tobago',
            'tn': 'Tunisia',
            'tr': 'Turkey',
            'tm': 'Turkmenistan',
            'tc': 'Turks and Caicos Islands',
            'tv': 'Tuvalu',
            'ug': 'Uganda',
            'ua': 'Ukraine',
            'ae': 'United Arab Emirates',
            'gb': 'United Kingdom of Great Britain and Northern Ireland',
            'us': 'United States of America',
            'um': 'United States Minor Outlying Islands',
            'uy': 'Uruguay',
            'uz': 'Uzbekistan',
            'vu': 'Vanuatu',
            've': 'Venezuela, Bolivarian Republic of',
            'vn': 'Viet Nam',
            'vg': 'Virgin Islands, British',
            'vi': 'Virgin Islands, U.S.',
            'wf': 'Wallis and Futuna',
            'eh': 'Western Sahara',
            'ye': 'Yemen',
            'zm': 'Zambia',
            'zw': 'Zimbabwe'
        };

        return countryNames[countryCode] || countryCode.toUpperCase();
    }

    renderFacets(elementId, items) {
        const container = document.getElementById(elementId);
        if (!container) return;

        container.innerHTML = items.slice(0, 10).map(item => {
            // For countries, use the getCountryName function
            let displayName = item.label || item.value || item.name;
            if (elementId === 'country-facets') {
                displayName = this.getCountryName(item.value.toLowerCase());
            }
            const count = item.count.toLocaleString();
            return `
                <li onclick="meowSearch.addFacetFilter('${elementId}', '${this.escapeHtml(item.value)}')">
                    <a href="#">${this.escapeHtml(displayName)}</a>
                    <span>${count}</span>
                </li>
            `;
        }).join('');
    }

    addFacetFilter(elementId, value) {
        // Determine filter type from element ID and map to API parameters
        const filterType = elementId.replace('-facets', '');

        // Map facet types to API parameters and sync form inputs
        switch(filterType) {
            case 'country': {
                this.currentFilters.country = value.toUpperCase();
                const el = document.getElementById('filter-country');
                if (el) el.value = value.toUpperCase();
                break;
            }
            case 'service':
                this.currentFilters.service = value;
                break;
            case 'port': {
                this.currentFilters.port = value;
                const el = document.getElementById('filter-port');
                if (el) el.value = value;
                break;
            }
            case 'org': {
                const asnMatch = value.match(/^AS(\d+)/);
                if (asnMatch) {
                    this.currentFilters.asn = asnMatch[1];
                }
                break;
            }
            default:
                this.currentFilters[filterType] = value;
        }

        this.currentPage = 1;
        this.loadHosts();
        this.updateActiveFiltersChips();
    }

    async loadHosts() {
        this.showListLoading();

        try {
            const params = new URLSearchParams({
                page: this.currentPage,
                limit: this.pageSize
            });

            // Add filters
            Object.keys(this.currentFilters).forEach(key => {
                if (this.currentFilters[key]) {
                    params.set(key, this.currentFilters[key]);
                }
            });

            // Add search query
            if (this.currentQuery) {
                params.set('q', this.currentQuery);
            }

            const response = await fetch(`/api/hosts?${params}`);
            const data = await response.json();

            this.renderHosts(data.hosts || []);
            this.updatePagination({
                current_page: data.page || 1,
                total_pages: Math.ceil((data.total || 0) / this.pageSize),
                total: data.total || 0
            });
        } catch (error) {
            console.error('Error loading hosts:', error);
            this.showError('Failed to load hosts');
        } finally {
            this.hideListLoading();
        }
    }

    applyAdvancedFilters() {
        // Get values from advanced filter inputs
        const searchValue = document.getElementById('filter-search')?.value.trim() || '';
        const countryValue = document.getElementById('filter-country')?.value || '';
        const portValue = document.getElementById('filter-port')?.value.trim() || '';
        const technologyValue = document.getElementById('filter-technology')?.value.trim() || '';
        const verifiedChecked = document.getElementById('filter-verified')?.checked || false;

        // Build filters object
        this.currentFilters = {};

        if (searchValue) {
            this.currentQuery = searchValue;
        } else {
            this.currentQuery = '';
        }

        if (countryValue) {
            this.currentFilters.country = countryValue.toUpperCase(); // API expects uppercase country codes
        }

        if (portValue) {
            // Handle comma-separated ports
            const ports = portValue.split(',').map(p => p.trim()).filter(p => p);
            if (ports.length > 0) {
                this.currentFilters.port = ports[0]; // API supports single port for now
            }
        }

        if (technologyValue) {
            this.currentFilters.technology = technologyValue;
        }

        if (verifiedChecked) {
            this.currentFilters.verified = 'true';
        }

        // Reset to first page and reload
        this.currentPage = 1;
        this.loadHosts();
        this.updateActiveFiltersChips();
    }

    updateActiveFiltersChips() {
        const container = document.getElementById('active-filters');
        const chipsContainer = document.getElementById('active-filters-chips');

        if (!container || !chipsContainer) return;

        const chips = [];

        // Add chip for search query
        if (this.currentQuery) {
            chips.push(this.createFilterChip('Search', this.currentQuery, 'search'));
        }

        // Add chip for country
        if (this.currentFilters.country) {
            const countryName = this.getCountryName(this.currentFilters.country.toLowerCase());
            chips.push(this.createFilterChip('Country', countryName, 'country'));
        }

        // Add chip for port
        if (this.currentFilters.port) {
            chips.push(this.createFilterChip('Port', this.currentFilters.port, 'port'));
        }

        // Add chip for service
        if (this.currentFilters.service) {
            chips.push(this.createFilterChip('Service', this.currentFilters.service, 'service'));
        }

        // Add chip for ASN
        if (this.currentFilters.asn) {
            chips.push(this.createFilterChip('ASN', 'AS' + this.currentFilters.asn, 'asn'));
        }

        // Add chip for cloud
        if (this.currentFilters.cloud) {
            chips.push(this.createFilterChip('Cloud', this.currentFilters.cloud, 'cloud'));
        }

        // Add chip for technology
        if (this.currentFilters.technology) {
            chips.push(this.createFilterChip('Technology', this.currentFilters.technology, 'technology'));
        }

        // Add chip for verified filter
        if (this.currentFilters.verified) {
            chips.push(this.createFilterChip('Filter', 'Verified only', 'verified'));
        }

        // Show/hide container based on whether there are active filters
        if (chips.length > 0) {
            chipsContainer.innerHTML = chips.join('');
            container.style.display = 'flex';
        } else {
            container.style.display = 'none';
        }
    }

    createFilterChip(label, value, filterType) {
        return `
            <div class="filter-chip">
                <span class="filter-chip-label">${label}:</span>
                <span class="filter-chip-value">${this.escapeHtml(value)}</span>
                <button class="filter-chip-remove" onclick="meowSearch.removeFilter('${filterType}')" title="Remove filter">
                    <svg viewBox="0 0 24 24" fill="none">
                        <path d="M18 6L6 18M6 6l12 12" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                </button>
            </div>
        `;
    }

    removeFilter(filterType) {
        switch (filterType) {
            case 'search':
                this.currentQuery = '';
                document.getElementById('filter-search').value = '';
                break;
            case 'country':
                delete this.currentFilters.country;
                document.getElementById('filter-country').value = '';
                break;
            case 'port':
                delete this.currentFilters.port;
                document.getElementById('filter-port').value = '';
                break;
            case 'technology':
                delete this.currentFilters.technology;
                document.getElementById('filter-technology').value = '';
                break;
            case 'service':
                delete this.currentFilters.service;
                break;
            case 'asn':
                delete this.currentFilters.asn;
                break;
            case 'cloud':
                delete this.currentFilters.cloud;
                break;
            case 'verified':
                delete this.currentFilters.verified;
                const verifiedCheckbox = document.getElementById('filter-verified');
                if (verifiedCheckbox) verifiedCheckbox.checked = false;
                break;
        }
        this.currentPage = 1;
        this.loadHosts();
        this.updateActiveFiltersChips();
    }

    clearFilters() {
        // Clear all filter inputs
        const filterSearch = document.getElementById('filter-search');
        const filterCountry = document.getElementById('filter-country');
        const filterPort = document.getElementById('filter-port');
        const filterTechnology = document.getElementById('filter-technology');

        const filterVerified = document.getElementById('filter-verified');

        if (filterSearch) filterSearch.value = '';
        if (filterCountry) filterCountry.value = '';
        if (filterPort) filterPort.value = '';
        if (filterTechnology) filterTechnology.value = '';
        if (filterVerified) filterVerified.checked = false;

        // Clear search input
        const searchInput = document.getElementById('search-query');
        if (searchInput) {
            searchInput.value = '';
        }

        // Reset all filters
        this.currentFilters = {};
        this.currentQuery = '';
        this.currentPage = 1;

        // Update chips display
        this.updateActiveFiltersChips();

        // Clear active filter chips
        document.querySelectorAll('.filter-chip.active').forEach(chip => {
            chip.classList.remove('active');
        });

        // Reload hosts
        this.loadHosts();
    }

    async loadHostPortsAsync(ip) {
        try {
            const response = await fetch(`/api/hosts/${ip}`);
            const host = await response.json();

            // Cache the result
            this.hostDetailsCache.set(ip, host);

            const services = host.services || [];
            const portTags = this.generatePortTags(services);

            // Update the UI
            const portsContainer = document.getElementById(`ports-${ip.replace(/\./g, '-')}`);
            if (portsContainer) {
                portsContainer.innerHTML = portTags;
            }
        } catch (error) {
            console.error(`Error loading ports for ${ip}:`, error);
            const portsContainer = document.getElementById(`ports-${ip.replace(/\./g, '-')}`);
            if (portsContainer) {
                portsContainer.innerHTML = '';
            }
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // Check if string contains binary/non-printable characters
    isBinaryString(str) {
        if (!str) return false;
        // Count non-printable characters (except common whitespace)
        let nonPrintable = 0;
        for (let i = 0; i < Math.min(str.length, 500); i++) {
            const code = str.charCodeAt(i);
            // Allow tab(9), newline(10), carriage return(13), and printable ASCII (32-126)
            if (code < 32 && code !== 9 && code !== 10 && code !== 13) {
                nonPrintable++;
            } else if (code > 126 && code < 160) {
                nonPrintable++;
            }
        }
        // If more than 10% non-printable, consider it binary
        return nonPrintable > str.length * 0.1;
    }

    // Format binary data as hexdump
    formatHexdump(str) {
        if (!str) return '';
        const lines = [];
        const bytes = new TextEncoder().encode(str);
        const bytesPerLine = 16;

        for (let offset = 0; offset < bytes.length && offset < 256; offset += bytesPerLine) {
            const chunk = bytes.slice(offset, offset + bytesPerLine);

            // Offset
            const offsetHex = offset.toString(16).padStart(8, '0');

            // Hex values
            let hexPart = '';
            let asciiPart = '';
            for (let i = 0; i < bytesPerLine; i++) {
                if (i < chunk.length) {
                    hexPart += chunk[i].toString(16).padStart(2, '0') + ' ';
                    // ASCII representation (printable chars only)
                    const charCode = chunk[i];
                    asciiPart += (charCode >= 32 && charCode <= 126) ? String.fromCharCode(charCode) : '.';
                } else {
                    hexPart += '   ';
                    asciiPart += ' ';
                }
                if (i === 7) hexPart += ' '; // Extra space in middle
            }

            lines.push(`<span class="hex-offset">${offsetHex}</span>  <span class="hex-bytes">${hexPart}</span> <span class="hex-ascii">|${asciiPart}|</span>`);
        }

        if (bytes.length > 256) {
            lines.push(`<span class="hex-truncated">... (${bytes.length - 256} more bytes)</span>`);
        }

        return lines.join('\n');
    }

    // Format banner - use hexdump if binary
    formatBanner(banner) {
        if (!banner) return '';
        if (this.isBinaryString(banner)) {
            return `<pre class="banner-text hexdump">${this.formatHexdump(banner)}</pre>`;
        }
        return `<pre class="banner-text">${this.escapeHtml(banner)}</pre>`;
    }

    // ==================== Field Rendering Methods ====================

    // Create a row with label on top for long values
    makeRow(label, value, isLong = false) {
        if (!value) return '';
        const displayValue = String(value);
        const longClass = isLong || displayValue.length > 60 ? ' long-value' : '';
        return `
            <div class="enrichment-row">
                <span class="enrichment-label">${this.escapeHtml(label)}</span>
                <span class="enrichment-value${longClass}">${this.escapeHtml(displayValue)}</span>
            </div>
        `;
    }

    // Create inline row for short key-value pairs
    makeInlineRow(label, value) {
        if (!value) return '';
        return `
            <div class="enrichment-row inline">
                <span class="enrichment-label">${this.escapeHtml(label)}</span>
                <span class="enrichment-value">${this.escapeHtml(String(value))}</span>
            </div>
        `;
    }

    // Render boolean indicators
    makeBool(label, value, style = null) {
        const cls = style || (value ? 'true' : 'false');
        const text = value ? 'Yes' : 'No';
        return `
            <div class="enrichment-row inline">
                <span class="enrichment-label">${this.escapeHtml(label)}</span>
                <span class="enrichment-bool ${cls}"><span class="indicator"></span>${text}</span>
            </div>
        `;
    }

    // Render tags/features
    makeTags(label, items, tagClass = '') {
        if (!items || !Array.isArray(items) || items.length === 0) return '';
        return `
            <div class="enrichment-row">
                <span class="enrichment-label">${this.escapeHtml(label)}</span>
                <div class="enrichment-tags">${items.map(item =>
                    `<span class="enrichment-tag ${tagClass}">${this.escapeHtml(String(item))}</span>`
                ).join('')}</div>
            </div>
        `;
    }

    // Render a complete section
    makeSection(title, rows) {
        if (!rows || rows.length === 0) return '';
        return `
            <div class="enrichment-section">
                <div class="enrichment-title">${title}</div>
                <div class="enrichment-grid">${rows.join('')}</div>
            </div>
        `;
    }

    // Parse array field that might be string, JSON string, or already an array
    parseArrayField(value) {
        if (!value) return null;
        if (Array.isArray(value)) return value;
        if (typeof value === 'string') {
            try {
                const parsed = JSON.parse(value);
                return Array.isArray(parsed) ? parsed : [parsed];
            } catch {
                return value.includes(',') ? value.split(',').map(s => s.trim()) : [value];
            }
        }
        return null;
    }

    // ==================== Generic Service Renderer ====================

    // Render a service section based on configuration
    renderServiceSection(config, data, serviceName) {
        const rows = [];

        for (const field of config.fields) {
            // Check optional condition
            if (field.condition && !field.condition(data)) continue;

            // Get value using getter or direct key
            let value = field.getter ? field.getter(data) : data?.[field.key];

            // Parse if needed
            if (field.parser) {
                if (field.parser === 'array') {
                    value = this.parseArrayField(value);
                } else if (DATA_PARSERS[field.parser]) {
                    value = DATA_PARSERS[field.parser](value, data);
                }
            }

            // Skip if no value
            if (value === null || value === undefined) continue;

            // Render based on type
            let rendered = '';
            switch (field.type) {
                case 'row':
                    rendered = this.makeRow(field.label, value, field.long);
                    break;
                case 'inline':
                    rendered = this.makeInlineRow(field.label, value);
                    break;
                case 'bool':
                    if (typeof value !== 'undefined') {
                        // Style can be a function or a direct value
                        const style = typeof field.style === 'function' ? field.style(value) : field.style;
                        rendered = this.makeBool(field.label, value, style);
                    }
                    break;
                case 'tags':
                    if (Array.isArray(value) && value.length > 0) {
                        rendered = this.makeTags(field.label, value, field.tagClass || '');
                    }
                    break;
                case 'custom':
                    if (field.renderer && this[field.renderer]) {
                        rendered = this[field.renderer](field, value, data);
                    }
                    break;
            }

            if (rendered) rows.push(rendered);
        }

        if (rows.length === 0) return '';

        // Get title (can be string or function)
        const title = typeof config.title === 'function'
            ? config.title(data, serviceName)
            : config.title;

        return this.makeSection(title, rows);
    }

    // Custom renderer for SMB shares
    renderSMBShares(field, shares, data) {
        if (!shares || !Array.isArray(shares) || shares.length === 0) return '';

        const shareItems = shares.map(share => `
            <div class="enrichment-list-item">
                <span class="item-name">${this.escapeHtml(share.name)}</span>
                ${share.type ? `<span class="item-type">${this.escapeHtml(share.type)}</span>` : ''}
                ${share.comment ? `<span class="item-comment">${this.escapeHtml(share.comment)}</span>` : ''}
            </div>
        `).join('');

        return `
            <div class="enrichment-row">
                <span class="enrichment-label">Shares</span>
                <div class="enrichment-list">${shareItems}</div>
            </div>
        `;
    }

    // Custom renderer for NFS exports
    renderNFSExports(field, exports, data) {
        if (!exports || !Array.isArray(exports) || exports.length === 0) return '';

        const exportItems = exports.map(exp => `
            <div class="enrichment-list-item">
                <span class="item-name" style="font-family: 'JetBrains Mono', monospace; font-size: 11px;">${this.escapeHtml(exp.directory || 'unknown')}</span>
                <span class="enrichment-tag info" style="font-size: 10px;">${(exp.groups || []).length} client(s)</span>
            </div>
            <div style="padding-left: 12px; margin-bottom: 8px;">
                ${(exp.groups || []).map(g => `<span class="enrichment-tag" style="font-size: 10px; margin: 2px;">${this.escapeHtml(g)}</span>`).join('')}
            </div>
        `).join('');

        return `
            <div class="enrichment-row">
                <span class="enrichment-label">NFS Exports (${exports.length})</span>
                <div class="enrichment-list" style="max-height: 200px; overflow-y: auto;">${exportItems}</div>
            </div>
        `;
    }

    // Custom renderer for RPC services list
    renderRPCServices(field, services, data) {
        if (!services || !Array.isArray(services) || services.length === 0) return '';

        const rpcItems = services.map(svc => `
            <div class="enrichment-list-item">
                <span class="item-name">${this.escapeHtml(svc.service || 'unknown')}</span>
                <span class="item-type">${this.escapeHtml(String(svc.program || ''))}</span>
                <span class="enrichment-tag info" style="font-size:10px">v${this.escapeHtml(String(svc.version || '?'))}</span>
                <span class="enrichment-tag" style="font-size:10px">${this.escapeHtml(svc.netid || '')}</span>
            </div>
        `).join('');

        return `
            <div class="enrichment-row">
                <span class="enrichment-label">Registered Programs (${services.length})</span>
                <div class="enrichment-list" style="max-height: 200px; overflow-y: auto;">${rpcItems}</div>
            </div>
        `;
    }

    // Custom renderer for key-value map (e.g. PostgreSQL parameters)
    renderKeyValueMap(field, value, data) {
        if (!value || typeof value !== 'object') return '';
        const entries = Object.entries(value);
        if (entries.length === 0) return '';
        const items = entries.map(([k, v]) => `<div class="enrichment-list-item"><span class="item-name">${this.escapeHtml(k)}</span><span class="item-type">${this.escapeHtml(String(v))}</span></div>`).join('');
        return `<div class="enrichment-row"><span class="enrichment-label">${this.escapeHtml(field.label || 'Parameters')} (${entries.length})</span><div class="enrichment-list" style="max-height:200px;overflow-y:auto;">${items}</div></div>`;
    }

    // Custom renderer for TLS version (backward compat: handles both numeric and string)
    renderTLSVersion(field, version, data) {
        if (!version) return '';
        if (typeof version === 'number') {
            const tlsVersionMap = { 769: 'TLS 1.0', 770: 'TLS 1.1', 771: 'TLS 1.2', 772: 'TLS 1.3' };
            return this.makeInlineRow('TLS Version', tlsVersionMap[version] || `0x${version.toString(16)}`);
        }
        return this.makeInlineRow('TLS Version', String(version));
    }

    // Custom renderer for cipher suite (backward compat: handles both numeric and string)
    renderCipherSuite(field, suite, data) {
        if (!suite) return '';
        if (typeof suite === 'number') {
            return this.makeInlineRow('Cipher Suite', `0x${suite.toString(16).toUpperCase()}`);
        }
        return this.makeInlineRow('Cipher Suite', String(suite));
    }

    // ==================== Main Render Function ====================

    renderEnrichmentData(data, fingerprintData, service) {
        if (!data && !fingerprintData) return '';

        const sections = [];
        const serviceName = service?.service?.toLowerCase() || '';

        // Try to match and render using config
        for (const [key, config] of Object.entries(SERVICE_RENDERERS)) {
            if (config.match(serviceName, data)) {
                const section = this.renderServiceSection(config, data, serviceName);
                if (section) sections.push(section);
                break; // Only use first match
            }
        }

        // Render generic sections (HTTP, Headers, TLS, etc.) - applies to all services
        sections.push(...this.renderGenericSections(data, fingerprintData));

        return `<div class="enrichment-data">${sections.join('')}</div>`;
    }

    // Render generic sections that apply to multiple service types
    renderGenericSections(data, fingerprintData) {
        const sections = [];

        // ============ HTTP Response ============
        if (data?.status_code || data?.response?.status_code) {
            const statusCode = data.status_code || data.response?.status_code;
            const statusLine = data.status_line || data.response?.status_line || '';
            sections.push(`
                <div class="enrichment-section">
                    <div class="enrichment-title">HTTP Response</div>
                    <div class="enrichment-grid">
                        <div class="enrichment-row inline">
                            <span class="enrichment-label">Status</span>
                            <span class="enrichment-value status-${Math.floor(statusCode/100)}xx">${statusCode} ${this.escapeHtml(statusLine)}</span>
                        </div>
                    </div>
                </div>
            `);
        }

        // ============ Headers ============
        const headers = data?.headers || data?.response?.headers;
        if (headers && typeof headers === 'object') {
            const headerRows = [];
            for (const [key, value] of Object.entries(headers)) {
                const displayValue = Array.isArray(value) ? value.map(v => typeof v === 'object' && v !== null ? JSON.stringify(v) : String(v)).join(', ') : (typeof value === 'object' && value !== null ? JSON.stringify(value) : String(value));
                const isLong = displayValue.length > 80;
                headerRows.push(this.makeRow(key, displayValue, isLong));
            }

            if (headerRows.length > 0) {
                sections.push(this.makeSection('Headers', headerRows));
            }
        }

        // ============ Fingerprint Data ============
        if (fingerprintData) {
            const fpRows = [];
            if (fingerprintData.jarm_fingerprint) {
                fpRows.push(this.makeInlineRow('JARM', fingerprintData.jarm_fingerprint));
            }
            if (fingerprintData.service) fpRows.push(this.makeInlineRow('Detected Service', fingerprintData.service));
            if (fingerprintData.product) fpRows.push(this.makeInlineRow('Product', fingerprintData.product));
            if (fingerprintData.version) fpRows.push(this.makeInlineRow('Version', fingerprintData.version));

            if (fpRows.length > 0) {
                sections.push(this.makeSection('Fingerprint Info', fpRows));
            }
        }

        return sections;
    }

    // ============ Fallback: render all data recursively ============
    renderGenericFallback(data, fingerprintData) {
        const rawData = data || fingerprintData;
        if (rawData) {
            const genericRows = this.renderGenericObject(rawData, 0);
            if (genericRows) {
                return `
                    <div class="enrichment-data">
                        <div class="enrichment-section">
                            <div class="enrichment-title">Details</div>
                            <div class="enrichment-grid">${genericRows}</div>
                        </div>
                    </div>
                `;
            }
        }

        return '';
    }

    // Helper to recursively render objects for fallback
    renderGenericObject(obj, depth = 0) {
        if (depth > 3) return ''; // Limit depth

        // Keys to skip (sensitive, too large, or potentially dangerous)
        const skipKeys = [
            'body', 'html', 'content', 'raw_body', 'response_body', 'raw',
            'data', 'payload', 'script', 'source', 'text', 'message_body',
            'enrichment_data', 'fingerprint_data', 'raw_response'
        ];

        const rows = [];
        for (const [key, value] of Object.entries(obj)) {
            if (value === null || value === undefined) continue;

            // Skip potentially dangerous HTML content fields
            const keyLower = key.toLowerCase();
            if (skipKeys.some(sk => keyLower.includes(sk))) continue;

            // Skip very long string values (likely HTML/JSON content)
            if (typeof value === 'string' && value.length > 500) continue;

            const label = this.formatLabel(key);

            if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
                const displayValue = String(value);
                const isLong = displayValue.length > 80;
                rows.push(`
                    <div class="enrichment-row">
                        <span class="enrichment-label">${this.escapeHtml(label)}</span>
                        <span class="enrichment-value${isLong ? ' long-value' : ''}">${this.escapeHtml(displayValue)}</span>
                    </div>
                `);
            } else if (Array.isArray(value)) {
                if (value.length > 0 && (typeof value[0] === 'string' || typeof value[0] === 'number')) {
                    rows.push(`
                        <div class="enrichment-row">
                            <span class="enrichment-label">${this.escapeHtml(label)}</span>
                            <div class="enrichment-tags">${value.slice(0, 10).map(v =>
                                `<span class="enrichment-tag">${this.escapeHtml(String(v))}</span>`
                            ).join('')}</div>
                        </div>
                    `);
                }
            } else if (typeof value === 'object') {
                const nested = this.renderGenericObject(value, depth + 1);
                if (nested) {
                    rows.push(`
                        <div class="enrichment-row">
                            <span class="enrichment-label">${this.escapeHtml(label)}</span>
                            <div class="enrichment-grid" style="margin-left: 8px; padding-left: 8px; border-left: 2px solid var(--border-primary);">${nested}</div>
                        </div>
                    `);
                }
            }
        }
        return rows.slice(0, 15).join('');
    }

    // Format snake_case/camelCase to Title Case
    formatLabel(key) {
        return key
            .replace(/_/g, ' ')
            .replace(/([a-z])([A-Z])/g, '$1 $2')
            .replace(/\b\w/g, c => c.toUpperCase());
    }

    // Sanitize string for use as HTML ID (remove special chars)
    sanitizeId(str) {
        return String(str).replace(/[^a-zA-Z0-9_-]/g, '_');
    }

    // Render a single service card
    renderSingleServiceCard(host, service, index, enrichedData, fingerprintData, domainOverride = null) {
        const serviceId = this.sanitizeId(`${service.service || 'open'}-${service.port}-${index}${domainOverride ? '-' + domainOverride.replace(/\./g, '_') : ''}`);
        // Banner can come from service.banner or fingerprintData.banner
        const banner = service.banner || fingerprintData?.banner || null;
        const hasBanner = !!banner;
        const hasEnrichment = !!enrichedData;
        const hasFingerprint = !!fingerprintData;

        const hasServiceName = service.service && service.service !== 'unknown';
        const hasAnyContent = hasBanner || hasEnrichment || hasFingerprint || service.product;

        // Build service title with domain or IP
        const serviceLabel = hasServiceName ? service.service : 'open';
        const hostPart = domainOverride || host.ip;
        const serviceTitle = `${hostPart}:${service.port} ${serviceLabel}`;

        // Extract technologies (handle both string and object formats)
        const technologies = [];
        if (enrichedData?.technologies) {
            enrichedData.technologies.forEach(t => {
                const name = typeof t === 'string' ? t : t?.name;
                if (name) technologies.push(name);
            });
        }
        if (enrichedData?.server) {
            technologies.push(enrichedData.server);
        }
        if (fingerprintData?.product) {
            technologies.push(fingerprintData.product);
        }
        if (service.product && !domainOverride) {
            technologies.push(service.product);
        }

        const os = enrichedData?.os || fingerprintData?.os || '';
        const techTags = [...new Set(technologies)].slice(0, 5).map(tech =>
            `<span class="tech-tag">${this.escapeHtml(String(tech))}</span>`
        ).join('');
        const osTag = os ? `<span class="tech-tag os">${this.escapeHtml(os)}</span>` : '';
        const fingerprint = fingerprintData?.jarm_fingerprint || fingerprintData?.fingerprint || '';

        const showBannerTab = hasBanner;
        const showDetailsTab = hasEnrichment || hasFingerprint;
        // Check if we have HTML body content to preview
        const htmlBody = enrichedData?.body || '';
        const hasHtmlPreview = htmlBody && htmlBody.length > 0;
        const bannerActive = showBannerTab ? 'active' : '';
        const detailsActive = !showBannerTab && showDetailsTab ? 'active' : '';

        // Status code badge for domain enrichments
        const statusCode = enrichedData?.status_code;
        const statusBadge = statusCode
            ? `<span class="status-badge status-${Math.floor(statusCode/100)}xx">${statusCode}</span>`
            : '';

        // Prepare JSON data for modal (combine all available data)
        const jsonDataForModal = {
            ip: host.ip,
            service: service.service,
            port: service.port,
            product: service.product,
            version: service.version,
            banner: banner,
            fingerprint_data: fingerprintData,
            enrichment_data: enrichedData,
            domain: domainOverride
        };
        // Escape </script> tags in JSON to prevent XSS when embedding in script tag
        const jsonDataStr = JSON.stringify(jsonDataForModal).replace(/<\//g, '<\\/');

        if (!hasAnyContent) {
            return `
                <div class="service-item enhanced service-minimal">
                    <div class="service-header">
                        <div class="service-title">${this.escapeHtml(serviceTitle)}</div>
                        ${statusBadge}
                    </div>
                </div>
            `;
        }

        return `
            <div class="service-item enhanced ${domainOverride ? 'domain-enrichment' : ''}">
                <script type="application/json" id="json-data-${serviceId}">${jsonDataStr}</script>
                <div class="service-header">
                    <div class="service-title">${this.escapeHtml(serviceTitle)}</div>
                    <div class="service-header-right">
                        ${statusBadge}
                        <div class="service-info">${this.escapeHtml(service.product || '')} ${this.escapeHtml(service.version || '')}</div>
                        <div class="service-tabs">
                            ${showBannerTab ? '<button class="service-tab ' + bannerActive + '" onclick="meowSearch.switchServiceTab(\'' + serviceId + '\', \'banner\')">BANNER</button>' : ''}
                            ${showDetailsTab ? '<button class="service-tab ' + detailsActive + '" onclick="meowSearch.switchServiceTab(\'' + serviceId + '\', \'details\')">DETAILS</button>' : ''}
                            ${hasHtmlPreview ? '<button class="service-tab html-btn" onclick="meowSearch.showHtmlModal(\'' + serviceId + '\')" title="Preview HTML page">&lt;/&gt;</button>' : ''}
                            <button class="service-tab json-btn" onclick="meowSearch.showJsonModal('${serviceId}')" title="View raw JSON">{ }</button>
                        </div>
                    </div>
                </div>
                <div class="service-content">
                    ${showBannerTab ? `
                    <div id="${serviceId}-banner" class="service-tab-panel ${bannerActive}">
                        <div class="tech-tags">
                            ${osTag}
                            ${techTags}
                        </div>
                        ${fingerprint ? `
                            <div class="fingerprint-tag">
                                Fingerprint: <code>${this.escapeHtml(fingerprint)}</code>
                            </div>
                        ` : ''}
                        ${this.formatBanner(banner)}
                    </div>
                    ` : ''}
                    ${showDetailsTab ? `
                    <div id="${serviceId}-details" class="service-tab-panel ${detailsActive}">
                        ${this.renderEnrichmentData(enrichedData, fingerprintData, service)}
                    </div>
                    ` : ''}
                </div>
            </div>
        `;
    }

    // Render service with all domain enrichments as separate cards
    renderServiceWithEnrichments(host, service, index) {
        const cards = [];

        // Parse fingerprint data (shared across all enrichments)
        let fingerprintData = null;
        if (service.fingerprint_data) {
            try {
                fingerprintData = JSON.parse(service.fingerprint_data);
            } catch (e) {
                fingerprintData = { raw: service.fingerprint_data };
            }
        }

        // Get SNI enrichments
        const enrichments = service.enrichments || [];
        const completedEnrichments = enrichments.filter(e => e.status === 'enriched');

        // If no SNI enrichments, render single card with legacy enrichment_data
        if (completedEnrichments.length === 0) {
            let enrichedData = null;
            if (service.enrichment_data) {
                try {
                    enrichedData = JSON.parse(service.enrichment_data);
                } catch (e) {
                    enrichedData = { raw: service.enrichment_data };
                }
            }
            return this.renderSingleServiceCard(host, service, index, enrichedData, fingerprintData, null);
        }

        // Render each enrichment as a separate service card
        completedEnrichments.forEach((enrichment, i) => {
            let enrichedData = null;
            if (enrichment.enrichment_data) {
                try {
                    enrichedData = JSON.parse(enrichment.enrichment_data);
                } catch (e) {
                    enrichedData = { raw: enrichment.enrichment_data };
                }
            }

            // domain is null for IP-direct, string for domain-based
            const domain = enrichment.domain || null;
            cards.push(this.renderSingleServiceCard(host, service, index + '-' + i, enrichedData, fingerprintData, domain));
        });

        return cards.join('');
    }

    switchServiceTab(serviceId, tabName) {
        // Find the service element
        const serviceElement = document.querySelector(`[id="${serviceId}-banner"]`).closest('.service-item');
        if (!serviceElement) {
            return;
        }

        // Remove active class from all tabs and panels for this service
        serviceElement.querySelectorAll('.service-tab').forEach(tab => {
            tab.classList.remove('active');
        });

        serviceElement.querySelectorAll('.service-tab-panel').forEach(panel => {
            panel.classList.remove('active');
        });

        // Add active class to clicked tab and corresponding panel
        const targetPanel = document.getElementById(`${serviceId}-${tabName}`);

        if (targetPanel) {
            targetPanel.classList.add('active');
        }

        // Find and activate the clicked tab using a more robust method
        serviceElement.querySelectorAll('.service-tab').forEach(tab => {
            if (tab.textContent.toLowerCase().includes(tabName.toLowerCase())) {
                tab.classList.add('active');
            }
        });
    }

    isGhostService(service) {
        return !service.service && !service.fingerprint_data && !service.banner && !service.product;
    }

    generatePortTags(services) {
        if (!services || services.length === 0) return '';

        const identified = [];
        const ghost = [];

        // Deduplicate by port, keeping identified over ghost
        const seen = new Map();
        for (const s of services) {
            const port = s.port;
            if (!seen.has(port) || (!this.isGhostService(s) && this.isGhostService(seen.get(port)))) {
                seen.set(port, s);
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

        // Identified services: show port number only (green tint)
        const displayIdentified = identified.slice(0, 3);
        for (const s of displayIdentified) {
            tags.push(`<span class="port-tag identified">${this.escapeHtml(String(s.port))}</span>`);
        }
        if (identified.length > 3) {
            tags.push(`<span class="port-tag more">+${identified.length - 3}</span>`);
        }

        // Ghost ports: single dimmed tag with just the count
        if (ghost.length > 0) {
            tags.push(`<span class="port-tag ghost">+${ghost.length}</span>`);
        }

        return tags.join('');
    }

    renderHosts(hosts) {
        const container = document.getElementById('hosts-list');

        if (!hosts || hosts.length === 0) {
            container.innerHTML = `
                <div class="empty-state" style="padding: 40px; text-align: center;">
                    <svg width="48" height="48" viewBox="0 0 24 24" fill="none" opacity="0.3">
                        <circle cx="12" cy="12" r="9" stroke="currentColor" stroke-width="2"/>
                        <path d="M12 7v5l3 3" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                    </svg>
                    <h3>No hosts found</h3>
                    <p>Try adjusting your search or filters</p>
                </div>
            `;
            return;
        }

        container.innerHTML = hosts.map(host => this.renderHostItem(host)).join('');

        // Add click handlers
        container.querySelectorAll('.host-item').forEach(item => {
            item.addEventListener('click', () => {
                const ip = item.dataset.ip;
                if (ip) {
                    this.selectHost(ip, item);
                }
            });
        });
    }

    renderHostItem(host) {
        // Extract services (if available) or use cached data
        let services = [];
        if (host.services && host.services.length > 0) {
            services = host.services;
        } else if (this.hostDetailsCache.has(host.ip)) {
            const cachedHost = this.hostDetailsCache.get(host.ip);
            if (cachedHost.services) {
                services = cachedHost.services;
            }
        }

        // If we still don't have services, fetch them asynchronously
        if (services.length === 0 && host.services_count > 0) {
            this.loadHostPortsAsync(host.ip);
        }

        const portTags = this.generatePortTags(services);

        const lastSeen = host.last_scan ? new Date(host.last_scan * 1000).toLocaleDateString() : '';
        const isActive = host.services_count > 0;

        return `
            <div class="host-item" data-ip="${this.escapeHtml(host.ip)}">
                <div class="host-top-line">
                    <div class="host-ip">${this.escapeHtml(host.ip)}</div>
                    <div class="host-ports" id="ports-${host.ip.replace(/\./g, '-')}">
                        ${portTags || '<span class="port-tag loading">...</span>'}
                    </div>
                    <div class="host-timestamp">${this.escapeHtml(lastSeen)}</div>
                </div>
                <div class="host-location-line">
                    ${host.country_name ? `
                    <div class="host-location">
                        ${host.country_code === 'XX'
                            ? '<svg width="16" height="12" viewBox="0 0 16 12" fill="none" style="vertical-align:middle;margin-right:4px"><rect width="16" height="12" rx="1" fill="#2a3a4a"/><rect x="4" y="1.5" width="8" height="6" rx=".5" stroke="#6b8aad" stroke-width=".8" fill="none"/><line x1="8" y1="7.5" x2="8" y2="9" stroke="#6b8aad" stroke-width=".8"/><line x1="5.5" y1="9.5" x2="10.5" y2="9.5" stroke="#6b8aad" stroke-width=".8" stroke-linecap="round"/></svg>'
                            : `<img src="https://flagcdn.com/16x12/${this.escapeHtml(host.country_code?.toLowerCase() || '')}.png" alt="${this.escapeHtml(host.country_name)}" onerror="this.style.display='none'">`}
                        ${this.escapeHtml(host.country_name)}
                    </div>
                    ` : ''}
                    ${host.city ? `<span>${this.escapeHtml(host.city)}</span>` : ''}
                    ${host.asn || host.as_org ? `<span class="separator">/</span>` : ''}
                    ${host.asn ? `<span>AS${this.escapeHtml(String(host.asn))}</span>` : ''}
                    ${host.asn && host.as_org ? `<span class="separator">/</span>` : ''}
                    ${host.as_org ? `<span>${this.escapeHtml(host.as_org)}</span>` : ''}
                </div>
                ${host.hostname ? `<div class="host-hostname">${this.escapeHtml(host.hostname)}</div>` : ''}
            </div>
        `;
    }

    selectHost(ip, element) {
        // Remove active class from previous selection
        document.querySelectorAll('.host-item.active').forEach(item => {
            item.classList.remove('active');
        });

        // Add active class to selected item
        element.classList.add('active');

        // Show details sidebar on mobile
        const sidebar = document.getElementById('details-sidebar');
        if (sidebar) {
            sidebar.classList.add('show');
        }

        // Load host details
        this.loadHostDetails(ip);
    }

    async loadHostDetails(ip) {
        // Check cache first
        if (this.hostDetailsCache.has(ip)) {
            this.renderHostDetails(this.hostDetailsCache.get(ip));
            return;
        }

        try {
            const response = await fetch(`/api/hosts/${ip}`);
            const host = await response.json();

            // Cache the result
            this.hostDetailsCache.set(ip, host);

            // Render details
            this.renderHostDetails(host);
        } catch (error) {
            console.error('Error loading host details:', error);
        }
    }

    renderHostDetails(host) {
        const container = document.getElementById('details-sidebar');
        const services = host.services || [];
        const certificates = host.certificates || [];
        const domains = host.domains || [];

        // Separate real services from ghost ports
        const realServices = services.filter(s => !this.isGhostService(s));
        const ghostPorts = services.filter(s => this.isGhostService(s));

        // Render domains section
        const domainsSection = domains.length > 0 ? `
            <div class="host-domains">
                <div class="domains-tags">
                    ${domains.slice(0, 10).map(d => `
                        <span class="domain-tag" title="Source: ${this.escapeHtml(d.source || '')}${d.discovered_port ? ', Port: ' + this.escapeHtml(String(d.discovered_port)) : ''}">
                            ${this.escapeHtml(d.domain)}
                        </span>
                    `).join('')}
                    ${domains.length > 10 ? `<span class="domain-tag more">+${domains.length - 10}</span>` : ''}
                </div>
            </div>
        ` : '';

        // Render unverified ports section
        const ghostSection = ghostPorts.length > 0 ? `
            <div class="detail-section">
                <h4>Unverified Ports (${ghostPorts.length})</h4>
                <div class="unverified-ports">
                    <div class="unverified-ports-list">
                        ${ghostPorts.sort((a, b) => a.port - b.port).map(s =>
                            `<span class="port-tag unverified">${this.escapeHtml(String(s.port))}</span>`
                        ).join('')}
                    </div>
                    <div class="unverified-ports-hint">no service identified</div>
                </div>
            </div>
        ` : '';

        container.innerHTML = `
            <div class="host-details">
                <div class="detail-header">
                    <h3>${this.escapeHtml(host.ip)}</h3>
                    ${host.hostname ? `<div style="color: var(--text-secondary); font-size: 14px; margin-top: 4px;">${this.escapeHtml(host.hostname)}</div>` : ''}
                    ${domainsSection}
                </div>

                ${realServices.length > 0 ? `
                <div class="detail-section">
                    <h4>Services (${realServices.length})</h4>
                    <div class="services-list">
                        ${realServices.map((service, index) => {
                            return this.renderServiceWithEnrichments(host, service, index);
                        }).join('')}
                    </div>
                </div>
                ` : ''}

                ${ghostSection}

                ${certificates.length > 0 ? `
                <div class="detail-section">
                    <h4>Certificates (${certificates.length})</h4>
                    <div class="certificates-list">
                        ${certificates.slice(0, 5).map(cert => {
                            const certHash = cert.fingerprint_sha256 || cert.fingerprint_md5 || 'unknown';

                            return `
                                <div class="cert-item">
                                    <div class="detail-grid">
                                        <div class="detail-label">Subject CN:</div>
                                        <div class="detail-value">${this.escapeHtml(cert.subject_cn || '-')}</div>
                                        <div class="detail-label">Issuer CN:</div>
                                        <div class="detail-value">${this.escapeHtml(cert.issuer_cn || '-')}</div>
                                        <div class="detail-label">Fingerprint:</div>
                                        <div class="detail-value">
                                            <a href="/certificates#${this.escapeHtml(certHash)}" class="cert-hash-link" title="Click to view in certificates section">
                                                ${this.escapeHtml(certHash)}
                                            </a>
                                        </div>
                                        <div class="detail-label">Valid Until:</div>
                                        <div class="detail-value">${cert.not_after ? new Date(cert.not_after * 1000).toLocaleDateString() : '-'}</div>
                                    </div>
                                </div>
                            `;
                        }).join('')}
                        ${certificates.length > 5 ? `
                            <div class="cert-more">
                                <em>... and ${certificates.length - 5} more certificates</em>
                            </div>
                        ` : ''}
                    </div>
                </div>
                ` : ''}
            </div>
        `;
    }

    toggleFilterChip(chip) {
        const filter = chip.dataset.filter;
        chip.classList.toggle('active');

        if (chip.classList.contains('active')) {
            // Parse filter (e.g., "services_count:>0")
            const [field, operator, value] = filter.split(/([:><!])/);
            if (field && operator && value) {
                this.currentFilters[field] = `${operator}${value}`;
            }
        } else {
            // Remove filter
            const [field] = filter.split(/[:><!]/);
            if (field) {
                delete this.currentFilters[field];
            }
        }

        this.currentPage = 1;
        this.loadHosts();
    }

    // Show JSON modal with pretty-printed data
    showJsonModal(serviceId) {
        const dataElement = document.getElementById(`json-data-${serviceId}`);
        if (!dataElement) return;

        const jsonData = JSON.parse(dataElement.textContent);
        const prettyJson = JSON.stringify(jsonData, null, 2);

        // Create modal if it doesn't exist
        let modal = document.getElementById('json-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'json-modal';
            modal.className = 'json-modal';
            modal.innerHTML = `
                <div class="json-modal-backdrop"></div>
                <div class="json-modal-content">
                    <div class="json-modal-header">
                        <h3>JSON Data</h3>
                        <div class="json-modal-actions">
                            <button class="json-copy-btn" title="Copy to clipboard">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                                Copy
                            </button>
                            <button class="json-close-btn" title="Close">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <line x1="18" y1="6" x2="6" y2="18"></line>
                                    <line x1="6" y1="6" x2="18" y2="18"></line>
                                </svg>
                            </button>
                        </div>
                    </div>
                    <pre class="json-modal-body"><code></code></pre>
                </div>
            `;
            document.body.appendChild(modal);

            // Close on backdrop click
            modal.querySelector('.json-modal-backdrop').addEventListener('click', () => this.closeJsonModal());
            modal.querySelector('.json-close-btn').addEventListener('click', () => this.closeJsonModal());
            modal.querySelector('.json-copy-btn').addEventListener('click', () => this.copyJsonToClipboard());

            // Close on Escape
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && modal.classList.contains('show')) {
                    this.closeJsonModal();
                }
            });
        }

        // Update content and show
        modal.querySelector('code').textContent = prettyJson;
        modal.classList.add('show');
        document.body.style.overflow = 'hidden';
    }

    closeJsonModal() {
        const modal = document.getElementById('json-modal');
        if (modal) {
            modal.classList.remove('show');
            document.body.style.overflow = '';
        }
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
        const originalText = btn.innerHTML;
        this.copyToClipboard(code).then(() => {
            btn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
                Copied!
            `;
            setTimeout(() => { btn.innerHTML = originalText; }, 2000);
        }).catch(() => {
            btn.innerHTML = `Failed`;
            setTimeout(() => { btn.innerHTML = originalText; }, 2000);
        });
    }

    // Show HTML preview modal — fetches server-side sanitized body, renders in strict sandbox iframe
    showHtmlModal(serviceId) {
        const dataElement = document.getElementById(`json-data-${serviceId}`);
        if (!dataElement) return;

        const jsonData = JSON.parse(dataElement.textContent);
        const htmlBody = jsonData.enrichment_data?.body || '';
        if (!htmlBody) return;

        const ip = jsonData.ip || '';
        const port = jsonData.port || '';
        const domain = jsonData.domain || '';

        // Create modal if it doesn't exist
        let modal = document.getElementById('html-modal');
        if (!modal) {
            modal = document.createElement('div');
            modal.id = 'html-modal';
            modal.className = 'html-modal';
            modal.innerHTML = `
                <div class="html-modal-backdrop"></div>
                <div class="html-modal-content">
                    <div class="html-modal-header">
                        <h3>HTML Preview</h3>
                        <div class="html-modal-tabs">
                            <button class="html-tab active" data-view="rendered">Rendered</button>
                            <button class="html-tab" data-view="source">Source</button>
                        </div>
                        <div class="html-modal-actions">
                            <button class="html-copy-btn" title="Copy HTML source">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                                </svg>
                                Copy
                            </button>
                            <button class="html-close-btn" title="Close">
                                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                                    <line x1="18" y1="6" x2="6" y2="18"></line>
                                    <line x1="6" y1="6" x2="18" y2="18"></line>
                                </svg>
                            </button>
                        </div>
                    </div>
                    <div class="html-modal-body">
                        <div class="html-view-rendered active">
                            <iframe sandbox="" class="html-preview-iframe"></iframe>
                        </div>
                        <div class="html-view-source">
                            <pre class="html-source-code"><code></code></pre>
                        </div>
                    </div>
                </div>
            `;
            document.body.appendChild(modal);

            // Event handlers
            modal.querySelector('.html-modal-backdrop').addEventListener('click', () => this.closeHtmlModal());
            modal.querySelector('.html-close-btn').addEventListener('click', () => this.closeHtmlModal());
            modal.querySelector('.html-copy-btn').addEventListener('click', () => this.copyHtmlToClipboard());

            // Tab switching
            modal.querySelectorAll('.html-tab').forEach(tab => {
                tab.addEventListener('click', (e) => {
                    const view = e.target.dataset.view;
                    modal.querySelectorAll('.html-tab').forEach(t => t.classList.remove('active'));
                    e.target.classList.add('active');
                    modal.querySelector('.html-view-rendered').classList.toggle('active', view === 'rendered');
                    modal.querySelector('.html-view-source').classList.toggle('active', view === 'source');
                });
            });

            // Close on Escape
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && modal.classList.contains('show')) {
                    this.closeHtmlModal();
                }
            });
        }

        // Source view: show raw body as text (safe — textContent, not innerHTML)
        const prettyHtml = this.formatHtml(htmlBody);
        modal.querySelector('.html-source-code code').textContent = prettyHtml;

        // Store raw HTML for copy
        modal.dataset.rawHtml = htmlBody;

        // Reset iframe while loading
        const iframe = modal.querySelector('.html-preview-iframe');
        iframe.removeAttribute('srcdoc');

        // Reset to rendered view and show modal
        modal.querySelectorAll('.html-tab').forEach(t => t.classList.remove('active'));
        modal.querySelector('.html-tab[data-view="rendered"]').classList.add('active');
        modal.querySelector('.html-view-rendered').classList.add('active');
        modal.querySelector('.html-view-source').classList.remove('active');

        modal.classList.add('show');
        document.body.style.overflow = 'hidden';

        // Fetch server-side sanitized body and render via srcdoc
        const params = new URLSearchParams({ ip, port });
        if (domain) params.set('domain', domain);
        fetch(`/api/body?${params}`)
            .then(resp => {
                if (!resp.ok) throw new Error('No preview');
                return resp.text();
            })
            .then(safeHtml => {
                iframe.srcdoc = safeHtml;
            })
            .catch(() => {
                iframe.srcdoc = '<html><body style="display:flex;align-items:center;justify-content:center;height:100%;margin:0;font-family:sans-serif;color:#666;"><p>No preview available</p></body></html>';
            });
    }

    closeHtmlModal() {
        const modal = document.getElementById('html-modal');
        if (modal) {
            modal.classList.remove('show');
            document.body.style.overflow = '';
            // Clear iframe content for security
            const iframe = modal.querySelector('.html-preview-iframe');
            if (iframe) {
                iframe.removeAttribute('srcdoc');
                iframe.src = 'about:blank';
            }
        }
    }

    copyHtmlToClipboard() {
        const modal = document.getElementById('html-modal');
        if (!modal) return;

        const html = modal.dataset.rawHtml || '';
        const btn = modal.querySelector('.html-copy-btn');
        const originalText = btn.innerHTML;
        this.copyToClipboard(html).then(() => {
            btn.innerHTML = `
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <polyline points="20 6 9 17 4 12"></polyline>
                </svg>
                Copied!
            `;
            setTimeout(() => { btn.innerHTML = originalText; }, 2000);
        }).catch(() => {
            btn.innerHTML = `Failed`;
            setTimeout(() => { btn.innerHTML = originalText; }, 2000);
        });
    }

    // Format HTML with indentation for readability
    formatHtml(html) {
        let formatted = '';
        let indent = 0;
        const tab = '  ';

        // Simple HTML formatter
        html = html.replace(/></g, '>\n<');
        const lines = html.split('\n');

        for (let line of lines) {
            line = line.trim();
            if (!line) continue;

            // Decrease indent for closing tags
            if (line.match(/^<\/\w/)) {
                indent = Math.max(0, indent - 1);
            }

            formatted += tab.repeat(indent) + line + '\n';

            // Increase indent for opening tags (not self-closing or void elements)
            if (line.match(/^<\w[^>]*[^\/]>$/) &&
                !line.match(/^<(area|base|br|col|embed|hr|img|input|link|meta|param|source|track|wbr)/i) &&
                !line.match(/<\/\w+>$/)) {
                indent++;
            }
        }

        return formatted.trim();
    }

    updatePagination(pagination) {
        this.currentPage = pagination.current_page || 1;
        this.totalPages = pagination.total_pages || 1;
        this.totalResults = pagination.total || 0;

        // Update counters
        const currentPageEl = document.getElementById('current-page');
        const totalPagesEl = document.getElementById('total-pages');
        const resultsCountEl = document.getElementById('results-count');
        const topResultsCountEl = document.getElementById('top-results-count');

        if (currentPageEl) currentPageEl.textContent = this.currentPage;
        if (totalPagesEl) totalPagesEl.textContent = this.totalPages;
        if (resultsCountEl) resultsCountEl.textContent = this.totalResults.toLocaleString();
        if (topResultsCountEl) topResultsCountEl.textContent = this.totalResults.toLocaleString();

        // Update buttons
        const prevBtn = document.getElementById('prev-page');
        const nextBtn = document.getElementById('next-page');

        if (prevBtn) prevBtn.disabled = this.currentPage <= 1;
        if (nextBtn) nextBtn.disabled = this.currentPage >= this.totalPages;
    }

    async previousPage() {
        if (this.currentPage > 1) {
            this.currentPage--;
            await this.loadHosts();
        }
    }

    async nextPage() {
        if (this.currentPage < this.totalPages) {
            this.currentPage++;
            await this.loadHosts();
        }
    }

    changePageSize(size) {
        this.pageSize = parseInt(size, 10);
        this.currentPage = 1;
        this.loadHosts();
    }

    showListLoading() {
        const hostsList = document.getElementById('hosts-list');
        if (hostsList) {
            hostsList.classList.add('loading');
            hostsList.style.opacity = '0.5';
            hostsList.style.pointerEvents = 'none';
        }
    }

    hideListLoading() {
        const hostsList = document.getElementById('hosts-list');
        if (hostsList) {
            hostsList.classList.remove('loading');
            hostsList.style.opacity = '';
            hostsList.style.pointerEvents = '';
        }
    }

    showError(message) {
        console.error(message);
        // Could show a toast notification here
    }

    exportHosts(format) {
        const params = new URLSearchParams({
            format: format,
            type: format === 'txt' ? 'services' : 'hosts',
            limit: this.totalResults || 1000,
            ...this.currentFilters
        });

        if (this.currentQuery) {
            params.set('q', this.currentQuery);
        }

        const apiKey = localStorage.getItem('meow_api_key');
        if (apiKey) {
            params.set('key', apiKey);
        }

        window.open(`/api/export?${params}`, '_blank');
    }
}

// Initialize when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.meowSearch = new MeowHostSearch();
});


