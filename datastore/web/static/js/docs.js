// Documentation Page JavaScript
// Handles tab switching, API debugger, curl copy, and smooth scroll

const API_ENDPOINTS = [
    // === Hosts ===
    {
        category: "Hosts",
        method: "GET",
        path: "/api/hosts",
        desc: "Search and filter hosts",
        params: [
            { name: "q", type: "string", desc: "Text search (IP, hostname, org)", required: false },
            { name: "country", type: "string", desc: "Country code (e.g. US, FR)", required: false },
            { name: "cloud", type: "string", desc: "Cloud provider (aws, gcp, azure)", required: false },
            { name: "port", type: "integer", desc: "Filter by open port", required: false },
            { name: "asn", type: "integer", desc: "AS number", required: false },
            { name: "service", type: "string", desc: "Service name (http, ssh, ftp)", required: false },
            { name: "technology", type: "string", desc: "Technology detected", required: false },
            { name: "verified", type: "boolean", desc: "Only verified hosts", required: false },
            { name: "limit", type: "integer", desc: "Results per page", required: false, default: "50" },
            { name: "page", type: "integer", desc: "Page number", required: false, default: "1" }
        ]
    },
    {
        category: "Hosts",
        method: "GET",
        path: "/api/hosts/:ip",
        desc: "Get detailed host information with services, certificates, and enrichments",
        params: [
            { name: "ip", type: "string", desc: "IP address", required: true, inPath: true }
        ]
    },
    // === Services ===
    {
        category: "Services",
        method: "GET",
        path: "/api/services",
        desc: "Search services across all hosts",
        params: [
            { name: "q", type: "string", desc: "Text search", required: false },
            { name: "service", type: "string", desc: "Service name", required: false },
            { name: "product", type: "string", desc: "Product name", required: false },
            { name: "limit", type: "integer", desc: "Results per page", required: false, default: "50" }
        ]
    },
    // === Certificates ===
    {
        category: "Certificates",
        method: "GET",
        path: "/api/certificates",
        desc: "Search TLS certificates",
        params: [
            { name: "q", type: "string", desc: "Text search", required: false },
            { name: "subject", type: "string", desc: "Subject CN filter", required: false },
            { name: "issuer", type: "string", desc: "Issuer CN filter", required: false },
            { name: "limit", type: "integer", desc: "Results per page", required: false, default: "50" },
            { name: "page", type: "integer", desc: "Page number", required: false, default: "1" }
        ]
    },
    {
        category: "Certificates",
        method: "GET",
        path: "/api/certificates/:fingerprint/hosts",
        desc: "Get hosts using a specific certificate",
        params: [
            { name: "fingerprint", type: "string", desc: "Certificate SHA256 fingerprint", required: true, inPath: true }
        ]
    },
    // === Domains ===
    {
        category: "Domains",
        method: "GET",
        path: "/api/domains",
        desc: "Search discovered domains",
        params: [
            { name: "q", type: "string", desc: "Domain search", required: false },
            { name: "protocol", type: "string", desc: "Protocol filter (http, ssh, ftp, smtp)", required: false },
            { name: "status", type: "integer", desc: "HTTP status code filter", required: false },
            { name: "limit", type: "integer", desc: "Results per page", required: false, default: "50" },
            { name: "page", type: "integer", desc: "Page number", required: false, default: "1" }
        ]
    },
    {
        category: "Domains",
        method: "GET",
        path: "/api/domains/stats",
        desc: "Get domain statistics overview",
        params: []
    },
    {
        category: "Domains",
        method: "GET",
        path: "/api/domains/:domain/services",
        desc: "Get services discovered on a specific domain",
        params: [
            { name: "domain", type: "string", desc: "Domain name", required: true, inPath: true }
        ]
    },
    {
        category: "Domains",
        method: "GET",
        path: "/api/body",
        desc: "Get HTTP response body preview for a service",
        params: [
            { name: "ip", type: "string", desc: "IP address", required: true },
            { name: "port", type: "integer", desc: "Port number", required: true }
        ]
    },
    // === MeowQL Search ===
    {
        category: "Search",
        method: "GET",
        path: "/api/search",
        desc: "Host-centric MeowQL search. Returns hosts matching the query with their services.",
        params: [
            { name: "q", type: "string", desc: "MeowQL query (e.g. port:443 country:US)", required: true },
            { name: "limit", type: "integer", desc: "Results per page", required: false, default: "50" },
            { name: "page", type: "integer", desc: "Page number", required: false, default: "1" }
        ]
    },
    {
        category: "Search",
        method: "GET",
        path: "/api/search/services",
        desc: "Service-centric MeowQL search. Returns individual services matching the query.",
        params: [
            { name: "q", type: "string", desc: "MeowQL query", required: true },
            { name: "limit", type: "integer", desc: "Results per page", required: false, default: "50" },
            { name: "page", type: "integer", desc: "Page number", required: false, default: "1" }
        ]
    },
    {
        category: "Search",
        method: "GET",
        path: "/api/autocomplete",
        desc: "Autocomplete suggestions for MeowQL fields and values",
        params: [
            { name: "q", type: "string", desc: "Partial input to autocomplete", required: true },
            { name: "field", type: "string", desc: "Field name to get value suggestions", required: false }
        ]
    },
    // === Statistics ===
    {
        category: "Statistics",
        method: "GET",
        path: "/api/stats/dashboard",
        desc: "Dashboard overview: total counts, top countries, top services, cloud distribution",
        params: []
    },
    {
        category: "Statistics",
        method: "GET",
        path: "/api/stats/countries",
        desc: "Country breakdown with host counts and cloud presence",
        params: []
    },
    {
        category: "Statistics",
        method: "GET",
        path: "/api/stats/services",
        desc: "Service distribution across all hosts",
        params: []
    },
    {
        category: "Statistics",
        method: "GET",
        path: "/api/stats/cloud",
        desc: "Cloud provider statistics",
        params: []
    },
    {
        category: "Statistics",
        method: "GET",
        path: "/api/stats/technologies",
        desc: "Detected technologies and frameworks",
        params: []
    },
    {
        category: "Statistics",
        method: "GET",
        path: "/api/stats/products",
        desc: "Product and version distribution",
        params: []
    },
    {
        category: "Statistics",
        method: "GET",
        path: "/api/facets",
        desc: "Facet counts for filter dropdowns (ports, services, countries, clouds)",
        params: []
    },
    // === Geographic ===
    {
        category: "Geographic",
        method: "GET",
        path: "/api/geomap",
        desc: "Geographic host distribution data for map visualization",
        params: [
            { name: "groups", type: "string", desc: "Service groups to include (comma-separated: admin,http,mail)", required: false }
        ]
    },
    {
        category: "Geographic",
        method: "GET",
        path: "/api/geomap/country/:code",
        desc: "Detailed breakdown for a specific country (services, ports, ASNs, cities, cloud)",
        params: [
            { name: "code", type: "string", desc: "ISO country code (e.g. US, FR)", required: true, inPath: true }
        ]
    },
    // === Export ===
    {
        category: "Export",
        method: "GET",
        path: "/api/export",
        desc: "Export scan data in various formats",
        params: [
            { name: "format", type: "string", desc: "Output format (json, csv)", required: false, default: "json" },
            { name: "type", type: "string", desc: "Data type to export (hosts, services)", required: false, default: "hosts" }
        ]
    },
    // === Scanning ===
    {
        category: "Scanning",
        method: "GET",
        path: "/api/scanners",
        desc: "List active scanner nodes connected via NATS",
        params: []
    },
    {
        category: "Scanning",
        method: "POST",
        path: "/api/scan",
        desc: "Submit a new scan request to connected scanner nodes",
        params: [
            { name: "target", type: "string", desc: "Target CIDR or IP range", required: true, inBody: true },
            { name: "ports", type: "string", desc: "Ports to scan (e.g. 80,443,22)", required: false, inBody: true },
            { name: "rate", type: "integer", desc: "Packets per second", required: false, inBody: true, default: "1000" }
        ]
    },
    {
        category: "Scanning",
        method: "GET",
        path: "/api/events/recent",
        desc: "Get recent scan events feed",
        params: []
    },
    // === Tools ===
    {
        category: "Tools",
        method: "GET",
        path: "/api/tools/dns",
        desc: "DNS resolution helper",
        params: [
            { name: "domain", type: "string", desc: "Domain name to resolve", required: true }
        ]
    },
    // === Debug ===
    {
        category: "Debug",
        method: "GET",
        path: "/api/debug/stats",
        desc: "Detailed system statistics (NATS, database, enrichment pipeline)",
        params: []
    }
];

const docsPage = {

    // -----------------------------------------------------------------------
    // State
    // -----------------------------------------------------------------------

    currentTab: 'api',
    selectedEndpoint: null,

    // -----------------------------------------------------------------------
    // Init
    // -----------------------------------------------------------------------

    init: function () {
        this.setupTabs();
        this.setupDebugger();
        this.setupCurlCopyButtons();
        this.setupSmoothScroll();
        this.readHash();

        // Listen for hash changes (back/forward navigation)
        window.addEventListener('hashchange', this.readHash.bind(this));
    },

    // -----------------------------------------------------------------------
    // Tab switching
    // -----------------------------------------------------------------------

    setupTabs: function () {
        var self = this;
        var tabs = document.querySelectorAll('.docs-tab');
        for (var i = 0; i < tabs.length; i++) {
            tabs[i].addEventListener('click', (function (tab) {
                return function (e) {
                    e.preventDefault();
                    var name = tab.getAttribute('data-tab');
                    if (name) self.switchTab(name);
                };
            })(tabs[i]));
        }
    },

    switchTab: function (tabName) {
        this.currentTab = tabName;

        // Update tab buttons
        var tabs = document.querySelectorAll('.docs-tab');
        for (var i = 0; i < tabs.length; i++) {
            if (tabs[i].getAttribute('data-tab') === tabName) {
                tabs[i].classList.add('active');
            } else {
                tabs[i].classList.remove('active');
            }
        }

        // Update content panels
        var panels = document.querySelectorAll('.docs-tab-content');
        for (var j = 0; j < panels.length; j++) {
            if (panels[j].getAttribute('data-tab') === tabName) {
                panels[j].classList.add('active');
            } else {
                panels[j].classList.remove('active');
            }
        }

        // Update URL hash without triggering scroll
        if (history.replaceState) {
            history.replaceState(null, '', '#' + tabName);
        } else {
            window.location.hash = tabName;
        }
    },

    readHash: function () {
        var hash = window.location.hash.replace('#', '').toLowerCase();
        var valid = ['quickstart', 'api', 'meowql', 'enrichment', 'config', 'debugger'];
        if (hash && valid.indexOf(hash) !== -1) {
            this.switchTab(hash);
        }
    },

    // -----------------------------------------------------------------------
    // API Debugger
    // -----------------------------------------------------------------------

    setupDebugger: function () {
        var self = this;
        var select = document.getElementById('debugger-endpoint-select');
        if (select) {
            this.populateEndpointSelect(select);
            select.addEventListener('change', function () {
                var idx = parseInt(select.value, 10);
                if (!isNaN(idx) && idx >= 0) {
                    self.onEndpointSelect(idx);
                } else {
                    self.clearDebuggerForm();
                }
            });
        }

        var sendBtn = document.getElementById('debugger-send-btn');
        if (sendBtn) {
            sendBtn.addEventListener('click', function () {
                self.sendRequest();
            });
        }

        var copyBtn = document.getElementById('debugger-copy-curl');
        if (copyBtn) {
            copyBtn.addEventListener('click', function () {
                self.copyCurl();
            });
        }
    },

    populateEndpointSelect: function (select) {
        // Clear existing options except the placeholder
        select.innerHTML = '';

        var placeholder = document.createElement('option');
        placeholder.value = '';
        placeholder.textContent = 'Select an endpoint...';
        placeholder.disabled = true;
        placeholder.selected = true;
        select.appendChild(placeholder);

        // Group endpoints by category
        var categories = [];
        var categoryMap = {};
        for (var i = 0; i < API_ENDPOINTS.length; i++) {
            var ep = API_ENDPOINTS[i];
            if (!categoryMap[ep.category]) {
                categoryMap[ep.category] = [];
                categories.push(ep.category);
            }
            categoryMap[ep.category].push({ index: i, endpoint: ep });
        }

        for (var c = 0; c < categories.length; c++) {
            var catName = categories[c];
            var group = document.createElement('optgroup');
            group.label = catName;

            var items = categoryMap[catName];
            for (var j = 0; j < items.length; j++) {
                var opt = document.createElement('option');
                opt.value = items[j].index;
                opt.textContent = items[j].endpoint.method + ' ' + items[j].endpoint.path;
                group.appendChild(opt);
            }
            select.appendChild(group);
        }
    },

    onEndpointSelect: function (index) {
        if (index < 0 || index >= API_ENDPOINTS.length) return;
        this.selectedEndpoint = API_ENDPOINTS[index];
        this.buildParamInputs(this.selectedEndpoint);
        this.updateCurl();
        this.clearResponse();
        var sendBtn = document.getElementById('debugger-send-btn');
        if (sendBtn) sendBtn.disabled = false;
    },

    clearDebuggerForm: function () {
        this.selectedEndpoint = null;
        var container = document.getElementById('debugger-params');
        if (container) container.innerHTML = '';
        var curlEl = document.getElementById('debugger-curl-output');
        if (curlEl) curlEl.textContent = '';
        this.clearResponse();
        var sendBtn = document.getElementById('debugger-send-btn');
        if (sendBtn) sendBtn.disabled = true;
    },

    clearResponse: function () {
        var responseArea = document.getElementById('debugger-response');
        if (responseArea) {
            responseArea.innerHTML = '<div class="debugger-response-placeholder">Response will appear here</div>';
        }
    },

    buildParamInputs: function (endpoint) {
        var container = document.getElementById('debugger-params');
        if (!container) return;
        container.innerHTML = '';

        if (!endpoint.params || endpoint.params.length === 0) {
            container.innerHTML = '<div class="debugger-no-params">This endpoint has no parameters</div>';
            return;
        }

        var self = this;

        for (var i = 0; i < endpoint.params.length; i++) {
            var param = endpoint.params[i];
            var row = document.createElement('div');
            row.className = 'debugger-param-row';

            var label = document.createElement('label');
            label.className = 'debugger-param-label';
            label.setAttribute('for', 'debugger-param-' + param.name);

            var nameSpan = document.createElement('span');
            nameSpan.className = 'debugger-param-name';
            nameSpan.textContent = param.name;
            label.appendChild(nameSpan);

            if (param.required) {
                var reqBadge = document.createElement('span');
                reqBadge.className = 'debugger-param-required';
                reqBadge.textContent = 'required';
                label.appendChild(reqBadge);
            }

            if (param.inPath) {
                var pathBadge = document.createElement('span');
                pathBadge.className = 'debugger-param-badge path';
                pathBadge.textContent = 'path';
                label.appendChild(pathBadge);
            } else if (param.inBody) {
                var bodyBadge = document.createElement('span');
                bodyBadge.className = 'debugger-param-badge body';
                bodyBadge.textContent = 'body';
                label.appendChild(bodyBadge);
            } else {
                var queryBadge = document.createElement('span');
                queryBadge.className = 'debugger-param-badge query';
                queryBadge.textContent = 'query';
                label.appendChild(queryBadge);
            }

            row.appendChild(label);

            var input;
            if (param.type === 'boolean') {
                input = document.createElement('select');
                input.id = 'debugger-param-' + param.name;
                input.className = 'debugger-param-input';
                input.setAttribute('data-param', param.name);
                input.setAttribute('data-type', param.type);

                var optEmpty = document.createElement('option');
                optEmpty.value = '';
                optEmpty.textContent = '-- not set --';
                input.appendChild(optEmpty);

                var optTrue = document.createElement('option');
                optTrue.value = 'true';
                optTrue.textContent = 'true';
                input.appendChild(optTrue);

                var optFalse = document.createElement('option');
                optFalse.value = 'false';
                optFalse.textContent = 'false';
                input.appendChild(optFalse);

                input.addEventListener('change', function () { self.updateCurl(); });
            } else {
                input = document.createElement('input');
                input.type = (param.type === 'integer') ? 'number' : 'text';
                input.id = 'debugger-param-' + param.name;
                input.className = 'debugger-param-input';
                input.setAttribute('data-param', param.name);
                input.setAttribute('data-type', param.type);
                input.placeholder = param.desc + (param.default ? ' (default: ' + param.default + ')' : '');

                input.addEventListener('input', function () { self.updateCurl(); });
                input.addEventListener('keydown', function (e) {
                    if (e.key === 'Enter') {
                        e.preventDefault();
                        self.sendRequest();
                    }
                });
            }

            row.appendChild(input);

            var desc = document.createElement('div');
            desc.className = 'debugger-param-desc';
            desc.textContent = param.desc;
            if (param.default) {
                desc.textContent += ' (default: ' + param.default + ')';
            }
            row.appendChild(desc);

            container.appendChild(row);
        }
    },

    getParamValues: function () {
        var values = {};
        var inputs = document.querySelectorAll('.debugger-param-input');
        for (var i = 0; i < inputs.length; i++) {
            var name = inputs[i].getAttribute('data-param');
            var val = inputs[i].value;
            if (val !== '' && val !== null) {
                values[name] = val;
            }
        }
        return values;
    },

    buildRequestURL: function (endpoint, values) {
        var path = endpoint.path;

        // Replace path parameters
        if (endpoint.params) {
            for (var i = 0; i < endpoint.params.length; i++) {
                var p = endpoint.params[i];
                if (p.inPath && values[p.name]) {
                    path = path.replace(':' + p.name, encodeURIComponent(values[p.name]));
                }
            }
        }

        // Build query string for GET requests (non-path, non-body params)
        if (endpoint.method === 'GET') {
            var queryParts = [];
            if (endpoint.params) {
                for (var j = 0; j < endpoint.params.length; j++) {
                    var param = endpoint.params[j];
                    if (!param.inPath && !param.inBody && values[param.name]) {
                        queryParts.push(
                            encodeURIComponent(param.name) + '=' + encodeURIComponent(values[param.name])
                        );
                    }
                }
            }
            if (queryParts.length > 0) {
                path += '?' + queryParts.join('&');
            }
        }

        return path;
    },

    buildRequestBody: function (endpoint, values) {
        if (endpoint.method !== 'POST') return null;

        var body = {};
        var hasBody = false;
        if (endpoint.params) {
            for (var i = 0; i < endpoint.params.length; i++) {
                var param = endpoint.params[i];
                if (param.inBody && values[param.name]) {
                    var val = values[param.name];
                    if (param.type === 'integer') {
                        val = parseInt(val, 10);
                        if (isNaN(val)) continue;
                    } else if (param.type === 'boolean') {
                        val = (val === 'true');
                    }
                    body[param.name] = val;
                    hasBody = true;
                }
            }
        }

        return hasBody ? body : null;
    },

    updateCurl: function () {
        var curlEl = document.getElementById('debugger-curl-output');
        if (!curlEl || !this.selectedEndpoint) {
            if (curlEl) curlEl.textContent = '';
            return;
        }

        var ep = this.selectedEndpoint;
        var values = this.getParamValues();
        var url = this.buildRequestURL(ep, values);
        var baseUrl = window.location.origin;

        var parts = ['curl'];

        if (ep.method !== 'GET') {
            parts.push('-X ' + ep.method);
        }

        // Add auth header if API key is set
        var apiKey = this.getApiKey();
        if (apiKey) {
            parts.push("-H 'X-API-Key: " + apiKey + "'");
        }

        if (ep.method === 'POST') {
            parts.push("-H 'Content-Type: application/json'");
            var body = this.buildRequestBody(ep, values);
            if (body) {
                parts.push("-d '" + JSON.stringify(body) + "'");
            }
        }

        parts.push("'" + baseUrl + url + "'");

        curlEl.textContent = parts.join(' \\\n  ');
    },

    sendRequest: function () {
        if (!this.selectedEndpoint) return;

        var self = this;
        var ep = this.selectedEndpoint;
        var values = this.getParamValues();

        // Validate required fields
        if (ep.params) {
            for (var i = 0; i < ep.params.length; i++) {
                var param = ep.params[i];
                if (param.required && !values[param.name]) {
                    this.displayError('Missing required parameter: ' + param.name);
                    var input = document.getElementById('debugger-param-' + param.name);
                    if (input) input.focus();
                    return;
                }
            }
        }

        var url = this.buildRequestURL(ep, values);
        var fetchOptions = {
            method: ep.method,
            headers: {}
        };

        // Add auth header
        var apiKey = this.getApiKey();
        if (apiKey) {
            fetchOptions.headers['X-API-Key'] = apiKey;
        }

        if (ep.method === 'POST') {
            fetchOptions.headers['Content-Type'] = 'application/json';
            var body = this.buildRequestBody(ep, values);
            if (body) {
                fetchOptions.body = JSON.stringify(body);
            }
        }

        // Show loading state
        var sendBtn = document.getElementById('debugger-send-btn');
        var sendLabel = sendBtn ? sendBtn.querySelector('.dbg-send-text') : null;
        if (sendBtn) {
            sendBtn.disabled = true;
            if (sendLabel) sendLabel.textContent = 'Sending...';
        }

        var startTime = performance.now();

        fetch(url, fetchOptions)
            .then(function (response) {
                var elapsed = Math.round(performance.now() - startTime);
                var contentType = response.headers.get('content-type') || '';

                // Collect interesting response headers
                var respHeaders = {};
                var headerNames = ['content-type', 'content-length', 'x-total-count', 'x-page', 'x-total-pages'];
                for (var h = 0; h < headerNames.length; h++) {
                    var hVal = response.headers.get(headerNames[h]);
                    if (hVal) respHeaders[headerNames[h]] = hVal;
                }

                if (contentType.indexOf('application/json') !== -1) {
                    return response.text().then(function (text) {
                        var parsed = null;
                        try {
                            parsed = JSON.parse(text);
                        } catch (e) {
                            // Not valid JSON, display as text
                        }
                        self.displayResponse(response.status, respHeaders, parsed !== null ? parsed : text, elapsed);
                    });
                } else {
                    return response.text().then(function (text) {
                        self.displayResponse(response.status, respHeaders, text, elapsed);
                    });
                }
            })
            .catch(function (err) {
                var elapsed = Math.round(performance.now() - startTime);
                self.displayError('Network error: ' + err.message, elapsed);
            })
            .finally(function () {
                if (sendBtn) {
                    sendBtn.disabled = false;
                    if (sendLabel) sendLabel.textContent = 'Send';
                }
            });
    },

    displayResponse: function (status, headers, body, time) {
        var container = document.getElementById('debugger-response');
        if (!container) return;

        var statusClass = 'info';
        if (status >= 200 && status < 300) statusClass = 'success';
        else if (status >= 400 && status < 500) statusClass = 'warning';
        else if (status >= 500) statusClass = 'error';

        var html = '';

        // Status bar
        html += '<div class="debugger-response-status">';
        html += '<span class="debugger-status-code ' + statusClass + '">' + this.escapeHtml(String(status)) + '</span>';
        html += '<span class="debugger-response-time">' + time + 'ms</span>';
        html += '</div>';

        // Response headers (if any)
        var headerKeys = Object.keys(headers);
        if (headerKeys.length > 0) {
            html += '<div class="debugger-response-headers">';
            for (var i = 0; i < headerKeys.length; i++) {
                html += '<span class="debugger-header-item">';
                html += '<span class="debugger-header-key">' + this.escapeHtml(headerKeys[i]) + ':</span> ';
                html += '<span class="debugger-header-value">' + this.escapeHtml(headers[headerKeys[i]]) + '</span>';
                html += '</span>';
            }
            html += '</div>';
        }

        // Body
        html += '<div class="debugger-response-body">';
        if (typeof body === 'object' && body !== null) {
            html += '<pre class="debugger-json">' + this.formatJSON(body) + '</pre>';
        } else if (typeof body === 'string' && body.length > 0) {
            html += '<pre class="debugger-text">' + this.escapeHtml(body) + '</pre>';
        } else {
            html += '<div class="debugger-empty-body">Empty response body</div>';
        }
        html += '</div>';

        container.innerHTML = html;
    },

    displayError: function (message, time) {
        var container = document.getElementById('debugger-response');
        if (!container) return;

        var html = '<div class="debugger-response-status">';
        html += '<span class="debugger-status-code error">ERR</span>';
        if (time !== undefined) {
            html += '<span class="debugger-response-time">' + time + 'ms</span>';
        }
        html += '</div>';
        html += '<div class="debugger-response-body">';
        html += '<div class="debugger-error-message">' + this.escapeHtml(message) + '</div>';
        html += '</div>';

        container.innerHTML = html;
    },

    formatJSON: function (obj) {
        return this._syntaxHighlight(JSON.stringify(obj, null, 2));
    },

    _syntaxHighlight: function (jsonStr) {
        // Escape HTML entities first
        var escaped = jsonStr
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;');

        // Apply syntax highlighting via regex
        return escaped.replace(
            /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(\s*:)?|\b(true|false)\b|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?|\bnull\b)/g,
            function (match) {
                var cls = 'json-number';   // default: number
                if (/^"/.test(match)) {
                    if (/:$/.test(match)) {
                        cls = 'json-key';
                    } else {
                        cls = 'json-string';
                    }
                } else if (/true|false/.test(match)) {
                    cls = 'json-boolean';
                } else if (/null/.test(match)) {
                    cls = 'json-null';
                }
                return '<span class="' + cls + '">' + match + '</span>';
            }
        );
    },

    copyCurl: function () {
        var curlEl = document.getElementById('debugger-curl-output');
        var btn = document.getElementById('debugger-copy-curl');
        if (!curlEl || !curlEl.textContent) return;
        this.copyToClipboard(curlEl.textContent, btn);
    },

    // -----------------------------------------------------------------------
    // Curl copy buttons (for API Reference static examples)
    // -----------------------------------------------------------------------

    setupCurlCopyButtons: function () {
        var self = this;
        // Delegate click events on .curl-copy-btn elements
        document.addEventListener('click', function (e) {
            var btn = e.target.closest('.curl-copy-btn');
            if (!btn) return;

            // Find the associated code block
            var codeBlock = btn.closest('.curl-example');
            if (!codeBlock) {
                codeBlock = btn.parentElement;
            }
            var codeEl = codeBlock ? codeBlock.querySelector('code, pre') : null;
            if (codeEl) {
                self.copyToClipboard(codeEl.textContent, btn);
            }
        });
    },

    // -----------------------------------------------------------------------
    // Smooth scroll for anchor links
    // -----------------------------------------------------------------------

    setupSmoothScroll: function () {
        document.addEventListener('click', function (e) {
            var link = e.target.closest('a[href^="#"]');
            if (!link) return;

            var href = link.getAttribute('href');
            if (!href || href === '#') return;

            // Skip tab-switching hashes
            var tabNames = ['#quickstart', '#api', '#meowql', '#debugger'];
            if (tabNames.indexOf(href) !== -1) return;

            var target = document.querySelector(href);
            if (target) {
                e.preventDefault();
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    },

    // -----------------------------------------------------------------------
    // Utility
    // -----------------------------------------------------------------------

    getApiKey: function () {
        // Check for the auth.js pattern
        if (window.meowAuth && window.meowAuth.key) {
            return window.meowAuth.key;
        }
        // Fallback: read from localStorage (same key as auth.js)
        try {
            return localStorage.getItem('meow_api_key') || '';
        } catch (e) {
            return '';
        }
    },

    copyToClipboard: function (text, btn) {
        if (!text) return;

        function showFeedback(b) {
            if (!b) return;
            b.classList.add('copied');
            setTimeout(function () { b.classList.remove('copied'); }, 1500);
        }

        if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(text).then(function () {
                showFeedback(btn);
            }).catch(function () {
                fallbackCopy(text, btn);
            });
        } else {
            fallbackCopy(text, btn);
        }

        function fallbackCopy(t, b) {
            var textarea = document.createElement('textarea');
            textarea.value = t;
            textarea.style.cssText = 'position:fixed;left:-9999px;top:-9999px;opacity:0;';
            document.body.appendChild(textarea);
            textarea.select();
            try {
                document.execCommand('copy');
                showFeedback(b);
            } catch (e) {
                // Silent failure
            }
            document.body.removeChild(textarea);
        }
    },

    escapeHtml: function (text) {
        if (!text) return '';
        var div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
};

// -----------------------------------------------------------------------
// Bootstrap
// -----------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', function () {
    var lo = document.querySelector('.loading-overlay');
    if (lo) lo.style.display = 'none';
    docsPage.init();
});
