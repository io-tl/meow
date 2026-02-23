const PORT_PRESETS = {
    top20: '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
    top50: '21,22,23,25,26,53,80,81,110,111,113,135,139,143,179,199,443,445,465,514,515,548,554,587,646,993,995,1025,1026,1027,1433,1720,1723,2000,2001,3306,3389,5060,5666,5900,6001,8000,8008,8080,8443,8888,10000,32768,49152,49154',
    top100: '7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157',
};

class MobileScan {
    constructor() {
        this.scanners = [];
        this.init();
    }

    init() {
        this.loadScanners();
        this.loadEvents();
        this.setupForm();
        this.setupPortPresets();
        this.setupDnsResolver();

        setInterval(() => this.loadScanners(), 5000);
        setInterval(() => this.loadEvents(), 3000);
    }

    // ===== Scanners =====
    async loadScanners() {
        try {
            const response = await fetch('/api/scanners');
            const data = await response.json();
            this.scanners = data.scanners || [];
            this.renderScannerChips();
            this.updateHeaderStatus();
            this.updateSubmitButton();
        } catch (error) {
            console.error('Failed to load scanners:', error);
        }
    }

    renderScannerChips() {
        const container = document.getElementById('scanner-chips');
        const emptyState = document.getElementById('scan-empty-state');
        const formCard = document.getElementById('scan-form-card');
        if (!container) return;

        const hasNodes = this.scanners.length > 0;

        if (emptyState) emptyState.style.display = hasNodes ? 'none' : '';
        container.style.display = hasNodes ? '' : 'none';
        if (formCard) {
            formCard.style.display = '';
            if (hasNodes) {
                formCard.classList.remove('disabled');
            } else {
                formCard.classList.add('disabled');
            }
        }

        if (!hasNodes) return;

        container.innerHTML = this.scanners.map(node => {
            const statusClass = node.status === 'scanning' ? 'scanning' : 'idle';
            const statusLabel = node.status === 'scanning' ? 'scanning' : 'idle';
            const shortId = node.node_id.length > 14 ? node.node_id.substring(0, 14) + '...' : node.node_id;
            const uptime = this.formatUptime(node.uptime_sec);
            return `<div class="m-scanner-chip"><span class="m-scanner-dot ${statusClass}"></span><span class="m-scanner-id">${this.esc(shortId)}</span><span class="m-scanner-status ${statusClass}">${statusLabel}</span><span class="m-scanner-uptime">${uptime}</span></div>`;
        }).join('');
    }

    updateHeaderStatus() {
        const count = this.scanners.length;
        const dot = document.getElementById('scanner-status-dot');
        const label = document.getElementById('scanner-count');

        if (dot) {
            dot.className = 'scanner-status-dot' + (count > 0 ? ' active' : '');
        }
        if (label) {
            label.textContent = count + ' scanner' + (count !== 1 ? 's' : '');
        }
    }

    updateSubmitButton() {
        const btn = document.getElementById('scan-submit-btn');
        if (btn) btn.disabled = this.scanners.length === 0;
    }

    // ===== Form =====
    setupForm() {
        const form = document.getElementById('scan-form');
        if (form) {
            form.addEventListener('submit', (e) => {
                e.preventDefault();
                this.submitScan();
            });
        }
    }

    setupPortPresets() {
        document.querySelectorAll('.m-port-preset').forEach(btn => {
            btn.addEventListener('click', () => {
                const preset = btn.dataset.preset;
                const input = document.getElementById('scan-ports');
                if (!input) return;
                document.querySelectorAll('.m-port-preset').forEach(b => b.classList.remove('active'));
                if (preset === 'clear') {
                    input.value = '';
                    input.focus();
                    return;
                }
                if (!PORT_PRESETS[preset]) return;
                input.value = PORT_PRESETS[preset];
                btn.classList.add('active');
            });
        });

        const input = document.getElementById('scan-ports');
        if (input) {
            input.addEventListener('input', () => {
                document.querySelectorAll('.m-port-preset').forEach(b => b.classList.remove('active'));
            });
        }
    }

    async submitScan() {
        const target = document.getElementById('scan-target').value.trim();
        const ports = document.getElementById('scan-ports').value.trim();
        const rateStr = document.getElementById('scan-rate').value.trim();

        if (!target) { this.showToast('Target is required', 'error'); return; }
        if (!ports) { this.showToast('Ports are required', 'error'); return; }

        const body = { target, ports };
        if (rateStr) {
            const rate = parseInt(rateStr, 10);
            if (rate > 0) body.rate_limit = rate;
        }

        const btn = document.getElementById('scan-submit-btn');
        if (btn) btn.disabled = true;

        try {
            const response = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await response.json();

            if (!response.ok) {
                this.showToast(data.error || 'Failed to submit scan', 'error');
                return;
            }

            this.showToast('Scan submitted: ' + data.request_id.substring(0, 8) + '...', 'success');
            document.getElementById('scan-target').value = '';
        } catch (error) {
            this.showToast('Network error', 'error');
        } finally {
            this.updateSubmitButton();
        }
    }

    // ===== Live Feed =====
    async loadEvents() {
        try {
            const response = await fetch('/api/events/recent');
            const data = await response.json();
            this.renderEvents(data.events || []);
        } catch (error) {
            // silent
        }
    }

    renderEvents(events) {
        const list = document.getElementById('feed-list');
        const countEl = document.getElementById('feed-count');
        if (!list) return;

        if (events.length === 0) {
            list.innerHTML = `<div class="m-feed-empty"><svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M2 12h4l3-9 6 18 3-9h4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span>No recent events</span></div>`;
            if (countEl) countEl.textContent = '';
            return;
        }

        if (countEl) countEl.textContent = events.length + ' events';

        const now = Math.floor(Date.now() / 1000);
        list.innerHTML = events.map(e => {
            const ago = this.formatAgo(now - e.at);
            const svc = e.service || e.product || '';
            const label = e.type === 'open' ? 'OPEN' : e.type === 'fingerprinted' ? 'FP' : 'ENR';
            return `<div class="m-feed-row"><span class="m-feed-type ${this.esc(e.type)}">${label}</span><span class="m-feed-target">${this.esc(e.ip)}:${e.port}</span><span class="m-feed-svc">${this.esc(svc)}</span><span class="m-feed-ago">${ago}</span></div>`;
        }).join('');
    }

    // ===== DNS Resolver =====
    setupDnsResolver() {
        const btn = document.getElementById('dns-resolve-btn');
        const clearBtn = document.getElementById('dns-clear-btn');
        const input = document.getElementById('dns-query');
        if (!input) return;

        if (btn) btn.addEventListener('click', () => this.resolveDns());
        if (clearBtn) clearBtn.addEventListener('click', () => this.clearDns());
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') { e.preventDefault(); this.resolveDns(); }
        });
    }

    clearDns() {
        const input = document.getElementById('dns-query');
        const results = document.getElementById('dns-results');
        if (input) { input.value = ''; input.focus(); }
        if (results) results.innerHTML = '';
    }

    fillDnsQuery(value) {
        const input = document.getElementById('dns-query');
        if (!input) return;
        input.value = value;
        input.focus();
        this.resolveDns();
    }

    async resolveDns() {
        const input = document.getElementById('dns-query');
        const results = document.getElementById('dns-results');
        const query = input?.value.trim();
        if (!query || !results) return;

        results.innerHTML = '<div class="m-dns-loading">Resolving...</div>';

        try {
            const response = await fetch('/api/tools/dns?q=' + encodeURIComponent(query));
            const data = await response.json();

            if (!response.ok) {
                results.innerHTML = `<div class="m-dns-error">${this.esc(data.error || 'Lookup failed')}</div>`;
                return;
            }

            this.renderDnsResults(data, results);
        } catch (error) {
            results.innerHTML = '<div class="m-dns-error">Network error</div>';
        }
    }

    renderDnsResults(data, container) {
        const rows = [];

        if (data.a) {
            data.a.forEach(ip => rows.push(this.dnsRow('A', ip, false, null, true)));
        }
        if (data.aaaa) {
            data.aaaa.forEach(ip => rows.push(this.dnsRow('AAAA', ip, false, null, true)));
        }
        if (data.cname) {
            rows.push(this.dnsRow('CNAME', data.cname, true));
        }
        if (data.ptr) {
            data.ptr.forEach(n => rows.push(this.dnsRow('PTR', n, true)));
        }
        if (data.mx) {
            data.mx.forEach(mx => rows.push(this.dnsRow('MX', mx.host, true, ' (pref ' + mx.pref + ')')));
        }
        if (data.ns) {
            data.ns.forEach(ns => rows.push(this.dnsRow('NS', ns, true)));
        }
        if (data.txt) {
            data.txt.forEach(txt => rows.push(this.dnsRow('TXT', txt, false)));
        }

        if (rows.length === 0) {
            container.innerHTML = '<div class="m-dns-error">No records found</div>';
            return;
        }

        container.innerHTML = rows.join('');

        container.querySelectorAll('.m-dns-link').forEach(el => {
            el.addEventListener('click', () => {
                this.fillDnsQuery(el.dataset.query);
            });
        });

        container.querySelectorAll('.m-dns-ip-link').forEach(el => {
            el.addEventListener('click', () => {
                this.fillScanTarget(el.dataset.ip);
            });
        });
    }

    fillScanTarget(ip) {
        const input = document.getElementById('scan-target');
        if (!input) return;
        input.value = ip;
        input.focus();
    }

    dnsRow(type, value, clickable, suffix, ipAction) {
        const escaped = this.esc(value);
        const sfx = suffix ? `<span class="m-dns-suffix">${this.esc(suffix)}</span>` : '';
        let valueHtml;
        if (ipAction) {
            valueHtml = `<span class="m-dns-value m-dns-ip-link" data-ip="${escaped}">${escaped}</span>${sfx}`;
        } else if (clickable) {
            valueHtml = `<span class="m-dns-value m-dns-link" data-query="${escaped}">${escaped}</span>${sfx}`;
        } else {
            valueHtml = `<span class="m-dns-value">${escaped}</span>${sfx}`;
        }
        return `<div class="m-dns-row"><span class="m-dns-type">${this.esc(type)}</span>${valueHtml}</div>`;
    }

    // ===== Helpers =====
    formatAgo(sec) {
        if (sec < 0) sec = 0;
        if (sec < 60) return sec + 's';
        if (sec < 3600) return Math.floor(sec / 60) + 'm';
        if (sec < 86400) return Math.floor(sec / 3600) + 'h';
        return Math.floor(sec / 86400) + 'd';
    }

    formatUptime(seconds) {
        if (!seconds || seconds <= 0) return '-';
        if (seconds < 60) return seconds + 's';
        if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        return h + 'h' + m + 'm';
    }

    showToast(message, type) {
        const toast = document.getElementById('scan-toast');
        if (!toast) return;
        toast.textContent = message;
        toast.className = 'm-scan-toast ' + type + ' visible';
        setTimeout(() => { toast.className = 'm-scan-toast'; }, 4000);
    }

    esc(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.mobileScan = new MobileScan();
});
