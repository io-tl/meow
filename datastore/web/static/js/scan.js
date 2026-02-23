const PORT_PRESETS = {
    top20: '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080',
    top50: '21,22,23,25,26,53,80,81,110,111,113,135,139,143,179,199,443,445,465,514,515,548,554,587,646,993,995,1025,1026,1027,1433,1720,1723,2000,2001,3306,3389,5060,5666,5900,6001,8000,8008,8080,8443,8888,10000,32768,49152,49154',
    top100: '7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1900,2000,2001,2049,2121,2717,3000,3128,3306,3389,3986,4899,5000,5009,5051,5060,5101,5190,5357,5432,5631,5666,5800,5900,6000,6001,6646,7070,8000,8008,8009,8080,8081,8443,8888,9100,9999,10000,32768,49152,49153,49154,49155,49156,49157',
};

class ScanPage {
    constructor() {
        this.pollInterval = null;
        this.scanners = [];
        this.init();
    }

    init() {
        this.loadScanners();
        this.loadEvents();
        this.pollInterval = setInterval(() => this.loadScanners(), 5000);
        this.eventInterval = setInterval(() => this.loadEvents(), 3000);
        this.setupForm();
        this.setupPortPresets();
    }

    async loadScanners() {
        try {
            const response = await fetch('/api/scanners');
            const data = await response.json();
            this.scanners = data.scanners || [];
            this.renderScannerNodes();
            this.updateSubmitButton();
            this.updateTopbar();
        } catch (error) {
            console.error('Failed to load scanners:', error);
        }
    }

    renderScannerNodes() {
        const container = document.getElementById('scanner-chips');
        if (!container) return;

        const count = this.scanners.length;

        if (count === 0) {
            container.className = 'scanner-chips empty';
            container.innerHTML = `
                <div class="scanner-empty-state">
                    <svg width="32" height="32" viewBox="0 0 24 24" fill="none">
                        <path d="M2 12h4l3-9 6 18 3-9h4" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
                    </svg>
                    <p>No scanner nodes connected</p>
                    <span>Start a SynScan daemon to enable scanning</span>
                </div>
            `;
            return;
        }

        container.className = 'scanner-chips';
        container.innerHTML = this.scanners.map(node => {
            const statusClass = node.status === 'scanning' ? 'scanning' : 'idle';
            const statusLabel = node.status === 'scanning' ? 'scanning' : 'idle';
            const uptime = this.formatUptime(node.uptime_sec);
            const shortId = node.node_id.length > 18 ? node.node_id.substring(0, 18) + '...' : node.node_id;
            const hostname = node.hostname || '';
            const tooltip = [node.node_id, node.transport, node.scan_id].filter(Boolean).join(' | ');
            return `<div class="scanner-chip" title="${this.escapeHtml(tooltip)}"><span class="scanner-chip-dot ${statusClass}"></span><span class="scanner-chip-id">${this.escapeHtml(shortId)}</span>${hostname ? `<span class="scanner-chip-host">(${this.escapeHtml(hostname)})</span>` : ''}<span class="scanner-chip-status ${statusClass}">${statusLabel}</span><span class="scanner-chip-uptime">&middot; ${uptime}</span></div>`;
        }).join('');
    }

    updateSubmitButton() {
        const btn = document.getElementById('scan-submit-btn');
        if (btn) {
            btn.disabled = this.scanners.length === 0;
        }
    }

    updateTopbar() {
        const count = this.scanners.length;
        const dot = document.getElementById('scan-status-dot');
        const label = document.getElementById('scan-scanner-count');

        if (dot) {
            dot.className = 'scan-status-dot' + (count > 0 ? ' active' : '');
        }
        if (label) {
            label.textContent = count + ' scanner' + (count !== 1 ? 's' : '');
        }
    }

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
        document.querySelectorAll('.port-preset-btn').forEach(btn => {
            btn.addEventListener('click', () => {
                const preset = btn.dataset.preset;
                const input = document.getElementById('scan-ports');
                if (!input) return;
                document.querySelectorAll('.port-preset-btn').forEach(b => b.classList.remove('active'));
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
                document.querySelectorAll('.port-preset-btn').forEach(b => b.classList.remove('active'));
            });
        }
    }

    async submitScan() {
        const target = document.getElementById('scan-target').value.trim();
        const ports = document.getElementById('scan-ports').value.trim();
        const rateStr = document.getElementById('scan-rate').value.trim();

        if (!target) {
            this.showToast('Target is required', 'error');
            return;
        }
        if (!ports) {
            this.showToast('Ports are required', 'error');
            return;
        }

        const body = { target: target, ports: ports };
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
        const section = document.getElementById('event-feed-section');
        const list = document.getElementById('event-feed-list');
        const countEl = document.getElementById('event-feed-count');
        if (!section || !list) return;

        if (events.length === 0) {
            section.style.display = 'none';
            return;
        }

        section.style.display = '';
        if (countEl) countEl.textContent = events.length + ' events';

        const now = Math.floor(Date.now() / 1000);
        list.innerHTML = events.map(e => {
            const ago = this.formatAgo(now - e.at);
            const svc = e.service || e.product || '';
            const label = e.type === 'open' ? 'OPEN' : e.type === 'fingerprinted' ? 'FINGER' : 'ENRICH';
            return `<div class="event-feed-row"><span class="event-feed-type ${this.escapeHtml(e.type)}">${label}</span><span class="event-feed-target">${this.escapeHtml(e.ip)}:${e.port}</span><span class="event-feed-svc">${this.escapeHtml(svc)}</span><span class="event-feed-ago">${ago}</span></div>`;
        }).join('');
    }

    formatAgo(sec) {
        if (sec < 0) sec = 0;
        if (sec < 60) return sec + 's';
        if (sec < 3600) return Math.floor(sec / 60) + 'm';
        if (sec < 86400) return Math.floor(sec / 3600) + 'h';
        return Math.floor(sec / 86400) + 'd';
    }

    showToast(message, type) {
        const toast = document.getElementById('scan-toast');
        if (!toast) return;

        toast.textContent = message;
        toast.className = 'scan-toast ' + type + ' visible';

        setTimeout(() => {
            toast.className = 'scan-toast';
        }, 4000);
    }

    formatUptime(seconds) {
        if (!seconds || seconds <= 0) return '-';
        if (seconds < 60) return seconds + 's';
        if (seconds < 3600) return Math.floor(seconds / 60) + 'm';
        const h = Math.floor(seconds / 3600);
        const m = Math.floor((seconds % 3600) / 60);
        return h + 'h ' + m + 'm';
    }

    escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.scanPage = new ScanPage();
});
