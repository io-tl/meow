class DebugDashboard {
    constructor() {
        this.refreshInterval = null;
        this.lastData = null;
        this.init();
    }

    init() {
        this.loadStats();
        this.refreshInterval = setInterval(() => this.loadStats(), 5000);
    }

    async loadStats() {
        try {
            const response = await fetch('/api/debug/stats');
            const data = await response.json();
            this.lastData = data;
            this.renderSummaryCards(data);
            this.renderNATSSection(data.nats);
            this.renderEnrichmentSection(data.database?.enrichment);
            this.renderTopServices(data.database?.top_services);
            this.updateTimestamp();
        } catch (error) {
            console.error('Failed to load debug stats:', error);
        }
    }

    renderSummaryCards(data) {
        const nats = data.nats || {};
        const db = data.database || {};
        const enrichment = db.enrichment || {};

        // NATS messages total
        const totalMsgs = (nats.in_msgs || 0) + (nats.out_msgs || 0);
        const el1 = document.getElementById('summary-nats-value');
        if (el1) el1.textContent = this.formatNumber(totalMsgs);

        const el1b = document.getElementById('summary-nats-badge');
        if (el1b) {
            el1b.textContent = nats.connected ? 'Connected' : 'Disconnected';
            el1b.className = 'debug-summary-badge ' + (nats.connected ? 'online' : 'offline');
        }

        // DB records total
        const totalRecords = (db.hosts || 0) + (db.services || 0) + (db.certificates || 0);
        const el2 = document.getElementById('summary-db-value');
        if (el2) el2.textContent = this.formatNumber(totalRecords);

        const el2b = document.getElementById('summary-db-detail');
        if (el2b) el2b.textContent = `${this.formatNumber(db.hosts || 0)} hosts, ${this.formatNumber(db.services || 0)} services`;

        // Enrichment % (only count enrichable services: enriched + pending + failed)
        const enrichable = (enrichment.enriched || 0) + (enrichment.pending || 0) + (enrichment.failed || 0);
        const pct = enrichable > 0 ? Math.round(((enrichment.enriched || 0) / enrichable) * 100) : 0;
        const el3 = document.getElementById('summary-enrichment-value');
        if (el3) el3.textContent = pct + '%';

        const el3b = document.getElementById('summary-enrichment-detail');
        if (el3b) el3b.textContent = `${this.formatNumber(enrichment.enriched || 0)} of ${this.formatNumber(enrichable)} services`;
    }

    renderNATSSection(nats) {
        if (!nats) return;

        // URL
        const urlEl = document.getElementById('nats-url');
        if (urlEl) urlEl.textContent = nats.url || 'N/A';

        // Status badge
        const statusEl = document.getElementById('nats-status');
        if (statusEl) {
            statusEl.innerHTML = `<span class="nats-status-dot"></span>${nats.connected ? 'Connected' : 'Disconnected'}`;
            statusEl.className = 'nats-status-badge ' + (nats.connected ? 'connected' : 'disconnected');
        }

        // Stats
        this.setTextById('nats-in-msgs', this.formatNumber(nats.in_msgs || 0));
        this.setTextById('nats-out-msgs', this.formatNumber(nats.out_msgs || 0));
        this.setTextById('nats-in-bytes', this.formatBytes(nats.in_bytes || 0));
        this.setTextById('nats-out-bytes', this.formatBytes(nats.out_bytes || 0));
        this.setTextById('nats-connections', nats.total_connections || 0);
        this.setTextById('nats-reconnects', nats.reconnects || 0);

        // Clients
        const clientsGrid = document.getElementById('nats-clients-grid');
        const clientsTitle = document.getElementById('nats-clients-title');
        if (!clientsGrid) return;

        const clients = nats.clients || [];
        if (clients.length === 0) {
            clientsGrid.innerHTML = '<div style="padding: 16px 20px; color: var(--text-muted); font-size: 13px;">No active clients</div>';
            if (clientsTitle) clientsTitle.textContent = 'Clients (0)';
            return;
        }

        if (clientsTitle) clientsTitle.textContent = `Clients (${clients.length})`;

        clientsGrid.innerHTML = clients.map(client => {
            const subjects = (client.subjects || []).map(s =>
                `<span class="nats-subject-tag">${this.escapeHtml(s)}</span>`
            ).join('');

            return `
                <div class="nats-client-card">
                    <div class="nats-client-name">
                        ${this.escapeHtml(client.name || 'Unnamed')}
                        <span class="nats-client-cid">CID ${client.cid}</span>
                    </div>
                    <div class="nats-client-stats">
                        <div class="nats-client-stat">
                            <span>Msgs In</span>
                            <span class="nats-client-stat-value">${this.formatNumber(client.in_msgs || 0)}</span>
                        </div>
                        <div class="nats-client-stat">
                            <span>Msgs Out</span>
                            <span class="nats-client-stat-value">${this.formatNumber(client.out_msgs || 0)}</span>
                        </div>
                        <div class="nats-client-stat">
                            <span>Bytes In</span>
                            <span class="nats-client-stat-value">${this.formatBytes(client.in_bytes || 0)}</span>
                        </div>
                        <div class="nats-client-stat">
                            <span>Bytes Out</span>
                            <span class="nats-client-stat-value">${this.formatBytes(client.out_bytes || 0)}</span>
                        </div>
                        <div class="nats-client-stat">
                            <span>Subs</span>
                            <span class="nats-client-stat-value">${client.subscriptions || 0}</span>
                        </div>
                        <div class="nats-client-stat">
                            <span>Uptime</span>
                            <span class="nats-client-stat-value">${this.escapeHtml(client.uptime || '-')}</span>
                        </div>
                    </div>
                    ${subjects ? `<div class="nats-client-subjects">${subjects}</div>` : ''}
                </div>
            `;
        }).join('');
    }

    renderEnrichmentSection(enrichment) {
        if (!enrichment) return;

        const enriched = enrichment.enriched || 0;
        const pending = enrichment.pending || 0;
        const failed = enrichment.failed || 0;
        const total = enriched + pending + failed;

        // Progress bar segments (only enrichable services)
        if (total > 0) {
            this.setStyle('progress-enriched', 'width', ((enriched / total) * 100) + '%');
            this.setStyle('progress-pending', 'width', ((pending / total) * 100) + '%');
            this.setStyle('progress-failed', 'width', ((failed / total) * 100) + '%');
        }

        // Counters
        this.setTextById('enrichment-enriched-count', this.formatNumber(enriched));
        this.setTextById('enrichment-pending-count', this.formatNumber(pending));
        this.setTextById('enrichment-failed-count', this.formatNumber(failed));
    }

    renderTopServices(services) {
        const container = document.getElementById('top-services-body');
        if (!container) return;

        if (!services || services.length === 0) {
            container.innerHTML = '<div style="padding: 12px 0; color: var(--text-muted); font-size: 13px;">No services data available</div>';
            return;
        }

        const maxCount = Math.max(...services.map(s => s.count || 0), 1);

        container.innerHTML = services.slice(0, 10).map(service => {
            const pct = ((service.count || 0) / maxCount) * 100;
            return `
                <div class="top-service-row">
                    <span class="top-service-name">${this.escapeHtml(service.type || service.service || service.name || 'unknown')}</span>
                    <div class="top-service-bar-wrapper">
                        <div class="top-service-bar" style="width: ${pct}%"></div>
                    </div>
                    <span class="top-service-count">${this.formatNumber(service.count || 0)}</span>
                </div>
            `;
        }).join('');
    }

    updateTimestamp() {
        const el = document.getElementById('debug-last-update');
        if (el) {
            const now = new Date();
            el.textContent = now.toLocaleTimeString();
        }
    }

    // Helpers
    setTextById(id, value) {
        const el = document.getElementById(id);
        if (el) el.textContent = value;
    }

    setStyle(id, prop, value) {
        const el = document.getElementById(id);
        if (el) el.style[prop] = value;
    }

    formatBytes(bytes) {
        if (bytes === 0) return '0 B';
        const k = 1024;
        const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
    }

    formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return Number(num).toLocaleString();
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

document.addEventListener('DOMContentLoaded', () => {
    window.debugDashboard = new DebugDashboard();
});
