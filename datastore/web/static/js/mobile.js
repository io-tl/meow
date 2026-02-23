// Mobile Dashboard
class MobileDashboard {
  constructor() {
    this.charts = {};
    this.init();
  }

  init() {
    this.loadDashboardStats();
    this.updateLastUpdateTime();
    this.setupPullToRefresh();

    // Auto-refresh every 5 minutes
    setInterval(() => {
      this.loadDashboardStats();
      this.updateLastUpdateTime();
    }, 300000);
  }

  // ===== Pull to Refresh =====
  setupPullToRefresh() {
    const content = document.getElementById('mobile-content');
    const indicator = document.getElementById('pull-indicator');
    let startY = 0;
    let pulling = false;

    content.addEventListener('touchstart', (e) => {
      if (content.scrollTop === 0) {
        startY = e.touches[0].clientY;
        pulling = true;
      }
    }, { passive: true });

    content.addEventListener('touchmove', (e) => {
      if (!pulling) return;
      const diff = e.touches[0].clientY - startY;
      if (diff > 60 && content.scrollTop === 0) {
        indicator.classList.add('visible');
      }
    }, { passive: true });

    content.addEventListener('touchend', () => {
      if (!pulling) return;
      pulling = false;
      if (indicator.classList.contains('visible')) {
        this.loadDashboardStats();
        this.updateLastUpdateTime();
        setTimeout(() => indicator.classList.remove('visible'), 1000);
      }
    }, { passive: true });
  }

  // ===== Data Loading =====
  async loadDashboardStats() {
    try {
      const response = await fetch('/api/stats/dashboard');
      const data = await response.json();
      this.updateSummaryCards(data);
      this.loadCharts();
    } catch (error) {
      console.error('Error loading dashboard stats:', error);
    }
  }

  updateSummaryCards(data) {
    this.animateNumber('total-hosts', data.total_hosts || 0);
    this.animateNumber('total-services', data.total_services || 0);
    this.animateNumber('total-certs', data.total_certificates || 0);
    this.animateNumber('total-countries', data.top_countries?.length || 0);
  }

  animateNumber(elementId, targetValue) {
    const element = document.getElementById(elementId);
    if (!element) return;

    const startValue = parseInt(element.textContent) || 0;
    const duration = 800;
    const startTime = performance.now();

    const animate = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      // Ease-out
      const eased = 1 - Math.pow(1 - progress, 3);
      const currentValue = Math.floor(startValue + (targetValue - startValue) * eased);
      element.textContent = currentValue.toLocaleString();
      if (progress < 1) requestAnimationFrame(animate);
    };

    requestAnimationFrame(animate);
  }

  // ===== Charts =====
  async loadCharts() {
    await Promise.all([
      this.loadCountriesChart(),
      this.loadServicesChart(),
      this.loadPortsChart(),
      this.loadTechnologiesChart()
    ]);
  }

  async loadCountriesChart() {
    try {
      const response = await fetch('/api/stats/countries');
      const data = await response.json();
      const ctx = document.getElementById('countriesChart').getContext('2d');

      if (this.charts.countries) this.charts.countries.destroy();

      this.charts.countries = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: data.countries?.slice(0, 6).map(c => c.name) || [],
          datasets: [{
            data: data.countries?.slice(0, 6).map(c => c.host_count) || [],
            backgroundColor: ['#4a9eff', '#3d8bfd', '#2a6ac0', '#a78bfa', '#8b5cf6', '#7c3aed'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '60%',
          plugins: {
            legend: {
              position: 'right',
              labels: {
                color: '#a8b3cf',
                padding: 8,
                font: { size: 11 },
                boxWidth: 12,
                boxHeight: 12
              }
            }
          }
        }
      });
    } catch (error) {
      console.error('Error loading countries chart:', error);
    }
  }

  async loadServicesChart() {
    try {
      const response = await fetch('/api/stats/services');
      const data = await response.json();
      const ctx = document.getElementById('servicesChart').getContext('2d');

      if (this.charts.services) this.charts.services.destroy();

      this.charts.services = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: data.services?.slice(0, 8).map(s => s.service) || [],
          datasets: [{
            label: 'Count',
            data: data.services?.slice(0, 8).map(s => s.count) || [],
            backgroundColor: '#4a9eff',
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          indexAxis: 'y',
          scales: {
            x: {
              beginAtZero: true,
              grid: { color: '#2a3550', drawBorder: false },
              ticks: { color: '#a8b3cf', font: { size: 10 } }
            },
            y: {
              grid: { display: false },
              ticks: { color: '#a8b3cf', font: { size: 11 } }
            }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    } catch (error) {
      console.error('Error loading services chart:', error);
    }
  }

  async loadPortsChart() {
    try {
      const response = await fetch('/api/facets');
      const data = await response.json();
      const ctx = document.getElementById('portsChart').getContext('2d');

      if (this.charts.ports) this.charts.ports.destroy();

      const ports = data.ports?.slice(0, 8) || [];

      this.charts.ports = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: ports.map(p => p.value),
          datasets: [{
            label: 'Hosts',
            data: ports.map(p => p.count),
            backgroundColor: ports.map((_, i) => {
              const colors = ['#4a9eff', '#00d4ff', '#a78bfa', '#34d399', '#fbbf24', '#f87171', '#f472b6', '#10b981'];
              return colors[i % colors.length];
            }),
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              grid: { color: '#2a3550', drawBorder: false },
              ticks: { color: '#a8b3cf', font: { size: 10 } }
            },
            x: {
              grid: { display: false },
              ticks: { color: '#a8b3cf', font: { size: 10 } }
            }
          },
          plugins: {
            legend: { display: false }
          }
        }
      });
    } catch (error) {
      console.error('Error loading ports chart:', error);
    }
  }

  async loadTechnologiesChart() {
    try {
      const response = await fetch('/api/stats/technologies');
      const data = await response.json();
      const ctx = document.getElementById('techChart').getContext('2d');

      if (this.charts.tech) this.charts.tech.destroy();

      const techData = data.technologies?.slice(0, 8) || [];

      this.charts.tech = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: techData.map(t => t.technology),
          datasets: [{
            data: techData.map(t => t.count),
            backgroundColor: ['#00d4ff', '#a78bfa', '#34d399', '#fbbf24', '#f87171', '#4a9eff', '#f472b6', '#10b981'],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          cutout: '60%',
          plugins: {
            legend: {
              position: 'right',
              labels: {
                color: '#a8b3cf',
                padding: 8,
                font: { size: 11 },
                boxWidth: 12,
                boxHeight: 12
              }
            }
          }
        }
      });
    } catch (error) {
      console.error('Error loading technologies chart:', error);
    }
  }

  updateLastUpdateTime() {
    const now = new Date();
    const timeString = now.toLocaleTimeString('en-US', {
      hour: '2-digit',
      minute: '2-digit',
      hour12: false
    });
    const element = document.getElementById('last-update');
    if (element) element.textContent = timeString;
  }
}

// Initialize
document.addEventListener('DOMContentLoaded', () => {
  window.mobileDashboard = new MobileDashboard();
});

