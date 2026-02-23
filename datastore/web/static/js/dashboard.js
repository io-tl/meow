// Dashboard JavaScript
class Dashboard {
  constructor() {
    this.charts = {};
    this.init();
  }

  init() {
    this.loadDashboardStats();
    this.updateLastUpdateTime();
    this.setupEventListeners();

    // Auto-refresh every 5 minutes
    setInterval(() => {
      this.loadDashboardStats();
      this.updateLastUpdateTime();
    }, 300000);
  }

  setupEventListeners() {
    // Add any interactive elements here
  }

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
    // Update main statistics
    this.animateNumber('total-hosts', data.total_hosts || 0);
    this.animateNumber('total-services', data.total_services || 0);
    this.animateNumber('total-certs', data.total_certificates || 0);
    this.animateNumber('total-countries', data.top_countries?.length || 0);
  }

  animateNumber(elementId, targetValue) {
    const element = document.getElementById(elementId);

    // Check if element exists before trying to animate it
    if (!element) {
      console.warn(`Element with id '${elementId}' not found`);
      return;
    }

    const startValue = parseInt(element.textContent) || 0;
    const duration = 1000;
    const startTime = performance.now();

    const animate = (currentTime) => {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const currentValue = Math.floor(startValue + (targetValue - startValue) * progress);

      element.textContent = currentValue.toLocaleString();

      if (progress < 1) {
        requestAnimationFrame(animate);
      }
    };

    requestAnimationFrame(animate);
  }

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

      if (this.charts.countries) {
        this.charts.countries.destroy();
      }

      this.charts.countries = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: data.countries?.slice(0, 8).map(c => c.name) || [],
          datasets: [{
            data: data.countries?.slice(0, 8).map(c => c.host_count) || [],
            backgroundColor: [
              '#4a9eff',
              '#3d8bfd',
              '#2a6ac0',
              '#a78bfa',
              '#8b5cf6',
              '#7c3aed',
              '#6d28d9',
              '#5b21b6'
            ],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#a8b3cf',
                padding: 10,
                font: {
                  size: 11
                }
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

      if (this.charts.services) {
        this.charts.services.destroy();
      }

      this.charts.services = new Chart(ctx, {
        type: 'bar',
        data: {
          labels: data.services?.slice(0, 10).map(s => s.service) || [],
          datasets: [{
            label: 'Count',
            data: data.services?.slice(0, 10).map(s => s.count) || [],
            backgroundColor: '#4a9eff',
            borderRadius: 4
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            y: {
              beginAtZero: true,
              grid: {
                color: '#2a3550',
                drawBorder: false
              },
              ticks: {
                color: '#a8b3cf'
              }
            },
            x: {
              grid: {
                display: false
              },
              ticks: {
                color: '#a8b3cf',
                maxRotation: 45,
                minRotation: 45
              }
            }
          },
          plugins: {
            legend: {
              display: false
            }
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

      if (this.charts.ports) {
        this.charts.ports.destroy();
      }

      this.charts.ports = new Chart(ctx, {
        type: 'radar',
        data: {
          labels: data.ports?.slice(0, 8).map(p => `Port ${p.value}`) || [],
          datasets: [{
            label: 'Services',
            data: data.ports?.slice(0, 8).map(p => p.count) || [],
            backgroundColor: 'rgba(74, 158, 255, 0.2)',
            borderColor: '#4a9eff',
            pointBackgroundColor: '#4a9eff',
            pointBorderColor: '#fff',
            pointHoverBackgroundColor: '#fff',
            pointHoverBorderColor: '#4a9eff'
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            r: {
              beginAtZero: true,
              grid: {
                color: '#2a3550'
              },
              pointLabels: {
                color: '#a8b3cf'
              },
              ticks: {
                color: '#a8b3cf',
                backdropColor: 'transparent'
              }
            }
          },
          plugins: {
            legend: {
              display: false
            }
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

      const ctx = document.getElementById('cloudChart').getContext('2d');

      if (this.charts.cloud) {
        this.charts.cloud.destroy();
      }

      // Prepare technology data for chart
      const techData = data.technologies?.slice(0, 10) || [];
      const labels = techData.map(t => t.technology);
      const counts = techData.map(t => t.count);

      this.charts.cloud = new Chart(ctx, {
        type: 'doughnut',
        data: {
          labels: labels,
          datasets: [{
            data: counts,
            backgroundColor: [
              '#00d4ff',
              '#a78bfa',
              '#34d399',
              '#fbbf24',
              '#f87171',
              '#4a9eff',
              '#f472b6',
              '#10b981',
              '#f59e0b',
              '#ef4444'
            ],
            borderWidth: 0
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: {
            legend: {
              position: 'bottom',
              labels: {
                color: '#a8b3cf',
                padding: 10,
                font: {
                  size: 11
                }
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
    if (element) {
      element.textContent = timeString;
    }
  }
}

// Chart refresh functions
function refreshCountryChart() {
  dashboard.loadCountriesChart();
}

function refreshServiceChart() {
  dashboard.loadServicesChart();
}

function refreshPortChart() {
  dashboard.loadPortsChart();
}

function refreshCloudChart() {
  dashboard.loadTechnologiesChart();
}

// Initialize dashboard when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  window.dashboard = new Dashboard();
});

