// Sidebar Toggle Functionality
class SidebarManager {
    constructor() {
        this.sidebar = null;
        this.toggleBtn = null;
        this.isCollapsed = false;
        this.storageKey = 'sidebar-collapsed';

        this.init();
    }

    init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setup());
        } else {
            this.setup();
        }
    }

    setup() {
        // Find sidebar element
        this.sidebar = document.querySelector('.sidebar');
        if (!this.sidebar) return;

        // Sync JS state with the class applied by the inline script
        this.isCollapsed = this.sidebar.classList.contains('collapsed');

        // Remove no-transition class after first paint to enable animations
        requestAnimationFrame(() => {
            requestAnimationFrame(() => {
                this.sidebar.classList.remove('no-transition');
            });
        });

        // Build proper tooltip elements for collapsed mode
        this.buildTooltips();

        // Create and add toggle button to main content
        this.createToggleButton();

        // Setup keyboard shortcut (Ctrl/Cmd + B)
        this.setupKeyboardShortcut();
    }

    buildTooltips() {
        const navItems = this.sidebar.querySelectorAll('.nav-item');
        navItems.forEach(item => {
            // Get the label text from the span or title attribute
            const span = item.querySelector('span');
            const label = span ? span.textContent.trim() : (item.getAttribute('title') || '');
            if (!label) return;

            // Store label for collapsed mode
            item.setAttribute('data-title', label);

            // Create tooltip element
            const tooltip = document.createElement('div');
            tooltip.className = 'nav-tooltip';
            tooltip.textContent = label;
            item.appendChild(tooltip);
        });
    }

    createToggleButton() {
        this.toggleBtn = document.getElementById('sidebar-toggle') || document.querySelector('.sidebar-toggle-btn');
        if (this.toggleBtn) {
            this.toggleBtn.addEventListener('click', () => this.toggle());
        }
    }

    setupKeyboardShortcut() {
        document.addEventListener('keydown', (e) => {
            // Ctrl/Cmd + B to toggle sidebar
            if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
                e.preventDefault();
                this.toggle();
            }
        });
    }

    toggle() {
        this.isCollapsed = !this.isCollapsed;

        if (this.isCollapsed) {
            this.sidebar.classList.add('collapsed');
        } else {
            this.sidebar.classList.remove('collapsed');
        }

        // Save state to localStorage
        localStorage.setItem(this.storageKey, this.isCollapsed.toString());

        // Emit custom event for other components to listen to
        this.sidebar.dispatchEvent(new CustomEvent('sidebar-toggled', {
            detail: { isCollapsed: this.isCollapsed }
        }));
    }

    expand() {
        if (this.isCollapsed) {
            this.toggle();
        }
    }

    collapse() {
        if (!this.isCollapsed) {
            this.toggle();
        }
    }
}

// Mobile Switch Banner
class MobileBannerManager {
    constructor() {
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setup());
        } else {
            this.setup();
        }
    }

    setup() {
        // Don't show on mobile pages
        if (window.location.pathname.startsWith('/mobile')) return;

        // Check if user dismissed the banner this session
        if (sessionStorage.getItem('mobile-banner-dismissed') === 'true') {
            document.body.classList.add('mobile-banner-dismissed');
            this.createFab();
            return;
        }

        this.createBanner();
    }

    createBanner() {
        const banner = document.createElement('div');
        banner.className = 'mobile-switch-banner';
        banner.innerHTML = `
            <div class="mobile-banner-logo">
                <svg width="64" height="64" viewBox="0 0 200 200" fill="none" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
                    <defs>
                        <radialGradient id="mbBodyGrad" cx="88.59" cy="129.81" r="67.73" gradientTransform="scale(1.129,0.886)" fx="88.59" fy="129.81" gradientUnits="userSpaceOnUse">
                            <stop offset="0%" stop-color="#1a6fd4"/><stop offset="100%" stop-color="#0a1f6b"/>
                        </radialGradient>
                        <radialGradient id="mbEyeGradL" cx="69.98" cy="101.98" r="29.5" gradientTransform="scale(1.042,0.96)" fx="69.98" fy="101.98" gradientUnits="userSpaceOnUse">
                            <stop offset="0%" stop-color="#ffe94d"/><stop offset="70%" stop-color="#f0a500"/><stop offset="100%" stop-color="#c47800"/>
                        </radialGradient>
                        <radialGradient id="mbEyeGradR" cx="112.22" cy="101.98" r="29.5" gradientTransform="scale(1.042,0.96)" fx="112.22" fy="101.98" gradientUnits="userSpaceOnUse">
                            <stop offset="0%" stop-color="#ffe94d"/><stop offset="70%" stop-color="#f0a500"/><stop offset="100%" stop-color="#c47800"/>
                        </radialGradient>
                    </defs>
                    <ellipse cx="100" cy="115" rx="55" ry="50" fill="url(#mbBodyGrad)" stroke="#00eeff" stroke-width="1.5"/>
                    <g transform="rotate(-6.28,90.45,82.01)"><polygon points="40,45 75,68 55,80" fill="#0a2a8a" stroke="#00eeff" stroke-width="1.5"/><polygon points="46,52 72,70 57,76" fill="#1a3fcc" opacity="0.6"/></g>
                    <g transform="matrix(-0.994,-0.109,-0.109,0.994,209.37,11.67)"><polygon points="40,45 75,68 55,80" fill="#0a2a8a" stroke="#00eeff" stroke-width="1.5"/><polygon points="46,52 72,70 57,76" fill="#1a3fcc" opacity="0.6"/></g>
                    <ellipse cx="78" cy="105" rx="16" ry="14" fill="url(#mbEyeGradL)"/>
                    <ellipse cx="122" cy="105" rx="16" ry="14" fill="url(#mbEyeGradR)"/>
                    <ellipse cx="78" cy="105" rx="5" ry="12" fill="#0a0a0a"/>
                    <ellipse cx="122" cy="105" rx="5" ry="12" fill="#0a0a0a"/>
                    <ellipse cx="74" cy="101" rx="3" ry="2" fill="#fff" opacity="0.8"/>
                    <ellipse cx="118" cy="101" rx="3" ry="2" fill="#fff" opacity="0.8"/>
                    <polygon points="93.7,131.9 103.7,131.9 98.7,125.9" fill="#00eeff" opacity="0.9"/>
                </svg>
                <div class="logo-text">MEOW</div>
            </div>
            <div class="mobile-banner-content">
                <h2>Mobile version available</h2>
                <p>This interface is optimized for larger screens. Switch to the mobile version for a better experience.</p>
            </div>
            <a href="/mobile" class="mobile-banner-link">
                <svg viewBox="0 0 24 24" fill="none">
                    <rect x="7" y="2" width="10" height="20" rx="2" stroke="currentColor" stroke-width="2"/>
                    <line x1="10" y1="18" x2="14" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
                </svg>
                Open Mobile View
            </a>
            <button class="mobile-banner-dismiss" id="mobile-banner-dismiss">Continue with desktop version</button>
        `;

        document.body.insertBefore(banner, document.body.firstChild);

        // Floating button (always in DOM, shown via CSS only when banner dismissed + small screen)
        this.createFab();

        document.getElementById('mobile-banner-dismiss').addEventListener('click', () => {
            sessionStorage.setItem('mobile-banner-dismissed', 'true');
            document.body.classList.add('mobile-banner-dismissed');
        });
    }

    createFab() {
        const fab = document.createElement('a');
        fab.href = '/mobile';
        fab.className = 'mobile-fab';
        fab.innerHTML = `
            <svg viewBox="0 0 24 24" fill="none">
                <rect x="7" y="2" width="10" height="20" rx="2" stroke="currentColor" stroke-width="2"/>
                <line x1="10" y1="18" x2="14" y2="18" stroke="currentColor" stroke-width="2" stroke-linecap="round"/>
            </svg>
            Mobile
        `;
        document.body.appendChild(fab);
    }
}

// Cat Logo Animator — random mimiques every ~20s
class CatAnimator {
    constructor() {
        this.logo = null;
        this.timer = null;
        this.animations = [
            { name: 'blink', duration: 500 },
            { name: 'double-blink', duration: 900 },
            { name: 'yawn', duration: 2600 },
            { name: 'look-around', duration: 2100 },
            { name: 'wide-eyes', duration: 1300 },
            { name: 'wink', duration: 600 },
            { name: 'wink-r', duration: 600 },
            { name: 'nose-twitch', duration: 1100 },
            { name: 'ear-twitch', duration: 900 },
            { name: 'ear-twitch-r', duration: 900 },
            { name: 'smile', duration: 2100 },
            { name: 'blep', duration: 2100 },
            { name: 'sleepy', duration: 3100 },
            { name: 'surprised', duration: 2100 },
        ];

        if (window.matchMedia('(prefers-reduced-motion: reduce)').matches) return;

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => this.setup());
        } else {
            this.setup();
        }
    }

    setup() {
        this.logo = document.querySelector('.sidebar .cat-logo');
        if (!this.logo) return;
        this.schedule();
    }

    schedule() {
        var delay = 10000 + Math.random() * 5000;
        this.timer = setTimeout(() => {
            this.play();
            this.schedule();
        }, delay);
    }

    play() {
        if (!this.logo) return;
        var anim = this.animations[Math.floor(Math.random() * this.animations.length)];
        this.logo.classList.add(anim.name);
        setTimeout(() => {
            if (this.logo) this.logo.classList.remove(anim.name);
        }, anim.duration);
    }

    destroy() {
        clearTimeout(this.timer);
    }
}

// Auto-initialize
const sidebarManager = new SidebarManager();
const mobileBannerManager = new MobileBannerManager();
const catAnimator = new CatAnimator();

// Export for global access
window.sidebarManager = sidebarManager;
