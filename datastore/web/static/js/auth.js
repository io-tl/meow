(function() {
    var STORAGE_KEY = 'meow_api_key';

    // Monkeypatch fetch to inject X-API-Key on /api/ requests
    var originalFetch = window.fetch;
    window.fetch = function(input, init) {
        var url = (typeof input === 'string') ? input : (input && input.url ? input.url : '');
        if (url.indexOf('/api/') !== -1) {
            init = init || {};
            init.headers = init.headers || {};
            if (init.headers instanceof Headers) {
                if (!init.headers.has('X-API-Key')) {
                    var key = localStorage.getItem(STORAGE_KEY);
                    if (key) init.headers.set('X-API-Key', key);
                }
            } else if (Array.isArray(init.headers)) {
                var key = localStorage.getItem(STORAGE_KEY);
                if (key) init.headers.push(['X-API-Key', key]);
            } else {
                if (!init.headers['X-API-Key']) {
                    var key = localStorage.getItem(STORAGE_KEY);
                    if (key) init.headers['X-API-Key'] = key;
                }
            }
        }
        return originalFetch.call(this, input, init).then(function(response) {
            if (response.status === 401 && url.indexOf('/api/') !== -1) {
                localStorage.removeItem(STORAGE_KEY);
                showLoginOverlay();
            }
            return response;
        });
    };

    // Also patch XMLHttpRequest for non-fetch callers
    var origOpen = XMLHttpRequest.prototype.open;
    var origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function(method, url) {
        this._meowUrl = url;
        return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function() {
        if (this._meowUrl && this._meowUrl.indexOf('/api/') !== -1) {
            var key = localStorage.getItem(STORAGE_KEY);
            if (key) this.setRequestHeader('X-API-Key', key);
        }
        return origSend.apply(this, arguments);
    };

    var overlayVisible = false;

    function showLoginOverlay() {
        if (overlayVisible) return;
        overlayVisible = true;

        function create() {
            if (document.getElementById('meow-auth-overlay')) return;

            var overlay = document.createElement('div');
            overlay.id = 'meow-auth-overlay';
            overlay.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(6,10,23,0.95);z-index:99999;display:flex;align-items:center;justify-content:center;font-family:Inter,sans-serif;';

            var box = document.createElement('div');
            box.style.cssText = 'background:#0d1117;border:1px solid rgba(99,179,237,0.2);border-radius:12px;padding:40px;width:360px;max-width:90vw;text-align:center;box-shadow:0 0 40px rgba(99,179,237,0.1);';

            var title = document.createElement('div');
            title.textContent = 'Authentication Required';
            title.style.cssText = 'color:#e2e8f0;font-size:18px;font-weight:600;margin-bottom:8px;';

            var subtitle = document.createElement('div');
            subtitle.textContent = 'Enter the API password to continue';
            subtitle.style.cssText = 'color:#718096;font-size:13px;margin-bottom:24px;';

            var input = document.createElement('input');
            input.type = 'password';
            input.placeholder = 'API password';
            input.autocomplete = 'off';
            input.setAttribute('data-lpignore', 'true');
            input.setAttribute('data-1p-ignore', 'true');
            input.style.cssText = 'width:100%;padding:10px 14px;background:#1a1f2e;border:1px solid rgba(99,179,237,0.2);border-radius:8px;color:#e2e8f0;font-size:14px;font-family:inherit;outline:none;box-sizing:border-box;margin-bottom:16px;';

            var error = document.createElement('div');
            error.style.cssText = 'color:#fc8181;font-size:12px;margin-bottom:12px;min-height:16px;';

            var btn = document.createElement('button');
            btn.textContent = 'Login';
            btn.style.cssText = 'width:100%;padding:10px;background:linear-gradient(135deg,#63b3ed,#4299e1);border:none;border-radius:8px;color:#fff;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;';

            function submit() {
                var val = input.value.trim();
                if (!val) { error.textContent = 'Password is required'; return; }
                error.textContent = '';
                btn.disabled = true;
                btn.textContent = 'Verifying...';
                originalFetch('/api/stats/dashboard', { headers: { 'X-API-Key': val } }).then(function(r) {
                    if (r.ok) {
                        localStorage.setItem(STORAGE_KEY, val);
                        location.reload();
                    } else {
                        error.textContent = 'Invalid password';
                        btn.disabled = false;
                        btn.textContent = 'Login';
                        input.value = '';
                        input.focus();
                    }
                }).catch(function() {
                    error.textContent = 'Connection error';
                    btn.disabled = false;
                    btn.textContent = 'Login';
                });
            }

            btn.addEventListener('click', submit);
            input.addEventListener('keydown', function(e) { if (e.key === 'Enter') submit(); });

            box.appendChild(title);
            box.appendChild(subtitle);
            box.appendChild(input);
            box.appendChild(error);
            box.appendChild(btn);
            overlay.appendChild(box);
            document.body.appendChild(overlay);
            input.focus();
        }

        if (document.body) {
            create();
        } else {
            document.addEventListener('DOMContentLoaded', create);
        }
    }
})();
