/*
 * Failover hook for online pages: when offline mode is enabled and the
 * backend stops answering, offer the /offline shell via a dismissible toast.
 */
(function () {
    'use strict';

    function buildOfflineHref(pathname, search) {
        var q = pathname === '/search' ? new URLSearchParams(search).get('q') : null;
        return q ? '/offline?q=' + encodeURIComponent(q) : '/offline';
    }

    self.OfflineWatch = { buildOfflineHref: buildOfflineHref };

    if (location.pathname === '/offline') return;

    // Single pref check; opted-out users pay nothing further (no timers).
    var enabled = false;
    try {
        enabled = window.OfflineMode ? OfflineMode.enabled()
            : localStorage.getItem('offline_mode') === 'true';
    } catch (e) {}
    if (!enabled) return;

    var PROBE_TIMEOUT_MS = 5000;
    var INTERVAL_MS = 60000;
    var dismissed = false;
    var toast = null;
    var link = null;

    function probe() {
        var ctrl = new AbortController();
        var timer = setTimeout(function () { ctrl.abort(); }, PROBE_TIMEOUT_MS);
        return fetch('/healthz', { cache: 'no-store', signal: ctrl.signal })
            .then(function (res) { return res.ok; })
            .catch(function () { return false; })
            .then(function (ok) { clearTimeout(timer); return ok; });
    }

    function buildToast() {
        toast = document.createElement('div');
        toast.className = 'offline-watch-toast';
        toast.setAttribute('role', 'status');

        var msg = document.createElement('span');
        msg.textContent = 'MTGBAN is unreachable.';

        link = document.createElement('a');
        link.href = '/offline';
        link.textContent = 'Browse offline';

        var close = document.createElement('button');
        close.type = 'button';
        close.setAttribute('aria-label', 'Dismiss');
        close.textContent = '×';
        close.addEventListener('click', function () {
            dismissed = true;
            hideToast();
        });

        toast.appendChild(msg);
        toast.appendChild(link);
        toast.appendChild(close);
        document.body.appendChild(toast);
    }

    function showToast() {
        if (dismissed) return;
        if (!toast) buildToast();
        link.href = buildOfflineHref(location.pathname, location.search);
        // Force reflow so the show transition runs on first append.
        void toast.offsetWidth;
        toast.classList.add('show');
    }

    function hideToast() {
        if (toast) toast.classList.remove('show');
    }

    function check() {
        probe().then(function (ok) {
            if (ok) {
                // Recovery re-arms the toast for the next outage.
                dismissed = false;
                hideToast();
            } else {
                showToast();
            }
        });
    }

    window.addEventListener('offline', check);
    setInterval(function () {
        // Visibility gate: background tabs stay quiet.
        if (document.hidden) return;
        check();
    }, INTERVAL_MS);
})();
