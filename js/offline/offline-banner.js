/*
 * Offline shell banner: live data age, stale warning, lapsed-auth notice,
 * and a back-online affordance driven by /healthz polling.
 */
(function () {
    'use strict';

    var POLL_MS = 30000;
    var PROBE_TIMEOUT_MS = 5000;
    var AGE_TICK_MS = 60000;

    var root = document.getElementById('offline-banner');
    if (!root || !window.OfflineAge) return;
    var ageEl = document.getElementById('offline-banner-age');
    var authEl = document.getElementById('offline-banner-auth');
    var backEl = document.getElementById('offline-banner-back');

    // Raw read against the pinned IDB schema (contract section 4).
    function metaGet(key) {
        return new Promise(function (resolve) {
            var req = indexedDB.open('mtgban-offline');
            req.onerror = function () { resolve(null); };
            req.onsuccess = function () {
                var db = req.result;
                try {
                    var get = db.transaction('meta').objectStore('meta').get(key);
                    get.onsuccess = function () { db.close(); resolve(get.result ? get.result.v : null); };
                    get.onerror = function () { db.close(); resolve(null); };
                } catch (e) {
                    db.close();
                    resolve(null);
                }
            };
        });
    }

    function getLastSync() {
        if (window.OfflineMode && typeof OfflineMode.status === 'function') {
            var s = OfflineMode.status();
            if (s && s.lastSync) return Promise.resolve(s.lastSync);
        }
        return metaGet('lastSync');
    }

    function renderAge() {
        getLastSync().then(function (lastSync) {
            var now = Date.now();
            var stale = OfflineAge.isStale(lastSync, now);
            ageEl.textContent = 'Offline data: ' + OfflineAge.formatAge(lastSync, now) + (stale ? ' (stale)' : '');
            root.classList.toggle('offline-banner-stale', stale);
        });
    }

    function renderAuth() {
        metaGet('authLapsed').then(function (lapsed) {
            authEl.hidden = !lapsed;
        });
    }

    function probe() {
        var ctrl = new AbortController();
        var timer = setTimeout(function () { ctrl.abort(); }, PROBE_TIMEOUT_MS);
        return fetch('/healthz', { cache: 'no-store', signal: ctrl.signal })
            .then(function (res) { return res.ok; })
            .catch(function () { return false; })
            .then(function (ok) { clearTimeout(timer); return ok; });
    }

    // Affordance only, never auto-navigate: auto-jumping would lose mid-browse context.
    function poll() {
        probe().then(function (ok) {
            var up = ok && navigator.onLine;
            if (up) {
                var q = new URLSearchParams(location.search).get('q');
                backEl.href = q ? '/search?q=' + encodeURIComponent(q) : '/search';
            }
            backEl.hidden = !up;
        });
    }

    renderAge();
    renderAuth();
    poll();
    setInterval(renderAge, AGE_TICK_MS);
    setInterval(poll, POLL_MS);
    window.addEventListener('online', poll);
    window.addEventListener('offline', function () { backEl.hidden = true; });
})();
