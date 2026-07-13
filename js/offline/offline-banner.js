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
    // The sync settings modal is server-rendered on /search, so it is unreachable
    // while the server is down; hide the link until the backend answers.
    var settingsEl = document.getElementById('offline-settings-link');

    // Raw read of the offline-db meta row shape {k, v}; safe before offline-db.js loads.
    // Versionless open may create an empty DB; offline-db.js ghost recovery handles it.
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
        if (window.OfflineMode && typeof OfflineMode.status === 'function') {
            var s = OfflineMode.status();
            if (s && s.authLapsed) {
                authEl.hidden = false;
                return;
            }
        }
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

    var pollTimer = null;

    // Affordance only, never auto-navigate: auto-jumping would lose mid-browse context.
    // One consistent label whether offline was manual or auto-failover; the button
    // only shows when the server is reachable, so it always means leave for live search.
    function poll() {
        if (document.hidden) return;
        probe().then(function (ok) {
            var up = ok && navigator.onLine;
            if (up) {
                clearInterval(pollTimer);
                pollTimer = null;
                var q = new URLSearchParams(location.search).get('q');
                var suffix = q ? '?q=' + encodeURIComponent(q) : '';
                var sealed = new URLSearchParams(location.search).get('sealed') === '1';
                backEl.textContent = 'Exit offline mode';
                backEl.href = (sealed ? '/sealed' : '/search') + suffix;
            } else if (!pollTimer) {
                // Cleared after back-online but server down again; re-arm.
                pollTimer = setInterval(poll, POLL_MS);
            }
            backEl.hidden = !up;
            if (settingsEl) settingsEl.style.display = up ? '' : 'none';
        });
    }

    renderAge();
    renderAuth();
    poll();
    setInterval(function () {
        renderAge();
        renderAuth();
    }, AGE_TICK_MS);
    pollTimer = setInterval(poll, POLL_MS);
    window.addEventListener('online', poll);
    window.addEventListener('offline', function () { backEl.hidden = true; if (settingsEl) settingsEl.style.display = 'none'; });

    backEl.addEventListener('click', function () {
        // Leaving via the banner is an explicit opt-out of manual offline.
        try { if (window.OfflinePrefer) OfflinePrefer.set(false); } catch (e) {}
    });
})();
