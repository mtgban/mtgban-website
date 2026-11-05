/*
 * Offline shell banner: live data age, stale and missing-sets warnings,
 * lapsed-auth notice, and a back-online affordance driven by /healthz polling.
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
    // The settings modal's body is fetched from /api/settings/modal, so it is
    // unreachable while the server is down; hide the link until it answers.
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

    // Sets a first sync running in this tab has yet to download.
    var left = 0;
    // What the last read of the database found, once there has been one.
    var read = false;
    var lastSync = null;
    var missing = 0;

    function paintAge() {
        var now = Date.now();
        ageEl.textContent = OfflineAge.bannerText(lastSync, now, left, missing);
        root.classList.toggle('offline-banner-stale', OfflineAge.isStale(lastSync, now) || missing > 0);
    }

    function renderAge() {
        Promise.all([getLastSync(), metaGet('missingSets')]).then(function (res) {
            read = true;
            lastSync = res[0];
            missing = res[1] || 0;
            paintAge();
        });
    }

    function onSyncMessage(e) {
        var m = e.detail || {};
        if (m.type === 'progress' && m.stage === 'prices') {
            left = m.total - m.done;
            // Only the count changed, and a first sync sends one per set
            if (read && !lastSync) paintAge();
        } else if (m.type === 'done' || m.type === 'error') {
            left = 0;
            renderAge();
        }
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

    // Affordance only, never auto-navigate: auto-jumping would lose mid-browse context.
    // One consistent label whether offline was manual or auto-failover; the button
    // only shows when the server is reachable. Polling never stops so a later
    // outage hides the link again.
    function poll() {
        if (document.hidden) return;
        probe().then(function (ok) {
            var up = ok && navigator.onLine;
            if (up) {
                var q = new URLSearchParams(location.search).get('q');
                var suffix = q ? '?q=' + encodeURIComponent(q) : '';
                var sealed = new URLSearchParams(location.search).get('sealed') === '1';
                backEl.textContent = 'Exit offline mode';
                backEl.href = (sealed ? '/sealed' : '/search') + suffix;
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
    setInterval(poll, POLL_MS);
    document.addEventListener('offline:sync-message', onSyncMessage);
    document.addEventListener('offline:synced', renderAge);
    window.addEventListener('online', poll);
    window.addEventListener('offline', function () { backEl.hidden = true; if (settingsEl) settingsEl.style.display = 'none'; });

    backEl.addEventListener('click', function () {
        // Leaving via the banner is an explicit opt-out of manual offline.
        try { if (window.OfflinePrefer) OfflinePrefer.set(false); } catch (e) {}
    });
})();
