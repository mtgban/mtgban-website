// Offline mode page-side orchestrator: opt-in lifecycle, status, settings UI.
(function () {
    'use strict';

    var PREF = 'offline_mode';
    // Roaming csv pref -> IDB meta array key (sync() reads the IDB copy and passes it to the worker)
    var SEL_PREFS = {
        offline_stores: 'storesSel',
        offline_editions: 'editionsSel',
        offline_img_editions: 'imgEditionsSel'
    };

    var state = { lastSync: null, setCount: 0, imgCount: 0, bytes: 0, syncing: false, authLapsed: false };

    function readPref(k) {
        try { return localStorage.getItem(k); } catch (e) { return null; }
    }
    function writePref(k, v) {
        try { localStorage.setItem(k, v); } catch (e) {}
    }
    function removePref(k) {
        try { localStorage.removeItem(k); } catch (e) {}
    }

    // The MTGBAN cookie is base64 over url.Values; OfflineMode is an ACL flag.
    function available() {
        var m = document.cookie.match(/(?:^|;\s*)MTGBAN=([^;]+)/);
        if (!m) return false;
        try {
            return new URLSearchParams(atob(decodeURIComponent(m[1]))).get('OfflineMode') === 'true';
        } catch (e) { return false; }
    }

    function enabled() { return readPref(PREF) === 'true'; }

    function supported() {
        return 'serviceWorker' in navigator && window.isSecureContext &&
            !!window.indexedDB && !!(window.crypto && window.crypto.subtle);
    }

    // Generate the non-extractable AES-GCM key once, at opt-in.
    function ensureKey() {
        return OfflineDB.getMeta('aesKey').then(function (key) {
            if (key) return key;
            return crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            ).then(function (k) {
                return OfflineDB.setMeta('aesKey', k).then(function () { return k; });
            });
        });
    }

    // Mirror the roaming csv prefs into IDB meta arrays for the worker.
    function reconcileSelections() {
        var ops = Object.keys(SEL_PREFS).map(function (prefKey) {
            var raw = readPref(prefKey);
            if (raw == null) return Promise.resolve();
            var arr = raw === '' ? [] : raw.split(',').filter(Boolean);
            return OfflineDB.setMeta(SEL_PREFS[prefKey], arr);
        });
        return Promise.all(ops);
    }

    function refreshStatus() {
        var ops = [
            OfflineDB.getMeta('lastSync').then(function(v) { state.lastSync = v || null; }),
            OfflineDB.countSets().then(function(n) { state.setCount = n; }),
            OfflineDB.getMeta('authLapsed').then(function(v) { state.authLapsed = !!v; }),
            OfflineDB.getMeta('imgCount').then(function(n) { state.imgCount = n || 0; })
        ];
        if (navigator.storage && navigator.storage.estimate) {
            ops.push(navigator.storage.estimate().then(function(est) { state.bytes = est.usage || 0; }));
        }
        return Promise.all(ops).catch(function() {});
    }

    function updateAuthNotice() {
        var el = document.getElementById('offline-auth-notice');
        if (el) el.hidden = !state.authLapsed;
    }

    function setAuthLapsed(flag) {
        state.authLapsed = flag;
        updateAuthNotice();
        return OfflineDB.setMeta('authLapsed', flag);
    }

    // Filter helper: only our SW's registrations.
    function isOurSW(r) {
        var s = r.active || r.waiting || r.installing;
        return s && s.scriptURL.endsWith('/sw.js');
    }

    // Device-local teardown; does not touch prefs.
    function cleanupLocal() {
        var unreg = navigator.serviceWorker
            ? navigator.serviceWorker.getRegistrations().then(function (regs) {
                return Promise.all(regs.filter(isOurSW).map(function (r) { return r.unregister(); }));
              }) : Promise.resolve();
        return unreg.then(function () {
            return caches.keys();
        }).then(function (names) {
            return Promise.all(names.filter(function (n) {
                return n.indexOf('mtgban-shell-') === 0 || n === 'mtgban-images-v1';
            }).map(function (n) { return caches.delete(n); }));
        }).then(function () {
            return OfflineDB.close();
        }).then(function () {
            return new Promise(function (resolve) {
                var req = indexedDB.deleteDatabase(OfflineDB.DB_NAME);
                req.onsuccess = req.onerror = req.onblocked = function () { resolve(); };
            });
        });
    }

    function enable() {
        if (!available() || !supported()) {
            return Promise.reject(new Error('offline mode not available'));
        }
        var persist = navigator.storage && navigator.storage.persist
            ? navigator.storage.persist() : Promise.resolve(false);
        var registered = false;
        return persist.then(function () {
            return navigator.serviceWorker.register('/sw.js');
        }).then(function () {
            registered = true;
            return ensureKey();
        }).then(function () {
            writePref(PREF, 'true');
            return reconcileSelections();
        }).then(function () {
            sync();
            return refreshStatus();
        }).catch(function (err) {
            if (registered) {
                navigator.serviceWorker.getRegistrations()
                    .then(function (regs) {
                        return Promise.all(regs.filter(isOurSW).map(function (r) { return r.unregister(); }));
                    })
                    .catch(function () {});
                removePref(PREF);
            }
            throw err;
        });
    }

    function disable() {
        if (syncWorker) {
            syncWorker.terminate();
            syncWorker = null;
            syncing = false;
        }
        // Remove selections first, offline_mode last: one userstate PATCH carries all.
        removePref('offline_stores');
        removePref('offline_editions');
        removePref('offline_img_editions');
        writePref(PREF, 'false');
        // Prefs record the opt-out first; the boot path retries cleanup if this fails.
        return cleanupLocal().then(function () {
            state = { lastSync: null, setCount: 0, imgCount: 0, bytes: 0, syncing: false, authLapsed: false };
            updateAuthNotice();
        });
    }

    // --- price sync worker plumbing ---
    var syncWorker = null;
    var syncing = false;

    function setSyncStatus(text) {
        var el = document.getElementById('offlineSyncStatus');
        if (el) el.textContent = text;
    }

    function status() {
        state.syncing = syncing;
        return state;
    }

    function ensureWorker() {
        if (syncWorker) return syncWorker;
        syncWorker = new Worker('/js/offline/offline-sync.js');
        syncWorker.onmessage = onSyncMessage;
        syncWorker.onerror = function(e) {
            syncing = false;
            syncWorker = null;
            setSyncStatus('sync failed: ' + (e.message || 'worker error'));
        };
        return syncWorker;
    }

    function onSyncMessage(ev) {
        var m = ev.data || {};
        document.dispatchEvent(new CustomEvent('offline:sync-message', { detail: m }));
        if (m.type === 'progress') {
            if (m.stage !== 'manifest' && state.authLapsed) setAuthLapsed(false);
            var label = m.stage + ' ' + m.done + '/' + m.total;
            if (m.code) label += ' (' + m.code + ')';
            setSyncStatus('syncing: ' + label);
        } else if (m.type === 'done') {
            syncing = false;
            state.bytes = m.bytes || 0;
            OfflineDB.setMeta('lastSync', new Date().toISOString()).then(refreshStatus).then(function() {
                updateAuthNotice();
                setSyncStatus('synced, ' + m.changedSets + ' sets updated');
                paintUsage();
            });
        } else if (m.type === 'error') {
            syncing = false;
            if (m.message === 'forbidden') {
                setAuthLapsed(true);
                setSyncStatus('sync stopped: offline access expired');
            } else {
                setSyncStatus('sync error at ' + m.stage + ': ' + m.message);
            }
        }
    }

    function sync() {
        if (syncing || !enabled()) return;
        syncing = true;
        setSyncStatus('syncing: starting');
        Promise.all([
            OfflineDB.getMeta('storesSel'),
            OfflineDB.getMeta('editionsSel'),
            OfflineDB.getMeta('imgEditionsSel'),
        ]).then(function(sel) {
            ensureWorker().postMessage({
                type: 'sync',
                stores: sel[0] || [],
                editions: sel[1] || [],
                imgEditions: sel[2] || [],
            });
        }).catch(function(err) {
            syncing = false;
            setSyncStatus('sync error: ' + err);
        });
    }

    function cancelSync() {
        if (syncWorker) syncWorker.postMessage({ type: 'cancel' });
    }

    function fmtBytes(n) {
        if (!n) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB'];
        var i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i];
    }

    // Repaint the settings storage line from current status; safe to call anytime.
    function paintUsage() {
        var usage = document.getElementById('settings-offline-usage');
        if (!usage) return;
        if (!enabled()) { usage.textContent = ''; return; }
        var s = status();
        usage.textContent = 'Using ' + fmtBytes(s.bytes) +
            (s.lastSync ? ', last sync ' + new Date(s.lastSync).toLocaleString() : ', not synced yet');
    }

    // Inline lucide cloud-off; conveys offline data at a glance.
    var CLOUD_OFF_SVG =
        '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' +
        '<path d="m2 2 20 20"/>' +
        '<path d="M5.782 5.782A7 7 0 0 0 9 19h8.5a4.5 4.5 0 0 0 1.307-.193"/>' +
        '<path d="M21.532 16.5A4.5 4.5 0 0 0 17.5 10h-1.79A7.008 7.008 0 0 0 10 5.07"/>' +
        '</svg>';

    // Navbar toggle: manually engage offline mode on this device. Shown only to
    // opted-in, entitled users; flips OfflinePrefer and navigates.
    function initNavToggle() {
        if (!available() || !enabled()) return;
        var utility = document.querySelector('.nav2-utility');
        if (!utility || document.getElementById('nav-offline-toggle')) return;

        var btn = document.createElement('button');
        btn.id = 'nav-offline-toggle';
        btn.type = 'button';
        btn.className = 'nav2-icon-btn ban-offline-toggle';
        btn.innerHTML = CLOUD_OFF_SVG;

        function paint() {
            var on = window.OfflinePrefer && OfflinePrefer.get();
            btn.classList.toggle('is-active', !!on);
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
            btn.title = on ? 'Offline mode on (tap to go back online)' : 'Switch to offline mode';
        }

        btn.addEventListener('click', function () {
            var on = !(window.OfflinePrefer && OfflinePrefer.get());
            if (window.OfflinePrefer) OfflinePrefer.set(on);
            var q = new URLSearchParams(location.search).get('q');
            var suffix = q ? '?q=' + encodeURIComponent(q) : '';
            location.href = (on ? '/offline' : '/search') + suffix;
        });

        var settingsBtn = document.getElementById('nav-settings-btn');
        if (settingsBtn) utility.insertBefore(btn, settingsBtn);
        else utility.appendChild(btn);
        paint();

        // Keep the active state in sync when another tab flips the flag.
        window.addEventListener('storage', function (e) {
            if (window.OfflinePrefer && e.key === OfflinePrefer.KEY) paint();
        });
    }

    // Settings modal glue: reveal the Offline section only when available().
    function initSettingsUI() {
        var section = document.getElementById('settings-offline-section');
        if (!section || !available()) return;
        section.style.display = '';
        var toggle = document.getElementById('settings-offline-toggle');
        var usage = document.getElementById('settings-offline-usage');
        if (!toggle || !usage) return;

        function paint() {
            toggle.checked = enabled();
            if (!enabled()) { paintUsage(); return; }
            refreshStatus().then(paintUsage);
        }

        toggle.addEventListener('change', function () {
            toggle.disabled = true;
            var op = toggle.checked ? enable() : disable();
            op.catch(function (err) {
                console.warn('offline mode:', err && err.message);
            }).then(function () {
                toggle.disabled = false;
                paint();
            });
        });
        paint();
    }

    window.OfflineMode = {
        available: available,
        enabled: enabled,
        enable: enable,
        disable: disable,
        sync: sync,
        cancelSync: cancelSync,
        status: status
    };

    if (available() && enabled() && supported()) {
        // Re-register heals a browser-evicted SW; no-op when installed.
        navigator.serviceWorker.register('/sw.js')
            .then(function () { return ensureKey(); })
            .then(function () { return reconcileSelections(); })
            .then(refreshStatus)
            .then(function () {
                updateAuthNotice();
                if (!state.authLapsed) {
                    sync();
                } else {
                    // a restored subscription self-heals at next page load
                    fetch('/api/offline/manifest.json', { credentials: 'same-origin' })
                        .then(function (resp) { if (resp.ok) { setAuthLapsed(false); sync(); } })
                        .catch(function () {});
                }
            })
            .catch(function () {});
    }

    if (supported() && !enabled()) {
        // Clean up this device when opt-out was roamed from another device.
        navigator.serviceWorker.getRegistrations().then(function (regs) {
            if (regs.some(isOurSW)) { cleanupLocal().catch(function () {}); }
        }).catch(function () {});
    }

    function initUI() {
        initSettingsUI();
        initNavToggle();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initUI);
    } else {
        initUI();
    }
})();
