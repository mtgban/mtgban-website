// Offline mode page-side orchestrator: opt-in lifecycle, status, settings UI.
(function () {
    'use strict';

    var PREF = 'offline_mode';
    // Roaming csv pref -> IDB meta array key (the worker reads the IDB copy).
    var SEL_PREFS = {
        offline_stores: 'storesSel',
        offline_editions: 'editionsSel',
        offline_img_editions: 'imgEditionsSel'
    };

    var state = { lastSync: null, setCount: 0, imgCount: 0, bytes: 0, syncing: false };

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
            OfflineDB.getMeta('lastSync').then(function (v) { state.lastSync = v || null; }),
            OfflineDB.open().then(function (db) {
                return new Promise(function (resolve) {
                    // The connection is shared; only OfflineDB.close() may close it.
                    var req = db.transaction('sets').objectStore('sets').count();
                    req.onsuccess = function () { state.setCount = req.result; resolve(); };
                    req.onerror = function () { resolve(); };
                });
            })
        ];
        if (navigator.storage && navigator.storage.estimate) {
            ops.push(navigator.storage.estimate().then(function (est) { state.bytes = est.usage || 0; }));
        }
        return Promise.all(ops).catch(function () {});
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
        return cleanupLocal().then(function () {
            // Remove selections first, offline_mode last: one userstate PATCH carries all.
            removePref('offline_stores');
            removePref('offline_editions');
            removePref('offline_img_editions');
            writePref(PREF, 'false');
            state = { lastSync: null, setCount: 0, imgCount: 0, bytes: 0, syncing: false };
        });
    }

    // Sync worker lands in phase 3; the entry point stays stable.
    function sync() {}

    function status() {
        return {
            lastSync: state.lastSync,
            setCount: state.setCount,
            imgCount: state.imgCount,
            bytes: state.bytes,
            syncing: state.syncing
        };
    }

    function fmtBytes(n) {
        if (!n) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB'];
        var i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i];
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
            if (!enabled()) { usage.textContent = ''; return; }
            refreshStatus().then(function () {
                var s = status();
                usage.textContent = 'Using ' + fmtBytes(s.bytes) +
                    (s.lastSync ? ', last sync ' + s.lastSync : ', not synced yet');
            });
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
        status: status
    };

    if (available() && enabled() && supported()) {
        // Re-register heals a browser-evicted SW; no-op when installed.
        navigator.serviceWorker.register('/sw.js')
            .then(function () { return ensureKey(); })
            .then(function () { return reconcileSelections(); })
            .then(refreshStatus)
            .catch(function () {});
    }

    if (supported() && !enabled()) {
        // Clean up this device when opt-out was roamed from another device.
        navigator.serviceWorker.getRegistrations().then(function (regs) {
            if (regs.some(isOurSW)) { cleanupLocal().catch(function () {}); }
        }).catch(function () {});
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initSettingsUI);
    } else {
        initSettingsUI();
    }
})();
