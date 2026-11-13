// Offline mode page-side orchestrator: opt-in lifecycle, status, settings UI.
(function () {
    'use strict';

    var PREF = 'offline_mode';
    // Whether the last ordinary page rendered the SearchOfflineMode flag
    var AVAILABLE_PREF = 'offline_available';
    // Roaming csv pref -> IDB meta array key (sync() reads the IDB copy and passes it to the worker)
    var SEL_PREFS = {
        offline_stores: 'storesSel',
        offline_editions: 'editionsSel',
        offline_img_editions: 'imgEditionsSel'
    };

    var state = { lastSync: null, setCount: 0, imgCount: 0, bytes: 0, syncing: false, authLapsed: false };

    // The same ?hash= cache-buster the templates give every asset, handed to
    // the sync worker, which passes it on to the scripts it imports.
    var src = document.currentScript ? document.currentScript.src : '';
    var hash = (/[?&]hash=([^&]*)/.exec(src) || [])[1] || '';

    function readPref(k) {
        try { return localStorage.getItem(k); } catch (e) { return null; }
    }
    function writePref(k, v) {
        try { localStorage.setItem(k, v); } catch (e) {}
    }
    function removePref(k) {
        try { localStorage.removeItem(k); } catch (e) {}
    }

    // The cached /offline shell is rendered without credentials, so its own
    // flag says nothing about the reader.
    function onShell() { return !!document.getElementById('offline-banner'); }

    // SearchOfflineMode is an ACL flag; the server renders it on <html>. The
    // shell takes the flag the last ordinary page left behind.
    function available() {
        if (document.documentElement.dataset.offlineMode === 'true') return true;
        return onShell() && readPref(AVAILABLE_PREF) === 'true';
    }

    if (!onShell()) {
        writePref(AVAILABLE_PREF, document.documentElement.dataset.offlineMode === 'true' ? 'true' : 'false');
    }

    function enabled() { return readPref(PREF) === 'true'; }

    function supported() {
        return 'serviceWorker' in navigator && window.isSecureContext &&
            !!window.indexedDB && !!(window.crypto && window.crypto.subtle);
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
            ops.push(navigator.storage.estimate().then(function(est) {
                state.bytes = est.usage || 0;
                state.quota = est.quota || 0;
            }));
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
                return n.indexOf('mtgban-shell-') === 0 || n.indexOf('mtgban-images-') === 0;
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
        var registering = false;
        return persist.then(function () {
            registering = true;
            return navigator.serviceWorker.register('/sw.js');
        }).then(function () {
            registered = true;
            if (window.BAN && window.BAN.track) window.BAN.track('ui.offline.sw', 'install_ok');
            return OfflineDB.ensureKey();
        }).then(function () {
            writePref(PREF, 'true');
            if (window.BAN && window.BAN.track) window.BAN.track('ui.offline.mode', 'enable');
            return reconcileSelections();
        }).then(function () {
            sync();
            return refreshStatus();
        }).catch(function (err) {
            if (registering && !registered && window.BAN && window.BAN.track) window.BAN.track('ui.offline.sw', 'install_fail');
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

    // Turning offline mode off deletes what Delete Offline Data does, so it
    // asks the same way first.
    function confirmDisable() {
        return window.confirm('Turn off offline mode and delete all offline data on this device? Prices, cards and card images will have to be downloaded again.');
    }

    function disable() {
        if (syncWorker) {
            syncWorker.terminate();
            syncWorker = null;
            setSyncing(false);
        }
        // Remove selections first, offline_mode last: one userstate PATCH carries all.
        removePref('offline_stores');
        removePref('offline_editions');
        removePref('offline_img_editions');
        writePref(PREF, 'false');
        if (window.BAN && window.BAN.track) window.BAN.track('ui.offline.mode', 'disable');
        // Prefs record the opt-out first; the boot path retries cleanup if this fails.
        return cleanupLocal().then(function () {
            state = { lastSync: null, setCount: 0, imgCount: 0, bytes: 0, syncing: false, authLapsed: false };
            updateAuthNotice();
        });
    }

    // --- price sync worker plumbing ---
    var syncWorker = null;
    var syncing = false;
    var pendingImages = false;

    // Warn on navigation while an asked-for sync is running, so it isn't silently dropped.
    function onBeforeUnload(e) {
        e.preventDefault();
        e.returnValue = '';
    }

    // guard is for a sync someone is watching; the page-load one resumes on
    // the next page, so it never stands between the user and a link.
    function setSyncing(v, guard) {
        syncing = v;
        if (v && guard) window.addEventListener('beforeunload', onBeforeUnload);
        else window.removeEventListener('beforeunload', onBeforeUnload);
    }

    // Drop the guard without claiming the sync ended, for a navigation the user
    // asked for. What is in flight is not lost: the boot path syncs again.
    function releaseUnloadGuard() {
        window.removeEventListener('beforeunload', onBeforeUnload);
    }

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
        syncWorker = new Worker('/js/offline/offline-sync.js?hash=' + hash);
        syncWorker.onmessage = onSyncMessage;
        syncWorker.onerror = function(e) {
            setSyncing(false);
            syncWorker = null;
            setSyncStatus('Sync failed: ' + (e.message || 'worker error'));
        };
        return syncWorker;
    }

    // What a finished sync says. Read before lastSync is written, so the
    // first sync on this device (or after a wipe) reads as the setup it is;
    // imageHint is for a page that offers the image sync.
    function doneStatusText(m, s, imageHint) {
        var text;
        if (!s.lastSync) {
            text = imageHint ? 'Ready offline - sync images to display pictures while offline' : 'Ready offline';
        } else {
            var n = m.changedSets || 0;
            text = n ? 'Updated ' + n + (n === 1 ? ' set' : ' sets') : 'Up to date';
        }
        var failed = m.failedSets || 0;
        if (failed) text += ' (' + failed + (failed === 1 ? ' set' : ' sets') + ' failed, retried on the next sync)';
        return text;
    }

    function onSyncMessage(ev) {
        var m = ev.data || {};
        document.dispatchEvent(new CustomEvent('offline:sync-message', { detail: m }));
        if (m.type === 'progress') {
            if (m.stage !== 'manifest' && state.authLapsed) setAuthLapsed(false);
            var label = m.stage + ' ' + m.done + '/' + m.total;
            if (m.code) label += ' (' + m.code + ')';
            setSyncStatus('Syncing: ' + label);
        } else if (m.type === 'done') {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.offline.sync', 'ok', 'catalog');
            if (window.BAN && window.BAN.track) window.BAN.track('ui.offline.sync', 'ok', 'prices');
            if (m.images && window.BAN && window.BAN.track) window.BAN.track('ui.offline.sync', 'ok', 'images');
            setSyncing(false);
            // A queued image sync keeps the page asking before it is left
            if (pendingImages) window.addEventListener('beforeunload', onBeforeUnload);
            state.bytes = m.bytes || 0;
            var done = doneStatusText(m, state, true);
            OfflineDB.setMeta('lastSync', new Date().toISOString()).then(refreshStatus).then(function() {
                updateAuthNotice();
                setSyncStatus(done);
                paintUsage();
            }).catch(function() {}).then(function() {
                document.dispatchEvent(new CustomEvent('offline:synced'));
                if (pendingImages) {
                    pendingImages = false;
                    sync({ images: true });
                }
            });
        } else if (m.type === 'error') {
            var failedAt = '';
            switch (m.stage) {
                case 'manifest': case 'catalog': failedAt = 'catalog'; break;
                case 'prices': failedAt = 'prices'; break;
                case 'images': failedAt = 'images'; break;
            }
            // Each stage before the failed one got through.
            if (failedAt !== 'catalog' && failedAt && window.BAN && window.BAN.track) window.BAN.track('ui.offline.sync', 'ok', 'catalog');
            if (failedAt === 'images' && window.BAN && window.BAN.track) window.BAN.track('ui.offline.sync', 'ok', 'prices');
            if (failedAt && window.BAN && window.BAN.track) window.BAN.track('ui.offline.sync', 'fail', failedAt);
            setSyncing(false);
            pendingImages = false;
            if (m.message === 'forbidden') {
                setAuthLapsed(true);
                setSyncStatus('Sync stopped: offline access expired');
            } else {
                setSyncStatus('Sync error at ' + m.stage + ': ' + m.message);
            }
        }
    }

    // opts.images opts the image stage in. Prices and the catalog are small
    // enough to refresh on any page load; images are a whole corpus, so they
    // only move when someone asks for them and can watch it happen.
    function sync(opts) {
        if (!enabled()) return;
        var withImages = !!(opts && opts.images);
        // An image sync asked for during a price refresh runs after it.
        if (syncing) {
            if (withImages) {
                pendingImages = true;
                setSyncing(true, true);
            }
            return;
        }
        setSyncing(true, withImages);
        setSyncStatus('Syncing: starting');
        Promise.all([
            OfflineDB.getMeta('storesSel'),
            OfflineDB.getMeta('editionsSel'),
            withImages ? OfflineDB.getMeta('imgEditionsSel') : Promise.resolve([]),
        ]).then(function(sel) {
            ensureWorker().postMessage({
                type: 'sync',
                full: !!(opts && opts.full),
                images: withImages,
                stores: sel[0] || [],
                editions: sel[1] || [],
                imgEditions: sel[2] || [],
            });
        }).catch(function(err) {
            setSyncing(false);
            setSyncStatus('Sync error: ' + err);
        });
    }

    // A pause while the image sync still waits on a price refresh drops it,
    // and leaves the refresh to finish.
    function cancelSync() {
        if (pendingImages) {
            pendingImages = false;
            releaseUnloadGuard();
            document.dispatchEvent(new CustomEvent('offline:sync-message', { detail: { type: 'done', images: true } }));
            return;
        }
        if (syncWorker) syncWorker.postMessage({ type: 'cancel' });
    }

    function fmtBytes(n) {
        if (!n) return '0 B';
        var units = ['B', 'KB', 'MB', 'GB'];
        var i = 0;
        while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
        return (i === 0 ? n : n.toFixed(1)) + ' ' + units[i];
    }

    // Sync-status suffix for the storage line: last-sync date, first-sync-in-progress, or not yet synced.
    function syncStatusText(s) {
        if (s.lastSync) return 'Last sync ' + new Date(s.lastSync).toLocaleString();
        if (s.syncing) return 'First sync in progress';
        return 'Not synced yet';
    }

    // The quota is what the browser would allow, not what a sync will download.
    function usageText(s) {
        var limit = s.quota ? ' (browser limit ' + fmtBytes(s.quota) + ')' : '';
        return 'Stored on this device: ' + fmtBytes(s.bytes) + limit + '.\n' + syncStatusText(s) + '.';
    }

    // Repaint the settings storage line from current status; safe to call anytime.
    function paintUsage() {
        var usage = document.getElementById('settings-offline-usage');
        if (!usage) return;
        if (!enabled()) { usage.textContent = ''; return; }
        usage.textContent = usageText(status());
    }

    // Re-measures and repaints the usage line, for the modal reopening or a
    // sync that ended without a done message.
    function refreshUsage() {
        return refreshStatus().then(paintUsage);
    }

    // Navbar toggle: manually engage offline mode on this device. The navbar
    // renders it hidden and its inline script shows it before the first paint;
    // this wires it, and follows the setting when it changes without a reload.
    function initNavToggle() {
        var btn = document.getElementById('nav-offline-toggle');
        if (!btn) return;
        btn.hidden = !available() || !enabled();
        if (btn.hidden || btn.dataset.wired) return;
        btn.dataset.wired = '1';

        function paint() {
            var on = window.OfflinePrefer && OfflinePrefer.get();
            btn.classList.toggle('is-active', !!on);
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
            btn.title = on ? 'Offline mode on (tap to go back online)' : 'Switch to offline mode';
        }

        btn.addEventListener('click', function () {
            var on = !(window.OfflinePrefer && OfflinePrefer.get());
            if (window.OfflinePrefer) OfflinePrefer.set(on);
            if (window.BAN && window.BAN.track) window.BAN.track('ui.nav.offline', on ? 'on' : 'off');
            var params = new URLSearchParams(location.search);
            var q = params.get('q');
            var qs = q ? 'q=' + encodeURIComponent(q) : '';
            // Preserve sealed context across the toggle.
            var sealed = location.pathname === '/sealed' || params.get('sealed') === '1';
            if (on) {
                var parts = [qs, sealed ? 'sealed=1' : ''].filter(Boolean);
                location.href = '/offline' + (parts.length ? '?' + parts.join('&') : '');
            } else {
                location.href = (sealed ? '/sealed' : '/search') + (qs ? '?' + qs : '');
            }
        });

        paint();

        // Keep the active state in sync when another tab flips the flag.
        window.addEventListener('storage', function (e) {
            if (window.OfflinePrefer && e.key === OfflinePrefer.KEY) paint();
        });
    }

    // Re-download everything currently selected, whatever the local state
    // says. The price side is a flag the worker reads; images track their own
    // per-edition rows, so those are dropped here to give the diff work to do.
    function forceResync() {
        if (syncing || !enabled()) return Promise.resolve();
        if (window.BAN && window.BAN.track) window.BAN.track('ui.offline.data', 'resync');
        setSyncStatus('Syncing: starting');
        return OfflineDB.getAllRows('imgstate').then(function (rows) {
            return Promise.all(rows.map(function (r) {
                return OfflineDB.deleteRow('imgstate', r.code);
            }));
        }).catch(function () {}).then(function () {
            sync({ full: true, images: true });
        });
    }

    // Everything this device stores: the database, the caches, and the worker
    // that fills them. The preference is left alone, so the next sync starts
    // from nothing rather than the feature switching itself off.
    function wipeLocal() {
        if (window.BAN && window.BAN.track) window.BAN.track('ui.offline.data', 'wipe');
        if (syncWorker) {
            syncWorker.terminate();
            syncWorker = null;
        }
        setSyncing(false);
        setSyncStatus('Deleting offline data...');
        return cleanupLocal().then(function () {
            state = { lastSync: null, setCount: 0, imgCount: 0, bytes: 0, syncing: false, authLapsed: false };
            setSyncStatus('Offline data deleted');
            paintUsage();
        }).catch(function (err) {
            setSyncStatus('Delete failed: ' + (err && err.message || err));
            throw err;
        });
    }

    // Settings modal glue: reveal the Offline section only when available().
    function initSettingsUI() {
        var section = document.getElementById('settings-offline-section');
        if (!section || !available()) return;
        if (section.dataset.wired) return;
        section.dataset.wired = '1';
        section.style.display = '';
        var toggle = document.getElementById('settings-offline-toggle');
        var usage = document.getElementById('settings-offline-usage');
        if (!toggle || !usage) return;

        var controls = document.getElementById('settings-offline-controls');
        var liveRow = document.getElementById('settings-offline-live-row');
        var liveToggle = document.getElementById('settings-offline-live');

        function paint() {
            toggle.checked = enabled();
            if (controls) controls.hidden = !enabled();
            if (liveRow) liveRow.hidden = !enabled();
            if (liveToggle) liveToggle.checked = OfflineLive.on('desktop');
            if (!enabled()) { paintUsage(); return; }
            refreshStatus().then(paintUsage);
        }

        // Applies on change, like the rest of this tab; the navbar's cloud
        // button follows it without a reload
        toggle.addEventListener('change', function () {
            if (!toggle.checked && !confirmDisable()) {
                toggle.checked = true;
                return;
            }
            toggle.disabled = true;
            var op = toggle.checked ? enable() : disable();
            op.then(function () {
                initNavToggle();
            }).catch(function (err) {
                setSyncStatus('Offline mode: ' + (err && err.message || err));
            }).then(function () {
                toggle.disabled = false;
                paint();
            });
        });
        if (liveToggle) {
            liveToggle.addEventListener('change', function () {
                OfflineLive.set(liveToggle.checked);
            });
        }
        var resyncBtn = document.getElementById('offline-resync-btn');
        if (resyncBtn) {
            resyncBtn.addEventListener('click', function () {
                resyncBtn.disabled = true;
                forceResync().catch(function () {}).then(function () { resyncBtn.disabled = false; });
            });
        }

        var wipeBtn = document.getElementById('offline-wipe-btn');
        if (wipeBtn) {
            wipeBtn.addEventListener('click', function () {
                if (!window.confirm('Delete all offline data on this device? Prices, cards and card images will be downloaded again on the next sync.')) return;
                wipeBtn.disabled = true;
                wipeLocal().catch(function () {}).then(function () {
                    wipeBtn.disabled = false;
                    paint();
                });
            });
        }

        paint();
    }

    window.OfflineMode = {
        available: available,
        enabled: enabled,
        enable: enable,
        disable: disable,
        confirmDisable: confirmDisable,
        sync: sync,
        forceResync: forceResync,
        wipeLocal: wipeLocal,
        cancelSync: cancelSync,
        releaseUnloadGuard: releaseUnloadGuard,
        status: status,
        syncStatusText: syncStatusText,
        usageText: usageText,
        doneStatusText: doneStatusText,
        refreshUsage: refreshUsage,
        initSettingsUI: initSettingsUI,
        initNavToggle: initNavToggle,
    };

    if (available() && enabled() && supported()) {
        // Re-register heals a browser-evicted SW; no-op when installed.
        navigator.serviceWorker.register('/sw.js')
            .then(function () { return OfflineDB.ensureKey(); })
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
