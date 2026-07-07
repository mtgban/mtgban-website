// Best-effort cross-device sync of favorites, recents, and prefs for signed-in users.
(function() {
    var BASE = '/api/userstate/';
    var DEBOUNCE_MS = 1500;
    var FETCH_KEY = 'mtgban_userstate_fetch'; // sessionStorage: {v, ts}
    var TTL_MS = 90 * 1000;

    // Tombstones: entries with a del timestamp. Newest intent (m) wins merges.
    var TOMB_TTL_MS = 30 * 24 * 60 * 60 * 1000;
    var TOMB_CAP = 50;
    function mtime(x) { return x.m || x.t || 0; }

    // Keys that map to dedicated server columns.
    var FAVORITES_KEY = 'mtgban_favorites';
    var RECENTS_KEY = 'mtgban_recent_searches';
    // Keys bundled into the preferences object.
    var PREF_KEYS = [
        'mtgban_fav_sort', 'mtgban_fav_sort_dir',
        'theme', 'chartDateRange', 'mtgban_nav_layout_v1',
        'chartReleasesLongRange', 'chartCheckpointTypes'
    ];

    // MTGBAN auth cookie is not HttpOnly; presence is a cheap signed-in gate.
    function isSignedIn() {
        return /(?:^|;\s*)MTGBAN=/.test(document.cookie);
    }

    var signedIn = isSignedIn();

    // Local-only bookkeeping keys (never synced).
    var DIRTY_KEY = 'mtgban_userstate_dirty';
    var SYNCED_KEY = 'mtgban_userstate_synced';

    // Fingerprints of the last payload synced per section, to skip no-op writes.
    var FP_KEY = 'mtgban_userstate_fp';
    function hashStr(s) {
        var h = 5381;
        for (var i = 0; i < s.length; i++) h = ((h << 5) + h + s.charCodeAt(i)) | 0;
        return String(h);
    }
    function readFPs() {
        try { return JSON.parse(readLocal(FP_KEY, '{}')); } catch (e) { return {}; }
    }
    function writeFP(section, payloadJSON) {
        try {
            var f = readFPs();
            f[section] = hashStr(payloadJSON);
            rawSetItem(FP_KEY, JSON.stringify(f));
        } catch (e) {}
    }
    function fpMatches(section, payloadJSON) { return readFPs()[section] === hashStr(payloadJSON); }

    var version = 0;
    var rawSetItem = localStorage.setItem.bind(localStorage);
    var pending = {}; // section -> true
    var timer = null;

    function isDirty() { return readLocal(DIRTY_KEY, '0') === '1'; }
    function markDirty() { try { rawSetItem(DIRTY_KEY, '1'); } catch (e) {} }
    function markClean() { try { rawSetItem(DIRTY_KEY, '0'); } catch (e) {} }

    function readLocal(key, fallback) {
        try {
            var v = localStorage.getItem(key);
            return v == null ? fallback : v;
        } catch (e) { return fallback; }
    }

    function readMarker() {
        try { var s = sessionStorage.getItem(FETCH_KEY); return s ? JSON.parse(s) : null; }
        catch (e) { return null; }
    }
    function writeMarker(v) {
        try { sessionStorage.setItem(FETCH_KEY, JSON.stringify({ v: v, ts: Date.now() })); }
        catch (e) {}
    }

    function buildPreferences() {
        var prefs = {};
        PREF_KEYS.forEach(function(k) {
            var v = readLocal(k, null);
            if (v != null) prefs[k] = v;
        });
        return prefs;
    }

    var KEY_TO_SECTION = (function() {
        var m = {};
        m[FAVORITES_KEY] = 'favorites';
        m[RECENTS_KEY] = 'recents';
        PREF_KEYS.forEach(function(k) { m[k] = 'preferences'; });
        return m;
    })();
    function sectionForKey(key) { return KEY_TO_SECTION[key] || null; }

    function payloadForSection(section) {
        if (section === 'favorites') return JSON.parse(readLocal(FAVORITES_KEY, '[]')).map(trimFavorite);
        if (section === 'recents') return JSON.parse(readLocal(RECENTS_KEY, '[]'));
        return buildPreferences();
    }

    // Apply server state into localStorage.
    function applyState(state) {
        if (!state) return;
        try {
            if (state.favorites) {
                var localBy = {};
                localFavorites().forEach(function(f) { if (f && f.id != null) localBy[f.id] = f; });
                var favs = state.favorites.map(function(f) {
                    var prev = f && f.id != null ? localBy[f.id] : null;
                    if (prev && !f.del) {
                        // Prices and refresh times are local-only; keep them across hydrates.
                        if (f.sellPrice == null && prev.sellPrice != null) { f.sellPrice = prev.sellPrice; f.sellVendor = prev.sellVendor; }
                        if (f.buyPrice == null && prev.buyPrice != null) { f.buyPrice = prev.buyPrice; f.buyVendor = prev.buyVendor; }
                        if (prev.refreshedAt) f.refreshedAt = prev.refreshedAt;
                    }
                    return f;
                });
                rawSetItem(FAVORITES_KEY, JSON.stringify(favs));
                writeFP('favorites', JSON.stringify(favs.map(trimFavorite)));
            }
            if (state.recents) {
                rawSetItem(RECENTS_KEY, JSON.stringify(state.recents));
                writeFP('recents', JSON.stringify(state.recents));
            }
            if (state.preferences) {
                Object.keys(state.preferences).forEach(function(k) {
                    if (PREF_KEYS.indexOf(k) >= 0) rawSetItem(k, String(state.preferences[k]));
                });
            }
        } catch (e) {}
        if (typeof state.version === 'number') version = state.version;
    }

    function rerender() {
        if (typeof window.renderFavorites === 'function') window.renderFavorites();
        if (typeof window.renderRecentSearches === 'function') window.renderRecentSearches();
        // Synced favorites arrive price-less; backfill (self-gating).
        if (typeof window.refreshFavorites === 'function') window.refreshFavorites();
    }

    // PATCH one section; keepalive lets it outlive navigation.
    // Resolves true when the write (or its reconcile) landed.
    function patchSection(section, keepalive) {
        var payloadJSON = JSON.stringify(payloadForSection(section));
        // Content already on the server: succeed without a request.
        if (fpMatches(section, payloadJSON)) return Promise.resolve(true);
        var body = '{"data":' + payloadJSON + ',"version":' + version + '}';
        return fetch(BASE + section, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: body,
            keepalive: keepalive === true
        }).then(function(r) {
            if (r.status === 409) return r.json().then(function(cur) { return reconcile(cur); });
            if (!r.ok) {
                console.warn('mtgban sync: ' + section + ' write failed (' + r.status + ')');
                return false;
            }
            return r.json().then(function(res) {
                if (res && typeof res.version === 'number') { version = res.version; writeMarker(version); }
                writeFP(section, payloadJSON);
                return true;
            });
        }).catch(function() {
            console.warn('mtgban sync: ' + section + ' write failed (network)');
            return false;
        });
    }

    function flush() {
        timer = null;
        var sections = Object.keys(pending);
        pending = {};
        var allOk = true;
        // Chain sequentially so version stays consistent across sections.
        sections.reduce(function(p, section) {
            return p.then(function() {
                return patchSection(section).then(function(ok) {
                    // Re-queue failures so the next flush retries them.
                    if (!ok) { allOk = false; pending[section] = true; }
                });
            });
        }, Promise.resolve()).then(function() {
            // Clear dirty only if everything synced and no new writes were scheduled.
            if (allOk && !timer && Object.keys(pending).length === 0) markClean();
        });
    }

    // Flush queued writes now (page hidden/unloading), via keepalive.
    function flushPending() {
        if (timer) { clearTimeout(timer); timer = null; }
        var sections = Object.keys(pending);
        if (!sections.length) return;
        pending = {};
        sections.forEach(function(section) { patchSection(section, true); });
    }

    function schedule(section) {
        pending[section] = true;
        if (timer) clearTimeout(timer);
        timer = setTimeout(flush, DEBOUNCE_MS);
    }

    // Merge server+local, push back, adopt version; attempt bounds 409 retries.
    var MAX_RECONCILE_ATTEMPTS = 5;
    function reconcile(serverState, attempt) {
        attempt = attempt || 0;
        if (!serverState) return Promise.resolve(false);
        var mergedFavs = mergeList(localFavorites(), serverState.favorites || [], function(f) { return f.id; }, 50);
        var mergedRecents = mergeList(localRecents(), serverState.recents || [], function(s) { return (s.q || '').toLowerCase(); }, 15);
        var mergedPrefs = mergePrefs(buildPreferences(), serverState.preferences || {});

        try {
            rawSetItem(FAVORITES_KEY, JSON.stringify(mergedFavs));
            rawSetItem(RECENTS_KEY, JSON.stringify(mergedRecents));
            Object.keys(mergedPrefs).forEach(function(k) {
                if (PREF_KEYS.indexOf(k) >= 0) rawSetItem(k, String(mergedPrefs[k]));
            });
        } catch (e) {}

        version = typeof serverState.version === 'number' ? serverState.version : version;
        rerender();

        // Nothing new to push: adopt version, skip the write.
        if (!localHasNew(mergedFavs, mergedRecents, mergedPrefs, serverState)) {
            writeFP('favorites', JSON.stringify(mergedFavs.map(trimFavorite)));
            writeFP('recents', JSON.stringify(mergedRecents));
            writeFP('preferences', JSON.stringify(mergedPrefs));
            markClean();
            writeMarker(version);
            return Promise.resolve(true);
        }

        var body = JSON.stringify({
            favorites: mergedFavs.map(trimFavorite), recents: mergedRecents,
            preferences: mergedPrefs, version: version
        });
        return fetch(BASE, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: body
        }).then(function(r) {
            if (r.status === 409) {
                // Someone else wrote; merge again, up to the retry budget.
                if (attempt >= MAX_RECONCILE_ATTEMPTS) return false;
                return r.json().then(function(s) { return reconcile(s, attempt + 1); });
            }
            if (!r.ok) {
                console.warn('mtgban sync: reconcile write failed (' + r.status + ')');
                return false;
            }
            return r.json().then(function(res) {
                if (res && typeof res.version === 'number') version = res.version;
                writeMarker(version);
                writeFP('favorites', JSON.stringify(mergedFavs.map(trimFavorite)));
                writeFP('recents', JSON.stringify(mergedRecents));
                writeFP('preferences', JSON.stringify(mergedPrefs));
                markClean();
                return true;
            });
        }).catch(function() {
            console.warn('mtgban sync: reconcile write failed (network)');
            return false;
        });
    }

    // True when local has an entry the server lacks or a newer copy of one.
    function localHasNew(favs, recents, prefs, server) {
        function newer(localList, serverList, idOf) {
            var sv = {};
            (serverList || []).forEach(function(x) {
                var id = idOf(x);
                if (id != null) sv[id] = mtime(x);
            });
            for (var i = 0; i < localList.length; i++) {
                var lid = idOf(localList[i]);
                if (lid == null) continue;
                if (!(lid in sv) || mtime(localList[i]) > sv[lid]) return true;
            }
            return false;
        }
        if (newer(favs, server.favorites, function(f) { return f.id; })) return true;
        if (newer(recents, server.recents, function(s) { return ('' + (s.q || '')).toLowerCase(); })) return true;
        var sp = server.preferences || {};
        var keys = Object.keys(prefs);
        for (var k = 0; k < keys.length; k++) { if (String(sp[keys[k]]) !== String(prefs[keys[k]])) return true; }
        return false;
    }

    // Merge by id: the copy with newer intent (m, fallback t) wins wholesale,
    // including its del and pinned state. Ties keep the local copy.
    function mergeList(local, server, idOf, cap) {
        var now = Date.now();
        var byId = {};
        var order = [];
        function add(item) {
            var id = idOf(item);
            if (id == null) return;
            var cur = byId[id];
            if (!cur) {
                byId[id] = item;
                order.push(id);
            } else if (mtime(item) > mtime(cur)) {
                byId[id] = item;
            }
        }
        (local || []).forEach(add);
        (server || []).forEach(add);
        var merged = order.map(function(id) { return byId[id]; });
        var live = merged.filter(function(x) { return !x.del; });
        var tombs = merged.filter(function(x) { return x.del && (now - mtime(x)) <= TOMB_TTL_MS; });
        live.sort(function(a, b) { return (b.t || 0) - (a.t || 0); });
        if (cap && live.length > cap) {
            // Keep pinned even when old; fill the rest with newest unpinned.
            var pinned = live.filter(function(x) { return x.pinned; });
            var unpinned = live.filter(function(x) { return !x.pinned; });
            live = pinned.concat(unpinned).slice(0, cap);
        }
        tombs.sort(function(a, b) { return mtime(b) - mtime(a); });
        if (tombs.length > TOMB_CAP) tombs = tombs.slice(0, TOMB_CAP);
        return live.concat(tombs);
    }

    // Preferences: last-write-wins per key (local wins on first merge).
    function mergePrefs(localPrefs, serverPrefs) {
        var out = {};
        Object.keys(serverPrefs || {}).forEach(function(k) { out[k] = serverPrefs[k]; });
        Object.keys(localPrefs || {}).forEach(function(k) { out[k] = localPrefs[k]; });
        return out;
    }

    function localFavorites() { try { return JSON.parse(readLocal(FAVORITES_KEY, '[]')); } catch (e) { return []; } }
    function localRecents() { try { return JSON.parse(readLocal(RECENTS_KEY, '[]')); } catch (e) { return []; } }

    // Sync only identity/intent fields; prices are refetched per device.
    function trimFavorite(f) {
        return {
            id: f.id, query: f.query, t: f.t, pinned: f.pinned,
            m: f.m, del: f.del,
            name: f.name, set: f.set, edition: f.edition, number: f.number,
            foil: f.foil, etched: f.etched,
            finishTag: f.finishTag, finishClass: f.finishClass,
            treatments: f.treatments, img: f.img, cw: f.cw
        };
    }

    // setItem shim: write through, mark dirty, schedule a debounced sync.
    function installSetItemShim() {
        localStorage.setItem = function(key, value) {
            rawSetItem(key, value);
            var section = sectionForKey(key);
            if (section) { markDirty(); schedule(section); }
        };
    }

    function hydrate() {
        var marker = readMarker();
        // Fresh and clean: local is current and already rendered; no request.
        if (!isDirty() && marker && typeof marker.ts === 'number' && (Date.now() - marker.ts) < TTL_MS) {
            if (typeof marker.v === 'number') version = marker.v;
            return;
        }

        var headers = {};
        if (marker && typeof marker.v === 'number') {
            version = marker.v;
            headers['If-None-Match'] = '"' + marker.v + '"';
        }

        fetch(BASE, { method: 'GET', headers: headers }).then(function(r) {
            if (r.status === 304) { writeMarker(version); return null; } // unchanged
            if (r.status === 401 || r.status === 503) return null; // anon / unavailable
            if (!r.ok) return null;
            return r.json();
        }).then(function(state) {
            if (!state) return;
            var firstSync = readLocal(SYNCED_KEY, null) === null;
            var hasLocal = localFavorites().length > 0 || localRecents().length > 0;
            rawSetItem(SYNCED_KEY, '1');
            if (isDirty() || (firstSync && hasLocal)) {
                reconcile(state);
            } else {
                applyState(state);
                rerender();
            }
            writeMarker(typeof state.version === 'number' ? state.version : version);
        }).catch(function() {});
    }

    // Anonymous visitors get no sync layer (no shim, listeners, or hydrate).
    if (signedIn) {
        installSetItemShim();

        // Flush before the page goes away so a just-made change still syncs.
        document.addEventListener('visibilitychange', function() {
            if (document.visibilityState === 'hidden') flushPending();
        });
        window.addEventListener('pagehide', flushPending);

        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', hydrate);
        } else {
            hydrate();
        }
    }
})();
