// User State Sync - background sync of favorites, recent searches, and UI
// preferences for signed-in users. localStorage stays the synchronous local
// cache; this layer hydrates from and writes through to the server. All server
// interaction is best-effort: failures leave localStorage authoritative.
(function() {
    var BASE = '/api/userstate/';
    var DEBOUNCE_MS = 1500;

    // Keys that map to dedicated server columns.
    var FAVORITES_KEY = 'mtgban_favorites';
    var RECENTS_KEY = 'mtgban_recent_searches';
    // Keys bundled into the preferences object.
    var PREF_KEYS = [
        'mtgban_fav_sort', 'mtgban_fav_sort_dir',
        'theme', 'chartDateRange', 'mtgban_nav_layout_v1',
        'chartReleasesLongRange', 'chartCheckpointTypes'
    ];

    // Signed-in detection: the MTGBAN auth cookie is not HttpOnly, so its mere
    // presence is a cheap gate. The server still authoritatively authorizes.
    function isSignedIn() {
        return /(?:^|;\s*)MTGBAN=/.test(document.cookie);
    }

    var version = 0;
    var rawSetItem = localStorage.setItem.bind(localStorage);
    var pending = {}; // section -> true
    var timer = null;

    function readLocal(key, fallback) {
        try {
            var v = localStorage.getItem(key);
            return v == null ? fallback : v;
        } catch (e) { return fallback; }
    }

    function buildPreferences() {
        var prefs = {};
        PREF_KEYS.forEach(function(k) {
            var v = readLocal(k, null);
            if (v != null) prefs[k] = v;
        });
        return prefs;
    }

    function sectionForKey(key) {
        if (key === FAVORITES_KEY) return 'favorites';
        if (key === RECENTS_KEY) return 'recents';
        if (PREF_KEYS.indexOf(key) >= 0) return 'preferences';
        return null;
    }

    function payloadForSection(section) {
        if (section === 'favorites') return JSON.parse(readLocal(FAVORITES_KEY, '[]'));
        if (section === 'recents') return JSON.parse(readLocal(RECENTS_KEY, '[]'));
        return buildPreferences();
    }

    // Apply a server state into localStorage (used on hydrate / reconcile).
    function applyState(state) {
        if (!state) return;
        try {
            if (state.favorites) rawSetItem(FAVORITES_KEY, JSON.stringify(state.favorites));
            if (state.recents) rawSetItem(RECENTS_KEY, JSON.stringify(state.recents));
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
    }

    // Send one PATCH for a section. On a version conflict, reconcile merges and
    // retries.
    function patchSection(section) {
        var body = JSON.stringify({ data: payloadForSection(section), version: version });
        return fetch(BASE + section, {
            method: 'PATCH',
            headers: { 'Content-Type': 'application/json' },
            body: body
        }).then(function(r) {
            if (r.status === 409) return r.json().then(function(cur) { return reconcile(cur); });
            if (!r.ok) return null;
            return r.json().then(function(res) { if (res && typeof res.version === 'number') version = res.version; });
        }).catch(function() {});
    }

    function flush() {
        timer = null;
        var sections = Object.keys(pending);
        pending = {};
        // Chain sequentially so version stays consistent across sections.
        sections.reduce(function(p, section) {
            return p.then(function() { return patchSection(section); });
        }, Promise.resolve());
    }

    function schedule(section) {
        pending[section] = true;
        if (timer) clearTimeout(timer);
        timer = setTimeout(flush, DEBOUNCE_MS);
    }

    // Merge server state into local, push the merged result back up, adopt the
    // server's version. Used on 409 and on first-login hydrate. attempt bounds
    // the 409 retry loop so a peer writing concurrently can't spin it forever.
    var MAX_RECONCILE_ATTEMPTS = 5;
    function reconcile(serverState, attempt) {
        attempt = attempt || 0;
        if (!serverState) return Promise.resolve();
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

        // Push merged full state up at the adopted version.
        var body = JSON.stringify({
            favorites: mergedFavs, recents: mergedRecents,
            preferences: mergedPrefs, version: version
        });
        return fetch(BASE, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: body
        }).then(function(r) {
            if (r.status === 409) {
                // Someone else wrote; merge again, up to the retry budget.
                if (attempt >= MAX_RECONCILE_ATTEMPTS) return null;
                return r.json().then(function(s) { return reconcile(s, attempt + 1); });
            }
            if (!r.ok) return null;
            return r.json().then(function(res) { if (res && typeof res.version === 'number') version = res.version; });
        }).catch(function() {});
    }

    // Union two lists by an identity function, keeping the entry with the newer
    // timestamp on collision. Pinned-first ordering is reapplied by the render
    // modules, so here we only dedupe and cap.
    function mergeList(local, server, idOf, cap) {
        var byId = {};
        var order = [];
        function add(item) {
            var id = idOf(item);
            if (id == null) return;
            if (byId[id]) {
                var existing = byId[id];
                var et = existing.t || 0, it = item.t || 0;
                if (it >= et) byId[id] = item; // newer wins
                if (existing.pinned && !byId[id].pinned) byId[id].pinned = existing.pinned;
            } else {
                byId[id] = item;
                order.push(id);
            }
        }
        (local || []).forEach(add);
        (server || []).forEach(add);
        var merged = order.map(function(id) { return byId[id]; });
        // Newest-first by timestamp, matching how unshift-based adds behave.
        merged.sort(function(a, b) { return (b.t || 0) - (a.t || 0); });
        if (cap && merged.length > cap) {
            // Keep pinned items even when old; fill the rest with newest unpinned.
            var pinned = merged.filter(function(x) { return x.pinned; });
            var unpinned = merged.filter(function(x) { return !x.pinned; });
            merged = pinned.concat(unpinned).slice(0, cap);
        }
        return merged;
    }

    // Preferences: last-write-wins per key. Local already reflects the most
    // recent device action, so local keys win over server on first merge.
    function mergePrefs(localPrefs, serverPrefs) {
        var out = {};
        Object.keys(serverPrefs || {}).forEach(function(k) { out[k] = serverPrefs[k]; });
        Object.keys(localPrefs || {}).forEach(function(k) { out[k] = localPrefs[k]; });
        return out;
    }

    function localFavorites() { try { return JSON.parse(readLocal(FAVORITES_KEY, '[]')); } catch (e) { return []; } }
    function localRecents() { try { return JSON.parse(readLocal(RECENTS_KEY, '[]')); } catch (e) { return []; } }

    // The setItem shim: pass through, then schedule a sync for allowlisted keys.
    localStorage.setItem = function(key, value) {
        rawSetItem(key, value);
        if (!isSignedIn()) return;
        var section = sectionForKey(key);
        if (section) schedule(section);
    };

    function hydrate() {
        if (!isSignedIn()) return;
        fetch(BASE, { method: 'GET' }).then(function(r) {
            if (r.status === 401 || r.status === 503) return null; // anon / unavailable
            if (!r.ok) return null;
            return r.json();
        }).then(function(state) {
            if (!state) return;
            var hasLocal = localFavorites().length > 0 || localRecents().length > 0;
            // Merge when this device has local data the server may not have;
            // otherwise just adopt the server state.
            if (hasLocal) {
                reconcile(state);
            } else {
                applyState(state);
                rerender();
            }
        }).catch(function() {});
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', hydrate);
    } else {
        hydrate();
    }
})();
