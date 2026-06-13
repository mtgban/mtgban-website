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

    // Send one PATCH for a section. Returns a promise. 409 handling is added in
    // the next task by the reconcile function.
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

    // Stub reconcile - replaced by the real merge in the next task. For now it
    // just adopts server state so the core works standalone.
    function reconcile(serverState) {
        applyState(serverState);
        rerender();
    }

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
            // First-sync merge is added in the next task; for now adopt server state.
            applyState(state);
            rerender();
        }).catch(function() {});
    }

    // Expose internals the next task (merge/reconcile) will build on.
    window.__userState = {
        applyState: applyState,
        rerender: rerender,
        readLocal: readLocal,
        buildPreferences: buildPreferences,
        getVersion: function() { return version; },
        setVersion: function(v) { version = v; },
        rawSetItem: rawSetItem,
        FAVORITES_KEY: FAVORITES_KEY,
        RECENTS_KEY: RECENTS_KEY,
        PREF_KEYS: PREF_KEYS,
        base: BASE
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', hydrate);
    } else {
        hydrate();
    }
})();
