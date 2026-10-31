// Best-effort cross-device sync of favorites, recents, the backpack, and prefs for signed-in users.
(function() {
    var BASE = '/api/userstate/';
    var DEBOUNCE_MS = 1500;
    // A browser refuses a keepalive request once the bodies of those in
    // flight pass 64 KiB; keepaliveLeft is what the ones in flight leave.
    var KEEPALIVE_MAX = 64 * 1024;
    var keepaliveLeft = KEEPALIVE_MAX;
    var FETCH_KEY = 'mtgban_userstate_fetch'; // sessionStorage: {v, ts}
    var TTL_MS = 90 * 1000;

    // Tombstones: entries with a del timestamp. Newest intent (m) wins merges.
    var mtime = ListStorage.mtime;

    // Keys that map to dedicated server columns.
    var FAVORITES_KEY = 'mtgban_favorites';
    var RECENTS_KEY = 'mtgban_recent_searches';
    var BACKPACK_KEY = 'mtgban_backpack';
    var BACKPACK_MAX = window.BAN_BACKPACK_MAX > 0 ? window.BAN_BACKPACK_MAX : 100;
    var BACKPACK_TABS = window.BAN_BACKPACK_TABS > 0 ? window.BAN_BACKPACK_TABS : 1;
    var PRESETS_KEY = 'mtgban_upload_presets';
    var ARBIT_KEY = 'mtgban_arbit_filters';
    var ARBIT_PRESETS_KEY = 'mtgban_arbit_presets';
    var TABS_KEY = 'mtgban_backpack_tabs';
    // Keys bundled into the preferences object.
    var PREF_KEYS = [
        'mtgban_fav_sort', 'mtgban_fav_sort_dir',
        'theme', 'chartDateRange', 'mtgban_nav_layout_v1',
        'chartReleasesLongRange', 'chartCheckpointTypes',
        'offline_mode', 'offline_stores', 'offline_editions', 'offline_img_editions',
        'mtgban_search_layout', 'mtgban_popular_collapsed', 'mtgban_store_factors',
        'mtgban_upload_presets', 'mtgban_arbit_filters', 'mtgban_arbit_presets',
        'mtgban_backpack_tabs', 'mtgban_backpack_sort'
    ];

    // The server renders whether the request carried the auth cookie; that is
    // a cheap signed-in gate, not a check of the signature.
    var signedIn = document.documentElement.dataset.signedIn === 'true';

    // Settles once the first hydrate has read the server, or at once without
    // sync: the shared page's Merge waits for it so it never merges unread.
    var markReady;
    window.UserStateSync = { ready: new Promise(function(res) { markReady = res; }) };

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

    // The server's clock, read off the Date header of each sync response:
    // saved filters and presets are stamped with it, so that a device whose
    // clock runs fast cannot outdate what another applied after it. It runs
    // on from its last sample by whichever of Date.now() and
    // performance.now() moved more: a clock set back while the page is open
    // moves only the second, and a system sleep, which stops it, only the
    // first; a clock set forward overshoots by what later() lets through.
    // A page takes the offset another page stored only if it is younger than
    // TTL_MS on this device's clock, as it is wherever hydrate skips its
    // request: a clock corrected since moves that age out of range.
    var CLOCK_KEY = 'mtgban_userstate_clock';
    var clock = (function() {
        try {
            var c = JSON.parse(readLocal(CLOCK_KEY, 'null'));
            var age = c ? Date.now() - c.at : NaN;
            var now = Date.now();
            return age >= 0 && age <= TTL_MS && isFinite(c.skew) ? { server: now + c.skew, perf: performance.now(), date: now } : null;
        } catch (e) { return null; }
    })();
    // The header was written somewhere in the round trip from sent, on
    // performance.now(): its middle is the nearest guess, and a trip longer
    // than CLOCK_RTT_MAX_MS leaves too wide a guess to replace the sample.
    var CLOCK_RTT_MAX_MS = 3000;
    function noteServerClock(r, sent) {
        var date = r && r.headers && typeof r.headers.get === 'function' ? Date.parse(r.headers.get('Date')) : NaN;
        var at = performance.now();
        if (!isFinite(date) || !(at - sent >= 0 && at - sent <= CLOCK_RTT_MAX_MS)) return;
        // The header counts whole seconds, so its midpoint is nearer
        var now = Date.now();
        clock = { server: date + 500, perf: (sent + at) / 2, date: now - (at - sent) / 2 };
        try { rawSetItem(CLOCK_KEY, JSON.stringify({ skew: serverNow() - now, at: now })); } catch (e) {}
    }
    function serverNow() {
        if (!clock) return Date.now();
        return clock.server + Math.max(Date.now() - clock.date, performance.now() - clock.perf);
    }
    // A stamp ahead of the server's clock, made before a device's first sync
    // or by an older version, counts as made now: else it outdates every
    // change until the clock catches up. later compares two stamps so, and
    // two that come out the same by the stamps as given, so that ones
    // brought back together keep their order.
    var CLOCK_TOLERANCE_MS = 5000;
    function onClock(t, now) { return t > now + CLOCK_TOLERANCE_MS ? now : t; }
    function clampStamp(t) { return onClock(t, serverNow()); }
    function later(a, b) {
        var now = serverNow(), x = onClock(a || 0, now), y = onClock(b || 0, now);
        return x !== y ? x > y : (a || 0) > (b || 0);
    }
    window.UserState = { now: serverNow, clamp: clampStamp, later: later };

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
        m[BACKPACK_KEY] = 'backpack';
        PREF_KEYS.forEach(function(k) { m[k] = 'preferences'; });
        return m;
    })();
    function sectionForKey(key) { return KEY_TO_SECTION[key] || null; }

    // payloadForSection is what a PATCH sends for the section, or null for a
    // favorites or recents value that does not parse: an unreadable local
    // copy must not replace the server's.
    function payloadForSection(section) {
        if (section === 'favorites') return parsedList(FAVORITES_KEY, trimFavorite);
        if (section === 'recents') return parsedList(RECENTS_KEY, trimRecent);
        if (section === 'backpack') return localBackpack().map(trimBackpack);
        return buildPreferences();
    }

    function parsedList(key, trim) {
        try { return JSON.parse(readLocal(key, '[]')).map(trim); } catch (e) { return null; }
    }

    // Card art on recent searches is owned by the device: recent-searches.js
    // captures it on result pages and refreshes missing art from the landing page.
    // It never travels over the wire, so drop whatever a server copy carries
    // (older clients did push it) and re-apply what this device already has -
    // otherwise a hydrate blanks the thumbnails of any entry whose art had not
    // been pushed yet.
    var RECENT_ART_KEYS = ['img', 'crop', 'foil', 'cw'];
    function recentId(s) { return ('' + ((s && s.q) || '')).toLowerCase(); }
    function keepRecentArt(recents) {
        var localBy = {};
        localRecents().forEach(function(s) { if (s && s.q != null) localBy[recentId(s)] = s; });
        return (recents || []).map(function(s) {
            if (!s) return s;
            var prev = s.q != null ? localBy[recentId(s)] : null;
            // Read prev before clearing s: a caller may hand us the local list.
            var art = {};
            if (prev && !s.del) {
                RECENT_ART_KEYS.forEach(function(k) { if (prev[k] != null) art[k] = prev[k]; });
            }
            RECENT_ART_KEYS.forEach(function(k) { delete s[k]; });
            Object.keys(art).forEach(function(k) { s[k] = art[k]; });
            return s;
        });
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
                var recents = keepRecentArt(state.recents);
                rawSetItem(RECENTS_KEY, JSON.stringify(recents));
                writeFP('recents', JSON.stringify(recents.map(trimRecent)));
            }
            if (state.backpack) {
                rawSetItem(BACKPACK_KEY, JSON.stringify(state.backpack));
                writeFP('backpack', JSON.stringify(state.backpack.map(trimBackpack)));
            }
            if (state.preferences) {
                // The saved filters merge in, should one have been applied
                // signed out: on a synced device the server's are as new
                var mine = {};
                if (readLocal(ARBIT_KEY, null) != null) mine[ARBIT_KEY] = readLocal(ARBIT_KEY, null);
                var prefs = mergePrefs(mine, state.preferences);
                Object.keys(prefs).forEach(function(k) {
                    if (PREF_KEYS.indexOf(k) >= 0) rawSetItem(k, String(prefs[k]));
                });
                // A list the merge repaired goes back to the server
                if (canonJSON(prefs) !== canonJSON(state.preferences)) { markDirty(); schedule('preferences'); }
            }
        } catch (e) {}
        if (typeof state.version === 'number') version = state.version;
    }

    // A body past the server's cap is refused with 413 on every write until
    // it shrinks; the backpack, which grows it most, says so once, and again
    // only after a write carrying it has landed.
    var toldTooLarge = false;
    function tooLarge() {
        if (toldTooLarge || typeof window.syncTooLarge !== 'function') return;
        toldTooLarge = true;
        window.syncTooLarge();
    }

    function rerender() {
        if (typeof window.renderFavorites === 'function') window.renderFavorites();
        if (typeof window.renderRecentSearches === 'function') window.renderRecentSearches();
        if (typeof window.renderBackpack === 'function') window.renderBackpack();
        if (window.UploadPresets && typeof window.UploadPresets.refresh === 'function') window.UploadPresets.refresh();
        if (window.ArbitFilters && typeof window.ArbitFilters.refresh === 'function') window.ArbitFilters.refresh();
        if (window.ArbitPresets && typeof window.ArbitPresets.refresh === 'function') window.ArbitPresets.refresh();
        if (window.StoreFactors && typeof window.StoreFactors.mirror === 'function') window.StoreFactors.mirror();
        // Synced favorites arrive price-less; backfill (self-gating).
        if (typeof window.refreshFavorites === 'function') window.refreshFavorites();
    }

    // A body past GZIP_OVER goes gzipped where the browser can, so a full
    // backpack stays under the server's 1 MB cap. Resolves to the fetch
    // options' headers and body. The 7000-card ceiling assumes
    // CompressionStream (Safari 16.4, Firefox 113): plain, nginx refuses a
    // body past about 2000 cards and as many removed ones.
    var GZIP_OVER = 32 * 1024;
    function encodeBody(body) {
        var plain = { headers: { 'Content-Type': 'application/json' }, body: body };
        if (body.length < GZIP_OVER || typeof CompressionStream !== 'function') return Promise.resolve(plain);
        var gz = new Blob([body]).stream().pipeThrough(new CompressionStream('gzip'));
        return new Response(gz).blob().then(function(blob) {
            return { headers: { 'Content-Type': 'application/json', 'Content-Encoding': 'gzip' }, body: blob };
        }, function() { return plain; });
    }

    // PATCH one section; keepalive lets it outlive navigation.
    // Resolves true when the write (or its reconcile) landed.
    function patchSection(section, keepalive) {
        var payload = payloadForSection(section);
        // Nothing readable to send: the section is settled, not retried.
        if (payload === null) return Promise.resolve(true);
        var payloadJSON = JSON.stringify(payload);
        // Content already on the server: succeed without a request.
        if (fpMatches(section, payloadJSON)) return Promise.resolve(true);
        var body = '{"data":' + payloadJSON + ',"version":' + version + '}';
        // Past the budget a plain request still lands on a hidden page.
        if (keepalive === true) {
            var size = new Blob([body]).size;
            keepalive = size <= keepaliveLeft;
            if (keepalive) keepaliveLeft -= size;
        }
        // A keepalive body is under 64 KiB already, and is sent at once:
        // the page may be gone before a compression settles.
        var sent;
        var encoded = keepalive === true ? Promise.resolve({ headers: { 'Content-Type': 'application/json' }, body: body }) : encodeBody(body);
        var req = encoded.then(function(enc) {
            sent = performance.now();
            return fetch(BASE + section, { method: 'PATCH', headers: enc.headers, body: enc.body, keepalive: keepalive === true });
        });
        if (keepalive) {
            var settle = function() { keepaliveLeft += size; };
            req.then(settle, settle);
        }
        return req.then(function(r) {
            noteServerClock(r, sent);
            if (r.status === 409) return r.json().then(function(cur) { return reconcile(cur); });
            if (!r.ok) {
                if (r.status === 413) tooLarge();
                console.warn('mtgban sync: ' + section + ' write failed (' + r.status + ')');
                return false;
            }
            return r.json().then(function(res) {
                if (res && typeof res.version === 'number') { version = res.version; writeMarker(version); }
                writeFP(section, payloadJSON);
                if (section === 'backpack') toldTooLarge = false;
                return true;
            });
        }).catch(function() {
            console.warn('mtgban sync: ' + section + ' write failed (network)');
            return false;
        });
    }

    // inflight is the last flush's writes, settled once they land.
    var inflight = Promise.resolve();
    function flush() {
        timer = null;
        var sections = Object.keys(pending);
        pending = {};
        var allOk = true;
        // Chain sequentially so version stays consistent across sections.
        inflight = sections.reduce(function(p, section) {
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
        return inflight;
    }

    // UserStateSync.flush writes what is queued now and settles once it and
    // any write already under way are saved, for a page about to ask the
    // server for them.
    window.UserStateSync.flush = function() {
        if (timer) clearTimeout(timer);
        var before = inflight;
        return Promise.all([before, flush()]);
    };

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
        var mergedRecents = mergeList(localRecents(), serverState.recents || [], recentId, 15);
        // BACKPACK_MAX is each backpack's size, so the cap goes per backpack.
        var mergedPack = ListStorage.capBackpack(mergeList(localBackpack(), serverState.backpack || [], ListStorage.backpackKey, 0, BACKPACK_MAX * BACKPACK_TABS), BACKPACK_MAX, BACKPACK_MAX * BACKPACK_TABS);
        var mergedPrefs = mergePrefs(buildPreferences(), serverState.preferences || {});
        // Must run before the write below: it reads the pre-merge local copies.
        mergedRecents = keepRecentArt(mergedRecents);

        try {
            rawSetItem(FAVORITES_KEY, JSON.stringify(mergedFavs));
            rawSetItem(RECENTS_KEY, JSON.stringify(mergedRecents));
            rawSetItem(BACKPACK_KEY, JSON.stringify(mergedPack.map(function(e) { return e.del ? ListStorage.backpackGone(e) : e; })));
            Object.keys(mergedPrefs).forEach(function(k) {
                if (PREF_KEYS.indexOf(k) >= 0) rawSetItem(k, String(mergedPrefs[k]));
            });
        } catch (e) {}

        version = typeof serverState.version === 'number' ? serverState.version : version;
        rerender();

        // Nothing new to push: adopt version, skip the write.
        if (!localHasNew(mergedFavs, mergedRecents, mergedPrefs, serverState, mergedPack)) {
            // Record a fingerprint only for a section the server verifiably
            // holds. Claiming one for a payload that was never sent makes the
            // next flush skip its PATCH, stranding the local copy for good.
            // Merging can still reorder or cap a list the server agrees on, so
            // re-queue whatever came out different instead of going clean.
            var trimmedFavs = mergedFavs.map(trimFavorite);
            var trimmedRecents = mergedRecents.map(trimRecent);
            var synced = true;
            if (sameList(trimmedFavs, (serverState.favorites || []).map(trimFavorite), function(f) { return f.id; })) {
                writeFP('favorites', JSON.stringify(trimmedFavs));
            } else { schedule('favorites'); synced = false; }
            if (sameList(trimmedRecents, (serverState.recents || []).map(trimRecent), recentId)) {
                writeFP('recents', JSON.stringify(trimmedRecents));
            } else { schedule('recents'); synced = false; }
            var trimmedPack = mergedPack.map(trimBackpack);
            if (sameList(trimmedPack, (serverState.backpack || []).map(trimBackpack), ListStorage.backpackKey)) {
                writeFP('backpack', JSON.stringify(trimmedPack));
            } else { schedule('backpack'); synced = false; }
            if (canonJSON(mergedPrefs) === canonJSON(serverState.preferences || {})) {
                writeFP('preferences', JSON.stringify(mergedPrefs));
            } else { schedule('preferences'); synced = false; }
            if (synced) markClean();
            writeMarker(version);
            return Promise.resolve(true);
        }

        var body = JSON.stringify({
            favorites: mergedFavs.map(trimFavorite), recents: mergedRecents.map(trimRecent),
            backpack: mergedPack.map(trimBackpack),
            preferences: mergedPrefs, version: version
        });
        var sent;
        return encodeBody(body).then(function(enc) {
            sent = performance.now();
            return fetch(BASE, { method: 'PUT', headers: enc.headers, body: enc.body });
        }).then(function(r) {
            noteServerClock(r, sent);
            if (r.status === 409) {
                // Someone else wrote; merge again, up to the retry budget.
                if (attempt >= MAX_RECONCILE_ATTEMPTS) return false;
                return r.json().then(function(s) { return reconcile(s, attempt + 1); });
            }
            if (!r.ok) {
                if (r.status === 413) tooLarge();
                console.warn('mtgban sync: reconcile write failed (' + r.status + ')');
                return false;
            }
            return r.json().then(function(res) {
                if (res && typeof res.version === 'number') version = res.version;
                writeMarker(version);
                toldTooLarge = false;
                writeFP('favorites', JSON.stringify(mergedFavs.map(trimFavorite)));
                writeFP('recents', JSON.stringify(mergedRecents.map(trimRecent)));
                writeFP('backpack', JSON.stringify(mergedPack.map(trimBackpack)));
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
    function localHasNew(favs, recents, prefs, server, pack) {
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
        if (newer(pack || [], server.backpack, ListStorage.backpackKey)) return true;
        var sp = server.preferences || {};
        var keys = Object.keys(prefs);
        for (var k = 0; k < keys.length; k++) { if (String(sp[keys[k]]) !== String(prefs[keys[k]])) return true; }
        return false;
    }

    // Merge by id: the copy with newer intent (m, fallback t) wins wholesale,
    // including its del and pinned state. Ties keep the local copy.
    // tombCap bounds the tombstones kept (ListStorage's default when unset).
    function mergeList(local, server, idOf, cap, tombCap) {
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
        live.sort(function(a, b) { return (b.t || 0) - (a.t || 0); });
        if (cap && live.length > cap) {
            // Keep pinned even when old; fill the rest with newest unpinned.
            var pinned = live.filter(function(x) { return x.pinned; });
            var unpinned = live.filter(function(x) { return !x.pinned; });
            live = pinned.concat(unpinned).slice(0, cap);
        }
        return live.concat(ListStorage.tombstones(merged, tombCap));
    }

    // A payload and the server's copy of it agree on content but not on shape:
    // JSONB does not preserve key order, and mergeList re-sorts and caps lists.
    // Compare on a canonical form - keys sorted, entries ordered by id.
    function canonJSON(x) {
        return JSON.stringify(canonValue(x));
    }
    function canonValue(x) {
        if (x === null || typeof x !== 'object') return x === undefined ? null : x;
        if (Array.isArray(x)) return x.map(canonValue);
        var out = {};
        Object.keys(x).sort().forEach(function(k) {
            if (x[k] !== undefined) out[k] = canonValue(x[k]);
        });
        return out;
    }
    function sameList(a, b, idOf) {
        function canon(list) {
            return canonJSON((list || []).slice().sort(function(x, y) {
                var xi = String(idOf(x)), yi = String(idOf(y));
                return xi < yi ? -1 : xi > yi ? 1 : 0;
            }));
        }
        return canon(a) === canon(b);
    }

    // Preferences: last-write-wins per key (local wins on first merge), but
    // the upload and arbitrage presets, lists of their own, merge preset by
    // preset, the saved arbitrage filters page group by page group, and the
    // backpack tabs tab by tab. A list on one side only goes through its
    // merge too, to be repaired.
    function mergePrefs(localPrefs, serverPrefs) {
        localPrefs = localPrefs || {};
        serverPrefs = serverPrefs || {};
        var out = {};
        Object.keys(serverPrefs).forEach(function(k) { out[k] = serverPrefs[k]; });
        Object.keys(localPrefs).forEach(function(k) { out[k] = localPrefs[k]; });
        if (PRESETS_KEY in out) out[PRESETS_KEY] = mergePresets(localPrefs[PRESETS_KEY], serverPrefs[PRESETS_KEY]);
        if (ARBIT_PRESETS_KEY in out) out[ARBIT_PRESETS_KEY] = mergeArbitPresets(localPrefs[ARBIT_PRESETS_KEY], serverPrefs[ARBIT_PRESETS_KEY]);
        if (ARBIT_KEY in out) out[ARBIT_KEY] = mergeArbitFilters(localPrefs[ARBIT_KEY], serverPrefs[ARBIT_KEY]);
        if (TABS_KEY in out) out[TABS_KEY] = mergeBackpackTabs(localPrefs[TABS_KEY], serverPrefs[TABS_KEY]);
        return out;
    }

    // Merge two backpack tab lists by pack: the newer add, rename or delete
    // (m, by later) wins, ties keep the local copy, and a delete stays as
    // {pack, del, m} so a stale list cannot bring the backpack back. The
    // order is that of the list reordered later (o), with the other's own
    // tabs after it; live stamps come back to the server's clock.
    function mergeBackpackTabs(local, server) {
        function parse(s) {
            try { var l = JSON.parse(s); return Array.isArray(l) ? l : []; } catch (e) { return []; }
        }
        function byPack(list) {
            var m = {};
            list.forEach(function(t) {
                var p = t && ListStorage.backpackPack(t);
                if (p && !m[p]) m[p] = t;
            });
            return m;
        }
        function reordered(list) { return list.reduce(function(o, t) { return Math.max(o, (t && t.o) || 0); }, 0); }
        var l = parse(local), sv = parse(server), mine = byPack(l), theirs = byPack(sv);
        var first = later(reordered(sv), reordered(l)) ? sv : l;
        var order = [];
        first.concat(first === l ? sv : l).forEach(function(t) {
            var p = t && ListStorage.backpackPack(t);
            if (p && order.indexOf(p) < 0) order.push(p);
        });
        var now = serverNow();
        return JSON.stringify(order.map(function(p) {
            var t = !mine[p] || (theirs[p] && later(theirs[p].m, mine[p].m)) ? theirs[p] : mine[p];
            if (!t.del && typeof t.m === 'number') t.m = onClock(t.m, now);
            if (!t.del && typeof t.o === 'number') t.o = onClock(t.o, now);
            return t;
        }));
    }

    // Merge two copies of the saved arbitrage filters, one state per page
    // group (arbit, global): the one applied later (t, by later) wins, ties
    // keep the local copy, and a winner ahead of the server's clock comes
    // back to it, which a sync then sends on so the server stops holding it.
    function mergeArbitFilters(local, server) {
        function parse(s) {
            try { var o = JSON.parse(s); return o && typeof o === 'object' && !Array.isArray(o) ? o : {}; } catch (e) { return {}; }
        }
        function stamp(e) { return (e && e.t) || 0; }
        var l = parse(local), sv = parse(server), out = {};
        Object.keys(sv).forEach(function(g) { out[g] = sv[g]; });
        Object.keys(l).forEach(function(g) {
            if (!out[g] || !later(stamp(out[g]), stamp(l[g]))) out[g] = l[g];
        });
        var now = serverNow();
        Object.keys(out).forEach(function(g) {
            if (out[g] && typeof out[g].t === 'number') out[g].t = onClock(out[g].t, now);
        });
        return JSON.stringify(out);
    }

    // Merge two preset lists by id: the newer save or delete (savedAt, by
    // later) wins, ties keep the local copy. Live presets by name, then the
    // deletes but those past the TTL the preset pages prune them at. The
    // stamps stay as given, to rank before presetsOnClock brings them back.
    var PRESET_TOMB_TTL_MS = 30 * 24 * 60 * 60 * 1000;
    function mergePresetList(local, server) {
        function parse(s) {
            try { var l = JSON.parse(s); return Array.isArray(l) ? l : []; } catch (e) { return []; }
        }
        // Of a save and a delete that come out the same on the clock, the delete
        function beats(p, cur) {
            var now = serverNow();
            if (!p.del !== !cur.del && onClock(p.savedAt || 0, now) === onClock(cur.savedAt || 0, now)) return !!p.del;
            return later(p.savedAt, cur.savedAt);
        }
        var byId = {};
        var order = [];
        parse(local).concat(parse(server)).forEach(function(p) {
            if (!p || !p.id) return;
            var cur = byId[p.id];
            if (!cur) order.push(p.id);
            if (!cur || beats(p, cur)) byId[p.id] = p;
        });
        var merged = order.map(function(id) { return byId[id]; });
        var live = merged.filter(function(p) { return !p.del; });
        live.sort(function(a, b) {
            var x = String(a.name).toLowerCase(), y = String(b.name).toLowerCase();
            return x < y ? -1 : x > y ? 1 : 0;
        });
        var now = serverNow();
        return live.concat(merged.filter(function(p) {
            return p.del && now - onClock(p.savedAt || 0, now) <= PRESET_TOMB_TTL_MS;
        }));
    }

    // presetsOnClock is a merged list as stored, its live stamps on the
    // server's clock. A delete keeps its own, which still counts as now
    // against a save it removed that runs ahead, so the save cannot return.
    function presetsOnClock(list) {
        var now = serverNow();
        list.forEach(function(p) { if (typeof p.savedAt === 'number' && !p.del) p.savedAt = onClock(p.savedAt, now); });
        return JSON.stringify(list);
    }

    function mergePresets(local, server) {
        return presetsOnClock(mergePresetList(local, server));
    }

    // The arbitrage presets merge as the upload ones do, then hold each page
    // group to the newest 10 and each name to 40 characters, as
    // arbit-presets.js saves them: two devices' lists cannot add up past it.
    // The cap ranks by later and leaves a delete for each preset it drops,
    // so a stale device cannot bring one back into a freed slot; a cut name
    // that another takes gets a number, as "Name (2)", within the 40.
    var ARBIT_PRESET_CAP = 10, ARBIT_PRESET_NAME_MAX = 40;
    function mergeArbitPresets(local, server) {
        var merged = mergePresetList(local, server);
        var kept = {}, count = {};
        var ranked = merged.filter(function(p) { return !p.del; }).sort(function(a, b) {
            if (later(a.savedAt, b.savedAt)) return -1;
            if (later(b.savedAt, a.savedAt)) return 1;
            return a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
        });
        ranked.forEach(function(p) {
            var g = String(p.group);
            count[g] = (count[g] || 0) + 1;
            if (count[g] <= ARBIT_PRESET_CAP) kept[p.id] = true;
        });
        var names = {};
        function nameKey(p, name) { return String(p.group) + '\n' + name.toLowerCase(); }
        ranked.forEach(function(p) {
            if (kept[p.id] && String(p.name).length <= ARBIT_PRESET_NAME_MAX) names[nameKey(p, String(p.name))] = true;
        });
        ranked.forEach(function(p) {
            var name = String(p.name);
            if (!kept[p.id] || name.length <= ARBIT_PRESET_NAME_MAX) return;
            var cut = name.slice(0, ARBIT_PRESET_NAME_MAX);
            for (var n = 2; names[nameKey(p, cut)]; n++) {
                cut = name.slice(0, ARBIT_PRESET_NAME_MAX - String(n).length - 3) + ' (' + n + ')';
            }
            names[nameKey(p, cut)] = true;
            p.name = cut;
        });
        var now = serverNow();
        var out = merged.filter(function(p) { return !p.del && kept[p.id]; });
        merged.forEach(function(p) {
            if (p.del) out.push(p);
            // Past the preset's own stamp, which may run up to the tolerance ahead
            else if (!kept[p.id]) out.push({ id: p.id, del: true, savedAt: Math.max(now, p.savedAt || 0) + 1 });
        });
        return presetsOnClock(out);
    }

    function localFavorites() { try { return JSON.parse(readLocal(FAVORITES_KEY, '[]')); } catch (e) { return []; } }
    function localBackpack() { try { return JSON.parse(readLocal(BACKPACK_KEY, '[]')); } catch (e) { return []; } }
    function localRecents() { try { return JSON.parse(readLocal(RECENTS_KEY, '[]')); } catch (e) { return []; } }

    // The backpack syncs identity and the count; prices stay on the page.
    // A removed entry keeps only what names it and orders it in a merge.
    function trimBackpack(e) {
        if (e.del) return ListStorage.backpackGone(e);
        return {
            id: e.id, cond: e.cond, pack: e.pack, qty: e.qty, t: e.t, m: e.m, del: e.del,
            name: e.name, edition: e.edition, set: e.set, number: e.number,
            finishTag: e.finishTag, finishClass: e.finishClass, img: e.img, cw: e.cw
        };
    }

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

    // Recents sync identity and intent only; the card art (img, crop, foil, cw)
    // is re-derived on each device from the search results page.
    function trimRecent(s) {
        return {
            q: s.q, sc: s.sc, t: s.t, m: s.m, del: s.del, pinned: s.pinned,
            set: s.set, keyrune: s.keyrune
        };
    }

    // setItem shim: write through, mark dirty, schedule a debounced sync.
    // Override Storage.prototype.setItem, not the localStorage instance:
    // `localStorage.setItem = fn` does not shadow the method in Firefox - the
    // Storage named-property setter stores a "setItem" key instead - so the
    // instance override silently never ran there and nothing ever synced.
    function installSetItemShim() {
        var proto = window.Storage && window.Storage.prototype;
        if (!proto || proto._mtgbanSyncShim) return;
        proto._mtgbanSyncShim = true;
        var nativeSetItem = proto.setItem;
        proto.setItem = function(key, value) {
            nativeSetItem.call(this, key, value);
            if (this === window.localStorage) {
                var section = sectionForKey(key);
                if (section) { markDirty(); schedule(section); }
            }
        };
        // Remove the stray "setItem" key the old instance assignment stored in
        // localStorage on Firefox.
        try { window.localStorage.removeItem('setItem'); } catch (e) {}
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

        var sent = performance.now();
        return fetch(BASE, { method: 'GET', headers: headers }).then(function(r) {
            noteServerClock(r, sent);
            if (r.status === 304) { writeMarker(version); return null; } // unchanged
            if (r.status === 401 || r.status === 503) return null; // anon / unavailable
            if (!r.ok) return null;
            return r.json();
        }).then(function(state) {
            if (!state) return;
            var firstSync = readLocal(SYNCED_KEY, null) === null;
            var hasLocal = localFavorites().length > 0 || localRecents().length > 0 ||
                localBackpack().some(function(e) { return e && !e.del; });
            rawSetItem(SYNCED_KEY, '1');
            var done = null;
            if (isDirty() || (firstSync && hasLocal)) {
                done = reconcile(state);
            } else {
                applyState(state);
                rerender();
            }
            writeMarker(typeof state.version === 'number' ? state.version : version);
            return done;
        }).catch(function() {});
    }

    // The one place ready settles for a signed-in page, whatever hydrate did.
    function hydrateAndSettle() {
        var p;
        try { p = hydrate(); } catch (e) {}
        Promise.resolve(p).then(markReady, markReady);
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
            document.addEventListener('DOMContentLoaded', hydrateAndSettle);
        } else {
            hydrateAndSettle();
        }
    } else {
        markReady();
    }
})();
