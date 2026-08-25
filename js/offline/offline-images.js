// Offline image sync: work-list math, size estimates, Cache Storage unpack.
// Loaded via importScripts in the sync worker and via a script tag on pages.
(function () {
    'use strict';

    var IMAGE_CACHE = 'mtgban-images-v2';

    function formatBytes(n) {
        if (!isFinite(n) || n <= 0) return '0 B';
        if (n < 1000) return Math.round(n) + ' B';
        var units = ['KB', 'MB', 'GB', 'TB'];
        var u = -1;
        do { n /= 1000; u++; } while (n >= 1000 && u < units.length - 1);
        var s = n >= 100 ? String(Math.round(n)) : String(Math.round(n * 10) / 10);
        return s + ' ' + units[u];
    }

    function computeWorkList(images, sel, states) {
        var work = [];
        var totalBytes = 0;
        var totalCount = 0;
        var missing = [];
        var codes = (sel || []).slice().sort();
        codes.forEach(function (code) {
            var img = images ? images[code] : null;
            if (!img) { missing.push(code); return; }
            var st = states ? states[code] : null;
            if (st && st.done && st.hash === img.h) return;
            work.push({ code: code, hash: img.h, count: img.n || 0, bytes: img.b || 0 });
            totalBytes += img.b || 0;
            totalCount += img.n || 0;
        });
        return { work: work, totalBytes: totalBytes, totalCount: totalCount, missing: missing };
    }

    function estimateSelection(images, codes) {
        var bytes = 0;
        var count = 0;
        var missing = [];
        (codes || []).forEach(function (code) {
            var img = images ? images[code] : null;
            if (!img) { missing.push(code); return; }
            bytes += img.b || 0;
            count += img.n || 0;
        });
        return { bytes: bytes, count: count, missing: missing };
    }

    // Sealed images are TCGplayer's jpg; singles are Scryfall's webp. The
    // extension is part of the url the cache is keyed on, so it is derived
    // from the key rather than written out at each call site.
    function imageURL(key) {
        var ext = key.indexOf('p-') === 0 ? '.jpg' : '.webp';
        return '/api/offline/images/' + encodeURIComponent(key) + ext;
    }

    // A corpus this size meets transient 5xx and dropped connections as a
    // matter of course, so each bundle gets its own retries before the set it
    // belongs to counts as failed.
    var MAX_ATTEMPTS = 3;
    var RETRY_BASE_MS = 500;

    function delay(ms) {
        return new Promise(function (resolve) { self.setTimeout(resolve, ms); });
    }

    // Marks the errors that must end the whole run rather than cost one set.
    function fatalError(message) {
        var err = new Error(message);
        err.fatal = true;
        return err;
    }

    // Where one set's bundle lives, under the base the server authorized us
    // for. The token rides in the url because the bucket has no other way to
    // take it; it is short-lived and scoped to the image tree.
    function bundleURL(auth, code, hash) {
        return auth.base + '/bundles/' + encodeURIComponent(code + '-' + hash) + '.zip' +
            '?Authorization=' + encodeURIComponent(auth.token);
    }

    // Maps a zip entry to where it is cached. The cache is keyed on this
    // site's own url rather than on the bucket url the bytes arrived from, so
    // a rotating token never strands a cached image and the renderers keep
    // pointing at one stable address that outlives any of this.
    function entryMeta(name) {
        var m = /^([A-Za-z0-9._-]+)\.(webp|jpg)$/.exec(name);
        if (!m) return null;
        return {
            key: m[1],
            url: '/api/offline/images/' + encodeURIComponent(m[1]) + '.' + m[2],
            type: m[2] === 'webp' ? 'image/webp' : 'image/jpeg',
        };
    }

    // Downloads one set's bundle. Null means the mirror has not published one
    // for this set yet, which is a skip rather than a failure.
    async function fetchBundle(auth, item) {
        var url = bundleURL(auth, item.code, item.hash);
        for (var attempt = 1; attempt <= MAX_ATTEMPTS; attempt++) {
            var resp = null;
            try {
                // No credentials: this is another origin, and the token in the
                // url is the whole of our authorization.
                resp = await self.fetch(url);
            } catch (err) {
                if (attempt === MAX_ATTEMPTS) throw err;
                await delay(RETRY_BASE_MS * attempt);
                continue;
            }
            // An expired or revoked token fails every remaining set the same
            // way, so stop rather than grinding through the whole selection.
            if (resp.status === 401 || resp.status === 403) {
                throw fatalError('bucket authorization rejected');
            }
            if (resp.status === 404) return null;
            if (resp.ok) return new Uint8Array(await resp.arrayBuffer());
            if (attempt === MAX_ATTEMPTS) {
                throw new Error('bundle ' + item.code + ': HTTP ' + resp.status);
            }
            await delay(RETRY_BASE_MS * attempt);
        }
        return null;
    }

    // Unpacks one bundle into the cache, returning the keys it stored.
    async function unpackBundle(cache, code, buf) {
        var entries = self.fflate.unzipSync(buf);
        var names = Object.keys(entries);
        var keys = [];
        for (var j = 0; j < names.length; j++) {
            var meta = entryMeta(names[j]);
            if (!meta) continue;
            try {
                await cache.put(new Request(meta.url), new Response(entries[names[j]], {
                    headers: { 'Content-Type': meta.type },
                }));
            } catch (err) {
                if (err && err.name === 'QuotaExceededError') {
                    throw fatalError('storage quota exceeded while unpacking ' + code);
                }
                throw err;
            }
            keys.push(meta.key);
        }
        return keys;
    }

    // Downloads and unpacks each stale set's bundle; imgstate rows are the
    // resume point. Bundles come straight from the bucket: one request per set
    // instead of one per image, and none of them through the site.
    async function syncImages(deps) {
        var plan = computeWorkList(deps.images, deps.sel, deps.states);
        var total = plan.work.length;
        var done = 0;
        var bytes = 0;
        var failed = 0;
        if (total === 0) return { done: 0, total: 0, bytes: 0, paused: false, missing: plan.missing, failed: 0 };
        if (deps.cancelled()) return { done: 0, total: total, bytes: 0, paused: true, missing: plan.missing, failed: 0 };

        if (self.navigator && self.navigator.storage && self.navigator.storage.estimate) {
            var est = await self.navigator.storage.estimate();
            var free = ((est.quota || 0) - (est.usage || 0)) * 0.9;
            if (plan.totalBytes > free) {
                throw new Error('not enough storage: need ' + formatBytes(plan.totalBytes) +
                    ', safe free space ' + formatBytes(free));
            }
        }

        // One authorization covers the whole run. Asking per set would put the
        // site back in the path for every set, which is what this avoids.
        var auth = await deps.getBucketAuth();
        if (!auth || !auth.base || !auth.token) {
            throw new Error('no bucket authorization; cannot sync images');
        }

        var cache = await self.caches.open(IMAGE_CACHE);
        for (var i = 0; i < plan.work.length; i++) {
            if (deps.cancelled()) return { done: done, total: total, bytes: bytes, paused: true, missing: plan.missing, failed: failed };
            var item = plan.work[i];
            deps.post({ type: 'progress', stage: 'images', done: done, total: total, code: item.code, bytes: bytes });

            // Mark in progress first so an interrupted unpack retries next sync.
            await deps.putImgState({ code: item.code, hash: item.hash, done: false });

            var buf = null;
            try {
                buf = await fetchBundle(auth, item);
                if (buf !== null) {
                    bytes += buf.byteLength;
                    var keys = await unpackBundle(cache, item.code, buf);
                    await deps.putImgState({ code: item.code, hash: item.hash, done: true, keys: keys });
                }
            } catch (err) {
                if (err && err.fatal) throw err;
                // One bad set costs that set, not the rest of the selection.
                // Its row stays not-done, so the next sync picks it up again.
                failed++;
            }
            // Two bundles must not be co-resident across the next await.
            buf = null;

            done++;
            deps.post({ type: 'progress', stage: 'images', done: done, total: total, code: item.code, bytes: bytes });
        }
        return { done: done, total: total, bytes: bytes, paused: false, missing: plan.missing, failed: failed };
    }

    // Removes cached images and state rows for editions no longer selected.
    async function evictImages(deps) {
        var sel = {};
        (deps.sel || []).forEach(function (c) { sel[c] = true; });
        var rows = await deps.getImgStates();
        var stale = rows.filter(function (r) { return !sel[r.code]; });
        if (stale.length === 0) return 0;
        var cache = await self.caches.open(IMAGE_CACHE);
        var removed = 0;
        for (var i = 0; i < stale.length; i++) {
            var row = stale[i];
            if (!row.keys) {
                // v1-era row (uuids field): the v1 cache is reaped wholesale by the SW, so just drop the row.
                await deps.deleteImgState(row.code);
                continue;
            }
            for (var j = 0; j < row.keys.length; j++) {
                if (await cache.delete(imageURL(row.keys[j]))) removed++;
            }
            await deps.deleteImgState(row.code);
        }
        return removed;
    }

    self.OfflineImages = {
        IMAGE_CACHE: IMAGE_CACHE,
        formatBytes: formatBytes,
        imageURL: imageURL,
        entryMeta: entryMeta,
        bundleURL: bundleURL,
        fetchBundle: fetchBundle,
        computeWorkList: computeWorkList,
        estimateSelection: estimateSelection,
        syncImages: syncImages,
        evictImages: evictImages,
    };
})();
