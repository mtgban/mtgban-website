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

    // How many image requests are in flight at once. Enough to keep a
    // connection busy without burying a phone's network stack.
    var FETCH_CONCURRENCY = 6;

    // Fetches one image into the cache. Reports its size, or 0 when the source
    // never published it, which is expected and not an error.
    async function fetchImage(cache, key) {
        var url = imageURL(key);
        var resp = await self.fetch(url, { credentials: 'same-origin' });
        if (resp.status === 403) throw new Error('forbidden');
        if (resp.status === 404) return 0;
        if (!resp.ok) throw new Error('image ' + key + ': HTTP ' + resp.status);
        var blob = await resp.blob();
        try {
            await cache.put(new Request(url), new Response(blob, {
                headers: { 'Content-Type': 'image/jpeg' },
            }));
        } catch (err) {
            if (err && err.name === 'QuotaExceededError') {
                throw new Error('storage quota exceeded while caching ' + key);
            }
            throw err;
        }
        return blob.size;
    }

    // Downloads each stale set's images; imgstate rows are the resume point.
    async function syncImages(deps) {
        var plan = computeWorkList(deps.images, deps.sel, deps.states);
        var total = plan.work.length;
        var done = 0;
        var bytes = 0;
        if (total === 0) return { done: 0, total: 0, bytes: 0, paused: false, missing: plan.missing };
        if (deps.cancelled()) return { done: 0, total: total, bytes: 0, paused: true, missing: plan.missing };

        if (self.navigator && self.navigator.storage && self.navigator.storage.estimate) {
            var est = await self.navigator.storage.estimate();
            var free = ((est.quota || 0) - (est.usage || 0)) * 0.9;
            if (plan.totalBytes > free) {
                throw new Error('not enough storage: need ' + formatBytes(plan.totalBytes) +
                    ', safe free space ' + formatBytes(free));
            }
        }

        var cache = await self.caches.open(IMAGE_CACHE);
        for (var i = 0; i < plan.work.length; i++) {
            if (deps.cancelled()) return { done: done, total: total, bytes: bytes, paused: true, missing: plan.missing };
            var item = plan.work[i];
            deps.post({ type: 'progress', stage: 'images', done: done, total: total, code: item.code, bytes: bytes });

            var keys = await deps.getImgKeys(item.code);
            // Mark in progress first so an interrupted set retries next sync.
            await deps.putImgState({ code: item.code, hash: item.hash, done: false });

            var stored = [];
            var next = 0;
            var cancelled = false;
            var workers = [];
            for (var w = 0; w < FETCH_CONCURRENCY; w++) {
                workers.push((async function () {
                    while (true) {
                        if (deps.cancelled()) { cancelled = true; return; }
                        var idx = next++;
                        if (idx >= keys.length) return;
                        var size = await fetchImage(cache, keys[idx]);
                        if (size > 0) {
                            bytes += size;
                            stored.push(keys[idx]);
                        }
                    }
                })());
            }
            await Promise.all(workers);
            if (cancelled) return { done: done, total: total, bytes: bytes, paused: true, missing: plan.missing };

            await deps.putImgState({ code: item.code, hash: item.hash, done: true, keys: stored.sort() });
            done++;
            deps.post({ type: 'progress', stage: 'images', done: done, total: total, code: item.code, bytes: bytes });
        }
        return { done: done, total: total, bytes: bytes, paused: false, missing: plan.missing };
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
        fetchImage: fetchImage,
        computeWorkList: computeWorkList,
        estimateSelection: estimateSelection,
        syncImages: syncImages,
        evictImages: evictImages,
    };
})();
