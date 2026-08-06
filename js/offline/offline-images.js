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

    // Bundle entries are flat <key>.jpg; key is the image key (scryfallId or p-<CODE>-<tcgId>).
    function entryMeta(name) {
        var m = /^([^\/]+)\.jpe?g$/i.exec(name);
        if (!m) return null;
        return {
            key: m[1],
            url: '/api/offline/images/' + m[1] + '.jpg',
            type: 'image/jpeg',
        };
    }

    function computeWorkList(images, sel, states) {
        var work = [];
        var totalBytes = 0;
        var totalCount = 0;
        var codes = (sel || []).slice().sort();
        codes.forEach(function (code) {
            var img = images ? images[code] : null;
            if (!img) return;
            var st = states ? states[code] : null;
            if (st && st.done && st.hash === img.h) return;
            work.push({ code: code, hash: img.h, count: img.n || 0, bytes: img.b || 0 });
            totalBytes += img.b || 0;
            totalCount += img.n || 0;
        });
        return { work: work, totalBytes: totalBytes, totalCount: totalCount };
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

    // Downloads and unpacks each stale bundle; imgstate rows are the resume point.
    async function syncImages(deps) {
        var plan = computeWorkList(deps.images, deps.sel, deps.states);
        var total = plan.work.length;
        var done = 0;
        var bytes = 0;
        if (total === 0) return { done: 0, total: 0, bytes: 0, paused: false };
        if (deps.cancelled()) return { done: 0, total: total, bytes: 0, paused: true };

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
            if (deps.cancelled()) return { done: done, total: total, bytes: bytes, paused: true };
            var item = plan.work[i];
            deps.post({ type: 'progress', stage: 'images', done: done, total: total, code: item.code, bytes: bytes });

            var resp = await self.fetch('/api/offline/imagebundles/' + item.code + '.zip',
                { credentials: 'same-origin' });
            if (resp.status === 403) throw new Error('forbidden');
            if (!resp.ok) throw new Error('bundle ' + item.code + ': HTTP ' + resp.status);
            var buf = new Uint8Array(await resp.arrayBuffer());
            bytes += buf.byteLength;

            // Mark in progress first so an interrupted unpack retries next sync.
            await deps.putImgState({ code: item.code, hash: item.hash, done: false });
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
                        throw new Error('storage quota exceeded while unpacking ' + item.code);
                    }
                    throw err;
                }
                keys.push(meta.key);
            }
            await deps.putImgState({ code: item.code, hash: item.hash, done: true, keys: keys });
            // two bundles must not be co-resident across the next await
            buf = null;
            entries = null;
            done++;
            deps.post({ type: 'progress', stage: 'images', done: done, total: total, code: item.code, bytes: bytes });
        }
        return { done: done, total: total, bytes: bytes, paused: false };
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
                if (await cache.delete('/api/offline/images/' + row.keys[j] + '.jpg')) removed++;
            }
            await deps.deleteImgState(row.code);
        }
        return removed;
    }

    self.OfflineImages = {
        IMAGE_CACHE: IMAGE_CACHE,
        formatBytes: formatBytes,
        entryMeta: entryMeta,
        computeWorkList: computeWorkList,
        estimateSelection: estimateSelection,
        syncImages: syncImages,
        evictImages: evictImages,
    };
})();
