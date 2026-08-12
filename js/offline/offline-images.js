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
        var m = /^([^\/]+)\.(webp|jpe?g)$/i.exec(name);
        if (!m) return null;
        var webp = m[2].toLowerCase() === 'webp';
        return {
            key: m[1],
            url: '/api/offline/images/' + m[1] + (webp ? '.webp' : '.jpg'),
            type: webp ? 'image/webp' : 'image/jpeg',
        };
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

    // Sealed images are TCGplayer's jpg; singles are Scryfall's webp, so the
    // extension a key is cached under is derived from the key rather than
    // written out at each call site.
    function imageURL(key) {
        var ext = key.indexOf('p-') === 0 ? '.jpg' : '.webp';
        return '/api/offline/images/' + encodeURIComponent(key) + ext;
    }

    // Marks the errors that must end the whole run rather than cost one edition.
    function fatalError(message) {
        var err = new Error(message);
        err.fatal = true;
        return err;
    }

    // Downloads and unpacks each stale bundle; imgstate rows are the resume point.
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

        var cache = await self.caches.open(IMAGE_CACHE);
        for (var i = 0; i < plan.work.length; i++) {
            if (deps.cancelled()) return { done: done, total: total, bytes: bytes, paused: true, missing: plan.missing, failed: failed };
            var item = plan.work[i];
            deps.post({ type: 'progress', stage: 'images', done: done, total: total, code: item.code, bytes: bytes });

            var buf = null;
            var entries = null;
            try {
                var resp = await self.fetch('/api/offline/imagebundles/' + item.code + '.zip',
                    { credentials: 'same-origin' });
                // Auth is gone, not this one set: every remaining bundle would
                // fail the same way, so stop rather than grinding through them.
                if (resp.status === 403) throw fatalError('forbidden');
                if (!resp.ok) throw new Error('bundle ' + item.code + ': HTTP ' + resp.status);
                buf = new Uint8Array(await resp.arrayBuffer());
                bytes += buf.byteLength;

                // Mark in progress first so an interrupted unpack retries next sync.
                await deps.putImgState({ code: item.code, hash: item.hash, done: false });
                entries = self.fflate.unzipSync(buf);
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
                            throw fatalError('storage quota exceeded while unpacking ' + item.code);
                        }
                        throw err;
                    }
                    keys.push(meta.key);
                }
                await deps.putImgState({ code: item.code, hash: item.hash, done: true, keys: keys });
            } catch (err) {
                if (err && err.fatal) throw err;
                // One bad bundle costs that edition, not the rest of the
                // selection; its row stays not-done so the next sync retries it.
                failed++;
            }
            // two bundles must not be co-resident across the next await
            buf = null;
            entries = null;
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
        entryMeta: entryMeta,
        imageURL: imageURL,
        computeWorkList: computeWorkList,
        estimateSelection: estimateSelection,
        syncImages: syncImages,
        evictImages: evictImages,
    };
})();
