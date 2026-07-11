// Offline image sync: work-list math, size estimates, Cache Storage unpack.
// Loaded via importScripts in the sync worker and via a script tag on pages.
(function () {
    'use strict';

    var IMAGE_CACHE = 'mtgban-images-v1';

    function formatBytes(n) {
        if (!isFinite(n) || n <= 0) return '0 B';
        if (n < 1000) return Math.round(n) + ' B';
        var units = ['KB', 'MB', 'GB', 'TB'];
        var u = -1;
        do { n /= 1000; u++; } while (n >= 1000 && u < units.length - 1);
        var s = n >= 100 ? String(Math.round(n)) : String(Math.round(n * 10) / 10);
        return s + ' ' + units[u];
    }

    // Cache key is always the .webp URL shape; jpg fallback entries only change Content-Type.
    function entryMeta(name) {
        var m = /^([^\/]+)\.(webp|jpe?g)$/i.exec(name);
        if (!m) return null;
        return {
            uuid: m[1],
            url: '/api/offline/images/' + m[1] + '.webp',
            contentType: m[2].toLowerCase() === 'webp' ? 'image/webp' : 'image/jpeg',
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

    self.OfflineImages = {
        IMAGE_CACHE: IMAGE_CACHE,
        formatBytes: formatBytes,
        entryMeta: entryMeta,
        computeWorkList: computeWorkList,
        estimateSelection: estimateSelection,
    };
})();
