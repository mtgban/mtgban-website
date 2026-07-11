// Pure data-age helpers; attaches to self so both windows and workers can load it.
(function (g) {
    'use strict';

    var MIN = 60 * 1000;
    var HOUR = 60 * MIN;
    var DAY = 24 * HOUR;
    var STALE_MS = 3 * DAY;

    function parse(iso) {
        if (!iso) return NaN;
        return Date.parse(iso);
    }

    function formatAge(iso, nowMs) {
        var t = parse(iso);
        if (isNaN(t)) return 'never synced';
        var diff = nowMs - t;
        if (diff < MIN) return 'just now';
        if (diff < HOUR) {
            var m = Math.floor(diff / MIN);
            return m + (m === 1 ? ' minute ago' : ' minutes ago');
        }
        if (diff < DAY) {
            var h = Math.floor(diff / HOUR);
            return h + (h === 1 ? ' hour ago' : ' hours ago');
        }
        var d = Math.floor(diff / DAY);
        return d + (d === 1 ? ' day ago' : ' days ago');
    }

    function isStale(iso, nowMs) {
        var t = parse(iso);
        if (isNaN(t)) return true;
        return nowMs - t > STALE_MS;
    }

    g.OfflineAge = { formatAge: formatAge, isStale: isStale, STALE_MS: STALE_MS };
})(typeof self !== 'undefined' ? self : globalThis);
