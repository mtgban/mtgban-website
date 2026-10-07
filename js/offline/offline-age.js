// Pure data-age helpers; attaches to self so both windows and workers can load it.
(function (g) {
    'use strict';

    var DAY = 24 * 60 * 60 * 1000;
    var STALE_MS = 3 * DAY;

    function parse(iso) {
        if (!iso) return NaN;
        return Date.parse(iso);
    }

    // The banner's line: when prices were last refreshed, marked stale past
    // STALE_MS.
    function refreshText(iso, nowMs) {
        var t = parse(iso);
        if (isNaN(t)) return 'Offline prices have not been refreshed on this device yet.';
        var stale = nowMs - t > STALE_MS ? ' (stale)' : '';
        return 'Offline prices last refreshed at ' + new Date(t).toLocaleString() + stale + '.';
    }

    function isStale(iso, nowMs) {
        var t = parse(iso);
        if (isNaN(t)) return true;
        return nowMs - t > STALE_MS;
    }

    g.OfflineAge = { refreshText: refreshText, isStale: isStale, STALE_MS: STALE_MS };
})(typeof self !== 'undefined' ? self : globalThis);
