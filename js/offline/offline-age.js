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

    // The banner's whole line. left is the sets a first sync has yet to
    // download, as far as this tab knows; missing is what the last sync left out.
    function bannerText(iso, nowMs, left, missing) {
        if (isNaN(parse(iso)) && left > 0) {
            return 'Prices are still downloading (' + left + (left === 1 ? ' set' : ' sets') + ' left). Some cards might be missing.';
        }
        var text = refreshText(iso, nowMs);
        if (missing > 0) {
            text += '\n' + (missing === 1 ? 'There is 1 set that needs' : 'There are ' + missing + ' sets that need') +
                ' to resync, a few results will be unavailable.';
        }
        return text;
    }

    function isStale(iso, nowMs) {
        var t = parse(iso);
        if (isNaN(t)) return true;
        return nowMs - t > STALE_MS;
    }

    g.OfflineAge = { refreshText: refreshText, bannerText: bannerText, isStale: isStale, STALE_MS: STALE_MS };
})(typeof self !== 'undefined' ? self : globalThis);
