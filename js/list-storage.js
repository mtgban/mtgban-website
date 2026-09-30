// localStorage lists of favorites and recent searches. A removed entry stays
// behind as a tombstone (del set) so user-state.js can sync the removal.
var ListStorage = (function() {
    var TOMB_TTL_MS = 30 * 24 * 60 * 60 * 1000;
    var TOMB_CAP = 50;

    function isLive(x) { return !x.del; }
    function mtime(x) { return x.m || x.t || 0; }

    function read(key) {
        try {
            var data = localStorage.getItem(key);
            return data ? JSON.parse(data) : [];
        } catch (e) {
            return [];
        }
    }

    // The tombstones worth keeping: unexpired, newest first, at most TOMB_CAP.
    function tombstones(list) {
        var now = Date.now();
        var tombs = list.filter(function(x) { return !isLive(x) && (now - mtime(x)) <= TOMB_TTL_MS; });
        tombs.sort(function(a, b) { return mtime(b) - mtime(a); });
        if (tombs.length > TOMB_CAP) tombs = tombs.slice(0, TOMB_CAP);
        return tombs;
    }

    // Keeps the first max live entries; a full or missing store drops the write.
    function save(key, list, max) {
        try {
            var live = list.filter(isLive);
            if (live.length > max) live = live.slice(0, max);
            localStorage.setItem(key, JSON.stringify(live.concat(tombstones(list))));
        } catch (e) {}
    }

    // Stable two-pass: pinned items first (by pin time desc), unpinned after (original order)
    function pinnedFirst(list) {
        var pinned = [];
        var unpinned = [];
        list.forEach(function(item) {
            if (item.pinned) pinned.push(item); else unpinned.push(item);
        });
        pinned.sort(function(a, b) { return (b.pinned || 0) - (a.pinned || 0); });
        return pinned.concat(unpinned);
    }

    return {
        isLive: isLive,
        mtime: mtime,
        read: read,
        save: save,
        tombstones: tombstones,
        pinnedFirst: pinnedFirst
    };
})();
