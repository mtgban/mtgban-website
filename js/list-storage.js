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

    // The tombstones worth keeping: unexpired, newest first, at most cap
    // (TOMB_CAP by default).
    function tombstones(list, cap) {
        cap = cap || TOMB_CAP;
        var now = Date.now();
        var tombs = list.filter(function(x) { return !isLive(x) && (now - mtime(x)) <= TOMB_TTL_MS; });
        tombs.sort(function(a, b) { return mtime(b) - mtime(a); });
        if (tombs.length > cap) tombs = tombs.slice(0, cap);
        return tombs;
    }

    // Keeps the first max live entries; a full or missing store drops the write.
    function save(key, list, max, tombCap) {
        try {
            var live = list.filter(isLive);
            if (live.length > max) live = live.slice(0, max);
            localStorage.setItem(key, JSON.stringify(live.concat(tombstones(list, tombCap))));
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

    // The grades a backpack entry can be in, best first.
    var BACKPACK_CONDS = ["NM", "SP", "MP", "HP", "PO"];

    // backpackCond is an entry's grade, NM when it has none it can use.
    function backpackCond(e) {
        return BACKPACK_CONDS.indexOf(e.cond) > 0 ? e.cond : "NM";
    }

    // backpackPack is the number of the backpack an entry is in, 1 when it
    // names none.
    function backpackPack(e) {
        var n = parseInt(e.pack, 10);
        return n > 1 ? n : 1;
    }

    // backpackKey names a backpack entry by backpack, card and grade: the
    // bare card id for NM in backpack 1, so an entry stored without either
    // is that one. A card id holds no "/" or "|".
    function backpackKey(e) {
        if (e.id == null) return e.id;
        var c = backpackCond(e), p = backpackPack(e);
        return (p > 1 ? p + "/" : "") + e.id + (c === "NM" ? "" : "|" + c);
    }

    // capBackpack keeps a backpack list's live entries, newest first, at
    // most max in each backpack and total in all, and its tombstones after.
    function capBackpack(list, max, total) {
        var per = {}, kept = 0;
        var live = list.filter(isLive).sort(function (a, b) { return (b.t || 0) - (a.t || 0); }).filter(function (e) {
            var p = backpackPack(e);
            if (kept >= total || (per[p] || 0) >= max) return false;
            per[p] = (per[p] || 0) + 1;
            kept++;
            return true;
        });
        return live.concat(list.filter(function (x) { return !isLive(x); }));
    }

    return {
        backpackConds: BACKPACK_CONDS,
        backpackCond: backpackCond,
        backpackKey: backpackKey,
        backpackPack: backpackPack,
        capBackpack: capBackpack,
        isLive: isLive,
        mtime: mtime,
        read: read,
        save: save,
        tombstones: tombstones,
        pinnedFirst: pinnedFirst
    };
})();
