// Offline navbar search controller: local-data suggestions and in-place query.
(function () {
    'use strict';
    var self = typeof window !== 'undefined' ? window : globalThis;

    var MIN_CHARS = 3;
    var MAX_ROWS = 10;

    // Build display suggestion rows from the local name index and card store.
    function suggest(rawValue, deps) {
        var needle = deps.normName(rawValue);
        if (needle.length < MIN_CHARS) return Promise.resolve([]);
        return deps.allNames().then(function (names) {
            var hits = [];
            for (var i = 0; i < names.length && hits.length < MAX_ROWS; i++) {
                if (names[i].key.indexOf(needle) !== -1) hits.push(names[i]);
            }
            return Promise.all(hits.map(function (h) {
                return deps.getCard(h.uuids[0]);
            }));
        }).then(function (cards) {
            var rows = [];
            for (var j = 0; j < cards.length; j++) {
                var c = cards[j];
                if (!c) continue;
                var set = deps.sets[c.set] || {};
                rows.push({
                    uuid: c.uuid,
                    name: c.n,
                    setCode: c.set,
                    setName: set.n || c.set,
                    number: c.num || '',
                    keyrune: set.k || ''
                });
            }
            return rows;
        });
    }

    self.OfflineSearch = { suggest: suggest };
})();
