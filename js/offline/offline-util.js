// Shared offline-mode helpers: name normalization, gzip, set payload loading.
// Plain script: attaches to self so pages and workers can both load it.
(function() {
    'use strict';

    // Exact normalization shared by the sync worker index build and offline-query.js.
    // Letters and digits of any script, as the online fold (internal/suggest);
    // marks go with their letter, so "ド" keys as "ト" rather than splitting.
    function normName(s) {
        return s.normalize('NFD').replace(/\p{M}/gu, '')
            .toLowerCase().replace(/[^\p{L}\p{N} ]+/gu, ' ')
            .replace(/\s+/g, ' ').trim();
    }

    // The version of what normName makes of a name, stamped on the stored
    // index: bump it with any change to normName's output.
    var NAME_FOLD = 2;

    function gzipCompress(buf) {
        var stream = new Response(buf).body.pipeThrough(new CompressionStream('gzip'));
        return new Response(stream).arrayBuffer();
    }

    function gzipDecompress(buf) {
        var stream = new Response(buf).body.pipeThrough(new DecompressionStream('gzip'));
        return new Response(stream).arrayBuffer();
    }

    // Decrypt + gunzip + decode one stored set; null when absent.
    function loadSetPayload(code) {
        return Promise.all([
            self.OfflineDB.getSet(code),
            self.OfflineDB.getMeta('aesKey'),
        ]).then(function(res) {
            var row = res[0], key = res[1];
            if (!row || !key) return null;
            return crypto.subtle.decrypt({ name: 'AES-GCM', iv: new Uint8Array(row.iv) }, key, row.blob)
                .then(gzipDecompress)
                .then(function(plain) { return self.OfflineFormat.decode(plain); });
        });
    }

    // Catalog display dictionaries persisted by the sync worker.
    function loadCatalogDicts() {
        return Promise.all([
            self.OfflineDB.getMeta('catalogSets'),
            self.OfflineDB.getMeta('catalogStores'),
            self.OfflineDB.getMeta('catalogFinishes'),
            self.OfflineDB.getMeta('catalogRarities'),
        ]).then(function(res) {
            return { sets: res[0] || {}, stores: res[1] || {}, finishes: res[2] || [], rarities: res[3] || [] };
        });
    }

    self.OfflineUtil = {
        normName: normName,
        NAME_FOLD: NAME_FOLD,
        gzipCompress: gzipCompress,
        gzipDecompress: gzipDecompress,
        loadSetPayload: loadSetPayload,
        loadCatalogDicts: loadCatalogDicts,
    };
})();
