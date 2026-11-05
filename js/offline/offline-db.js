// IndexedDB wrapper for offline mode.
// Plain script: attaches to self so pages and workers can both load it.
(function() {
    'use strict';

    var DB_NAME = 'mtgban-offline';
    var DB_VERSION = 1;

    // keyPath per object store; the sync worker and page code rely on these key names.
    var STORES = { meta: 'k', sets: 'code', cards: 'uuid', names: 'key', imgstate: 'code' };

    var dbPromise = null;

    // Returns true if the DB opened with no stores; symptom of a blocked delete.
    function isGhostDb(db) {
        return !db.objectStoreNames.contains('meta');
    }

    function open(retried) {
        if (!dbPromise) {
            dbPromise = new Promise(function(resolve, reject) {
                var req = indexedDB.open(DB_NAME, DB_VERSION);
                req.onupgradeneeded = function() {
                    var db = req.result;
                    Object.keys(STORES).forEach(function(name) {
                        if (!db.objectStoreNames.contains(name)) {
                            db.createObjectStore(name, { keyPath: STORES[name] });
                        }
                    });
                };
                req.onsuccess = function() {
                    var db = req.result;
                    if (!retried && isGhostDb(db)) {
                        db.close();
                        dbPromise = new Promise(function(res2, rej2) {
                            var del = indexedDB.deleteDatabase(DB_NAME);
                            del.onsuccess = del.onerror = del.onblocked = function() {
                                // Free the slot so open(true) opens fresh instead of returning this promise.
                                dbPromise = null;
                                open(true).then(res2, rej2);
                            };
                        });
                        dbPromise.then(resolve, reject);
                        return;
                    }
                    db.onversionchange = function() { db.close(); dbPromise = null; };
                    resolve(db);
                };
                req.onerror = function() { dbPromise = null; reject(req.error); };
            });
        }
        return dbPromise;
    }

    // Callers close the handle before indexedDB.deleteDatabase.
    function close() {
        if (!dbPromise) return Promise.resolve();
        var p = dbPromise;
        dbPromise = null;
        return p.then(function(db) { db.close(); }, function() {});
    }

    // One transaction; resolves with out.result once the whole tx commits.
    function withTx(storeNames, mode, fn) {
        return open().then(function(db) {
            return new Promise(function(resolve, reject) {
                var tx = db.transaction(storeNames, mode);
                var out = { result: undefined };
                tx.oncomplete = function() { resolve(out.result); };
                tx.onerror = function() { reject(tx.error); };
                tx.onabort = function() { reject(tx.error || new Error('transaction aborted')); };
                fn(tx, out);
            });
        });
    }

    function getMeta(k) {
        return withTx(['meta'], 'readonly', function(tx, out) {
            var req = tx.objectStore('meta').get(k);
            req.onsuccess = function() { out.result = req.result ? req.result.v : undefined; };
        });
    }

    function setMeta(k, v) {
        return withTx(['meta'], 'readwrite', function(tx) {
            tx.objectStore('meta').put({ k: k, v: v });
        });
    }

    // ensureKey returns the key the set rows are encrypted with, creating it if
    // there is none. What a lost key encrypted can't be read again, so a new key
    // takes the rows and the record of their sync with it, in one transaction:
    // no reader sees a new key over old rows, and the next sync starts over.
    function ensureKey() {
        return getMeta('aesKey').then(function(key) {
            if (key) return key;
            return crypto.subtle.generateKey(
                { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
            ).then(function(fresh) {
                return withTx(['meta', 'sets'], 'readwrite', function(tx, out) {
                    var meta = tx.objectStore('meta');
                    var req = meta.get('aesKey');
                    req.onsuccess = function() {
                        // Another tab got here first; its key stands
                        if (req.result) {
                            out.result = req.result.v;
                            return;
                        }
                        tx.objectStore('sets').clear();
                        meta.delete('lastSync');
                        meta.delete('missingSets');
                        meta.put({ k: 'aesKey', v: fresh });
                        out.result = fresh;
                    };
                });
            });
        });
    }

    function putSet(row) {
        return withTx(['sets'], 'readwrite', function(tx) {
            tx.objectStore('sets').put(row);
        });
    }

    function getSet(code) {
        return withTx(['sets'], 'readonly', function(tx, out) {
            var req = tx.objectStore('sets').get(code);
            req.onsuccess = function() { out.result = req.result; };
        });
    }

    // Cheap count without fetching blobs.
    function countSets() {
        return withTx(['sets'], 'readonly', function(tx, out) {
            var req = tx.objectStore('sets').count();
            req.onsuccess = function() { out.result = req.result; };
        });
    }

    // Cursor walk keeps only one blob resident at a time.
    function listSetVersions() {
        return withTx(['sets'], 'readonly', function(tx, out) {
            out.result = [];
            var req = tx.objectStore('sets').openCursor();
            req.onsuccess = function() {
                var cur = req.result;
                if (!cur) return;
                out.result.push({ code: cur.value.code, version: cur.value.version });
                cur.continue();
            };
        });
    }

    function putCards(batch) {
        return withTx(['cards', 'names'], 'readwrite', function(tx) {
            var cards = tx.objectStore('cards');
            (batch.cards || []).forEach(function(row) { cards.put(row); });
            var names = tx.objectStore('names');
            (batch.names || []).forEach(function(row) { names.put(row); });
        });
    }

    function getCard(uuid) {
        return withTx(['cards'], 'readonly', function(tx, out) {
            var req = tx.objectStore('cards').get(uuid);
            req.onsuccess = function() { out.result = req.result; };
        });
    }

    function lookupName(normKey) {
        return withTx(['names'], 'readonly', function(tx, out) {
            var req = tx.objectStore('names').get(normKey);
            req.onsuccess = function() { out.result = req.result ? req.result.uuids : []; };
        });
    }

    // The name index as last scanned, and the catalog version it was read
    // under. The sync rewrites the index only with a new catalog, stamped
    // once the index is in, so a list read under the stamp still set is current.
    var names = null;

    // The name index in key order, backing the suggestion and search name
    // scans: scanned once per catalog version, not on every keystroke.
    function allNames(knownVersion) {
        var read = knownVersion !== undefined ? Promise.resolve(knownVersion) : getMeta('catalogVersion');
        return read.then(function(version) {
            if (names && names.version === version) return names.list;
            var list = scanNames();
            names = { version: version, list: list };
            list.catch(function() {
                if (names && names.list === list) names = null;
            });
            return list;
        });
    }

    function scanNames() {
        return withTx(['names'], 'readonly', function(tx, out) {
            out.result = [];
            var req = tx.objectStore('names').openCursor();
            req.onsuccess = function() {
                var cur = req.result;
                if (!cur) return;
                out.result.push({ key: cur.value.key, uuids: cur.value.uuids });
                cur.continue();
            };
        });
    }

    // What one search needs to know, read in a single transaction rather than
    // one per matched set. Read for each search, not kept: a first sync adds
    // sets long before lastSync moves.
    function searchState() {
        return withTx(['meta', 'sets'], 'readonly', function(tx, out) {
            out.result = {};
            var meta = tx.objectStore('meta');
            ['lastSync', 'catalogVersion'].forEach(function(k) {
                var req = meta.get(k);
                req.onsuccess = function() { out.result[k] = req.result ? req.result.v : undefined; };
            });
            var keys = tx.objectStore('sets').getAllKeys();
            keys.onsuccess = function() { out.result.stored = keys.result; };
        });
    }

    // The cards as last read, and the catalog version they were read under.
    var catalogCards = null;

    // catalog holds every card in memory, once per catalog version, so a search
    // doesn't go to the database per card.
    function catalog(version) {
        if (catalogCards && catalogCards.version === version) return catalogCards.loaded;
        var loaded = getAllRows('cards').then(function(list) {
            var byId = new Map();
            list.forEach(function(card) { byId.set(card.uuid, card); });
            return { list: list, byId: byId };
        });
        catalogCards = { version: version, loaded: loaded };
        loaded.catch(function() {
            if (catalogCards && catalogCards.loaded === loaded) catalogCards = null;
        });
        return loaded;
    }

    function checkStore(store) {
        if (!Object.prototype.hasOwnProperty.call(STORES, store)) {
            throw new Error('unknown store ' + store);
        }
    }

    // Generic row access for stores without dedicated helpers (imgstate).
    function getAllRows(store) {
        checkStore(store);
        return withTx([store], 'readonly', function(tx, out) {
            var req = tx.objectStore(store).getAll();
            req.onsuccess = function() { out.result = req.result; };
        });
    }

    function putRow(store, row) {
        checkStore(store);
        return withTx([store], 'readwrite', function(tx) {
            tx.objectStore(store).put(row);
        });
    }

    function deleteRow(store, key) {
        checkStore(store);
        return withTx([store], 'readwrite', function(tx) {
            tx.objectStore(store).delete(key);
        });
    }

    // Drops card metadata ahead of a catalog version swap; sets stay intact.
    function clearCatalog() {
        return withTx(['cards', 'names'], 'readwrite', function(tx) {
            tx.objectStore('cards').clear();
            tx.objectStore('names').clear();
        });
    }

    function clearAll() {
        return withTx(Object.keys(STORES), 'readwrite', function(tx) {
            Object.keys(STORES).forEach(function(name) { tx.objectStore(name).clear(); });
        });
    }

    self.OfflineDB = {
        DB_NAME: DB_NAME,
        open: open,
        close: close,
        isGhostDb: isGhostDb,
        getMeta: getMeta,
        setMeta: setMeta,
        ensureKey: ensureKey,
        putSet: putSet,
        getSet: getSet,
        countSets: countSets,
        listSetVersions: listSetVersions,
        putCards: putCards,
        getCard: getCard,
        lookupName: lookupName,
        allNames: allNames,
        searchState: searchState,
        catalog: catalog,
        getAllRows: getAllRows,
        putRow: putRow,
        deleteRow: deleteRow,
        clearCatalog: clearCatalog,
        clearAll: clearAll,
    };
})();
