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

    function hasSet(code) {
        return withTx(['sets'], 'readonly', function(tx, out) {
            var req = tx.objectStore('sets').count(code);
            req.onsuccess = function() { out.result = req.result > 0; };
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

    // Full name-index scan backing the offline search substring matcher.
    function allNames() {
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
        putSet: putSet,
        getSet: getSet,
        hasSet: hasSet,
        countSets: countSets,
        listSetVersions: listSetVersions,
        putCards: putCards,
        getCard: getCard,
        lookupName: lookupName,
        allNames: allNames,
        getAllRows: getAllRows,
        putRow: putRow,
        clearCatalog: clearCatalog,
        clearAll: clearAll,
    };
})();
