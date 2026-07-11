// Minimal IndexedDB wrapper for offline mode. The full v1 schema is created
// here; phase 3 adds sets/cards/names helpers without a version bump.
(function (root) {
    'use strict';

    var DB_NAME = 'mtgban-offline';
    var DB_VERSION = 1;

    // Memoized shared connection; only close() may tear it down.
    var dbPromise = null;

    function open() {
        if (dbPromise) return dbPromise;
        dbPromise = new Promise(function (resolve, reject) {
            var req = indexedDB.open(DB_NAME, DB_VERSION);
            req.onupgradeneeded = function () {
                var db = req.result;
                if (!db.objectStoreNames.contains('meta')) db.createObjectStore('meta', { keyPath: 'k' });
                if (!db.objectStoreNames.contains('sets')) db.createObjectStore('sets', { keyPath: 'code' });
                if (!db.objectStoreNames.contains('cards')) db.createObjectStore('cards', { keyPath: 'uuid' });
                if (!db.objectStoreNames.contains('names')) db.createObjectStore('names', { keyPath: 'key' });
                if (!db.objectStoreNames.contains('imgstate')) db.createObjectStore('imgstate', { keyPath: 'code' });
            };
            req.onsuccess = function () { resolve(req.result); };
            req.onerror = function () { dbPromise = null; reject(req.error); };
        });
        return dbPromise;
    }

    function close() {
        if (!dbPromise) return Promise.resolve();
        var p = dbPromise;
        dbPromise = null;
        return p.then(function (db) { db.close(); }, function () {});
    }

    function getMeta(k) {
        return open().then(function (db) {
            return new Promise(function (resolve, reject) {
                var req = db.transaction('meta').objectStore('meta').get(k);
                req.onsuccess = function () { resolve(req.result ? req.result.v : undefined); };
                req.onerror = function () { reject(req.error); };
            });
        });
    }

    function setMeta(k, v) {
        return open().then(function (db) {
            return new Promise(function (resolve, reject) {
                var tx = db.transaction('meta', 'readwrite');
                tx.objectStore('meta').put({ k: k, v: v });
                tx.oncomplete = function () { resolve(); };
                tx.onerror = function () { reject(tx.error); };
            });
        });
    }

    root.OfflineDB = { open: open, getMeta: getMeta, setMeta: setMeta, close: close, DB_NAME: DB_NAME };
})(self);
