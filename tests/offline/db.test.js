const { test, expect } = require('bun:test');

// Only isGhostDb is testable in bun (no IDB runtime); open()'s delete-and-reopen recovery is now covered with a scripted fake below.
globalThis.self = globalThis.self || globalThis;
require('../../js/offline/offline-db.js');

const { isGhostDb } = globalThis.OfflineDB;

test('ghost DB missing meta store is detected', () => {
    var ghost = { objectStoreNames: { contains: () => false } };
    expect(isGhostDb(ghost)).toBe(true);
});

test('healthy DB with meta store present is not ghost', () => {
    var healthy = { objectStoreNames: { contains: () => true } };
    expect(isGhostDb(healthy)).toBe(false);
});

test('ghost check targets the meta store specifically', () => {
    var metaMissing = { objectStoreNames: { contains: (n) => n !== 'meta' } };
    expect(isGhostDb(metaMissing)).toBe(true);
    var metaPresent = { objectStoreNames: { contains: (n) => n === 'meta' } };
    expect(isGhostDb(metaPresent)).toBe(false);
});

// --- ghost recovery with a scripted fake indexedDB ---

const { readFileSync } = require('fs');
const { join } = require('path');

// Fresh module instance bound to a fake indexedDB (module state is per-load).
function loadWithFakeIDB(fakeIDB) {
    const src = readFileSync(join(__dirname, '..', '..', 'js', 'offline', 'offline-db.js'), 'utf8');
    const sandbox = {};
    new Function('self', 'indexedDB', src)(sandbox, fakeIDB);
    return sandbox.OfflineDB;
}

// First open yields a ghost DB (no stores); after deleteDatabase, opens are healthy.
function makeGhostThenHealthyIDB() {
    let opens = 0;
    return {
        get opens() { return opens; },
        open() {
            opens++;
            const ghost = opens === 1;
            const req = {};
            setTimeout(() => {
                req.result = {
                    objectStoreNames: { contains: () => !ghost },
                    close() {},
                };
                if (req.onsuccess) req.onsuccess();
            }, 0);
            return req;
        },
        deleteDatabase() {
            const del = {};
            setTimeout(() => { if (del.onsuccess) del.onsuccess(); }, 0);
            return del;
        },
    };
}

test('ghost recovery reopens instead of deadlocking', async () => {
    const fake = makeGhostThenHealthyIDB();
    const DB = loadWithFakeIDB(fake);
    const db = await Promise.race([
        DB.open(),
        new Promise((_, rej) => setTimeout(() => rej(new Error('deadlock: open() never settled')), 500)),
    ]);
    expect(fake.opens).toBe(2);
    expect(db.objectStoreNames.contains('meta')).toBe(true);
});

test('concurrent opens during ghost recovery share one recovered db', async () => {
    const fake = makeGhostThenHealthyIDB();
    const DB = loadWithFakeIDB(fake);
    const both = Promise.all([DB.open(), DB.open()]);
    const timeout = new Promise((_, rej) => setTimeout(() => rej(new Error('deadlock')), 500));
    const [a, b] = await Promise.race([both, timeout]);
    expect(a.objectStoreNames.contains('meta')).toBe(true);
    expect(b).toBe(a);
    expect(fake.opens).toBe(2);
});

// --- the name index, read once per catalog version ---

// A fake indexedDB holding state.version as the catalogVersion stamp and
// state.names as the name index, counting the scans of it in state.scans;
// state.failNext fails the next scan.
function makeCatalogIDB(state) {
    const db = {
        objectStoreNames: { contains: () => true },
        close() {},
        transaction() {
            const tx = {};
            let pending = 0;
            const settle = () => { if (--pending === 0) setTimeout(() => tx.oncomplete && tx.oncomplete(), 0); };
            tx.objectStore = (store) => ({
                get(k) {
                    const req = {};
                    pending++;
                    setTimeout(() => {
                        const stamped = store === 'meta' && k === 'catalogVersion' && state.version !== undefined;
                        req.result = stamped ? { k: k, v: state.version } : undefined;
                        if (req.onsuccess) req.onsuccess();
                        settle();
                    }, 0);
                    return req;
                },
                openCursor() {
                    state.scans++;
                    if (state.failNext) {
                        // The walk fails as a transaction error, as withTx sees it
                        state.failNext = false;
                        setTimeout(() => { tx.error = new Error('scan failed'); tx.onerror(); }, 0);
                        return {};
                    }
                    const rows = state.names.slice();
                    const req = {};
                    let i = 0;
                    pending++;
                    const step = () => setTimeout(() => {
                        req.result = i < rows.length ? { value: rows[i], continue() { i++; step(); } } : null;
                        if (req.onsuccess) req.onsuccess();
                        if (!req.result) settle();
                    }, 0);
                    step();
                    return req;
                },
            });
            return tx;
        },
    };
    return {
        open() {
            const req = {};
            setTimeout(() => { req.result = db; if (req.onsuccess) req.onsuccess(); }, 0);
            return req;
        },
    };
}

test('the name index is scanned once per catalog version', async () => {
    const state = { version: 'v1', names: [{ key: 'bolt', uuids: ['a'] }], scans: 0 };
    const DB = loadWithFakeIDB(makeCatalogIDB(state));
    const [first, concurrent] = await Promise.all([DB.allNames(), DB.allNames()]);
    const again = await DB.allNames();
    expect(state.scans).toBe(1);
    expect(concurrent).toBe(first);
    expect(again).toBe(first);
    expect(first).toEqual([{ key: 'bolt', uuids: ['a'] }]);

    // A sync that rebuilt the index stamps a new version: the next read scans it
    state.version = 'v2';
    state.names = [{ key: 'bolt', uuids: ['a'] }, { key: 'shock', uuids: ['b'] }];
    expect((await DB.allNames()).map((n) => n.key)).toEqual(['bolt', 'shock']);
    expect(state.scans).toBe(2);

    // Offline mode turned off clears the stamp with the index
    state.version = undefined;
    state.names = [];
    expect(await DB.allNames()).toEqual([]);
    expect(state.scans).toBe(3);
});

test('a scan that fails is not kept: the next read under the same stamp scans again', async () => {
    const state = { version: 'v1', names: [{ key: 'bolt', uuids: ['a'] }], scans: 0, failNext: true };
    const DB = loadWithFakeIDB(makeCatalogIDB(state));
    await expect(DB.allNames()).rejects.toThrow('scan failed');
    expect(await DB.allNames()).toEqual([{ key: 'bolt', uuids: ['a'] }]);
    expect(state.scans).toBe(2);
});

// A small stand-in for IndexedDB: enough of a transaction for ensureKey.
const KEY_PATHS = { meta: 'k', sets: 'code' };
let stores = {};

function fakeTransaction() {
    const tx = { oncomplete: null };
    let pending = 0;
    const settle = () => queueMicrotask(() => { if (pending === 0 && tx.oncomplete) tx.oncomplete(); });
    tx.objectStore = (name) => ({
        get(key) {
            const req = {};
            pending++;
            queueMicrotask(() => {
                req.result = stores[name].get(key);
                pending--;
                if (req.onsuccess) req.onsuccess();
                settle();
            });
            return req;
        },
        put(row) { stores[name].set(row[KEY_PATHS[name]], row); },
        delete(key) { stores[name].delete(key); },
        clear() { stores[name].clear(); },
    });
    settle();
    return tx;
}

globalThis.indexedDB = {
    open() {
        const req = {
            result: { objectStoreNames: { contains: () => true }, transaction: fakeTransaction },
        };
        queueMicrotask(() => req.onsuccess());
        return req;
    },
};

function seed(meta) {
    stores = {
        meta: new Map(Object.entries(meta).map(([k, v]) => [k, { k, v }])),
        sets: new Map([['NEO', { code: 'NEO', version: 'v1' }], ['MH2', { code: 'MH2', version: 'v1' }]]),
    };
}

const realGenerate = crypto.subtle.generateKey;

test('ensureKey leaves everything alone when there is a key', async () => {
    seed({ aesKey: 'old', lastSync: 'then', missingSets: 2 });
    let generated = 0;
    crypto.subtle.generateKey = async () => { generated++; return 'new'; };
    expect(await globalThis.OfflineDB.ensureKey()).toBe('old');
    expect(generated).toBe(0);
    expect(stores.sets.size).toBe(2);
    expect(stores.meta.get('lastSync').v).toBe('then');
    crypto.subtle.generateKey = realGenerate;
});

// What the lost key encrypted can't be read, and the banner must not call it fresh.
test('a new key takes the rows it cannot read and the record of their sync', async () => {
    seed({ lastSync: 'then', missingSets: 2, catalogVersion: 'c1' });
    crypto.subtle.generateKey = async () => 'new';
    expect(await globalThis.OfflineDB.ensureKey()).toBe('new');
    expect(stores.meta.get('aesKey').v).toBe('new');
    expect(stores.sets.size).toBe(0);
    expect(stores.meta.has('lastSync')).toBe(false);
    expect(stores.meta.has('missingSets')).toBe(false);
    expect(stores.meta.get('catalogVersion').v).toBe('c1');
    crypto.subtle.generateKey = realGenerate;
});

test('a key another tab stored first stands, with its rows', async () => {
    seed({});
    crypto.subtle.generateKey = async () => {
        stores.meta.set('aesKey', { k: 'aesKey', v: 'theirs' });
        return 'mine';
    };
    expect(await globalThis.OfflineDB.ensureKey()).toBe('theirs');
    expect(stores.meta.get('aesKey').v).toBe('theirs');
    expect(stores.sets.size).toBe(2);
    crypto.subtle.generateKey = realGenerate;
});

test('only the database creates the key', () => {
    const { readFileSync } = require('fs');
    const { join } = require('path');
    for (const file of ['offline-mode.js', 'offline-sync.js']) {
        expect(readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', file), 'utf8')).not.toContain('generateKey');
    }
});
