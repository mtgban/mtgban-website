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
