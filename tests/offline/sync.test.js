import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const DIR = join(import.meta.dir, '..', '..', 'js', 'offline');

// Loads the sync worker against an in-memory database holding two synced
// sets and one edition of downloaded images; prices fail when asked to.
function loadWorker({ pricesFail = false, aesKey = 'k', extraSets = {}, cancelAtFirstPrice = false } = {}) {
    const meta = { aesKey, storesKey: '', catalogVersion: 'c1' };
    const imgstate = { NEO: { code: 'NEO', keys: ['a'], done: true } };
    const sets = { NEO: { code: 'NEO', version: 'v1', blob: 'neo' }, DMU: { code: 'DMU', version: 'v1', blob: 'dmu' } };
    const posts = [];
    const db = {
        getMeta: async (k) => meta[k],
        setMeta: async (k, v) => { meta[k] = v; },
        listSetVersions: async () => Object.values(sets).map((r) => ({ code: r.code, version: r.version })),
        getSet: async (code) => sets[code] && { ...sets[code] },
        putSet: async (row) => { sets[row.code] = row; },
        getAllRows: async (store) => (store === 'imgstate' ? Object.values(imgstate) : []),
        putRow: async () => {},
        deleteRow: async (store, code) => { delete (store === 'imgstate' ? imgstate : sets)[code]; },
    };
    const self = {
        postMessage: (m) => posts.push(m),
        caches: { open: async () => ({ delete: async () => true }) },
        OfflineDB: db,
        OfflineUtil: { gzipCompress: async (b) => b },
    };
    const manifest = { catalog: 'c1', sets: { NEO: 'v1', DMU: 'v1', ...extraSets }, images: {} };
    const fetch = async (url) => {
        if (url.includes('manifest')) return { ok: true, status: 200, json: async () => manifest };
        if (cancelAtFirstPrice) self.onmessage({ data: { type: 'cancel' } });
        if (pricesFail) throw new TypeError('Failed to fetch');
        return { ok: true, status: 200, arrayBuffer: async () => new ArrayBuffer(4) };
    };
    const crypto = {
        getRandomValues: (a) => a,
        subtle: { encrypt: async () => new ArrayBuffer(8), generateKey: async () => 'new-key' },
    };
    new Function('self', 'fetch', readFileSync(join(DIR, 'offline-images.js'), 'utf8'))(self, fetch);
    const src = readFileSync(join(DIR, 'offline-sync.js'), 'utf8') + '\n;return runSync;';
    const runSync = new Function('self', 'importScripts', 'fetch', 'crypto', 'OfflineImages', 'OfflineDB', src)(
        self, () => {}, fetch, crypto, self.OfflineImages, db);
    return { runSync, imgstate, sets, posts, meta };
}

test('a price-only sync keeps the downloaded images', async () => {
    const w = loadWorker();
    await w.runSync({ type: 'sync', stores: [], editions: [], imgEditions: [] });
    expect(Object.keys(w.imgstate)).toEqual(['NEO']);
    expect(w.posts.at(-1)).toMatchObject({ type: 'done', images: false });
});

test('an image sync with nothing selected releases the images', async () => {
    const w = loadWorker();
    await w.runSync({ type: 'sync', images: true, stores: [], editions: [], imgEditions: [] });
    expect(Object.keys(w.imgstate)).toEqual([]);
    expect(w.posts.at(-1)).toMatchObject({ type: 'done', images: true });
});

test('a full resync that loses the network keeps the old prices, unstamped', async () => {
    const w = loadWorker({ pricesFail: true });
    await w.runSync({ type: 'sync', full: true, stores: [], editions: [], imgEditions: [] });
    expect(w.sets.NEO).toMatchObject({ version: null, blob: 'neo' });
    expect(w.sets.DMU).toMatchObject({ version: null, blob: 'dmu' });
    expect(w.posts.at(-1)).toMatchObject({ type: 'done', failedSets: 2 });
});

test('a failed set goes when a new key cannot decrypt it', async () => {
    const w = loadWorker({ pricesFail: true, aesKey: null });
    await w.runSync({ type: 'sync', stores: [], editions: [], imgEditions: [] });
    expect(w.sets).toEqual({});
});

const SYNC = { type: 'sync', stores: [], editions: [], imgEditions: [] };

test('a sync with every set stored records none missing', async () => {
    const w = loadWorker({ extraSets: { MH2: 'v1' } });
    await w.runSync(SYNC);
    expect(w.meta.missingSets).toBe(0);
});

test('a set that failed and was never stored counts as missing', async () => {
    const w = loadWorker({ pricesFail: true, extraSets: { MH2: 'v1', ONE: 'v1' } });
    await w.runSync(SYNC);
    expect(w.meta.missingSets).toBe(2);
    expect(w.posts.at(-1)).toMatchObject({ type: 'done', failedSets: 2 });
});

test('a stored set whose refresh failed keeps its cards, so is not missing', async () => {
    const w = loadWorker({ pricesFail: true });
    await w.runSync({ ...SYNC, full: true });
    expect(w.posts.at(-1)).toMatchObject({ type: 'done', failedSets: 2 });
    expect(w.meta.missingSets).toBe(0);
});

test('a failed set a new key cannot read counts as missing', async () => {
    const w = loadWorker({ pricesFail: true, aesKey: null });
    await w.runSync(SYNC);
    expect(w.meta.missingSets).toBe(2);
});

test('sets a cancelled new-key sync never reached count as missing', async () => {
    const w = loadWorker({ aesKey: null, cancelAtFirstPrice: true, extraSets: { MH2: 'v1' } });
    await w.runSync(SYNC);
    // The one set in flight landed, and the two stored ones it left are unreadable
    expect(w.meta.missingSets).toBe(2);
});

test('only the selected editions can be missing', async () => {
    const w = loadWorker({ pricesFail: true, extraSets: { MH2: 'v1', ONE: 'v1' } });
    await w.runSync({ ...SYNC, editions: ['NEO', 'MH2'] });
    expect(w.meta.missingSets).toBe(1);
});
