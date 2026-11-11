import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const DIR = join(import.meta.dir, '..', '..', 'js', 'offline');

// The real normName and its fold version, which the stored index is stamped with.
globalThis.self = globalThis.self || globalThis;
require('../../js/offline/offline-util.js');
const { normName, NAME_FOLD } = globalThis.OfflineUtil;

// Loads the sync worker against an in-memory database holding two synced
// sets and one edition of downloaded images; prices fail when asked to.
function loadWorker({ pricesFail = false, aesKey = 'k', extraSets = {}, cancelAtFirstPrice = false,
    catalogVersion = 'c1:' + NAME_FOLD, catalog = null } = {}) {
    const control = { cancelAtFirstPrice, onDone: null };
    const meta = { aesKey, storesKey: '', catalogVersion };
    const index = {};
    const imgstate = { NEO: { code: 'NEO', keys: ['a'], done: true } };
    const sets = { NEO: { code: 'NEO', version: 'v1', blob: 'neo' }, DMU: { code: 'DMU', version: 'v1', blob: 'dmu' } };
    const posts = [];
    const db = {
        getMeta: async (k) => meta[k],
        setMeta: async (k, v) => { meta[k] = v; },
        ensureKey: async () => {
            if (meta.aesKey) return meta.aesKey;
            Object.keys(sets).forEach((code) => { delete sets[code]; });
            delete meta.lastSync;
            meta.aesKey = 'new-key';
            return meta.aesKey;
        },
        listSetVersions: async () => Object.values(sets).map((r) => ({ code: r.code, version: r.version })),
        getSet: async (code) => sets[code] && { ...sets[code] },
        putSet: async (row) => { sets[row.code] = row; },
        getAllRows: async (store) => (store === 'imgstate' ? Object.values(imgstate) : []),
        putRow: async () => {},
        deleteRow: async (store, code) => { delete (store === 'imgstate' ? imgstate : sets)[code]; },
        clearCatalog: async () => { Object.keys(index).forEach((k) => { delete index[k]; }); },
        putCards: async (batch) => { batch.names.forEach((row) => { index[row.key] = row.uuids; }); },
    };
    const self = {
        postMessage: (m) => {
            posts.push(m);
            if (m.type === 'done' && control.onDone) control.onDone();
        },
        caches: { open: async () => ({ delete: async () => true }) },
        location: { search: '' },
        OfflineDB: db,
        OfflineUtil: { gzipCompress: async (b) => b, normName, NAME_FOLD },
    };
    const manifest = { catalog: 'c1', sets: { NEO: 'v1', DMU: 'v1', ...extraSets }, images: {} };
    const fetch = async (url) => {
        if (url.includes('manifest')) return { ok: true, status: 200, json: async () => manifest };
        if (url.includes('catalog')) return { ok: true, status: 200, json: async () => catalog };
        if (control.cancelAtFirstPrice) self.onmessage({ data: { type: 'cancel' } });
        if (pricesFail) throw new TypeError('Failed to fetch');
        return { ok: true, status: 200, arrayBuffer: async () => new ArrayBuffer(4) };
    };
    const crypto = {
        getRandomValues: (a) => a,
        subtle: { encrypt: async () => new ArrayBuffer(8) },
    };
    new Function('self', 'fetch', readFileSync(join(DIR, 'offline-images.js'), 'utf8'))(self, fetch);
    const src = readFileSync(join(DIR, 'offline-sync.js'), 'utf8') + '\n;return runSync;';
    const runSync = new Function('self', 'importScripts', 'fetch', 'crypto', 'OfflineImages', 'OfflineDB', src)(
        self, () => {}, fetch, crypto, self.OfflineImages, db);
    // Through the worker's own message handler, which clears an earlier cancel
    const sync = (msg) => new Promise((resolve) => {
        control.onDone = resolve;
        self.onmessage({ data: msg });
    });
    return { runSync, sync, control, imgstate, sets, posts, meta, index };
}

// The worker asks for the scripts of the build its page passed in ?hash=,
// not whatever copy the browser cached under the bare url.
test('the worker imports its scripts at its page\'s build', () => {
    const urls = [];
    const self = { location: { search: '?hash=abc' } };
    new Function('self', 'importScripts', readFileSync(join(DIR, 'offline-sync.js'), 'utf8'))(self, (...u) => urls.push(...u));
    expect(urls.length).toBe(5);
    for (const url of urls) expect(url.endsWith('.js?hash=abc')).toBe(true);
});

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

// A set the cancelled run left behind has to come back on its own.
test('the sync after a cancelled new-key sync fetches the rest', async () => {
    const w = loadWorker({ aesKey: null, cancelAtFirstPrice: true, extraSets: { MH2: 'v1' } });
    await w.sync(SYNC);
    expect(Object.keys(w.sets)).toEqual(['DMU']);
    w.control.cancelAtFirstPrice = false;
    await w.sync(SYNC);
    expect(Object.keys(w.sets).sort()).toEqual(['DMU', 'MH2', 'NEO']);
    expect(w.meta.missingSets).toBe(0);
});

test('only the selected editions can be missing', async () => {
    const w = loadWorker({ pricesFail: true, extraSets: { MH2: 'v1', ONE: 'v1' } });
    await w.runSync({ ...SYNC, editions: ['NEO', 'MH2'] });
    expect(w.meta.missingSets).toBe(1);
});

// An index stamped by an earlier normName is rebuilt though the catalog is
// the same, so a name in another script becomes findable without a new one.
test('an index from an earlier name fold is rebuilt', async () => {
    const catalog = { version: 'c1', cards: {
        'u-jp': { n: '精霊龍、ウギン', set: 'FRF' },
        'u-ru': { n: 'Шивский дракон', set: 'M10' },
    } };
    const w = loadWorker({ catalogVersion: 'c1', catalog });
    await w.runSync(SYNC);
    expect(w.index).toEqual({ '精霊龍 ウキン': ['u-jp'], 'шивскии дракон': ['u-ru'] });
    expect(w.meta.catalogVersion).toBe('c1:' + NAME_FOLD);
});

test('an index from this name fold is kept', async () => {
    const w = loadWorker();
    await w.runSync(SYNC);
    expect(w.posts.some((m) => m.stage === 'catalog')).toBe(false);
});
