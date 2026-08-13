import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// the module under test is a plain script attaching to self
globalThis.self = globalThis.self || globalThis;

// Bun rejects relative URL strings in Request; remap /path -> http://localhost/path.
const _NativeRequest = globalThis.Request;
globalThis.Request = class Request extends _NativeRequest {
    constructor(input, init) {
        if (typeof input === 'string' && input.startsWith('/')) input = 'http://localhost' + input;
        super(input, init);
    }
};

// The shipped file is a plain script attaching to self; load it into a sandbox.
function loadOfflineImages() {
    const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-images.js'), 'utf8');
    const sandbox = {};
    new Function('self', src)(sandbox);
    return sandbox.OfflineImages;
}

const OfflineImages = loadOfflineImages();

const images = {
    NEO: { h: 'aaaa', n: 302, b: 24800000 },
    MID: { h: 'bbbb', n: 400, b: 30000000 },
    VOW: { h: 'cccc', n: 350, b: 28000000 },
};

test('formatBytes renders human sizes', () => {
    expect(OfflineImages.formatBytes(0)).toBe('0 B');
    expect(OfflineImages.formatBytes(302)).toBe('302 B');
    expect(OfflineImages.formatBytes(1000)).toBe('1 KB');
    expect(OfflineImages.formatBytes(123456)).toBe('123 KB');
    expect(OfflineImages.formatBytes(24800000)).toBe('24.8 MB');
    expect(OfflineImages.formatBytes(1400000000)).toBe('1.4 GB');
    expect(OfflineImages.formatBytes(9500000000)).toBe('9.5 GB');
});

test('fetchImage caches under the per-image url and reports its size', async () => {
    const { cache, caches } = makeFakeCache();
    const mod = loadWithExtras({ caches, fetch: makeImageFetch({ 'key-aaa': [255, 216, 1] }) });
    expect(await mod.fetchImage(cache, 'key-aaa')).toBe(3);
    expect(cache.store[0].req.url).toEndWith('/api/offline/images/key-aaa.webp');
    expect(cache.store[0].resp.headers.get('Content-Type')).toBe('image/jpeg');
});

test('fetchImage treats an unpublished image as a skip, not a failure', async () => {
    const { cache, caches } = makeFakeCache();
    const mod = loadWithExtras({ caches, fetch: makeImageFetch({}) });
    expect(await mod.fetchImage(cache, 'never-published')).toBe(0);
    expect(cache.store).toHaveLength(0);
});

test('fetchImage retries a transient 5xx and succeeds', async () => {
    const { cache, caches } = makeFakeCache();
    let calls = 0;
    const mod = loadWithExtras({
        caches,
        setTimeout: fn => fn(),
        fetch: async () => {
            calls++;
            if (calls < 3) return new Response(null, { status: 504 });
            return new Response(new Uint8Array([1, 2, 3]));
        },
    });
    expect(await mod.fetchImage(cache, 'key-aaa')).toBe(3);
    expect(calls).toBe(3);
});

test('fetchImage retries a network error before giving up', async () => {
    const { cache, caches } = makeFakeCache();
    let calls = 0;
    const mod = loadWithExtras({
        caches,
        setTimeout: fn => fn(),
        fetch: async () => {
            calls++;
            throw new TypeError('Failed to fetch');
        },
    });
    await expect(mod.fetchImage(cache, 'key-aaa')).rejects.toThrow('Failed to fetch');
    expect(calls).toBe(3);
});

test('fetchImage does not retry a 403, which means auth lapsed', async () => {
    const { cache, caches } = makeFakeCache();
    let calls = 0;
    const mod = loadWithExtras({
        caches,
        setTimeout: fn => fn(),
        fetch: async () => { calls++; return new Response(null, { status: 403 }); },
    });
    await expect(mod.fetchImage(cache, 'key-aaa')).rejects.toThrow('forbidden');
    expect(calls).toBe(1);
});

test('computeWorkList selects missing, changed, and unfinished bundles', () => {
    const states = {
        NEO: { code: 'NEO', hash: 'aaaa', done: true },  // up to date: skip
        MID: { code: 'MID', hash: 'old', done: true },   // hash changed: resync
        VOW: { code: 'VOW', hash: 'cccc', done: false }, // interrupted: resume
    };
    const plan = OfflineImages.computeWorkList(images, ['NEO', 'MID', 'VOW'], states);
    expect(plan.work.map(w => w.code)).toEqual(['MID', 'VOW']);
    expect(plan.totalBytes).toBe(58000000);
    expect(plan.totalCount).toBe(750);
});

test('computeWorkList ignores bundle-less codes and handles empty input', () => {
    const plan = OfflineImages.computeWorkList(images, ['NEO', 'NOPE'], {});
    expect(plan.work).toEqual([{ code: 'NEO', hash: 'aaaa', count: 302, bytes: 24800000 }]);
    expect(plan.missing).toEqual(['NOPE']);
    const empty = OfflineImages.computeWorkList(null, null, null);
    expect(empty.work).toEqual([]);
    expect(empty.missing).toEqual([]);
});

test('computeWorkList reports missing codes separately from up-to-date skips', () => {
    const states = { NEO: { code: 'NEO', hash: 'aaaa', done: true } };
    const plan = OfflineImages.computeWorkList(images, ['NEO', 'NOPE'], states);
    expect(plan.work).toEqual([]);
    expect(plan.missing).toEqual(['NOPE']);
});

test('computeWorkList sorts work by set code', () => {
    const plan = OfflineImages.computeWorkList(images, ['VOW', 'MID', 'NEO'], null);
    expect(plan.work.map(w => w.code)).toEqual(['MID', 'NEO', 'VOW']);
});

test('estimateSelection sums manifest counts and bytes', () => {
    const est = OfflineImages.estimateSelection(images, ['NEO', 'MID', 'NOPE']);
    expect(est.bytes).toBe(54800000);
    expect(est.count).toBe(702);
    expect(est.missing).toEqual(['NOPE']);
    expect(OfflineImages.estimateSelection(images, []).bytes).toBe(0);
});

// --- syncImages tests (DI fakes) ---

// Load a fresh module instance with extra sandbox properties injected as globals.
function loadWithExtras(extras) {
    const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-images.js'), 'utf8');
    const sandbox = Object.assign({}, extras);
    new Function('self', src)(sandbox);
    return sandbox.OfflineImages;
}

// Serves one response per image key. An absent key 404s, which is how the
// server reports an image the source never published.
function makeImageFetch(bytesByKey) {
    return async (url) => {
        const key = String(url).replace(/^.*\/images\//, '').replace(/\.(webp|jpg)$/, '');
        if (!(key in bytesByKey)) return new Response(null, { status: 404 });
        return new Response(new Uint8Array(bytesByKey[key]));
    };
}

// deps.getImgKeys backed by a plain map.
function keysFrom(map) {
    return async (code) => map[code] || [];
}

// Minimal fake cache that records put calls; returns caches wrapper.
function makeFakeCache() {
    const store = [];
    const cache = { store, put: async (req, resp) => store.push({ req, resp }) };
    const caches = { open: async () => cache };
    return { cache, caches };
}

test('syncImages returns immediately when no work is needed', async () => {
    const mod = loadWithExtras({});
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: 100 } },
        sel: ['TST'],
        states: { TST: { code: 'TST', hash: 'h1', done: true } },
        post: () => {},
        cancelled: () => false,
        putImgState: async () => {},
    });
    expect(result).toEqual({ done: 0, total: 0, bytes: 0, paused: false, missing: [], failed: 0 });
});

test('syncImages returns missing codes with zero total when selection has no images yet', async () => {
    const mod = loadWithExtras({});
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: 100 } },
        sel: ['NOPE'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async () => {},
    });
    expect(result).toEqual({ done: 0, total: 0, bytes: 0, paused: false, missing: ['NOPE'], failed: 0 });
});

test('syncImages includes missing codes alongside completed work', async () => {
    const { caches } = makeFakeCache();
    const mod = loadWithExtras({ caches, fetch: makeImageFetch({ 'key-aaa': [1, 2, 3] }) });
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: 3 } },
        sel: ['TST', 'NOPE'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async () => {},
        getImgKeys: keysFrom({ TST: ['key-aaa'] }),
    });
    expect(result).toEqual({ done: 1, total: 1, bytes: 3, paused: false, missing: ['NOPE'], failed: 0 });
});

test('syncImages downloads each image and marks done', async () => {
    const { cache, caches } = makeFakeCache();
    const posts = [];
    const states = [];
    const mod = loadWithExtras({
        caches,
        fetch: makeImageFetch({ 'key-aaa': [255, 216], 'key-bbb': [255, 216] }),
    });
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 2, b: 4 } },
        sel: ['TST'],
        states: {},
        post: m => posts.push(m),
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
        getImgKeys: keysFrom({ TST: ['key-aaa', 'key-bbb'] }),
    });
    expect(result).toEqual({ done: 1, total: 1, bytes: 4, paused: false, missing: [], failed: 0 });
    expect(posts).toHaveLength(2);
    expect(cache.store).toHaveLength(2);
    expect(states).toEqual([
        { code: 'TST', hash: 'h1', done: false },
        { code: 'TST', hash: 'h1', done: true, keys: ['key-aaa', 'key-bbb'] },
    ]);
});

test('syncImages survives an image the server keeps failing on', async () => {
    const { caches } = makeFakeCache();
    const states = [];
    const mod = loadWithExtras({
        caches,
        setTimeout: fn => fn(),
        fetch: async url => String(url).includes('key-bad')
            ? new Response(null, { status: 504 })
            : new Response(new Uint8Array([1, 2])),
    });
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 2, b: 4 } },
        sel: ['TST'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
        getImgKeys: keysFrom({ TST: ['key-good', 'key-bad'] }),
    });
    expect(result).toEqual({ done: 1, total: 1, bytes: 2, paused: false, missing: [], failed: 1 });
    // Left not-done on purpose: the next sync retries the image that failed.
    expect(states[states.length - 1]).toEqual({
        code: 'TST', hash: 'h1', done: false, keys: ['key-good'],
    });
});

test('syncImages moves on to the next set after one set fails', async () => {
    const { caches } = makeFakeCache();
    const mod = loadWithExtras({
        caches,
        setTimeout: fn => fn(),
        fetch: async url => String(url).includes('key-bad')
            ? new Response(null, { status: 504 })
            : new Response(new Uint8Array([1, 2])),
    });
    const result = await mod.syncImages({
        images: { AAA: { h: 'h1', n: 1, b: 2 }, BBB: { h: 'h2', n: 1, b: 2 } },
        sel: ['AAA', 'BBB'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async () => {},
        getImgKeys: keysFrom({ AAA: ['key-bad'], BBB: ['key-good'] }),
    });
    expect(result).toEqual({ done: 2, total: 2, bytes: 2, paused: false, missing: [], failed: 1 });
});

test('syncImages records only the images the server actually had', async () => {
    const { cache, caches } = makeFakeCache();
    const states = [];
    const mod = loadWithExtras({ caches, fetch: makeImageFetch({ 'key-aaa': [1, 2] }) });
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 2, b: 4 } },
        sel: ['TST'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
        getImgKeys: keysFrom({ TST: ['key-aaa', 'key-gone'] }),
    });
    // the 404 is expected and must not fail the set or be recorded as cached
    expect(result.done).toBe(1);
    expect(result.bytes).toBe(2);
    expect(cache.store).toHaveLength(1);
    expect(states[1].keys).toEqual(['key-aaa']);
});

test('syncImages resumes a set left done:false by a previous interrupted run', async () => {
    const { caches } = makeFakeCache();
    const states = [];
    const mod = loadWithExtras({ caches, fetch: makeImageFetch({ 'key-aaa': [1, 2, 3] }) });
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: 3 } },
        sel: ['TST'],
        states: { TST: { code: 'TST', hash: 'h1', done: false } },
        post: () => {},
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
        getImgKeys: keysFrom({ TST: ['key-aaa'] }),
    });
    expect(result.done).toBe(1);
    expect(states[states.length - 1]).toMatchObject({ code: 'TST', done: true });
});

test('syncImages refuses when projected bytes exceed 90pct of free storage', async () => {
    const fakeNavigator = { storage: { estimate: async () => ({ quota: 1000, usage: 500 }) } };
    // totalBytes = 600 > (1000 - 500) * 0.9 = 450 -> should throw
    const { caches } = makeFakeCache();
    let fetched = false;
    const mod = loadWithExtras({ navigator: fakeNavigator, caches, fetch: async () => { fetched = true; return new Response(new Uint8Array(0)); } });
    await expect(mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: 600 } },
        sel: ['TST'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async () => {},
    })).rejects.toThrow('not enough storage');
    expect(fetched).toBe(false);
});

test('syncImages stops cleanly on QuotaExceededError; imgstate stays done:false', async () => {
    const store = [];
    const cache = {
        store,
        put: async () => {
            const err = new Error('quota');
            err.name = 'QuotaExceededError';
            throw err;
        },
    };
    const caches = { open: async () => cache };
    const states = [];
    const mod = loadWithExtras({ caches, fetch: makeImageFetch({ 'key-aaa': [1, 2, 3] }) });
    await expect(mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: 3 } },
        sel: ['TST'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
        getImgKeys: keysFrom({ TST: ['key-aaa'] }),
    })).rejects.toThrow('storage quota exceeded');
    // never marked done, so the next sync retries the set
    expect(states).toEqual([{ code: 'TST', hash: 'h1', done: false }]);
});

test('syncImages throws forbidden on 403', async () => {
    const { caches } = makeFakeCache();
    const states = [];
    const mod = loadWithExtras({ caches, fetch: async () => new Response(null, { status: 403 }) });
    await expect(mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: 100 } },
        sel: ['TST'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
        getImgKeys: keysFrom({ TST: ['key-aaa'] }),
    })).rejects.toThrow('forbidden');
    // a lapsed subscription must not leave the set marked complete
    expect(states.some(r => r.done)).toBe(false);
});

// --- imgCount math (mirrors runImagesStage in offline-sync.js) ---
// done rows sum manifest[r.code].n; fall back to +1 when code is absent.
function computeImgCount(doneRows, imgMap) {
    return doneRows.filter(function (r) { return r.done; }).reduce(function (sum, r) {
        return sum + (imgMap[r.code] ? imgMap[r.code].n : 1);
    }, 0);
}

test('imgCount sums per-image counts from manifest for done rows', () => {
    const imgMap = { NEO: { n: 302 }, MID: { n: 400 } };
    const rows = [
        { code: 'NEO', done: true },
        { code: 'MID', done: true },
        { code: 'VOW', done: false }, // not done: excluded
    ];
    expect(computeImgCount(rows, imgMap)).toBe(702);
});

test('imgCount falls back to 1 per row when code is absent from manifest', () => {
    const imgMap = { NEO: { n: 302 } };
    const rows = [
        { code: 'NEO', done: true },
        { code: 'UNKNOWN', done: true }, // absent: counts as 1
    ];
    expect(computeImgCount(rows, imgMap)).toBe(303);
});

test('imgCount returns 0 when no done rows', () => {
    expect(computeImgCount([], {})).toBe(0);
    expect(computeImgCount([{ code: 'NEO', done: false }], { NEO: { n: 302 } })).toBe(0);
});

test('syncImages pauses between sets when cancelled', async () => {
    const { caches } = makeFakeCache();
    let calls = 0;
    const mod = loadWithExtras({ caches, fetch: makeImageFetch({ 'a': [1], 'b': [2] }) });
    const result = await mod.syncImages({
        images: { AAA: { h: 'h1', n: 1, b: 1 }, BBB: { h: 'h2', n: 1, b: 1 } },
        sel: ['AAA', 'BBB'],
        states: {},
        post: () => {},
        cancelled: () => calls++ > 1,
        putImgState: async () => {},
        getImgKeys: keysFrom({ AAA: ['a'], BBB: ['b'] }),
    });
    expect(result.paused).toBe(true);
    expect(result.done).toBeLessThan(2);
});

// --- eviction ---

// Fake cache keyed by pathname, with delete/keys support.
function makeFakeCacheMap(initial) {
    const entries = new Map(Object.entries(initial || {}));
    const cache = {
        entries,
        put: async (req, resp) => entries.set(typeof req === 'string' ? req : new URL(req.url).pathname, resp),
        delete: async (url) => entries.delete(typeof url === 'string' ? url : new URL(url.url).pathname),
        keys: async () => Array.from(entries.keys()).map((u) => ({ url: 'http://localhost' + u })),
    };
    return { cache, caches: { open: async () => cache } };
}

test('evictImages removes deselected editions by recorded keys', async () => {
    const fake = makeFakeCacheMap({
        '/api/offline/images/key-neo.webp': 'x',
        '/api/offline/images/key-mid.webp': 'x',
    });
    const mod = loadWithExtras({ caches: fake.caches });
    const deleted = [];
    const removed = await mod.evictImages({
        sel: ['NEO'],
        getImgStates: async () => [
            { code: 'NEO', hash: 'a', done: true, keys: ['key-neo'] },
            { code: 'MID', hash: 'b', done: true, keys: ['key-mid'] },
        ],
        deleteImgState: async (code) => deleted.push(code),
    });
    expect(removed).toBe(1);
    expect(deleted).toEqual(['MID']);
    expect(fake.cache.entries.has('/api/offline/images/key-neo.webp')).toBe(true);
    expect(fake.cache.entries.has('/api/offline/images/key-mid.webp')).toBe(false);
});

test('evictImages drops legacy uuids rows without touching the cache', async () => {
    const fake = makeFakeCacheMap({
        '/api/offline/images/key-neo.webp': 'x',
    });
    const mod = loadWithExtras({ caches: fake.caches });
    const deleted = [];
    const removed = await mod.evictImages({
        sel: ['NEO'],
        getImgStates: async () => [{ code: 'MID', hash: 'b', done: true, uuids: ['uuid-mid'] }],
        deleteImgState: async (code) => deleted.push(code),
    });
    expect(removed).toBe(0);
    expect(deleted).toEqual(['MID']);
    expect(fake.cache.entries.has('/api/offline/images/key-neo.webp')).toBe(true);
});

test('syncImages records cached keys on the imgstate row for eviction', async () => {
    const { caches } = makeFakeCache();
    const states = [];
    const mod = loadWithExtras({ caches, fetch: makeImageFetch({ 'k1': [1], 'k2': [2] }) });
    await mod.syncImages({
        images: { TST: { h: 'h1', n: 2, b: 2 } },
        sel: ['TST'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
        getImgKeys: keysFrom({ TST: ['k1', 'k2'] }),
    });
    // evictImages deletes by these keys, so they must be the cached set
    expect(states[states.length - 1].keys).toEqual(['k1', 'k2']);
});
