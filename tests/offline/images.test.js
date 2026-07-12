import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// fflate.min.js needs self in scope before import
globalThis.self = globalThis.self || globalThis;
const fflate = await import('../../js/vendor/fflate.min.js');

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

test('entryMeta maps bundle entries to cache keys', () => {
    expect(OfflineImages.entryMeta('abc-123.webp')).toEqual({
        uuid: 'abc-123',
        url: '/api/offline/images/abc-123.webp',
        contentType: 'image/webp',
    });
    // cwebp-missing fallback entries: jpg bytes behind the canonical .webp key
    expect(OfflineImages.entryMeta('abc-123.jpg').contentType).toBe('image/jpeg');
    expect(OfflineImages.entryMeta('abc-123.jpg').url).toBe('/api/offline/images/abc-123.webp');
    expect(OfflineImages.entryMeta('nested/abc.webp')).toBeNull();
    expect(OfflineImages.entryMeta('README.txt')).toBeNull();
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
    expect(OfflineImages.computeWorkList(null, null, null).work).toEqual([]);
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

// Build a zip from a name -> bytes map using the vendored fflate.
function makeZip(files) {
    const entries = {};
    for (const [name, data] of Object.entries(files)) {
        entries[name] = data instanceof Uint8Array ? data : new Uint8Array(data);
    }
    return fflate.zipSync(entries);
}

// Minimal fake cache that records put calls; returns caches wrapper.
function makeFakeCache() {
    const store = [];
    const cache = { store, put: async (req, resp) => store.push({ req, resp }) };
    const caches = { open: async () => cache };
    return { cache, caches };
}

test('syncImages returns immediately when no work is needed', async () => {
    const mod = loadWithExtras({ fflate });
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: 100 } },
        sel: ['TST'],
        states: { TST: { code: 'TST', hash: 'h1', done: true } },
        post: () => {},
        cancelled: () => false,
        putImgState: async () => {},
    });
    expect(result).toEqual({ done: 0, total: 0, bytes: 0, paused: false });
});

test('syncImages downloads, unpacks, and marks done', async () => {
    const zip = makeZip({ 'uuid-aaa.webp': [82, 73, 70, 70], 'uuid-bbb.jpg': [255, 216], 'notes.txt': [104, 105] });
    const { cache, caches } = makeFakeCache();
    const posts = [];
    const states = [];
    const mod = loadWithExtras({ fflate, caches, fetch: async () => new Response(zip) });
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 2, b: zip.byteLength } },
        sel: ['TST'],
        states: {},
        post: m => posts.push(m),
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
    });
    expect(result).toEqual({ done: 1, total: 1, bytes: zip.byteLength, paused: false });
    expect(posts).toHaveLength(2);
    expect(posts[0]).toMatchObject({ type: 'progress', stage: 'images', done: 0, total: 1, code: 'TST', bytes: 0 });
    expect(posts[1]).toMatchObject({ type: 'progress', stage: 'images', done: 1, total: 1, bytes: zip.byteLength });
    // webp and jpg entries stored (.txt skipped); jpg keyed as .webp URL
    expect(cache.store).toHaveLength(2);
    const webpEntry = cache.store.find(e => e.req.url.endsWith('uuid-aaa.webp'));
    const jpgEntry = cache.store.find(e => e.req.url.endsWith('uuid-bbb.webp'));
    expect(webpEntry.resp.headers.get('Content-Type')).toBe('image/webp');
    expect(jpgEntry.resp.headers.get('Content-Type')).toBe('image/jpeg');
    expect(states).toEqual([
        { code: 'TST', hash: 'h1', done: false },
        { code: 'TST', hash: 'h1', done: true },
    ]);
});

test('syncImages resumes a bundle left done:false by a previous interrupted run', async () => {
    const zip = makeZip({ 'uuid-aaa.webp': [1, 2, 3] });
    const { cache, caches } = makeFakeCache();
    const states = [];
    const mod = loadWithExtras({ fflate, caches, fetch: async () => new Response(zip) });
    const result = await mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: zip.byteLength } },
        sel: ['TST'],
        states: { TST: { code: 'TST', hash: 'h1', done: false } },
        post: () => {},
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
    });
    expect(result.done).toBe(1);
    expect(result.paused).toBe(false);
    expect(cache.store).toHaveLength(1);
    expect(states).toEqual([
        { code: 'TST', hash: 'h1', done: false },
        { code: 'TST', hash: 'h1', done: true },
    ]);
});

test('syncImages refuses when projected bytes exceed 90pct of free storage', async () => {
    const fakeNavigator = { storage: { estimate: async () => ({ quota: 1000, usage: 500 }) } };
    // totalBytes = 600 > (1000 - 500) * 0.9 = 450 -> should throw
    const { caches } = makeFakeCache();
    let fetched = false;
    const mod = loadWithExtras({ fflate, navigator: fakeNavigator, caches, fetch: async () => { fetched = true; return new Response(new Uint8Array(0)); } });
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
    const zip = makeZip({ 'uuid-aaa.webp': [1, 2, 3] });
    const quotaErr = Object.assign(new Error('quota'), { name: 'QuotaExceededError' });
    const fakeCache = { put: async () => { throw quotaErr; } };
    const fakeCaches = { open: async () => fakeCache };
    const states = [];
    const posts = [];
    const mod = loadWithExtras({ fflate, caches: fakeCaches, fetch: async () => new Response(zip) });
    await expect(mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: zip.byteLength } },
        sel: ['TST'],
        states: {},
        post: m => posts.push(m),
        cancelled: () => false,
        putImgState: async r => states.push({ ...r }),
    })).rejects.toThrow('storage quota exceeded');
    // imgstate written done:false before unpack; never updated to done:true
    expect(states).toEqual([{ code: 'TST', hash: 'h1', done: false }]);
    // only one progress post (pre-bundle); nothing posted after error
    expect(posts).toHaveLength(1);
});

test('syncImages throws forbidden on 403 and writes no imgstate', async () => {
    const { caches } = makeFakeCache();
    const states = [];
    const posts = [];
    const mod = loadWithExtras({ fflate, caches, fetch: async () => new Response(null, { status: 403 }) });
    await expect(mod.syncImages({
        images: { TST: { h: 'h1', n: 1, b: 100 } },
        sel: ['TST'],
        states: {},
        post: m => posts.push(m),
        cancelled: () => false,
        putImgState: async r => states.push(r),
    })).rejects.toThrow('forbidden');
    // fetch failed before putImgState; no imgstate written
    expect(states).toHaveLength(0);
    // only pre-bundle progress post; nothing after 403
    expect(posts).toHaveLength(1);
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

test('syncImages pauses between bundles when cancelled', async () => {
    const zip = makeZip({ 'uuid-aaa.webp': [1, 2, 3] });
    const { cache, caches } = makeFakeCache();
    const posts = [];
    let callCount = 0;
    // false on first two cancelled() checks (pre-loop + AAA iteration), true on third (skips BBB)
    const cancelled = () => callCount++ > 1;
    const mod = loadWithExtras({ fflate, caches, fetch: async () => new Response(zip) });
    const result = await mod.syncImages({
        images: {
            AAA: { h: 'h1', n: 1, b: zip.byteLength },
            BBB: { h: 'h2', n: 1, b: zip.byteLength },
        },
        sel: ['AAA', 'BBB'],
        states: {},
        post: m => posts.push(m),
        cancelled,
        putImgState: async () => {},
    });
    expect(result).toEqual({ done: 1, total: 2, bytes: zip.byteLength, paused: true });
    // AAA processed (1 cache entry); BBB skipped
    expect(cache.store).toHaveLength(1);
    // AAA's two posts; BBB cancel before any post for BBB
    expect(posts).toHaveLength(2);
    expect(posts[0]).toMatchObject({ code: 'AAA', done: 0 });
    expect(posts[1]).toMatchObject({ code: 'AAA', done: 1 });
});
