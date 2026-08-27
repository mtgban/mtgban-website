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

const SRC = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-images.js'), 'utf8');

// The shipped file is a plain script attaching to self; load it into a sandbox.
function loadWithExtras(extras) {
    const sandbox = Object.assign({ fflate }, extras);
    new Function('self', SRC)(sandbox);
    return sandbox.OfflineImages;
}

const OfflineImages = loadWithExtras({});

const BASE = 'https://bucket.example.invalid/file/mtgban-images/magic';
const AUTH = { base: BASE, token: 'tok-abc', expires: '2026-08-12T09:00:00Z' };

const images = {
    NEO: { h: 'aaaa', n: 302, b: 24800000 },
    MID: { h: 'bbbb', n: 400, b: 30000000 },
    VOW: { h: 'cccc', n: 350, b: 28000000 },
};

// Build a zip from a name -> bytes map using the vendored fflate.
function zip(entries) {
    const out = {};
    Object.keys(entries).forEach((n) => { out[n] = new Uint8Array(entries[n]); });
    return fflate.zipSync(out);
}

// Minimal fake cache that records put calls; returns caches wrapper.
function makeFakeCache() {
    const store = [];
    const cache = {
        store,
        put: async (req, resp) => store.push({ req, resp }),
        match: async () => undefined,
        delete: async () => true,
    };
    return { cache, caches: { open: async () => cache } };
}

// A fetch that serves zips by bundle path and records every url it was asked for.
function makeBundleFetch(bundles, opts) {
    const calls = [];
    const o = opts || {};
    return {
        calls,
        fetch: async (url) => {
            calls.push(String(url));
            const name = String(url).split('?')[0].split('/bundles/')[1];
            if (o.status) return new Response(null, { status: o.status });
            if (!(name in bundles)) return new Response(null, { status: 404 });
            return new Response(bundles[name]);
        },
    };
}

function syncDeps(over) {
    return Object.assign({
        images: images,
        sel: ['NEO'],
        states: {},
        post: () => {},
        cancelled: () => false,
        putImgState: async () => {},
        getBucketAuth: async () => AUTH,
    }, over);
}

test('formatBytes renders human sizes', () => {
    expect(OfflineImages.formatBytes(0)).toBe('0 B');
    expect(OfflineImages.formatBytes(302)).toBe('302 B');
    expect(OfflineImages.formatBytes(24800000)).toBe('24.8 MB');
    expect(OfflineImages.formatBytes(9500000000)).toBe('9.5 GB');
});

// The cache key is this site's own url, not the bucket url the bytes came
// from, so a rotating token never strands an already-cached image.
test('entryMeta maps bundle entries to stable local cache keys', () => {
    expect(OfflineImages.entryMeta('ab154b52-1234-5678-9abc-def012345678.webp')).toEqual({
        key: 'ab154b52-1234-5678-9abc-def012345678',
        url: '/api/offline/images/ab154b52-1234-5678-9abc-def012345678.webp',
        type: 'image/webp',
    });
    // Sealed is webp too: the mirror converts everything on the way in, so
    // there is no longer a format to work out from the key.
    expect(OfflineImages.entryMeta('p-MH3-541185.webp')).toEqual({
        key: 'p-MH3-541185',
        url: '/api/offline/images/p-MH3-541185.webp',
        type: 'image/webp',
    });
    expect(OfflineImages.entryMeta('p-MH3-541185.jpg')).toBeNull();
    expect(OfflineImages.entryMeta('nested/abc.webp')).toBeNull();
    expect(OfflineImages.entryMeta('README.txt')).toBeNull();
    expect(OfflineImages.entryMeta('../escape.webp')).toBeNull();
});

test('bundleURL addresses the bucket and carries the token', () => {
    const u = OfflineImages.bundleURL(AUTH, 'NEO', 'aaaa');
    expect(u).toBe(BASE + '/bundles/NEO-aaaa.zip?Authorization=tok-abc');
});

test('computeWorkList selects missing, changed, and unfinished bundles', () => {
    const states = {
        NEO: { code: 'NEO', hash: 'aaaa', done: true },
        MID: { code: 'MID', hash: 'old', done: true },
        VOW: { code: 'VOW', hash: 'cccc', done: false },
    };
    const plan = OfflineImages.computeWorkList(images, ['NEO', 'MID', 'VOW'], states);
    expect(plan.work.map(w => w.code)).toEqual(['MID', 'VOW']);
    expect(plan.totalBytes).toBe(58000000);
});

test('computeWorkList reports missing codes separately from up-to-date skips', () => {
    const plan = OfflineImages.computeWorkList(images, ['NEO', 'NOPE'], { NEO: { code: 'NEO', hash: 'aaaa', done: true } });
    expect(plan.work).toEqual([]);
    expect(plan.missing).toEqual(['NOPE']);
});

test('estimateSelection sums manifest counts and bytes', () => {
    const est = OfflineImages.estimateSelection(images, ['NEO', 'MID', 'NOPE']);
    expect(est.bytes).toBe(54800000);
    expect(est.count).toBe(702);
    expect(est.missing).toEqual(['NOPE']);
});

test('syncImages returns immediately when no work is needed', async () => {
    const mod = loadWithExtras({});
    const res = await mod.syncImages(syncDeps({ states: { NEO: { code: 'NEO', hash: 'aaaa', done: true } } }));
    expect(res).toEqual({ done: 0, total: 0, bytes: 0, paused: false, missing: [], failed: 0 });
});

test('syncImages unpacks a bundle into the cache under local urls', async () => {
    const { cache, caches } = makeFakeCache();
    const bundles = { 'NEO-aaaa.zip': zip({ 'key-a.webp': [1, 2], 'p-NEO-9.webp': [3] }) };
    const f = makeBundleFetch(bundles);
    const states = [];
    const mod = loadWithExtras({ caches, fetch: f.fetch });

    const res = await mod.syncImages(syncDeps({ putImgState: async r => states.push({ ...r }) }));

    expect(res.done).toBe(1);
    expect(res.failed).toBe(0);
    const urls = cache.store.map(e => e.req.url).sort();
    expect(urls).toEqual([
        'http://localhost/api/offline/images/key-a.webp',
        'http://localhost/api/offline/images/p-NEO-9.webp',
    ]);
    expect(cache.store.find(e => e.req.url.endsWith('.webp')).resp.headers.get('Content-Type')).toBe('image/webp');
    expect(states[0]).toEqual({ code: 'NEO', hash: 'aaaa', done: false });
    expect(states[1].done).toBe(true);
    expect(states[1].keys.sort()).toEqual(['key-a', 'p-NEO-9']);
});

// The whole point of the rework: image bytes come from the bucket, and the
// site is asked only for permission. A request for image bytes to our own
// origin would put the server back in the path for every card.
test('syncImages fetches image bytes only from the bucket', async () => {
    const { caches } = makeFakeCache();
    const f = makeBundleFetch({ 'NEO-aaaa.zip': zip({ 'key-a.webp': [1] }) });
    const mod = loadWithExtras({ caches, fetch: f.fetch });
    await mod.syncImages(syncDeps({}));
    expect(f.calls.length).toBe(1);
    f.calls.forEach((u) => expect(u.startsWith(BASE + '/')).toBe(true));
});

test('syncImages authorizes once for the whole run, not once per set', async () => {
    const { caches } = makeFakeCache();
    const f = makeBundleFetch({
        'NEO-aaaa.zip': zip({ 'a.webp': [1] }),
        'MID-bbbb.zip': zip({ 'b.webp': [1] }),
        'VOW-cccc.zip': zip({ 'c.webp': [1] }),
    });
    let authCalls = 0;
    const mod = loadWithExtras({ caches, fetch: f.fetch });
    const res = await mod.syncImages(syncDeps({
        sel: ['NEO', 'MID', 'VOW'],
        getBucketAuth: async () => { authCalls++; return AUTH; },
    }));
    expect(res.done).toBe(3);
    expect(authCalls).toBe(1);
});

test('syncImages treats a bundle the mirror has not published as a skip', async () => {
    const { caches } = makeFakeCache();
    const f = makeBundleFetch({});
    const states = [];
    const mod = loadWithExtras({ caches, fetch: f.fetch });
    const res = await mod.syncImages(syncDeps({ putImgState: async r => states.push({ ...r }) }));
    expect(res.failed).toBe(0);
    // left not-done, so a later sync picks it up once the mirror publishes it
    expect(states.every(r => r.done === false)).toBe(true);
});

test('syncImages keeps going when one set fails and leaves it not-done', async () => {
    const { caches } = makeFakeCache();
    const good = zip({ 'a.webp': [1] });
    const fetchFn = async (url) => {
        const name = String(url).split('?')[0].split('/bundles/')[1];
        if (name.startsWith('MID')) return new Response(null, { status: 500 });
        return new Response(good);
    };
    const states = [];
    const mod = loadWithExtras({ caches, fetch: fetchFn, setTimeout: fn => fn() });
    const res = await mod.syncImages(syncDeps({
        sel: ['NEO', 'MID', 'VOW'],
        putImgState: async r => states.push({ ...r }),
    }));
    expect(res.failed).toBe(1);
    expect(res.done).toBe(3);
    const mid = states.filter(r => r.code === 'MID');
    expect(mid.every(r => r.done === false)).toBe(true);
    expect(states.filter(r => r.code === 'VOW' && r.done === true)).toHaveLength(1);
});

// A rejected token fails every remaining set the same way, so grinding through
// the rest of the selection just wastes the user's time and bandwidth.
test('syncImages stops the run when the bucket rejects the token', async () => {
    const { caches } = makeFakeCache();
    const f = makeBundleFetch({}, { status: 403 });
    const mod = loadWithExtras({ caches, fetch: f.fetch });
    await expect(mod.syncImages(syncDeps({ sel: ['NEO', 'MID', 'VOW'] })))
        .rejects.toThrow('bucket authorization rejected');
    expect(f.calls.length).toBe(1);
});

test('syncImages refuses when projected bytes exceed 90pct of free storage', async () => {
    const { caches } = makeFakeCache();
    const mod = loadWithExtras({
        caches,
        navigator: { storage: { estimate: async () => ({ quota: 1000, usage: 0 }) } },
    });
    await expect(mod.syncImages(syncDeps({}))).rejects.toThrow('not enough storage');
});

test('syncImages pauses between sets when cancelled', async () => {
    const { caches } = makeFakeCache();
    const f = makeBundleFetch({ 'NEO-aaaa.zip': zip({ 'a.webp': [1] }) });
    let calls = 0;
    const mod = loadWithExtras({ caches, fetch: f.fetch });
    const res = await mod.syncImages(syncDeps({
        sel: ['NEO', 'MID'],
        cancelled: () => { calls++; return calls > 2; },
    }));
    expect(res.paused).toBe(true);
});
