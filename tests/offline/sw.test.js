import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const src = readFileSync(join(import.meta.dir, '..', '..', 'sw.js'), 'utf8');

// Runs sw.js against a stubbed worker scope. serve(url) answers each fetch;
// the cache entries land in `stored`.
function loadWorker(build, dev, serve) {
    const handlers = {};
    const stored = {};
    const self = {
        __BUILD: build,
        __DEV: dev,
        location: { origin: 'https://mtgban.test' },
        addEventListener: (type, fn) => { handlers[type] = fn; },
        skipWaiting: () => Promise.resolve(),
        clients: { claim: () => Promise.resolve() },
    };
    const cache = {
        put: (url, res) => { stored[url] = res; return Promise.resolve(); },
        match: (req) => Promise.resolve(stored[(req.url || req).replace(self.location.origin, '')]),
    };
    const caches = {
        open: () => Promise.resolve(cache),
        match: (req) => cache.match(req),
        keys: () => Promise.resolve([]),
    };
    function Request(url, opts) { this.url = url; Object.assign(this, opts); }
    const fetch = (req) => serve(req.url || req);
    const Response = { error: () => 'error' };
    new Function('self', 'caches', 'fetch', 'Request', 'Response', src)(self, caches, fetch, Request, Response);
    return { handlers, stored };
}

function answer(url) {
    return Promise.resolve(url.startsWith('https://') ? { ok: false } : { ok: true, url });
}

function install(w) {
    let done;
    w.handlers.install({ waitUntil: (p) => { done = p; } });
    return done;
}

// Online, dev serves the file on disk; the cache stands in only offline.
test('dev goes to the network before the cache', async () => {
    for (const [dev, want] of [[true, 'network'], [false, 'cache']]) {
        const w = loadWorker('new', dev, answer);
        await install(w);
        w.stored['/js/utils.js?hash=new'] = 'cache';
        let res;
        w.handlers.fetch({
            request: { method: 'GET', url: 'https://mtgban.test/js/utils.js?hash=new', mode: 'no-cors' },
            respondWith: (p) => { res = p; },
        });
        const got = await res;
        expect(got === 'cache' ? 'cache' : 'network').toBe(want);
    }
});
