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

// The base with the default body of each block the page defines taken out,
// as the page renders it: a {{block}} default the page overrides never loads.
function renderedBase(base, page) {
    const defined = new Set([...page.matchAll(/{{define "([^"]+)"}}/g)].map((m) => m[1]));
    const tags = /{{-?\s*(block|if|range|with|define|end)\b[^}]*}}/g;
    let out = '';
    let at = 0;
    let skip = 0;
    let depth = 0;
    for (const m of base.matchAll(tags)) {
        if (!skip) out += base.slice(at, m.index);
        at = m.index + m[0].length;
        if (m[1] !== 'end') {
            depth++;
            const name = /"([^"]+)"/.exec(m[0]);
            if (!skip && m[1] === 'block' && name && defined.has(name[1])) skip = depth;
            // OfflinePage sets NoBackpack, so these tags never reach the shell.
            if (!skip && m[0].includes('not .NoBackpack')) skip = depth;
        } else {
            if (skip === depth) skip = 0;
            depth--;
        }
    }
    return out + base.slice(at);
}

// A script or sheet the shell loads but the worker never cached fails only
// offline, which is when nobody is looking. The page's own and its base's
// count alike.
test('the worker caches every script and sheet the offline pages load', async () => {
    const w = loadWorker('b1', false, answer);
    await install(w);
    const cached = new Set(Object.keys(w.stored).map((url) => url.split('?')[0]));
    const root = join(import.meta.dir, '..', '..', 'templates');
    const read = (file) => readFileSync(join(root, file), 'utf8');
    for (const [file, base] of [['offline.html', 'base.html'], ['mobile/offline.html', 'mobile/base-mobile.html']]) {
        const page = read(file);
        const html = page + renderedBase(read(base), page);
        const assets = [...html.matchAll(/(?:src|href)="(\/(?:js|css)\/[^"?]+)/g)].map((m) => m[1]);
        expect(assets.length).toBeGreaterThan(5);
        expect(assets.filter((path) => !cached.has(path))).toEqual([]);
    }
});

test('a block the page defines drops the base default', () => {
    const base = '<a src="/js/a.js">{{block "icons" .}}<b src="/js/b.js">{{if .X}}x{{end}}{{end}}<c src="/js/c.js">';
    expect(renderedBase(base, '{{define "icons"}}none{{end}}')).toBe('<a src="/js/a.js"><c src="/js/c.js">');
    expect(renderedBase(base, '')).toBe('<a src="/js/a.js"><b src="/js/b.js">x<c src="/js/c.js">');
});
