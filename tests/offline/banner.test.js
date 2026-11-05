const { test, expect } = require('bun:test');

// Shared modules attach to self; give bun one.
globalThis.self = globalThis.self || globalThis;
require('../../js/offline/offline-age.js');

// Mirrors the back-URL logic in poll().
function buildBackUrl(search) {
    var q = new URLSearchParams(search).get('q');
    return q ? '/search?q=' + encodeURIComponent(q) : '/search';
}

// --- back-URL construction ---

test('no query param produces bare search URL', () => {
    expect(buildBackUrl('')).toBe('/search');
    expect(buildBackUrl('?foo=bar')).toBe('/search');
});

test('q param is carried through and encoded', () => {
    // URLSearchParams decodes + as space; encodeURIComponent re-encodes to %20.
    expect(buildBackUrl('?q=black+lotus')).toBe('/search?q=black%20lotus');
    expect(buildBackUrl('?q=simple')).toBe('/search?q=simple');
});

test('special characters in q are percent-encoded', () => {
    var result = buildBackUrl('?q=a%26b');
    expect(result).toBe('/search?q=a%26b');
});

// --- poll lifecycle against the shipped file ---

import { readFileSync } from 'fs';
import { join } from 'path';

function makeEl() {
    return { textContent: '', href: '', hidden: true, style: {}, addEventListener() {}, classList: { names: new Set(), toggle(name, on) { this.names[on ? 'add' : 'delete'](name); } } };
}

// Loads the real offline-banner.js with fake DOM, timers, fetch, and indexedDB.
function makeHarness(meta = {}) {
    const els = {
        'offline-banner': makeEl(),
        'offline-banner-age': makeEl(),
        'offline-banner-auth': makeEl(),
        'offline-banner-back': makeEl(),
        'offline-settings-link': makeEl(),
    };
    const listeners = {};
    const doc = {
        hidden: false,
        getElementById: (id) => els[id] || null,
        addEventListener: (type, fn) => { listeners[type] = fn; },
    };
    const timers = [];
    const fakeSetInterval = (fn) => { timers.push({ fn, cleared: false }); return timers.length - 1; };
    const fakeClearInterval = (id) => { if (timers[id]) timers[id].cleared = true; };
    let serverUp = true;
    const fakeFetch = () => Promise.resolve({ ok: serverUp });
    const fakeDB = {
        close() {},
        transaction: () => ({ objectStore: () => ({ get(key) {
            const get = {};
            setTimeout(() => { get.result = key in meta ? { v: meta[key] } : undefined; get.onsuccess(); }, 0);
            return get;
        } }) }),
    };
    const opens = { count: 0 };
    const fakeIDB = { open() { opens.count++; const req = { result: fakeDB }; setTimeout(() => req.onsuccess(), 0); return req; } };
    const age = globalThis.OfflineAge;
    const win = { addEventListener() {}, OfflineAge: age };
    const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-banner.js'), 'utf8');
    new Function('window', 'document', 'navigator', 'location', 'indexedDB', 'fetch',
        'setInterval', 'clearInterval', 'OfflineAge', src)(
        win, doc, { onLine: true }, { search: '' }, fakeIDB, fakeFetch,
        fakeSetInterval, fakeClearInterval, age);
    const flush = () => new Promise((r) => setTimeout(r, 5));
    return {
        els,
        meta,
        opens,
        fire(type, detail) { listeners[type]({ detail }); },
        setServer(up) { serverUp = up; },
        flush,
        async tick() { timers.forEach((t) => { if (!t.cleared) t.fn(); }); await flush(); },
    };
}

test('banner hides exit link when the server dies after being seen up', async () => {
    const h = makeHarness();
    await h.flush(); // initial poll resolves: server up
    expect(h.els['offline-banner-back'].hidden).toBe(false);
    h.setServer(false); // backend dies, network stays up
    await h.tick(); // next 30s tick must still fire and hide the link
    expect(h.els['offline-banner-back'].hidden).toBe(true);
    expect(h.els['offline-settings-link'].style.display).toBe('none');
});

test('banner re-shows exit link when the server comes back', async () => {
    const h = makeHarness();
    await h.flush();
    h.setServer(false);
    await h.tick();
    h.setServer(true);
    await h.tick();
    expect(h.els['offline-banner-back'].hidden).toBe(false);
    expect(h.els['offline-banner-back'].textContent).toBe('Exit offline mode');
});

// --- the missing-sets warning ---

const REFRESHED = new Date().toISOString();

test('a sync that left sets out says so and raises the warning colour', async () => {
    const h = makeHarness({ lastSync: REFRESHED, missingSets: 3 });
    await h.flush();
    expect(h.els['offline-banner-age'].textContent).toContain('\nThere are 3 sets that need to resync, a few results will be unavailable.');
    expect(h.els['offline-banner'].classList.names.has('offline-banner-stale')).toBe(true);
});

test('a complete sync shows only the refresh time', async () => {
    const h = makeHarness({ lastSync: REFRESHED, missingSets: 0 });
    await h.flush();
    expect(h.els['offline-banner-age'].textContent).toBe(OfflineAge.refreshText(REFRESHED, Date.now()));
    expect(h.els['offline-banner'].classList.names.has('offline-banner-stale')).toBe(false);
});

test('a first sync counts down, and a finished one redraws from what it recorded', async () => {
    const h = makeHarness();
    await h.flush();
    h.fire('offline:sync-message', { type: 'progress', stage: 'prices', done: 40, total: 869 });
    await h.flush();
    expect(h.els['offline-banner-age'].textContent).toBe('Prices are still downloading (829 sets left). Some cards might be missing.');

    h.fire('offline:sync-message', { type: 'done' });
    h.meta.lastSync = REFRESHED;
    h.meta.missingSets = 0;
    h.fire('offline:synced');
    await h.flush();
    expect(h.els['offline-banner-age'].textContent).toBe(OfflineAge.refreshText(REFRESHED, Date.now()));
});

test('the countdown does not go back to the database for each set', async () => {
    const h = makeHarness();
    await h.flush();
    const opens = h.opens.count;
    for (let done = 0; done < 50; done++) {
        h.fire('offline:sync-message', { type: 'progress', stage: 'prices', done, total: 869 });
    }
    expect(h.els['offline-banner-age'].textContent).toBe('Prices are still downloading (820 sets left). Some cards might be missing.');
    await h.flush();
    expect(h.opens.count).toBe(opens);
});

test('progress before the first read does not claim a first sync', async () => {
    const h = makeHarness({ lastSync: REFRESHED });
    h.fire('offline:sync-message', { type: 'progress', stage: 'prices', done: 1, total: 5 });
    expect(h.els['offline-banner-age'].textContent).toBe('');
    await h.flush();
    expect(h.els['offline-banner-age'].textContent).toBe(OfflineAge.refreshText(REFRESHED, Date.now()));
});

test('a first sync that errors stops counting', async () => {
    const h = makeHarness();
    await h.flush();
    h.fire('offline:sync-message', { type: 'progress', stage: 'prices', done: 1, total: 5 });
    h.fire('offline:sync-message', { type: 'error' });
    await h.flush();
    expect(h.els['offline-banner-age'].textContent).toBe(OfflineAge.refreshText(null, Date.now()));
});

test('a refresh of sets already here does not redraw for each set', async () => {
    const h = makeHarness({ lastSync: REFRESHED });
    await h.flush();
    h.els['offline-banner-age'].textContent = 'untouched';
    h.fire('offline:sync-message', { type: 'progress', stage: 'prices', done: 1, total: 5 });
    await h.flush();
    expect(h.els['offline-banner-age'].textContent).toBe('untouched');
});
