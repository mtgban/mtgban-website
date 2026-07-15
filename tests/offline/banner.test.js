const { test, expect } = require('bun:test');

// OfflineAge is a dependency; load it as the banner would.
globalThis.self = globalThis.self || globalThis;
require('../../js/offline/offline-age.js');
const OfflineAge = globalThis.OfflineAge;

const NOW = Date.parse('2026-07-11T12:00:00Z');
const DAY = 24 * 60 * 60 * 1000;

function ago(ms) { return new Date(NOW - ms).toISOString(); }

// Mirrors the text assembly in renderAge().
function bannerAgeText(lastSync, nowMs) {
    var stale = OfflineAge.isStale(lastSync, nowMs);
    return 'Offline data: ' + OfflineAge.formatAge(lastSync, nowMs) + (stale ? ' (stale)' : '');
}

// Mirrors the back-URL logic in poll().
function buildBackUrl(search) {
    var q = new URLSearchParams(search).get('q');
    return q ? '/search?q=' + encodeURIComponent(q) : '/search';
}

// --- banner age text ---

test('fresh data shows age without stale suffix', () => {
    expect(bannerAgeText(ago(0), NOW)).toBe('Offline data: just now');
    expect(bannerAgeText(ago(30 * 60 * 1000), NOW)).toBe('Offline data: 30 minutes ago');
});

test('data older than three days shows stale suffix', () => {
    expect(bannerAgeText(ago(3 * DAY + 1), NOW)).toBe('Offline data: 3 days ago (stale)');
    expect(bannerAgeText(ago(7 * DAY), NOW)).toBe('Offline data: 7 days ago (stale)');
});

test('null lastSync shows never-synced with stale suffix', () => {
    expect(bannerAgeText(null, NOW)).toBe('Offline data: never synced (stale)');
});

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
    return { textContent: '', href: '', hidden: true, style: {}, addEventListener() {}, classList: { toggle() {} } };
}

// Loads the real offline-banner.js with fake DOM, timers, fetch, and indexedDB.
function makeHarness() {
    const els = {
        'offline-banner': makeEl(),
        'offline-banner-age': makeEl(),
        'offline-banner-auth': makeEl(),
        'offline-banner-back': makeEl(),
        'offline-settings-link': makeEl(),
    };
    const doc = { hidden: false, getElementById: (id) => els[id] || null };
    const timers = [];
    const fakeSetInterval = (fn) => { timers.push({ fn, cleared: false }); return timers.length - 1; };
    const fakeClearInterval = (id) => { if (timers[id]) timers[id].cleared = true; };
    let serverUp = true;
    const fakeFetch = () => Promise.resolve({ ok: serverUp });
    const fakeIDB = { open() { const req = {}; setTimeout(() => { if (req.onerror) req.onerror(); }, 0); return req; } };
    const age = { isStale: () => false, formatAge: () => 'just now' };
    const win = { addEventListener() {}, OfflineAge: age };
    const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-banner.js'), 'utf8');
    new Function('window', 'document', 'navigator', 'location', 'indexedDB', 'fetch',
        'setInterval', 'clearInterval', 'OfflineAge', src)(
        win, doc, { onLine: true }, { search: '' }, fakeIDB, fakeFetch,
        fakeSetInterval, fakeClearInterval, age);
    const flush = () => new Promise((r) => setTimeout(r, 5));
    return {
        els,
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
