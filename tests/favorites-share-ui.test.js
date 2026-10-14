import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/favorites.js', import.meta.url), 'utf8');

// The share button is drawn only for a signed-in reader, on both layouts.
test('the share button is gated on the session cookie', () => {
    const start = source.indexOf('function shareButtonHtml');
    expect(start).toBeGreaterThan(-1);
    const fn = source.slice(start, source.indexOf('\n    }\n', start));
    expect(fn).toContain("if (!isSignedIn()) return '';");
    expect(fn).toContain('openFavoritesShare');
    // Both render paths call it.
    expect(source).toContain("shareButtonHtml('mobile')");
    expect(source).toContain("shareButtonHtml('desktop')");
});

// Opening the panel reuses an existing link and only makes one when none
// exists; stopping sends the DELETE.
test('open reuses an existing link, creates one otherwise, stop revokes', async () => {
    const calls = [];
    const headers = [];
    let existing = { id: 'LINKLINKLINKLINKLINKLI' };
    const fetch = (url, opts) => {
        calls.push((opts && opts.method) + ' ' + url);
        headers.push(opts && opts.headers);
        const method = opts && opts.method;
        if (method === 'GET') return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(existing) });
        if (method === 'POST') { existing = { id: 'NEWNEWNEWNEWNEWNEWNEWN' }; return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(existing) }); }
        if (method === 'DELETE') { existing = {}; return Promise.resolve({ ok: true, status: 204 }); }
        return Promise.reject(new Error('unexpected ' + method));
    };
    const inserted = [];
    const header = { insertAdjacentHTML: (where, html) => inserted.push(html) };
    const pane = { querySelector: sel => (sel.indexOf('header') >= 0 ? header : null) };
    const btn = { closest: () => pane };
    const byId = {};
    const document = {
        readyState: 'complete', cookie: 'MTGBAN=abc',
        addEventListener: () => {},
        getElementById: id => byId[id] || null,
        querySelector: () => null,
        querySelectorAll: () => [],
        createElement: () => ({ style: {}, classList: { add: () => {}, remove: () => {} } }),
    };
    const localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
    const window = { location: { origin: 'https://ban.test' }, addEventListener: () => {} };
    new Function('window', 'document', 'localStorage', 'fetch', 'navigator', 'location', 'ListStorage', 'escapeAttr', 'escapeHtml',
        source)(window, document, localStorage, fetch, {}, window.location, { read: () => [], save: () => {}, isLive: () => true, pinnedFirst: l => l, tombstones: () => [] }, s => String(s), s => String(s));

    await window.openFavoritesShare(btn);
    expect(calls).toEqual(['GET /api/userstate/share']);
    expect(inserted.length).toBe(1);
    expect(inserted[0]).toContain('https://ban.test/search/shared?id=LINKLINKLINKLINKLINKLI');
    expect(inserted[0]).toContain('id="fav-share-panel"');

    existing = {};
    await window.openFavoritesShare(btn);
    expect(calls.slice(1)).toEqual(['GET /api/userstate/share', 'POST /api/userstate/share']);
    expect(inserted[1]).toContain('NEWNEWNEWNEWNEWNEWNEWN');

    byId['fav-share-panel'] = { remove: () => { byId['fav-share-panel'] = null; } };
    await window.stopFavoritesShare();
    expect(calls[calls.length - 1]).toBe('DELETE /api/userstate/share');
    expect(byId['fav-share-panel']).toBeNull();
    // Every request carries the header the server takes as same-origin.
    expect(headers.length).toBe(calls.length);
    headers.forEach(h => expect(h['X-Requested-With']).toBe('fetch'));
});

// Two quick clicks share one request chain: one GET, and with no link one POST.
test('a second click while the share opens sends nothing new', async () => {
    const calls = [];
    const fetch = (url, opts) => {
        calls.push(opts.method);
        const body = opts.method === 'POST' ? { id: 'NEWNEWNEWNEWNEWNEWNEWN' } : {};
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) });
    };
    const header = { insertAdjacentHTML: () => {} };
    const pane = { querySelector: () => header };
    const btn = { closest: () => pane };
    const document = {
        readyState: 'complete', cookie: 'MTGBAN=abc',
        addEventListener: () => {},
        getElementById: () => null,
        querySelector: () => null,
        querySelectorAll: () => [],
        createElement: () => ({ style: {}, classList: { add: () => {}, remove: () => {} } }),
    };
    const localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
    const window = { location: { origin: 'https://ban.test' }, addEventListener: () => {} };
    new Function('window', 'document', 'localStorage', 'fetch', 'navigator', 'location', 'ListStorage', 'escapeAttr', 'escapeHtml',
        source)(window, document, localStorage, fetch, {}, window.location, { read: () => [], save: () => {}, isLive: () => true, pinnedFirst: l => l, tombstones: () => [] }, s => String(s), s => String(s));

    const first = window.openFavoritesShare(btn);
    const second = window.openFavoritesShare(btn);
    expect(second).toBe(first);
    await first;
    expect(calls).toEqual(['GET', 'POST']);
});
