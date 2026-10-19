import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/favorites-shared.js', import.meta.url), 'utf8');
const listStorageSource = readFileSync(new URL('../js/list-storage.js', import.meta.url), 'utf8');

// Loads the script against a page holding `rows`, signed in or not, with a
// fake localStorage and a fetch recorder; returns the exported helpers.
function load(rows, signedIn, stored) {
    const values = new Map();
    if (stored) values.set('mtgban_favorites', JSON.stringify(stored));
    const localStorage = {
        getItem: key => (values.has(key) ? values.get(key) : null),
        setItem: (key, value) => values.set(key, value),
    };
    const fetches = [];
    const fetch = url => { fetches.push(url); return Promise.resolve({ ok: true, json: () => Promise.resolve({}) }); };
    const document = {
        readyState: 'complete',
        body: { classList: { contains: () => false } },
        addEventListener: () => {},
        getElementById: () => null,
        querySelector: () => null,
        querySelectorAll: () => [],
    };
    const window = { BAN_SHARED_FAVORITES: { rows, signedIn } };
    new Function('window', 'document', 'localStorage', 'fetch', listStorageSource + '\n' + source)(window, document, localStorage, fetch);
    return { api: window.SharedFavorites, values, fetches };
}

const shared = [
    { id: 'a', name: 'A', set: 'LEA', query: 'A s:LEA' },
    { id: 'b', name: 'B', set: 'CMR', number: '1', foil: true, finishTag: 'Foil', finishClass: 'foil', query: 'B s:CMR cns:1 f:foil', img: 'https://img/b.jpg' },
    { id: 'c', name: 'C', set: 'SLD', query: 'C s:SLD' },
];

test('merge adds the cards the viewer lacks with a fresh time', () => {
    const { api } = load(shared, false);
    const res = api.mergeInto([{ id: 'b', name: 'B', t: 5 }], shared, 1000, {});
    expect(res.added).toBe(2);
    expect(res.already).toBe(1);
    expect(res.skipped).toBe(0);
    const ids = res.list.map(f => f.id);
    expect(ids).toEqual(['b', 'a', 'c']);
    const added = res.list.find(f => f.id === 'a');
    expect(added.t).toBe(1000);
    expect(added.m).toBe(1000);
    expect(added.pinned).toBeUndefined();
    expect(added.query).toBe('A s:LEA');
});

test('merge copies the prices the page fetched', () => {
    const { api } = load(shared, true);
    const res = api.mergeInto([], shared, 1, { a: { sellPrice: 2.5, sellVendor: 'CK', buyPrice: 1, buyVendor: 'SCG' } });
    const a = res.list.find(f => f.id === 'a');
    expect(a.sellPrice).toBe(2.5);
    expect(a.sellVendor).toBe('CK');
    expect(a.buyPrice).toBe(1);
    const c = res.list.find(f => f.id === 'c');
    expect(c.sellPrice).toBeNull();
});

test('merge stops at the cap and counts the rest as skipped', () => {
    const { api } = load(shared, false);
    const full = [];
    for (let i = 0; i < 50; i++) full.push({ id: 'own' + i, name: 'Own', t: i });
    const res = api.mergeInto(full, shared, 1, {});
    expect(res.added).toBe(0);
    expect(res.skipped).toBe(3);
    expect(res.list.length).toBe(50);
    const partial = full.slice(0, 48);
    const res2 = api.mergeInto(partial, shared, 1, {});
    expect(res2.added).toBe(2);
    expect(res2.skipped).toBe(1);
});

test('a re-added card drops its old tombstone', () => {
    const { api } = load(shared, false);
    const res = api.mergeInto([{ id: 'a', name: 'A', t: 5, del: 6, m: 6 }], shared, 1000, {});
    const copies = res.list.filter(f => f.id === 'a');
    expect(copies.length).toBe(1);
    expect(copies[0].del).toBeUndefined();
    expect(res.added).toBe(3);
});

test('the toast names what happened', () => {
    const { api } = load(shared, false);
    expect(api.toastText({ added: 2, already: 1, skipped: 0 })).toBe('Added 2, already had 1');
    expect(api.toastText({ added: 0, already: 0, skipped: 3 })).toBe('3 skipped (favorites are capped at 50)');
    expect(api.toastText({ added: 0, already: 3, skipped: 0 })).toBe('Already had 3');
    expect(api.toastText({ added: 0, already: 0, skipped: 0 })).toBe('Nothing to merge');
});

test('a signed-out page fetches no prices', () => {
    const { fetches } = load(shared, false);
    expect(fetches).toEqual([]);
});

test('a signed-in page fetches prices in one batch for a short list', () => {
    const { fetches } = load(shared, true);
    expect(fetches).toEqual(['/data/prices/' + encodeURIComponent('a,b,c')]);
});

// Loads the script with a Merge button stub and, when given, a sync whose
// first read the test settles; returns the click handler and the writes.
function loadWithButton(signedIn, sync) {
    const values = new Map();
    const writes = [];
    const localStorage = {
        getItem: key => (values.has(key) ? values.get(key) : null),
        setItem: (key, value) => { writes.push(key); values.set(key, value); },
    };
    const handlers = {};
    const btn = { disabled: false, textContent: 'Merge', addEventListener: (type, fn) => { handlers[type] = fn; } };
    const document = {
        readyState: 'complete',
        body: { classList: { contains: () => false } },
        addEventListener: () => {},
        getElementById: id => (id === 'shared-merge' ? btn : null),
        querySelector: () => null,
        querySelectorAll: () => [],
    };
    const window = { BAN_SHARED_FAVORITES: { rows: shared, signedIn } };
    if (sync) window.UserStateSync = sync;
    const fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve({}) });
    new Function('window', 'document', 'localStorage', 'fetch', listStorageSource + '\n' + source)(window, document, localStorage, fetch);
    return { btn, writes, click: () => handlers.click({ preventDefault() {} }) };
}

test('a signed-in merge waits for the first sync read', async () => {
    let settle;
    const ready = new Promise(res => { settle = res; });
    const { btn, writes, click } = loadWithButton(true, { ready });
    click();
    expect(btn.disabled).toBe(true);
    expect(btn.textContent).toBe('Syncing your favorites');
    expect(writes).toEqual([]);
    settle();
    await ready;
    await Promise.resolve();
    expect(writes).toEqual(['mtgban_favorites']);
    expect(btn.disabled).toBe(false);
    expect(btn.textContent).toBe('Merge');
});

test('a signed-out merge saves at once without the sync', () => {
    let touched = false;
    const sync = { get ready() { touched = true; return Promise.resolve(); } };
    const { btn, writes, click } = loadWithButton(false, sync);
    click();
    expect(writes).toEqual(['mtgban_favorites']);
    expect(btn.disabled).toBe(false);
    expect(touched).toBe(false);
});
