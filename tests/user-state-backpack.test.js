import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/user-state.js', import.meta.url), 'utf8');
const listStorage = readFileSync(new URL('../js/list-storage.js', import.meta.url), 'utf8');

function realListStorage() {
    const window = {};
    new Function('window', listStorage + '; window.ListStorage = ListStorage;')(window);
    return window.ListStorage;
}

// Runs user-state.js signed in with a local backpack against a server copy,
// and returns the backpack the reconcile PUT pushes; clean leaves the dirty
// flag unset; max stands in for the tier's backpack size.
async function reconcileBackpack(local, server, clean, max) {
    const m = clean ? {} : { mtgban_userstate_dirty: '1' };
    if (local) m.mtgban_backpack = JSON.stringify(local);
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const rendered = [];
    const window = { addEventListener() {}, renderBackpack: () => rendered.push(m.mtgban_backpack) };
    if (max) window.BAN_BACKPACK_MAX = max;
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    const state = { version: 3, favorites: [], recents: [], preferences: {}, backpack: server };
    const puts = [];
    const writes = [];
    const fetch = (url, opts) => {
        if (opts && (opts.method === 'PUT' || opts.method === 'PATCH')) writes.push(opts.method);
        if (opts && opts.method === 'PUT') puts.push(JSON.parse(opts.body));
        return Promise.resolve({ status: 200, ok: true, json: () => Promise.resolve(state) });
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        window, document, storage, session, fetch, realListStorage());
    for (let i = 0; i < 20; i++) await Promise.resolve();
    return { pushed: puts.length ? puts[0].backpack : null, stored: JSON.parse(m.mtgban_backpack), rendered, writes, m };
}

const entry = (id, qty, m, extra) => Object.assign({ id, name: 'N ' + id, edition: 'E', set: 'S', number: '1', finishTag: '', finishClass: '', img: '', cw: false, qty, t: m, m }, extra);

test('the key maps to the backpack section and the merge keeps the newer quantity', async () => {
    const { pushed } = await reconcileBackpack(
        [entry('a', 3, 10), entry('b', 1, 2)],
        [entry('a', 1, 5), entry('c', 2, 7)]);
    expect(pushed.filter((e) => !e.del).map((e) => [e.id, e.qty]).sort()).toEqual([['a', 3], ['b', 1], ['c', 2]]);
});

test('a newer removal beats an older quantity', async () => {
    const now = Date.now(); // tombstones older than 30 days are dropped
    const { pushed } = await reconcileBackpack(
        [entry('a', 2, now - 5), entry('b', 1, now - 1, { del: now - 1 })],
        [entry('a', 4, now - 2, { del: now - 2 }), entry('b', 1, now - 6)]);
    const live = pushed.filter((e) => !e.del).map((e) => e.id);
    expect(live).toEqual([]);
    expect(pushed.find((e) => e.id === 'a').del).toBe(now - 2);
});

test('a newer add beats an older removal', async () => {
    const now = Date.now();
    const { pushed } = await reconcileBackpack(
        [entry('a', 2, now - 1)],
        [entry('a', 4, now - 5, { del: now - 5 })]);
    const a = pushed.find((e) => e.id === 'a');
    expect(a.del).toBeUndefined();
    expect(a.qty).toBe(2);
});

test('the pushed entries carry only the synced fields', async () => {
    const { pushed } = await reconcileBackpack([entry('a', 1, 10, { cond: 'SP', sellPrice: 5, query: 'x' })], []);
    expect(Object.keys(pushed[0]).sort()).toEqual(['cond', 'cw', 'edition', 'finishClass', 'finishTag', 'id', 'img', 'm', 'name', 'number', 'qty', 'set', 't'].sort());
    expect(pushed[0].sellPrice).toBeUndefined();
});

test('the merge caps the backpack at 100 live entries, newest first', async () => {
    const local = [];
    for (let i = 0; i < 150; i++) local.push(entry('l' + i, 1, 1000 + i));
    const server = [];
    for (let i = 0; i < 60; i++) server.push(entry('s' + i, 1, 2000 + i));
    const { pushed } = await reconcileBackpack(local, server);
    const live = pushed.filter((e) => !e.del);
    expect(live.length).toBe(100);
    expect(live.some((e) => e.id === 's59')).toBe(true);
    expect(live.some((e) => e.id === 'l149')).toBe(true);
    expect(live.some((e) => e.id === 'l0')).toBe(false);
});

test('a larger tier size keeps every card through the merge', async () => {
    const local = [];
    for (let i = 0; i < 150; i++) local.push(entry('l' + i, 1, 1000 + i));
    const server = [];
    for (let i = 0; i < 100; i++) server.push(entry('s' + i, 1, 2000 + i));
    const { pushed } = await reconcileBackpack(local, server, false, 500);
    expect(pushed.filter((e) => !e.del)).toHaveLength(250);
});

test('a reconcile adopts the server backpack', async () => {
    const { stored, rendered } = await reconcileBackpack([], [entry('z', 2, 3)]);
    expect(stored.map((e) => e.id)).toEqual(['z']);
    expect(rendered.length).toBeGreaterThan(0);
});

test('a clean hydrate stores the server backpack, re-renders and pushes nothing', async () => {
    const now = Date.now();
    const { stored, rendered, writes, m } = await reconcileBackpack(null, [entry('z', 2, now - 3)], true);
    expect(stored.map((e) => e.id)).toEqual(['z']);
    expect(rendered.length).toBeGreaterThan(0);
    expect(writes).toEqual([]);
    expect(m.mtgban_userstate_dirty).toBeUndefined();
});

test('a Clear of more than 50 cards stays cleared through a reconcile', async () => {
    const now = Date.now();
    const local = [], server = [];
    for (let i = 0; i < 100; i++) {
        local.push(entry('c' + i, 1, now - 1000, { del: now - 10 - i, m: now - 10 - i }));
        server.push(entry('c' + i, 1, now - 1000));
    }
    const { pushed, stored } = await reconcileBackpack(local, server);
    expect(pushed.filter((e) => !e.del)).toHaveLength(0);
    // Every tombstone stays local, so a failed push cannot bring cards back.
    expect(stored).toHaveLength(100);
    expect(stored.filter((e) => !e.del)).toHaveLength(0);
});

test('a backpack built signed out survives the first sign-in', async () => {
    const now = Date.now();
    const { pushed, stored } = await reconcileBackpack([entry('a', 2, now - 5)], [], true);
    expect(stored.filter((e) => !e.del).map((e) => [e.id, e.qty])).toEqual([['a', 2]]);
    expect(pushed.filter((e) => !e.del).map((e) => e.id)).toEqual(['a']);
});

test('the merge keeps a card\'s grades apart', async () => {
    const { pushed } = await reconcileBackpack(
        [entry('a', 3, 10, { cond: 'SP' }), entry('a', 1, 4)],
        [entry('a', 2, 5, { cond: 'SP' }), entry('a', 5, 7, { cond: 'HP' })]);
    expect(pushed.filter((e) => !e.del).map((e) => [e.cond || 'NM', e.qty]).sort()).toEqual([['HP', 5], ['NM', 1], ['SP', 3]]);
});

test('an entry without a grade merges with the NM one', async () => {
    const { pushed } = await reconcileBackpack([entry('a', 3, 10, { cond: 'NM' })], [entry('a', 2, 5)]);
    expect(pushed.map((e) => [e.id, e.qty])).toEqual([['a', 3]]);
});
