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
async function reconcileBackpack(local, server, clean, max, tabs, extra) {
    const m = Object.assign(clean ? {} : { mtgban_userstate_dirty: '1' }, extra);
    if (local) m.mtgban_backpack = JSON.stringify(local);
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const rendered = [];
    const window = { addEventListener() {}, renderBackpack: () => rendered.push(m.mtgban_backpack) };
    if (max) window.BAN_BACKPACK_MAX = max;
    if (tabs) window.BAN_BACKPACK_TABS = tabs;
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    const state = { version: 3, favorites: [], recents: [], preferences: {}, backpack: server };
    const puts = [];
    const writes = [];
    const encodings = [];
    const fetch = async (url, opts) => {
        if (opts && (opts.method === 'PUT' || opts.method === 'PATCH')) writes.push(opts.method);
        if (opts && opts.method === 'PUT') {
            const gzipped = opts.headers['Content-Encoding'] === 'gzip';
            encodings.push(gzipped ? 'gzip' : 'plain');
            const text = gzipped ? await new Response(opts.body.stream().pipeThrough(new DecompressionStream('gzip'))).text() : opts.body;
            puts.push(JSON.parse(text));
        }
        return { status: 200, ok: true, json: () => Promise.resolve(state) };
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        window, document, storage, session, fetch, realListStorage());
    // A big body is compressed first, which takes a few turns of the loop.
    for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0));
    return { pushed: puts.length ? puts[0].backpack : null, prefs: puts.length ? puts[0].preferences : null, stored: JSON.parse(m.mtgban_backpack), rendered, writes, encodings, m };
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
    const { pushed } = await reconcileBackpack([entry('a', 1, 10, { cond: 'SP', pack: 2, sellPrice: 5, query: 'x' })], []);
    expect(Object.keys(pushed[0]).sort()).toEqual(['cond', 'pack', 'cw', 'edition', 'finishClass', 'finishTag', 'id', 'img', 'm', 'name', 'number', 'qty', 'set', 't'].sort());
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

test('the merge keeps a card in two backpacks apart', async () => {
    const { pushed } = await reconcileBackpack([entry('a', 3, 10, { pack: 2 })], [entry('a', 2, 5)]);
    expect(pushed.filter((e) => !e.del).map((e) => [e.pack || 1, e.qty]).sort()).toEqual([[1, 2], [2, 3]]);
});

test('the merge caps each backpack at the size, newest first', async () => {
    const local = [], server = [];
    for (let i = 0; i < 5; i++) local.push(entry('l' + i, 1, 1000 + i, { pack: 2 }));
    for (let i = 0; i < 4; i++) server.push(entry('s' + i, 1, 2000 + i));
    const { pushed } = await reconcileBackpack(local, server, false, 3, 2);
    const live = pushed.filter((e) => !e.del).map((e) => e.id).sort();
    expect(live).toEqual(['l2', 'l3', 'l4', 's1', 's2', 's3']);
});

test('the merge caps the backpacks together at size times allowance', async () => {
    const local = [entry('a', 1, 1000), entry('b', 1, 1001, { pack: 2 }), entry('c', 1, 1002, { pack: 3 })];
    const { pushed } = await reconcileBackpack(local, [], false, 1, 2);
    expect(pushed.filter((e) => !e.del).map((e) => e.id).sort()).toEqual(['b', 'c']);
});

test('the backpack names sync as a preference', async () => {
    const tabs = JSON.stringify([{ pack: 1, name: 'Trades' }, { pack: 2 }]);
    const { prefs } = await reconcileBackpack([entry('a', 1, 10)], [], false, 0, 0, { mtgban_backpack_tabs: tabs });
    expect(prefs.mtgban_backpack_tabs).toBe(tabs);
});

// Runs user-state.js signed in on a device with unsynced writes holding the
// local backpack tabs, and returns the tab list reconcile pushes.
async function reconcileTabs(local, server) {
    const m = { mtgban_userstate_dirty: '1', mtgban_backpack_tabs: JSON.stringify(local) };
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    const state = { version: 3, favorites: [], recents: [], backpack: [], preferences: { mtgban_backpack_tabs: JSON.stringify(server) } };
    const puts = [];
    const fetch = async (url, opts) => {
        if (opts && opts.method === 'PUT') puts.push(JSON.parse(opts.body));
        return { status: 200, ok: true, json: () => Promise.resolve(state) };
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        { addEventListener() {} }, document, storage, session, fetch, realListStorage());
    for (let i = 0; i < 10; i++) await new Promise((r) => setTimeout(r, 0));
    expect(puts.length).toBe(1);
    return JSON.parse(puts[0].preferences.mtgban_backpack_tabs);
}
const shown = (list) => list.map((t) => t.pack + (t.del ? ' deleted' : ':' + t.name));

test('a stale device keeps the backpacks another renamed, added and deleted', async () => {
    const pushed = await reconcileTabs(
        [{ pack: 1, name: 'Main' }, { pack: 2, name: 'Backpack 2' }, { pack: 3, name: 'Old' }],
        [{ pack: 1, name: 'Main', m: 1 }, { pack: 2, name: 'Trades', m: 5 }, { pack: 4, name: 'Backpack 4', m: 6 }, { pack: 3, del: true, m: 7 }]);
    expect(shown(pushed)).toEqual(['1:Main', '2:Trades', '3 deleted', '4:Backpack 4']);
});

test('the newer rename wins on either side, and so does the newer order', async () => {
    const local = [{ pack: 2, name: 'Trades', m: 9, o: 8 }, { pack: 1, name: 'Main', m: 1, o: 8 }, { pack: 5, name: 'New', m: 9, o: 8 }];
    const server = [{ pack: 1, name: 'Binder', m: 4, o: 3 }, { pack: 3, name: 'Cube', m: 4, o: 3 }, { pack: 2, name: 'B', m: 4, o: 3 }];
    expect(shown(await reconcileTabs(local, server))).toEqual(['2:Trades', '1:Binder', '5:New', '3:Cube']);
    server.forEach((t) => { t.o = 10; });
    expect(shown(await reconcileTabs(local, server))).toEqual(['1:Binder', '3:Cube', '2:Trades', '5:New']);
});

test('a big backpack is pushed gzipped and a small one plain', async () => {
    const big = [];
    for (let i = 0; i < 300; i++) big.push(entry('b' + i, 1, 1000 + i, { img: 'https://cards.scryfall.io/normal/front/a/b/' + i + '.jpg' }));
    const gz = await reconcileBackpack(big, [], false, 1000);
    expect(gz.encodings).toEqual(['gzip']);
    expect(gz.pushed.filter((e) => !e.del)).toHaveLength(300);
    const plain = await reconcileBackpack([entry('a', 1, 10)], []);
    expect(plain.encodings).toEqual(['plain']);
});

test('a removed entry is pushed and kept with only what names and orders it', async () => {
    const now = Date.now();
    const gone = entry('a', 2, now - 5, { cond: 'SP', pack: 2, del: now - 5 });
    const { pushed, stored } = await reconcileBackpack([gone, entry('b', 1, now - 1)], []);
    const want = { id: 'a', cond: 'SP', pack: 2, t: now - 5, m: now - 5, del: now - 5 };
    expect(pushed.find((e) => e.id === 'a')).toEqual(want);
    expect(stored.find((e) => e.id === 'a')).toEqual(want);
});
