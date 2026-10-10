import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/user-state.js', import.meta.url), 'utf8');

test('upload presets ride the synced preferences', () => {
    const m = source.match(/var PREF_KEYS = \[([\s\S]*?)\];/);
    expect(m).not.toBeNull();
    expect(m[1]).toContain("'mtgban_upload_presets'");
});

test('upload.html loads list-storage.js before user-state.js', () => {
    const html = readFileSync(new URL('../templates/upload.html', import.meta.url), 'utf8');
    const listStorageIdx = html.indexOf('/js/list-storage.js');
    const userStateIdx = html.indexOf('/js/user-state.js');
    expect(listStorageIdx).toBeGreaterThan(-1);
    expect(userStateIdx).toBeGreaterThan(-1);
    expect(listStorageIdx).toBeLessThan(userStateIdx);
});

// Runs user-state.js signed in, with a server holding prefs, and returns what
// UploadPresets.refresh saw in storage when hydrate called it.
async function hydrateWith(preferences) {
    const m = {};
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const seen = [];
    const window = { addEventListener() {}, UploadPresets: { refresh: () => seen.push(m.mtgban_upload_presets) } };
    const document = { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} };
    const res = { status: 200, ok: true, json: () => Promise.resolve({ version: 3, favorites: [], recents: [], preferences }) };
    const fetch = () => Promise.resolve(res);
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        window, document, storage, session, fetch, { mtime: (x) => x.m || x.t || 0 });
    for (let i = 0; i < 10; i++) await Promise.resolve();
    return seen;
}

test('hydrate refreshes the upload presets after writing the synced list', async () => {
    const list = JSON.stringify([{ id: 'p_a', name: 'A', opts: { mode: 'false' } }]);
    const seen = await hydrateWith({ mtgban_upload_presets: list });
    expect(seen).toEqual([list]);
});

// Runs user-state.js signed in on a device with unsynced writes, and returns
// the preset list reconcile pushes over the server's.
async function reconcilePresets(local, server) {
    const m = { mtgban_userstate_dirty: '1', mtgban_upload_presets: JSON.stringify(local) };
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const window = { addEventListener() {} };
    const document = { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} };
    const state = { version: 3, favorites: [], recents: [], preferences: { mtgban_upload_presets: JSON.stringify(server) } };
    const puts = [];
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PUT') puts.push(JSON.parse(opts.body));
        return Promise.resolve({ status: 200, ok: true, json: () => Promise.resolve(state) });
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        window, document, storage, session, fetch, { mtime: (x) => x.m || x.t || 0, tombstones: () => [] });
    for (let i = 0; i < 20; i++) await Promise.resolve();
    expect(puts.length).toBe(1);
    return JSON.parse(puts[0].preferences.mtgban_upload_presets);
}

const preset = (id, name, savedAt) => ({ id, name, savedAt, opts: { mode: 'false' } });

test('a stale device keeps the presets another device saved', async () => {
    const pushed = await reconcilePresets(
        [preset('p_a', 'A', 1), preset('p_y', 'Y', 5)],
        [preset('p_a', 'A', 1), preset('p_x', 'X', 4)]);
    expect(pushed.map((p) => p.id)).toEqual(['p_a', 'p_x', 'p_y']);
});

test('a preset deleted on one device stays deleted, and the newer save wins', async () => {
    const pushed = await reconcilePresets(
        [preset('p_a', 'A', 1), { id: 'p_x', del: true, savedAt: 6 }],
        [preset('p_a', 'A renamed', 2), preset('p_x', 'X', 4)]);
    expect(pushed.filter((p) => !p.del).map((p) => p.name)).toEqual(['A renamed']);
    expect(pushed.find((p) => p.id === 'p_x').del).toBe(true);
});

test('the saved arbitrage filters ride the synced preferences', () => {
    const m = source.match(/var PREF_KEYS = \[([\s\S]*?)\];/);
    expect(m[1]).toContain("'mtgban_arbit_filters'");
});

test('arbit.html loads list-storage.js before user-state.js', () => {
    const html = readFileSync(new URL('../templates/arbit.html', import.meta.url), 'utf8');
    const listStorageIdx = html.indexOf('/js/list-storage.js');
    const userStateIdx = html.indexOf('/js/user-state.js');
    expect(listStorageIdx).toBeGreaterThan(-1);
    expect(userStateIdx).toBeGreaterThan(listStorageIdx);
});

test('hydrate hands the synced arbitrage filters to the page', async () => {
    const m = {};
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const seen = [];
    const window = { addEventListener() {}, ArbitFilters: { refresh: () => seen.push(m.mtgban_arbit_filters) } };
    const document = { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} };
    const filters = JSON.stringify({ arbit: { q: 'f=1&minsell=2', t: 9 } });
    const res = { status: 200, ok: true, json: () => Promise.resolve({ version: 3, favorites: [], recents: [], preferences: { mtgban_arbit_filters: filters } }) };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        window, document, storage, session, () => Promise.resolve(res), { mtime: (x) => x.m || x.t || 0 });
    for (let i = 0; i < 10; i++) await Promise.resolve();
    expect(seen).toEqual([filters]);
});

// Runs reconcile on a device with unsynced arbitrage filters, and returns
// the copy it pushes over the server's.
async function reconcileArbit(local, server) {
    const m = { mtgban_userstate_dirty: '1', mtgban_arbit_filters: JSON.stringify(local) };
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const document = { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} };
    const state = { version: 3, favorites: [], recents: [], preferences: { mtgban_arbit_filters: JSON.stringify(server) } };
    const puts = [];
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PUT') puts.push(JSON.parse(opts.body));
        return Promise.resolve({ status: 200, ok: true, json: () => Promise.resolve(state) });
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        { addEventListener() {} }, document, storage, session, fetch, { mtime: (x) => x.m || x.t || 0, tombstones: () => [] });
    for (let i = 0; i < 20; i++) await Promise.resolve();
    expect(puts.length).toBe(1);
    return JSON.parse(puts[0].preferences.mtgban_arbit_filters);
}

test('each page group keeps the filters applied last, on whichever device', async () => {
    const pushed = await reconcileArbit(
        { arbit: { q: 'f=1&minsell=2', t: 5 }, global: { q: 'f=1&minsell=7', t: 1 } },
        { arbit: { q: 'f=1&minsell=9', t: 4 }, global: { q: 'f=1', t: 3 } });
    expect(pushed).toEqual({ arbit: { q: 'f=1&minsell=2', t: 5 }, global: { q: 'f=1', t: 3 } });
});

test('a page group only one device saved survives the merge', async () => {
    const pushed = await reconcileArbit(
        { arbit: { q: 'f=1&minsell=2', t: 5 } },
        { global: { q: 'f=1&minsell=7', t: 3 } });
    expect(pushed).toEqual({ arbit: { q: 'f=1&minsell=2', t: 5 }, global: { q: 'f=1&minsell=7', t: 3 } });
});

test('the arbitrage presets ride the synced preferences', () => {
    const m = source.match(/var PREF_KEYS = \[([\s\S]*?)\];/);
    expect(m[1]).toContain("'mtgban_arbit_presets'");
});

// Runs reconcile on a device with unsynced arbitrage presets, and returns
// the list it pushes over the server's.
async function reconcileArbitPresets(local, server) {
    const m = { mtgban_userstate_dirty: '1', mtgban_arbit_presets: JSON.stringify(local) };
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const document = { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} };
    const state = { version: 3, favorites: [], recents: [], preferences: { mtgban_arbit_presets: JSON.stringify(server) } };
    const puts = [];
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PUT') puts.push(JSON.parse(opts.body));
        return Promise.resolve({ status: 200, ok: true, json: () => Promise.resolve(state) });
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        { addEventListener() {} }, document, storage, session, fetch, { mtime: (x) => x.m || x.t || 0, tombstones: () => [] });
    for (let i = 0; i < 20; i++) await Promise.resolve();
    expect(puts.length).toBe(1);
    return JSON.parse(puts[0].preferences.mtgban_arbit_presets);
}

const arbitPreset = (id, name, savedAt, group = 'arbit') => ({ id, name, savedAt, group, q: 'f=1&minsell=' + savedAt });

test('arbitrage presets made on two devices both survive, and a delete sticks', async () => {
    const pushed = await reconcileArbitPresets(
        [arbitPreset('p_a', 'Mine', 5), { id: 'p_c', del: true, savedAt: 9 }],
        [arbitPreset('p_b', 'Theirs', 4, 'global'), arbitPreset('p_c', 'Gone', 3)]);
    expect(pushed.filter((p) => !p.del).map((p) => p.id)).toEqual(['p_a', 'p_b']);
    expect(pushed.find((p) => p.id === 'p_c').del).toBe(true);
});
