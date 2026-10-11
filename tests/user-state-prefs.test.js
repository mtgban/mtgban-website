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
        [preset('p_a', 'A', 1), { id: 'p_x', del: true, savedAt: Date.now() }],
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
        [arbitPreset('p_a', 'Mine', 5), { id: 'p_c', del: true, savedAt: Date.now() }],
        [arbitPreset('p_b', 'Theirs', 4, 'global'), arbitPreset('p_c', 'Gone', 3)]);
    expect(pushed.filter((p) => !p.del).map((p) => p.id)).toEqual(['p_a', 'p_b']);
    expect(pushed.find((p) => p.id === 'p_c').del).toBe(true);
});

test('a sync response\'s Date sets the clock the saved filters are stamped with', async () => {
    const m = {};
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const window = { addEventListener() {} };
    const document = { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} };
    // The server's clock an hour behind this device's
    const server = new Date(Date.now() - 60 * 60 * 1000).toUTCString();
    const res = {
        status: 200, ok: true, headers: { get: (h) => (h === 'Date' ? server : null) },
        json: () => Promise.resolve({ version: 3, favorites: [], recents: [], preferences: {} }),
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        window, document, storage, session, () => Promise.resolve(res), { mtime: (x) => x.m || x.t || 0 });
    expect(Math.abs(window.UserState.now() - Date.now())).toBeLessThan(1000);
    for (let i = 0; i < 10; i++) await Promise.resolve();
    expect(Math.abs(window.UserState.now() - (Date.parse(server) + 500))).toBeLessThan(1000);
});

// The clock a page loads with, signed out so that no response resets it,
// from an offset another page stored at the time given.
function clockAt(skew, at) {
    const m = { mtgban_userstate_clock: JSON.stringify({ skew, at }) };
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const window = { addEventListener() {} };
    const document = { cookie: '', readyState: 'complete', addEventListener() {} };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        window, document, storage, {}, () => Promise.reject(new Error('no fetch')), { mtime: () => 0 });
    return window.UserState.now() - Date.now();
}

test('a stored clock offset holds only while it is younger than a hydrate\'s TTL', () => {
    const hour = 60 * 60 * 1000;
    expect(Math.abs(clockAt(-hour, Date.now() - 10 * 1000) + hour)).toBeLessThan(100);
    // Stored ten minutes ago, or ahead of a clock set back since
    expect(Math.abs(clockAt(-hour, Date.now() - 10 * 60 * 1000))).toBeLessThan(100);
    expect(Math.abs(clockAt(-hour, Date.now() + hour))).toBeLessThan(100);
});

// The clock a hydrate leaves, its response arriving rtt after the request
// with a Date the server wrote halfway, on the device's own clock, and an
// offset of held already stored. jump then sets the device clock by, after
// passes, and asleep passes with performance.now() stopped, as in a sleep.
async function clockAfterTrip(rtt, held, jump = 0, after = 0, asleep = 0) {
    const clock = { t: 1700000000000, p: 5000 };
    const FakeDate = { now: () => clock.t, parse: Date.parse };
    const FakePerf = { now: () => clock.p };
    const m = { mtgban_userstate_clock: JSON.stringify({ skew: held, at: clock.t - 1000 }) };
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const window = { addEventListener() {} };
    const document = { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} };
    const date = new Date(clock.t + rtt / 2).toUTCString();
    const fetch = () => {
        clock.t += rtt;
        clock.p += rtt;
        return Promise.resolve({ status: 304, ok: false, headers: { get: (h) => (h === 'Date' ? date : null) } });
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'Date', 'performance', source)(
        window, document, storage, { getItem: () => null, setItem() {} }, fetch, { mtime: () => 0 }, FakeDate, FakePerf);
    for (let i = 0; i < 10; i++) await Promise.resolve();
    const real = clock.t + after + asleep;
    clock.t += jump + after + asleep;
    clock.p += after;
    return window.UserState.now() - real;
}

test('the clock offset reads a response\'s Date against the middle of its round trip', async () => {
    // The header's half second, on a clock the device shares
    expect(await clockAfterTrip(2000, 0)).toBe(500);
    // Too slow a trip keeps the offset held
    expect(await clockAfterTrip(10000, 1234)).toBe(1234);
});

test('an open page\'s clock runs on past a correction to the device\'s', async () => {
    expect(await clockAfterTrip(2000, 0, -60 * 60 * 1000, 5000)).toBe(500);
});

test('an open page\'s clock runs on through a sleep that stops performance.now()', async () => {
    expect(await clockAfterTrip(2000, 0, 0, 0, 10 * 60 * 60 * 1000)).toBe(500);
});

test('a delete stamped ahead of the clock still beats an older save, as made now', async () => {
    const day = 24 * 60 * 60 * 1000, hour = 60 * 60 * 1000;
    const pushed = await reconcilePresets(
        [{ id: 'p_x', del: true, savedAt: Date.now() + hour }, preset('p_a', 'A1', Date.now() + hour)],
        [preset('p_x', 'X', Date.now() - day), preset('p_a', 'A2', Date.now() + 2 * hour)]);
    const x = pushed.find((p) => p.id === 'p_x');
    expect(x.del).toBe(true);
    // keeping its own stamp, which counts as now while it runs ahead
    expect(x.savedAt).toBeGreaterThan(Date.now() + 60 * 60 * 1000 - 1000);
    // Of two copies brought back to now together, the later one as given wins
    expect(pushed.find((p) => p.id === 'p_a').name).toBe('A2');
});

test('two devices\' arbitrage presets merge to the newest 10 per page group, names cut to 40', async () => {
    const mine = [], theirs = [];
    for (let i = 0; i < 8; i++) mine.push(arbitPreset('p_m' + i, 'Mine ' + i, 100 + i));
    for (let i = 0; i < 8; i++) theirs.push(arbitPreset('p_t' + i, 'Theirs ' + i, 200 + i));
    theirs.push(arbitPreset('p_g', 'G'.repeat(60), 50, 'global'));
    const pushed = await reconcileArbitPresets(mine, theirs);
    const arbit = pushed.filter((p) => !p.del && p.group === 'arbit').map((p) => p.savedAt).sort((a, b) => a - b);
    expect(arbit).toEqual([106, 107, 200, 201, 202, 203, 204, 205, 206, 207]);
    const global = pushed.filter((p) => p.group === 'global');
    expect(global.map((p) => p.name)).toEqual(['G'.repeat(40)]);
});

test('presets brought back to now together keep their order for the cap', async () => {
    const list = [];
    for (let i = 0; i < 16; i++) list.push(arbitPreset('p_' + i, 'Preset ' + i, Date.now() + 60 * 60 * 1000 + i * 1000));
    const pushed = await reconcileArbitPresets(list, []);
    expect(pushed.filter((p) => !p.del).map((p) => Number(p.id.slice(2))).sort((a, b) => a - b)).toEqual([6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
    expect(pushed.filter((p) => !p.del).every((p) => p.savedAt < Date.now() + 1000)).toBe(true);
});

test('a preset the cap dropped stays dropped when a stale device still holds it', async () => {
    const list = [];
    for (let i = 0; i < 11; i++) list.push(arbitPreset('p_' + i, 'Preset ' + i, 100 + i));
    const first = await reconcileArbitPresets(list, []);
    expect(first.find((p) => p.id === 'p_0').del).toBe(true);
    // A delete frees a slot; a device that never synced still holds p_0
    const afterDelete = first.filter((p) => p.id !== 'p_5').concat([{ id: 'p_5', del: true, savedAt: Date.now() }]);
    const second = await reconcileArbitPresets([list[0], { id: 'p_gone', del: true, savedAt: Date.now() }], afterDelete);
    const live = second.filter((p) => !p.del).map((p) => p.id);
    expect(live).not.toContain('p_0');
    expect(live.length).toBe(9);
});

test('a preset the cap drops far ahead of the clock stays dropped when a stale device holds it', async () => {
    const hour = 60 * 60 * 1000;
    const list = [];
    for (let i = 0; i < 11; i++) list.push(arbitPreset('p_' + i, 'Preset ' + i, Date.now() + hour + i));
    const first = await reconcileArbitPresets(list, []);
    expect(first.find((p) => p.id === 'p_0').del).toBe(true);
    // Later, a delete frees a slot and a device that never synced still holds p_0
    await new Promise((r) => setTimeout(r, 20));
    const afterDelete = first.filter((p) => p.id !== 'p_5').concat([{ id: 'p_5', del: true, savedAt: Date.now() }]);
    const second = await reconcileArbitPresets([list[0], { id: 'p_gone', del: true, savedAt: Date.now() }], afterDelete);
    expect(second.filter((p) => !p.del).map((p) => p.id)).not.toContain('p_0');
    // A delete and a save both ahead come out the same; the delete wins
    const third = await reconcileArbitPresets(
        [{ id: 'p_x', del: true, savedAt: Date.now() + hour }],
        [arbitPreset('p_x', 'X', Date.now() + 2 * hour)]);
    expect(third.find((p) => p.id === 'p_x').del).toBe(true);
});

test('two long names cut to the same 40 characters stay apart', async () => {
    const stem = 'Sealed under fifty dollars with the spread';
    const pushed = await reconcileArbitPresets(
        [arbitPreset('p_a', stem + ' wide', 5)],
        [arbitPreset('p_b', stem + ' narrow', 4), arbitPreset('p_c', stem.slice(0, 40), 3)]);
    const names = Object.fromEntries(pushed.map((p) => [p.id, p.name]));
    expect(names.p_c).toBe(stem.slice(0, 40));
    expect(names.p_a).toBe(stem.slice(0, 36) + ' (2)');
    expect(names.p_b).toBe(stem.slice(0, 36) + ' (3)');
    expect(Object.values(names).every((n) => n.length <= 40)).toBe(true);
});

test('a delete past the 30 days a preset page keeps it is dropped by the merge too', async () => {
    const day = 24 * 60 * 60 * 1000;
    const pushed = await reconcileArbitPresets(
        [arbitPreset('p_a', 'Mine', Date.now())],
        [{ id: 'p_old', del: true, savedAt: Date.now() - 31 * day }, { id: 'p_new', del: true, savedAt: Date.now() - day }]);
    expect(pushed.map((p) => p.id)).toEqual(['p_a', 'p_new']);
});

// Hydrates a clean device from a server an hour behind this device's clock,
// holding preferences, and returns what the device stored and the
// preferences it then sends back.
async function hydrateBehind(preferences) {
    const m = {};
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const document = { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} };
    const date = new Date(Date.now() - 60 * 60 * 1000).toUTCString();
    const patches = [];
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PATCH') patches.push(JSON.parse(opts.body).data);
        const body = { version: 3, favorites: [], recents: [], preferences };
        return Promise.resolve({ status: 200, ok: true, headers: { get: (h) => (h === 'Date' ? date : null) }, json: () => Promise.resolve(body) });
    };
    const timers = [];
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', source)(
        { addEventListener() {} }, document, storage, session, fetch, { mtime: (x) => x.m || x.t || 0, tombstones: () => [] },
        (fn) => timers.push(fn), () => {});
    for (let i = 0; i < 10; i++) await Promise.resolve();
    timers.splice(0).forEach((fn) => fn());
    for (let i = 0; i < 10; i++) await Promise.resolve();
    return { stored: m, patches, serverNow: Date.parse(date) + 500 };
}

test('stamps ahead of the server\'s clock count as made now, on hydrate and in a merge', async () => {
    const hour = 60 * 60 * 1000;
    const ahead = Date.now();
    const { stored, patches, serverNow } = await hydrateBehind({
        mtgban_arbit_filters: JSON.stringify({ arbit: { q: 'f=1&minsell=2', t: ahead } }),
        mtgban_upload_presets: JSON.stringify([preset('p_a', 'A', ahead)]),
    });
    const filters = JSON.parse(stored.mtgban_arbit_filters);
    expect(Math.abs(filters.arbit.t - serverNow)).toBeLessThan(1000);
    expect(Math.abs(JSON.parse(stored.mtgban_upload_presets)[0].savedAt - serverNow)).toBeLessThan(1000);
    expect(patches.length).toBe(1);
    expect(JSON.parse(patches[0].mtgban_arbit_filters)).toEqual(filters);

    const pushed = await reconcileArbit(
        { arbit: { q: 'f=1&minsell=2', t: Date.now() + hour }, global: { q: 'f=1&minsell=7', t: Date.now() + hour } },
        { arbit: { q: 'f=1&minsell=9', t: Date.now() - 1000 }, global: { q: 'f=1', t: Date.now() + hour + 1 } });
    expect(pushed.arbit.q).toBe('f=1&minsell=2');
    expect(pushed.arbit.t).toBeLessThan(Date.now() + 1000);
    // Both counting as now, the later as given wins
    expect(pushed.global.q).toBe('f=1');
});

// syncDevice loads user-state.js on a device whose clock runs skew ahead
// of a server shared with other devices, lets its sync and any write it
// schedules run, and returns the requests it sent.
async function syncDevice(server, device) {
    const FakeDate = { now: () => Date.now() + device.skew, parse: Date.parse };
    const storage = { getItem: (k) => (k in device.m ? device.m[k] : null), setItem: (k, v) => { device.m[k] = String(v); }, removeItem: (k) => { delete device.m[k]; } };
    const sent = [];
    const reply = (status, body) => Promise.resolve({
        status, ok: status === 200, headers: { get: (h) => (h === 'Date' ? new Date().toUTCString() : null) },
        json: () => Promise.resolve(body),
    });
    const state = () => ({ version: server.version, favorites: [], recents: [], preferences: Object.assign({}, server.preferences) });
    const fetch = (url, opts) => {
        const method = (opts && opts.method) || 'GET';
        sent.push(method);
        if (method === 'GET') return reply(200, state());
        const body = JSON.parse(opts.body);
        if (body.version !== server.version) return reply(409, state());
        server.preferences = method === 'PUT' ? body.preferences : body.data;
        server.version++;
        return reply(200, { version: server.version });
    };
    const timers = [];
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', 'Date', source)(
        { addEventListener() {} }, { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} }, storage,
        { getItem: () => null, setItem() {} }, fetch, { mtime: (x) => x.m || x.t || 0, tombstones: () => [] },
        (fn) => timers.push(fn), () => {}, FakeDate);
    for (let i = 0; i < 20; i++) await Promise.resolve();
    timers.splice(0).forEach((fn) => fn());
    for (let i = 0; i < 20; i++) await Promise.resolve();
    return sent;
}

test('a device an hour fast that saved before its first sync leaves the server on the clock', async () => {
    const hour = 60 * 60 * 1000;
    const server = { version: 1, preferences: {} };
    const a = { skew: hour, m: {} };
    const b = { skew: 0, m: {} };
    a.m.mtgban_userstate_dirty = '1';
    a.m.mtgban_arbit_filters = JSON.stringify({ arbit: { q: 'f=1&minsell=2', t: Date.now() + hour } });
    expect(await syncDevice(server, a)).toContain('PUT');
    expect(JSON.parse(server.preferences.mtgban_arbit_filters).arbit.t).toBeLessThan(Date.now() + 1000);

    // 1.5 s on, as in the review, past the header's whole second: A syncs
    // again, then B applies other filters, and they hold on both devices
    await new Promise((r) => setTimeout(r, 1500));
    await syncDevice(server, a);
    expect(JSON.parse(a.m.mtgban_arbit_filters).arbit.q).toBe('f=1&minsell=2');
    b.m.mtgban_userstate_dirty = '1';
    b.m.mtgban_arbit_filters = JSON.stringify({ arbit: { q: 'f=1&minsell=9', t: Date.now() } });
    await syncDevice(server, b);
    expect(JSON.parse(server.preferences.mtgban_arbit_filters).arbit.q).toBe('f=1&minsell=9');
    await syncDevice(server, a);
    expect(JSON.parse(a.m.mtgban_arbit_filters).arbit.q).toBe('f=1&minsell=9');
});

test('a preset the cap drops stays dropped against its own stamp up to the tolerance ahead', async () => {
    const list = [];
    for (let i = 0; i < 10; i++) list.push(arbitPreset('p_' + i, 'Preset ' + i, Date.now() + 4500 + i));
    const dropped = arbitPreset('p_old', 'Old', Date.now() + 4000);
    const first = await reconcileArbitPresets(list.concat([dropped]), []);
    const tomb = first.find((p) => p.id === 'p_old');
    expect(tomb.del).toBe(true);
    expect(tomb.savedAt).toBeGreaterThan(dropped.savedAt);
    // A delete frees a slot, and a device that never synced still holds p_old
    const afterDelete = first.filter((p) => p.id !== 'p_5').concat([{ id: 'p_5', del: true, savedAt: Date.now() }]);
    const second = await reconcileArbitPresets([dropped, { id: 'p_gone', del: true, savedAt: Date.now() }], afterDelete);
    expect(second.filter((p) => !p.del).map((p) => p.id)).not.toContain('p_old');
});

test('a device hydrating an over-long preset list alone holds it to 10 and sends it back', async () => {
    const list = [];
    for (let i = 0; i < 16; i++) list.push(arbitPreset('p_' + i, 'Preset ' + i, 100 + i));
    const { stored, patches } = await hydrateBehind({ mtgban_arbit_presets: JSON.stringify(list) });
    const kept = JSON.parse(stored.mtgban_arbit_presets).filter((p) => !p.del).map((p) => p.savedAt).sort((a, b) => a - b);
    expect(kept).toEqual([106, 107, 108, 109, 110, 111, 112, 113, 114, 115]);
    expect(patches.length).toBe(1);
    expect(JSON.parse(patches[0].mtgban_arbit_presets).filter((p) => !p.del).length).toBe(10);
});
