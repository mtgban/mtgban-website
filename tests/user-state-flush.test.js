import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/user-state.js', import.meta.url), 'utf8');
const listStorage = readFileSync(new URL('../js/list-storage.js', import.meta.url), 'utf8');

function realListStorage() {
    const window = {};
    new Function('window', listStorage + '; window.ListStorage = ListStorage;')(window);
    return window.ListStorage;
}

// Runs user-state.js signed in, with the sync shim on a Storage of its own
// and the debounce timer in the test's hands, and returns what a flush
// after one write sends.
async function flushAfterWrite(key, value) {
    const m = {};
    class Storage {
        getItem(k) { return k in m ? m[k] : null; }
        setItem(k, v) { m[k] = String(v); }
        removeItem(k) { delete m[k]; }
    }
    const storage = new Storage();
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const window = { addEventListener() {}, Storage, localStorage: storage };
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    const writes = [];
    // The GET answers as for a visitor, so nothing hydrates; a PATCH lands.
    const fetch = async (url, opts) => {
        if (opts && opts.method === 'PATCH') {
            const gzipped = opts.headers['Content-Encoding'] === 'gzip';
            const text = gzipped ? await new Response(opts.body.stream().pipeThrough(new DecompressionStream('gzip'))).text() : opts.body;
            writes.push({ url, gzipped, body: JSON.parse(text) });
            return { status: 200, ok: true, headers: { get: () => null }, json: () => Promise.resolve({ version: 1 }) };
        }
        return Promise.resolve({ status: 401, ok: false, headers: { get: () => null }, json: () => Promise.resolve(null) });
    };
    const timers = [];
    const setTimeout = (fn) => { timers.push(fn); return timers.length; };
    const clearTimeout = () => {};
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', source)(
        window, document, storage, session, fetch, realListStorage(), setTimeout, clearTimeout);
    for (let i = 0; i < 10; i++) await Promise.resolve();
    storage.setItem(key, value);
    expect(timers.length).toBe(1);
    timers[0]();
    // A big body is compressed first, which takes a few turns of the loop.
    for (let i = 0; i < 10; i++) await turn();
    return { writes, m };
}

// turn waits one turn of the event loop, past the script's stubbed timers.
const turn = () => new Promise((r) => globalThis.setTimeout(r, 0));

test('a favorites value that does not parse is not sent, and the flush settles', async () => {
    const { writes, m } = await flushAfterWrite('mtgban_favorites', '{not json');
    expect(writes).toEqual([]);
    expect(m.mtgban_userstate_dirty).toBe('0');
});

test('a recents value that does not parse is not sent either', async () => {
    const { writes } = await flushAfterWrite('mtgban_recent_searches', '[1,');
    expect(writes).toEqual([]);
});

test('a readable favorites value is sent trimmed', async () => {
    const { writes } = await flushAfterWrite('mtgban_favorites', JSON.stringify([{ id: 'x', name: 'X', query: 'q', extra: 1 }]));
    expect(writes.length).toBe(1);
    expect(writes[0].url).toBe('/api/userstate/favorites');
    expect(writes[0].body.data.length).toBe(1);
    expect(writes[0].body.data[0].extra).toBeUndefined();
});

// Hides the page after writing each value, and returns the keepalive flag of
// every PATCH the hide-time flush sends, by section. Each of later hides the
// page again after its own writes; hold keeps every request in flight.
async function keepaliveOnHide(values, later = [], hold = false) {
    const m = {};
    class Storage {
        getItem(k) { return k in m ? m[k] : null; }
        setItem(k, v) { m[k] = String(v); }
        removeItem(k) { delete m[k]; }
    }
    const storage = new Storage();
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const window = { addEventListener() {}, Storage, localStorage: storage };
    const listeners = {};
    const document = {
        documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', visibilityState: 'visible',
        addEventListener: (type, fn) => { listeners[type] = fn; },
    };
    const sent = {};
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PATCH') {
            sent[url.split('/').pop()] = opts.keepalive;
            // A held request stays in flight, its body counted.
            if (hold) return new Promise(() => {});
            return Promise.resolve({ status: 200, ok: true, headers: { get: () => null }, json: () => Promise.resolve({ version: 1 }) });
        }
        return Promise.resolve({ status: 401, ok: false, headers: { get: () => null }, json: () => Promise.resolve(null) });
    };
    const setTimeout = () => 1;
    const clearTimeout = () => {};
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', source)(
        window, document, storage, session, fetch, realListStorage(), setTimeout, clearTimeout);
    for (let i = 0; i < 10; i++) await Promise.resolve();
    for (const next of [values, ...later]) {
        for (const [key, value] of Object.entries(next)) storage.setItem(key, value);
        document.visibilityState = 'hidden';
        listeners.visibilitychange();
        for (let i = 0; i < 10; i++) await turn();
    }
    return sent;
}

test('a hide-time flush sends keepalive only within the browser\'s 64 KiB', async () => {
    const sent = await keepaliveOnHide({
        mtgban_favorites: JSON.stringify([{ id: 'x', name: 'X', query: 'q' }]),
        mtgban_backpack: JSON.stringify(backpackOf(400)),
    });
    expect(sent).toEqual({ favorites: true, backpack: false });
});

test('a later hide counts the keepalive bodies still in flight', async () => {
    const sent = await keepaliveOnHide(
        { mtgban_backpack: JSON.stringify(backpackOf(200)) },
        [{ mtgban_favorites: JSON.stringify(backpackOf(200)) }],
        true);
    expect(sent).toEqual({ backpack: true, favorites: false });
});

// backpackOf is n entries of about 200 bytes each.
function backpackOf(n) {
    const pack = [];
    for (let i = 0; i < n; i++) {
        pack.push({ id: 'uuid-' + i, name: 'Card ' + i, edition: 'Edition', set: 'SET', number: String(i), qty: 1, t: i, m: i,
            img: 'https://cards.scryfall.io/normal/front/0/0/' + 'x'.repeat(60) + i + '.jpg' });
    }
    return pack;
}

test('a big backpack goes gzipped, a small one plain', async () => {
    const big = await flushAfterWrite('mtgban_backpack', JSON.stringify(backpackOf(400)));
    expect(big.writes.map((w) => [w.url, w.gzipped, w.body.data.length])).toEqual([['/api/userstate/backpack', true, 400]]);
    const small = await flushAfterWrite('mtgban_backpack', JSON.stringify(backpackOf(2)));
    expect(small.writes.map((w) => w.gzipped)).toEqual([false]);
});

test('a write refused as too large tells the backpack once until a backpack write lands, a 400 not at all', async () => {
    const m = {};
    class Storage {
        getItem(k) { return k in m ? m[k] : null; }
        setItem(k, v) { m[k] = String(v); }
        removeItem(k) { delete m[k]; }
    }
    const storage = new Storage();
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    let told = 0;
    const window = { addEventListener() {}, Storage, localStorage: storage, syncTooLarge: () => { told++; } };
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    let status = 400;
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PATCH') {
            const ok = status === 200 || (status === 413 && !url.endsWith('/backpack'));
            return Promise.resolve({ status: ok ? 200 : status, ok, headers: { get: () => null }, json: () => Promise.resolve({ version: 1 }) });
        }
        return Promise.resolve({ status: 401, ok: false, headers: { get: () => null }, json: () => Promise.resolve(null) });
    };
    let timers = [];
    const setTimeout = (fn) => { timers.push(fn); return timers.length; };
    const clearTimeout = () => {};
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', source)(
        window, document, storage, session, fetch, realListStorage(), setTimeout, clearTimeout);
    for (let i = 0; i < 10; i++) await Promise.resolve();
    const write = async (n, key = 'mtgban_backpack') => {
        storage.setItem(key, JSON.stringify(key === 'mtgban_backpack' ? backpackOf(n) : [{ id: 'f' + n, name: 'F', query: 'q' }]));
        const due = timers;
        timers = [];
        due.forEach((fn) => fn());
        for (let i = 0; i < 10; i++) await turn();
    };
    await write(1);
    expect(told).toBe(0);
    status = 413;
    await write(2);
    await write(3);
    expect(told).toBe(1);
    // Favorites landing while the backpack is refused does not re-arm it.
    await write(4, 'mtgban_favorites');
    await write(5);
    expect(told).toBe(1);
    status = 200;
    await write(6);
    status = 413;
    await write(7);
    expect(told).toBe(2);
});

test('UserStateSync.flush sends what is queued without waiting, and settles once it lands', async () => {
    const m = {};
    class Storage {
        getItem(k) { return k in m ? m[k] : null; }
        setItem(k, v) { m[k] = String(v); }
        removeItem(k) { delete m[k]; }
    }
    const storage = new Storage();
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const window = { addEventListener() {}, Storage, localStorage: storage };
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    let land;
    const sent = [];
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PATCH') {
            sent.push(url);
            return new Promise((r) => { land = () => r({ status: 200, ok: true, headers: { get: () => null }, json: () => Promise.resolve({ version: 1 }) }); });
        }
        return Promise.resolve({ status: 401, ok: false, headers: { get: () => null }, json: () => Promise.resolve(null) });
    };
    const timers = [];
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', source)(
        window, document, storage, session, fetch, realListStorage(), (fn) => timers.push(fn), () => {});
    for (let i = 0; i < 10; i++) await Promise.resolve();
    storage.setItem('mtgban_backpack', JSON.stringify([{ id: 'a', qty: 1, t: 1, m: 1 }]));
    let settled = false;
    window.UserStateSync.flush().then(() => { settled = true; });
    for (let i = 0; i < 10; i++) await turn();
    expect(sent).toEqual(['/api/userstate/backpack']);
    expect(settled).toBe(false);
    land();
    for (let i = 0; i < 10; i++) await turn();
    expect(settled).toBe(true);
});

test('UserStateSync.flush also waits for a write the debounce already sent', async () => {
    const m = {};
    class Storage {
        getItem(k) { return k in m ? m[k] : null; }
        setItem(k, v) { m[k] = String(v); }
        removeItem(k) { delete m[k]; }
    }
    const storage = new Storage();
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const window = { addEventListener() {}, Storage, localStorage: storage };
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    let land;
    const sent = [];
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PATCH') {
            sent.push(url);
            return new Promise((r) => { land = () => r({ status: 200, ok: true, headers: { get: () => null }, json: () => Promise.resolve({ version: 1 }) }); });
        }
        return Promise.resolve({ status: 401, ok: false, headers: { get: () => null }, json: () => Promise.resolve(null) });
    };
    const timers = [];
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', source)(
        window, document, storage, session, fetch, realListStorage(), (fn) => timers.push(fn), () => {});
    for (let i = 0; i < 10; i++) await Promise.resolve();
    storage.setItem('mtgban_backpack', JSON.stringify([{ id: 'a', qty: 1, t: 1, m: 1 }]));
    timers[timers.length - 1]();
    for (let i = 0; i < 10; i++) await turn();
    expect(sent).toEqual(['/api/userstate/backpack']);
    let settled = false;
    window.UserStateSync.flush().then(() => { settled = true; });
    for (let i = 0; i < 10; i++) await turn();
    expect(sent.length).toBe(1);
    expect(settled).toBe(false);
    land();
    for (let i = 0; i < 10; i++) await turn();
    expect(settled).toBe(true);
});

test('UserStateSync.flush with nothing queued keeps dirty until the write in flight lands', async () => {
    const m = {};
    class Storage {
        getItem(k) { return k in m ? m[k] : null; }
        setItem(k, v) { m[k] = String(v); }
        removeItem(k) { delete m[k]; }
    }
    const storage = new Storage();
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const window = { addEventListener() {}, Storage, localStorage: storage };
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    let fail;
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PATCH') {
            return new Promise((r) => { fail = () => r({ status: 500, ok: false, headers: { get: () => null }, json: () => Promise.resolve(null) }); });
        }
        return Promise.resolve({ status: 401, ok: false, headers: { get: () => null }, json: () => Promise.resolve(null) });
    };
    const timers = [];
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', 'console', source)(
        window, document, storage, session, fetch, realListStorage(), (fn) => timers.push(fn), () => {}, { warn() {} });
    for (let i = 0; i < 10; i++) await Promise.resolve();
    storage.setItem('mtgban_backpack', JSON.stringify([{ id: 'a', qty: 1, t: 1, m: 1 }]));
    expect(m.mtgban_userstate_dirty).toBe('1');
    timers[timers.length - 1]();
    for (let i = 0; i < 10; i++) await turn();
    let settled = false;
    window.UserStateSync.flush().then(() => { settled = true; });
    for (let i = 0; i < 10; i++) await turn();
    expect(settled).toBe(false);
    expect(m.mtgban_userstate_dirty).toBe('1');
    fail();
    for (let i = 0; i < 10; i++) await turn();
    expect(settled).toBe(true);
    expect(m.mtgban_userstate_dirty).toBe('1');
});

test('a flush that throws does not stop the next one from sending', async () => {
    const m = {};
    class Storage {
        getItem(k) { return k in m ? m[k] : null; }
        setItem(k, v) { m[k] = String(v); }
        removeItem(k) { delete m[k]; }
    }
    const storage = new Storage();
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const window = { addEventListener() {}, Storage, localStorage: storage };
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    const sent = [];
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PATCH') {
            sent.push(url);
            return Promise.resolve({ status: 200, ok: true, headers: { get: () => null }, json: () => Promise.resolve({ version: 1 }) });
        }
        return Promise.resolve({ status: 401, ok: false, headers: { get: () => null }, json: () => Promise.resolve(null) });
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', source)(
        window, document, storage, session, fetch, realListStorage(), () => 1, () => {});
    for (let i = 0; i < 10; i++) await Promise.resolve();
    // A null entry throws in trimBackpack, before the write's own catch.
    storage.setItem('mtgban_backpack', '[null]');
    await window.UserStateSync.flush().catch(() => {});
    expect(sent).toEqual([]);
    expect(m.mtgban_userstate_dirty).toBe('1');
    storage.setItem('mtgban_favorites', JSON.stringify([{ id: 'x', name: 'X', query: 'q' }]));
    await window.UserStateSync.flush();
    expect(sent).toEqual(['/api/userstate/favorites']);
    // The backpack that threw never landed, so the state stays dirty.
    expect(m.mtgban_userstate_dirty).toBe('1');
});

test('a keepalive write that fails is sent again by the next flush', async () => {
    const m = {};
    class Storage {
        getItem(k) { return k in m ? m[k] : null; }
        setItem(k, v) { m[k] = String(v); }
        removeItem(k) { delete m[k]; }
    }
    const storage = new Storage();
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const listeners = {};
    const window = { addEventListener(type, fn) { listeners[type] = fn; }, Storage, localStorage: storage };
    const document = { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} };
    const sent = [];
    let failing = true;
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PATCH') {
            sent.push(url);
            const ok = !failing;
            return Promise.resolve({ status: ok ? 200 : 500, ok, headers: { get: () => null }, json: () => Promise.resolve({ version: 1 }) });
        }
        return Promise.resolve({ status: 401, ok: false, headers: { get: () => null }, json: () => Promise.resolve(null) });
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', source)(
        window, document, storage, session, fetch, realListStorage(), () => 1, () => {});
    for (let i = 0; i < 10; i++) await Promise.resolve();
    // The tab is hidden with a favorite queued, and its keepalive write fails.
    storage.setItem('mtgban_favorites', JSON.stringify([{ id: 'x', name: 'X', query: 'q' }]));
    listeners.pagehide();
    for (let i = 0; i < 10; i++) await Promise.resolve();
    expect(sent).toEqual(['/api/userstate/favorites']);
    failing = false;
    // Back on the page, an edit elsewhere flushes the favorite again with it.
    storage.setItem('mtgban_recent_searches', JSON.stringify([{ query: 'bolt' }]));
    await window.UserStateSync.flush();
    expect(sent.filter((u) => u.endsWith('/favorites')).length).toBe(2);
    expect(m.mtgban_userstate_dirty).toBe('0');
});
