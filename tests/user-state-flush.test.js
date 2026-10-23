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
    const fetch = (url, opts) => {
        if (opts && opts.method === 'PATCH') {
            writes.push({ url, body: JSON.parse(opts.body) });
            return Promise.resolve({ status: 200, ok: true, headers: { get: () => null }, json: () => Promise.resolve({ version: 1 }) });
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
    for (let i = 0; i < 20; i++) await Promise.resolve();
    return { writes, m };
}

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
