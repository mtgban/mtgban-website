import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'favorites.js'), 'utf8');

// loadFavorites runs favorites.js with one stored favorite and a stubbed
// fetch; answer(url) is the response. The toast's text is what the reader sees.
function loadFavorites(answer) {
    const calls = [];
    const toast = { textContent: '', classList: { add() {}, remove() {} } };
    const window = { addEventListener() {} };
    const document = {
        readyState: 'loading',
        addEventListener() {},
        getElementById: (id) => (id === 'desktop-fav-toast' ? toast : null),
        querySelectorAll: () => [],
    };
    const store = [{ id: 'ban:1', t: 1, sellPrice: 2, buyPrice: 1 }];
    const ListStorage = { read: () => store, save() {}, isLive: () => true };
    const localStorage = { getItem: () => null, setItem() {} };
    const fetch = (url) => {
        calls.push(url);
        return Promise.resolve(answer(url));
    };
    new Function('window', 'document', 'ListStorage', 'localStorage', 'fetch', source)(
        window, document, ListStorage, localStorage, fetch);
    return { window, toast, calls };
}

const settle = () => new Promise((r) => setTimeout(r, 0));

// /data/prices/ refuses with a status: the toast names it rather than saying
// the prices are up to date, and the button is not locked for an hour.
test('a refused manual refresh says why and can be tried again', async () => {
    for (const [status, want] of [[429, 'Too many requests'], [401, 'Signed out'], [503, 'Could not refresh']]) {
        const { window, toast, calls } = loadFavorites(() => ({ ok: false, status }));
        window.manualRefreshFavorites();
        await settle();
        expect(toast.textContent).toContain(want);
        window.manualRefreshFavorites();
        await settle();
        expect(calls.length).toBe(2);
    }
});

test('an answered manual refresh still reports its result, once an hour', async () => {
    const { window, toast, calls } = loadFavorites(() => ({ ok: true, json: () => Promise.resolve({}) }));
    window.manualRefreshFavorites();
    await settle();
    expect(toast.textContent).toBe('Prices are up to date');
    window.manualRefreshFavorites();
    await settle();
    expect(calls).toEqual(['/data/prices/ban%3A1']);
});
