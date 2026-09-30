import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/list-storage.js', import.meta.url), 'utf8');

function load() {
    const values = new Map();
    const localStorage = {
        getItem: (key) => (values.has(key) ? values.get(key) : null),
        setItem: (key, value) => values.set(key, value),
    };
    const ListStorage = new Function('localStorage', source + '\nreturn ListStorage;')(localStorage);
    return { ListStorage, values };
}

const DAY = 24 * 60 * 60 * 1000;

test('save caps the live entries and keeps the recent tombstones, newest first', () => {
    const { ListStorage, values } = load();
    const now = Date.now();
    ListStorage.save('k', [
        { q: 'a', t: 3 },
        { q: 'gone', t: 1, del: now - 2 * DAY, m: now - 2 * DAY },
        { q: 'b', t: 2 },
        { q: 'expired', t: 1, del: now - 31 * DAY, m: now - 31 * DAY },
        { q: 'c', t: 1 },
        { q: 'newer', t: 1, del: now - DAY, m: now - DAY },
    ], 2);
    expect(JSON.parse(values.get('k')).map((x) => x.q)).toEqual(['a', 'b', 'newer', 'gone']);
});

test('at most 50 tombstones are kept', () => {
    const { ListStorage } = load();
    const now = Date.now();
    const tombs = Array.from({ length: 60 }, (_, i) => ({ q: 'q' + i, del: now - i, m: now - i }));
    const kept = ListStorage.tombstones(tombs);
    expect(kept).toHaveLength(50);
    expect(kept[0].q).toBe('q0');
    expect(kept[49].q).toBe('q49');
});

test('read answers an empty list for a missing or unreadable key', () => {
    const { ListStorage, values } = load();
    expect(ListStorage.read('missing')).toEqual([]);
    values.set('bad', '{not json');
    expect(ListStorage.read('bad')).toEqual([]);
});

test('pinnedFirst puts the latest pin on top and keeps the rest in order', () => {
    const { ListStorage } = load();
    const list = [{ q: 'a' }, { q: 'b', pinned: 1 }, { q: 'c' }, { q: 'd', pinned: 2 }];
    expect(ListStorage.pinnedFirst(list).map((x) => x.q)).toEqual(['d', 'b', 'a', 'c']);
});
