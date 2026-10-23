import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/alerts.js', import.meta.url), 'utf8');

// Loads js/alerts.js as tests/alerts-channels.test.js does: a stub window
// and document, so the IIFE registers its listener and exports its helpers.
function load(window = {}) {
    const document = {
        addEventListener: function () {},
        getElementById: function () { return null; },
    };
    new Function('window', 'document', source)(window, document);
    return window.alertsChannels;
}

function loadSort(window = {}) {
    load(window);
    return window.alertsSort;
}

// memoryStorage is the slice of localStorage the sort reads and writes.
function memoryStorage() {
    const items = {};
    return {
        items,
        getItem: k => (k in items ? items[k] : null),
        setItem: (k, v) => { items[k] = String(v); },
    };
}

test('deleteAllPrompt names the count and warns it is final', () => {
    const h = load();
    expect(h.deleteAllPrompt(3)).toBe('Delete all 3 alerts? This cannot be undone.');
    expect(h.deleteAllPrompt(1)).toBe('Delete your only alert? This cannot be undone.');
});

test('deletedNote speaks only when the server deleted another count', () => {
    const h = load();
    expect(h.deletedNote(3, 3)).toBe('');
    expect(h.deletedNote(3, undefined)).toBe('');
    expect(h.deletedNote(3, 4)).toBe('Deleted 4 alerts');
    expect(h.deletedNote(3, 1)).toBe('Deleted 1 alert');
});

test('existingForCard lists the card\'s alerts in create mode only', () => {
    const h = load();
    const existing = [
        { id: 1, card_id: 'card-1' },
        { id: 2, card_id: 'card-2' },
        { id: 3, card_id: 'card-1' },
    ];
    expect(h.existingForCard(existing, 'card-1', null).map(a => a.id)).toEqual([1, 3]);
    expect(h.existingForCard(existing, 'card-3', null)).toEqual([]);
    // Edit mode shows the form alone; the box above it stays hidden.
    expect(h.existingForCard(existing, 'card-1', '1')).toEqual([]);
    expect(h.existingForCard(null, 'card-1', null)).toEqual([]);
});

test('bestPrice is the best offer on the side in the condition among the checked stores', () => {
    const h = load();
    const stores = [
        { shorthand: 'CK', prices: { NM: 0.63, SP: 0.5 } },
        { shorthand: 'CSI', prices: { NM: 0.02 } },
        { shorthand: 'SCG', prices: {} },
        { shorthand: 'ABU', prices: null },
    ];
    expect(h.bestPrice(stores, 'retail', 'NM', [])).toBe(0.02);
    expect(h.bestPrice(stores, 'retail', 'NM', ['ck', 'SCG'])).toBe(0.63);
    expect(h.bestPrice(stores, 'retail', 'SP', [])).toBe(0.5);
    expect(h.bestPrice(stores, 'retail', 'HP', [])).toBe(null);
    expect(h.bestPrice(stores, 'retail', 'NM', ['SCG'])).toBe(null);
    // A buylist's best offer is its highest, as the server defaults it.
    expect(h.bestPrice(stores, 'buylist', 'NM', [])).toBe(0.63);
    expect(h.bestPrice(stores, 'buylist', 'NM', ['CSI'])).toBe(0.02);
    expect(h.bestPrice(stores, 'buylist', 'HP', [])).toBe(null);
    // A picked-only store counts only once it is checked.
    const withNet = stores.concat([{ shorthand: 'TCGDirectNet', prices: { NM: 3.3 }, picked_only: true }]);
    expect(h.bestPrice(withNet, 'buylist', 'NM', [])).toBe(0.63);
    expect(h.bestPrice(withNet, 'buylist', 'NM', ['TCGDirectNet'])).toBe(3.3);
});

test('storesNote names the stores watching every one leaves out', () => {
    const h = load();
    expect(h.storesNote([{ shorthand: 'CK', name: 'Card Kingdom' }])).toBe('leave all unchecked to watch every one');
    expect(h.storesNote([
        { shorthand: 'CK', name: 'Card Kingdom' },
        { shorthand: 'TCGDirectNet', name: 'TCG Direct (net)', picked_only: true },
    ])).toBe('leave all unchecked to watch every one but TCG Direct (net)');
    expect(h.storesNote(null)).toBe('leave all unchecked to watch every one');
});

test('referenceUsed only for a percentage threshold', () => {
    const h = load();
    expect(h.referenceUsed('', '')).toBe(false);
    expect(h.referenceUsed('abs', 'abs')).toBe(false);
    expect(h.referenceUsed('pct', '')).toBe(true);
    expect(h.referenceUsed('abs', 'pct')).toBe(true);
});

test('parseSort takes a known field and direction, else the server order', () => {
    const h = loadSort();
    expect(h.parseSort('name:asc')).toEqual({ field: 'name', dir: 'asc' });
    expect(h.parseSort('fired:desc')).toEqual({ field: 'fired', dir: 'desc' });
    for (const v of [null, '', 'name', 'name:up', 'price:asc', 'name:asc:x']) {
        expect(h.parseSort(v)).toEqual({ field: 'created', dir: 'desc' });
    }
});

test('the sort is saved and read back through localStorage', () => {
    const storage = memoryStorage();
    const h = loadSort({ localStorage: storage });
    expect(h.loadSort()).toEqual({ field: 'created', dir: 'desc' });
    h.saveSort({ field: 'now', dir: 'asc' });
    expect(storage.items.alertsSort).toBe('now:asc');
    expect(h.loadSort()).toEqual({ field: 'now', dir: 'asc' });
    storage.items.alertsSort = 'bogus';
    expect(h.loadSort()).toEqual({ field: 'created', dir: 'desc' });
});

test('the sort falls back to the server order when storage throws', () => {
    const window = {};
    Object.defineProperty(window, 'localStorage', { get() { throw new Error('denied'); } });
    const h = loadSort(window);
    expect(h.loadSort()).toEqual({ field: 'created', dir: 'desc' });
    expect(() => h.saveSort({ field: 'name', dir: 'asc' })).not.toThrow();
    const broken = { getItem() { throw new Error('quota'); }, setItem() { throw new Error('quota'); } };
    const g = loadSort({ localStorage: broken });
    expect(g.loadSort()).toEqual({ field: 'created', dir: 'desc' });
    expect(() => g.saveSort({ field: 'name', dir: 'asc' })).not.toThrow();
});

test('alertSortData reads the row attributes, empty ones as null', () => {
    const h = loadSort();
    const attrs = {
        'data-id': '7', 'data-name': 'Mox Opal', 'data-side': 'buylist', 'data-status': 'paused',
        'data-now': '12.50', 'data-created': '1700000000', 'data-fired': '',
    };
    const tr = { getAttribute: k => (k in attrs ? attrs[k] : null) };
    expect(h.alertSortData(tr)).toEqual({
        id: 7, name: 'Mox Opal', side: 'buylist', status: 'paused',
        now: 12.5, created: 1700000000, fired: null,
    });
});

// The server's order: newest first.
const ROWS = [
    { id: 5, name: 'mox opal', side: 'retail', status: 'active', now: 80, created: 500, fired: null },
    { id: 4, name: 'Black Lotus', side: 'buylist', status: 'unresolvable', now: null, created: 400, fired: 40 },
    { id: 3, name: 'Card 10', side: 'buylist', status: 'paused', now: 5, created: 300, fired: 90 },
    { id: 2, name: 'Card 9', side: 'retail', status: 'over_allowance', now: 80, created: 200, fired: null },
    { id: 1, name: 'Mox Opal', side: 'buylist', status: 'active', now: 0.25, created: 100, fired: 60 },
];

function ids(h, field, dir) {
    return h.sortAlerts(ROWS, { field, dir }).map(r => r.id);
}

test('sortAlerts orders each field both ways, ties in the server order', () => {
    const h = loadSort();
    expect(ids(h, 'created', 'desc')).toEqual([5, 4, 3, 2, 1]);
    expect(ids(h, 'created', 'asc')).toEqual([1, 2, 3, 4, 5]);
    // Case-blind, numbers by value; the two Mox Opals keep the server order.
    expect(ids(h, 'name', 'asc')).toEqual([4, 2, 3, 5, 1]);
    expect(ids(h, 'name', 'desc')).toEqual([5, 1, 3, 2, 4]);
    expect(ids(h, 'side', 'asc')).toEqual([4, 3, 1, 5, 2]);
    expect(ids(h, 'side', 'desc')).toEqual([5, 2, 4, 3, 1]);
    expect(ids(h, 'status', 'asc')).toEqual([5, 1, 3, 2, 4]);
    expect(ids(h, 'status', 'desc')).toEqual([4, 2, 3, 5, 1]);
});

test('sortAlerts puts a row with no offer or no firing last either way', () => {
    const h = loadSort();
    expect(ids(h, 'now', 'desc')).toEqual([5, 2, 3, 1, 4]);
    expect(ids(h, 'now', 'asc')).toEqual([1, 3, 5, 2, 4]);
    expect(ids(h, 'fired', 'desc')).toEqual([3, 1, 4, 5, 2]);
    expect(ids(h, 'fired', 'asc')).toEqual([4, 1, 3, 5, 2]);
    // The input is left as it was.
    expect(ROWS.map(r => r.id)).toEqual([5, 4, 3, 2, 1]);
});
