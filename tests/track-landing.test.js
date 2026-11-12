import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { loadMetrics, el, dispatch } from './metrics-loader.js';
import { trackProblems, trackText } from './track-registry.js';

const favorites = readFileSync(new URL('../js/favorites.js', import.meta.url), 'utf8');

const count = (html, s) => html.split(s).length - 1;
const run = (name, value) => 'data-track="' + name + '"' + (value ? ' data-track-value="' + value + '"' : '');

// stub is an element whose attributes live in attrs and whose classes live in a set.
function stub(attrs) {
    const classes = new Set();
    const handlers = {};
    return {
        attrs, handlers, dataset: {},
        getAttribute: (k) => (k in attrs ? attrs[k] : null),
        setAttribute: (k, v) => { attrs[k] = String(v); },
        addEventListener: (type, fn) => { handlers[type] = fn; },
        classList: {
            add: (c) => classes.add(c),
            remove: (c) => classes.delete(c),
            contains: (c) => classes.has(c),
            toggle: (c, on) => { if (on === undefined ? !classes.has(c) : on) classes.add(c); else classes.delete(c); },
        },
    };
}

// container is a pane favorites.js renders into; items answers its drag-and-drop query.
function container(id, chartsEnabled, items = []) {
    return {
        id, innerHTML: '', dataset: { chartsEnabled: chartsEnabled ? 'true' : 'false' },
        querySelector: () => null,
        querySelectorAll: (sel) => (sel.indexOf('draggable') >= 0 ? items : []),
    };
}

// runFavorites loads favorites.js over a page with the given panes, stars and stored list.
function runFavorites({ favs = [], panes = {}, stars = [], sort = {}, BAN, confirmDialog } = {}) {
    let list = favs.map((f) => ({ ...f }));
    const sortValues = new Map(Object.entries(sort));
    const document = {
        readyState: 'complete', documentElement: { dataset: {} },
        addEventListener: () => {},
        getElementById: (id) => panes[id] || null,
        querySelector: () => null,
        querySelectorAll: (sel) => (sel.indexOf('fav-btn') >= 0 ? stars : []),
        createElement: () => ({ style: {}, classList: { add: () => {}, remove: () => {} } }),
    };
    const window = {
        location: { origin: 'https://ban.test' }, addEventListener: () => {},
        CardRow: { read: () => ({ id: 'c1', t: 1 }) },
    };
    if (BAN) window.BAN = BAN;
    if (confirmDialog) window.confirmDialog = confirmDialog;
    const ListStorage = {
        read: () => list.map((f) => ({ ...f })),
        save: (_, next) => { list = next.map((f) => ({ ...f })); },
        isLive: (f) => !f.del,
        pinnedFirst: (l) => l.filter((f) => f.pinned).concat(l.filter((f) => !f.pinned)),
        tombstones: () => [],
    };
    const localStorage = {
        getItem: (k) => (sortValues.has(k) ? sortValues.get(k) : null),
        setItem: (k, v) => sortValues.set(k, String(v)),
        removeItem: (k) => sortValues.delete(k),
    };
    new Function('window', 'document', 'localStorage', 'fetch', 'navigator', 'location', 'ListStorage', 'escapeAttr', 'escapeHtml', 'setTimeout', 'requestIdleCallback',
        favorites)(window, document, localStorage, () => Promise.reject(new Error('offline')), {}, window.location, ListStorage, String, String, () => 0, undefined);
    return { window, list: () => list };
}

// nine favorites, the fifth pinned, each field a reader's list holds seeded with text no count may carry.
function nine() {
    const out = [];
    for (let i = 0; i < 9; i++) {
        out.push({
            id: 'zzid' + i, name: 'zzname' + i, set: 'zzset', query: 'zzquery' + i, t: 100 - i, pinned: i === 4 ? 5 : undefined,
            number: 'zznum', edition: 'zzedition', finishTag: 'zzfinish', finishClass: 'zzclass', treatments: ['zztreat'],
            sellVendor: 'zzsell', buyVendor: 'zzbuy', sellPrice: 1, buyPrice: 1,
        });
    }
    return out;
}

test('the desktop pane marks every control', () => {
    const pane = container('desktop-favorites', true);
    runFavorites({ favs: nine(), panes: { 'desktop-favorites': pane } });
    const html = pane.innerHTML;
    expect(count(html, run('ui.fav', 'open'))).toBe(8);
    expect(count(html, run('ui.fav', 'pin'))).toBe(7);
    expect(count(html, run('ui.fav', 'unpin'))).toBe(1);
    expect(count(html, run('ui.fav', 'delete'))).toBe(8);
    expect(count(html, run('ui.fav', 'page'))).toBe(2);
    expect(count(html, run('ui.fav', 'refresh'))).toBe(1);
    expect(count(html, run('ui.fav.csv', 'download'))).toBe(1);
    expect(count(html, run('ui.fav.csv', 'import'))).toBe(1);
    expect(count(html, run('ui.fav.upload', 'retail'))).toBe(1);
    expect(count(html, run('ui.fav.upload', 'buylist'))).toBe(1);
    expect(count(html, 'data-track="ui.fav.chart"')).toBe(1);
    expect(trackProblems(html)).toEqual([]);
    expect(html).toContain('zzquery0');
    expect(trackText(html)).not.toContain('zz');
});

test('the mobile pane marks entries, pins and refresh', () => {
    const pane = container('m-favorites', false);
    runFavorites({ favs: nine(), panes: { 'm-favorites': pane } });
    const html = pane.innerHTML;
    expect(count(html, run('ui.fav', 'open'))).toBe(9);
    expect(count(html, run('ui.fav', 'pin'))).toBe(8);
    expect(count(html, run('ui.fav', 'unpin'))).toBe(1);
    expect(count(html, run('ui.fav', 'refresh'))).toBe(1);
    expect(html).not.toContain('data-track-value="delete"');
    expect(html).not.toContain('ui.fav.csv');
    expect(trackProblems(html)).toEqual([]);
});

test('the empty state still offers the import', () => {
    const pane = container('desktop-favorites', true);
    runFavorites({ panes: { 'desktop-favorites': pane } });
    expect(count(pane.innerHTML, run('ui.fav.csv', 'import'))).toBe(1);
    expect(count(pane.innerHTML, 'data-track=')).toBe(1);
});

test('a sort pill counts the direction it left', () => {
    const calls = [];
    const { window } = runFavorites({ sort: { mtgban_fav_sort: 'chrono', mtgban_fav_sort_dir: 'desc' }, BAN: { track: (...a) => calls.push(a) } });
    window.cycleFavSort('chrono');
    window.cycleFavSort('sell');
    expect(calls).toEqual([['ui.fav.sort', 'chrono', 'asc'], ['ui.fav.sort', 'sell', 'desc']]);
});

test('a star counts add then remove', () => {
    const calls = [];
    const btn = stub({ 'data-card-id': 'c1', 'data-track': 'ui.result.icon', 'data-track-value': 'star_add' });
    const { window } = runFavorites({ stars: [btn], BAN: { track: (...a) => calls.push(a) } });
    window.toggleFavorite(btn);
    expect(btn.getAttribute('data-track-value')).toBe('star_remove');
    window.toggleFavorite(btn);
    expect(btn.getAttribute('data-track-value')).toBe('star_add');
    expect(calls).toEqual([['ui.fav', 'add'], ['ui.fav', 'remove']]);
});

test('marking stars at load counts nothing', () => {
    const calls = [];
    const btn = stub({ 'data-card-id': 'c1', 'data-track': 'ui.result.icon', 'data-track-value': 'star_add' });
    runFavorites({ favs: [{ id: 'c1', t: 1 }], stars: [btn], BAN: { track: (...a) => calls.push(a) } });
    expect(calls).toEqual([]);
    expect(btn.getAttribute('data-track-value')).toBe('star_remove');
});

test('clearing counts when it is confirmed, and clears with no BAN', () => {
    const calls = [];
    let kept = null;
    const pane = container('desktop-favorites', true);
    const page = runFavorites({ favs: nine(), panes: { 'desktop-favorites': pane }, BAN: { track: (...a) => calls.push(a) }, confirmDialog: (msg, cb) => { kept = cb; } });
    page.window.clearFavorites({ closest: () => null });
    expect(calls).toEqual([]);
    kept();
    expect(calls).toEqual([['ui.fav', 'clear']]);
    expect(page.list().filter((f) => !f.del)).toEqual([]);

    const bare = runFavorites({ favs: nine() });
    bare.window.clearFavorites({ closest: () => null });
    expect(bare.list().filter((f) => !f.del)).toEqual([]);
});

test('a drop that reorders counts once', () => {
    const calls = [];
    const a = stub({});
    a.dataset.favId = 'zzid0';
    a.querySelector = () => null;
    const b = stub({});
    b.dataset.favId = 'zzid1';
    b.querySelector = () => null;
    const pane = container('desktop-favorites', true, [a, b]);
    const page = runFavorites({ favs: nine(), panes: { 'desktop-favorites': pane }, BAN: { track: (...x) => calls.push(x) } });
    const ev = { preventDefault: () => {}, dataTransfer: { setData: () => {} } };
    a.handlers.dragstart(ev);
    b.handlers.drop(ev);
    expect(calls).toEqual([['ui.fav', 'reorder']]);
    expect(page.list().map((f) => f.id).slice(0, 2)).toEqual(['zzid1', 'zzid0']);
    a.handlers.dragend();
    b.handlers.drop(ev); // a drop with no drag under way moves nothing
    expect(calls.length).toBe(1);
});

// A pin or remove button sits inside the entry's anchor: the button's own name wins.
test('a button inside an entry counts as the button', () => {
    const page = loadMetrics({ cfg: { on: true, page: '', build: 'abc' } });
    const entry = el({ 'data-track': 'ui.fav', 'data-track-value': 'open', href: '?q=x' }, null, 'a');
    const pin = el({ 'data-track': 'ui.fav', 'data-track-value': 'pin' }, entry, 'button');
    const icon = el({}, pin, 'svg');
    pin.handlers.push((ev) => ev.stopPropagation());
    dispatch(page, 'click', icon);
    page.hide();
    expect(page.sent().map((e) => [e.n, e.v, e.c])).toEqual([['ui.fav', 'pin', 1]]);
});

// The shared list has its own two names; the owner's list names stay off it.
test('the shared page marks Merge and its entries only', () => {
    for (const file of ['../templates/favorites-shared.html', '../templates/mobile/favorites-shared.html']) {
        const src = readFileSync(new URL(file, import.meta.url), 'utf8');
        const merge = src.match(/<[^>]*id="shared-merge"[^>]*>/);
        expect(merge).not.toBeNull();
        expect(merge[0]).toContain('data-track="ui.fav.merge"');
        expect(count(src, 'data-track="ui.fav.shared_open"')).toBe(1);
        expect(src).not.toContain('data-track="ui.fav"');
        expect(src).not.toContain('data-track-value');
    }
});
