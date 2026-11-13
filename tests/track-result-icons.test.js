import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const favorites = readFileSync(new URL('../js/favorites.js', import.meta.url), 'utf8');
const quickIcons = readFileSync(new URL('../js/search-quick-icons.js', import.meta.url), 'utf8');

// stub is an element whose attributes live in attrs and whose classes live in a set.
function stub(attrs) {
    const classes = new Set();
    const handlers = {};
    return {
        attrs, handlers,
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

// runFavorites loads favorites.js over a page holding one star, with a list kept in memory.
function runFavorites(btn) {
    let list = [];
    const document = {
        readyState: 'complete', documentElement: { dataset: {} },
        addEventListener: () => {},
        getElementById: () => null,
        querySelector: () => null,
        querySelectorAll: (sel) => (sel.indexOf('fav-btn') >= 0 ? [btn] : []),
        createElement: () => ({ style: {}, classList: { add: () => {}, remove: () => {} } }),
    };
    const window = {
        location: { origin: 'https://ban.test' }, addEventListener: () => {},
        CardRow: { read: () => ({ id: 'c1', t: 1 }) },
    };
    const ListStorage = {
        read: () => list.map((f) => ({ ...f })),
        save: (_, favs) => { list = favs.map((f) => ({ ...f })); },
        isLive: (f) => !f.del, pinnedFirst: (l) => l, tombstones: () => [],
    };
    const localStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
    new Function('window', 'document', 'localStorage', 'fetch', 'navigator', 'location', 'ListStorage', 'escapeAttr', 'escapeHtml', 'setTimeout',
        favorites)(window, document, localStorage, () => Promise.reject(new Error('offline')), {}, window.location, ListStorage, String, String, () => 0);
    return window;
}

test('a star says what its next click does', () => {
    const btn = stub({ 'data-card-id': 'c1', 'data-track': 'ui.result.icon', 'data-track-value': 'star_add' });
    const window = runFavorites(btn);
    window.toggleFavorite(btn);
    expect(btn.classList.contains('active')).toBe(true);
    expect(btn.getAttribute('data-track-value')).toBe('star_remove');
    window.toggleFavorite(btn);
    expect(btn.classList.contains('active')).toBe(false);
    expect(btn.getAttribute('data-track-value')).toBe('star_add');
});

test('a star with no data-track is left alone', () => {
    const btn = stub({ 'data-card-id': 'c1' });
    const window = runFavorites(btn);
    window.toggleFavorite(btn);
    expect(btn.classList.contains('active')).toBe(true);
    expect(btn.getAttribute('data-track-value')).toBeNull();
});

test('the kebab moves a group\'s icons to the menu scope and back', () => {
    const icons = [
        stub({ 'data-track': 'ui.result.icon', 'data-track-value': 'scryfall', 'data-track-scope': 'header' }),
        stub({ 'data-track': 'ui.result.icon', 'data-track-value': 'bell', 'data-track-scope': 'header' }),
    ];
    const toggle = stub({});
    const actions = stub({});
    actions.querySelectorAll = () => [];
    const group = stub({});
    group.querySelector = (sel) => (sel === '.qi-toggle' ? toggle : sel === '.qi-actions' ? actions : null);
    group.querySelectorAll = (sel) => (sel === '[data-track="ui.result.icon"]' ? icons : []);
    const docHandlers = {};
    const document = {
        querySelectorAll: (sel) => (sel === '.result-quick-icons' ? [group] : []),
        addEventListener: (type, fn) => { docHandlers[type] = fn; },
        createElement: () => ({}),
    };
    new Function('document', quickIcons)(document);

    toggle.handlers.click({ stopPropagation: () => {} });
    expect(icons.map((i) => i.getAttribute('data-track-scope'))).toEqual(['menu', 'menu']);
    docHandlers.click({});
    expect(icons.map((i) => i.getAttribute('data-track-scope'))).toEqual(['header', 'header']);
    // A pick from the open menu closes it, and the next inline click is the header's again.
    toggle.handlers.click({ stopPropagation: () => {} });
    actions.handlers.click({});
    expect(icons.map((i) => i.getAttribute('data-track-scope'))).toEqual(['header', 'header']);
});
