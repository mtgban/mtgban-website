import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/command-palette.js', import.meta.url), 'utf8');
const utils = readFileSync(new URL('../js/utils.js', import.meta.url), 'utf8');

// An element that takes any call or property the palette reaches for, and
// keeps what it was given: values set, listeners added, and one stable child
// per selector, so the input and the results list are the same object each
// time the palette looks them up.
function fakeElement() {
    const state = { value: '', innerHTML: '', textContent: '', style: {}, handlers: {}, children: {} };
    state.classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
    state.addEventListener = (type, fn) => { state.handlers[type] = fn; };
    state.querySelector = sel => state.children[sel] || (state.children[sel] = fakeElement());
    state.querySelectorAll = () => [];
    // Anything else is another such element, which can also be called.
    return new Proxy(function () {}, {
        get(target, prop) {
            if (typeof prop === 'symbol') return undefined;
            if (!(prop in state)) state[prop] = fakeElement();
            return state[prop];
        },
        set(target, prop, value) { state[prop] = value; return true; },
        apply: () => fakeElement(),
    });
}

// Opens the palette's recent view over a stored list, and presses Enter on
// its first row. Hands back the row's markup, where it went, and the list.
function runRecent(stored) {
    const values = new Map([['mtgban_recent_searches', JSON.stringify(stored)]]);
    const localStorage = {
        getItem: key => values.get(key) || null,
        setItem: (key, value) => values.set(key, value),
    };
    // The first element the palette makes is its overlay, which holds the
    // input and the results list.
    let overlay;
    const document = {
        body: fakeElement(),
        head: fakeElement(),
        activeElement: null,
        createElement: () => {
            const el = fakeElement();
            if (!overlay) overlay = el;
            return el;
        },
        getElementById: () => null,
        querySelector: () => null,
        querySelectorAll: () => [],
        addEventListener: () => {},
    };
    const location = { href: '', pathname: '/search', search: '' };
    const window = {
        __BAN_PALETTE: { nav: [] },
        innerWidth: 1280,
        location,
        addEventListener: () => {},
    };
    const setTimeout = fn => { fn(); return 0; };
    new Function('window', 'document', 'localStorage', 'location', 'setTimeout', 'clearTimeout', utils + '\n' + source)(
        window, document, localStorage, location, setTimeout, () => {});

    const input = overlay.querySelector('#cp-input');
    input.value = '<';
    input.handlers.input();
    const html = overlay.querySelector('#cp-results').innerHTML;
    input.handlers.keydown({ key: 'Enter', preventDefault() {} });
    return { html, href: location.href, searches: JSON.parse(values.get('mtgban_recent_searches')) };
}

test('a recent search run under a pinned bar runs again under it', () => {
    const { html, href, searches } = runRecent([{ q: 'bolt', sc: 's:sos', t: 1 }]);
    expect(html).toContain('Recent search in s:sos');
    expect(href).toBe('/search?q=bolt&scope=s%3Asos');
    expect(searches[0]).toMatchObject({ q: 'bolt', sc: 's:sos' });
});

test('a recent search with no bar runs by its query alone', () => {
    const { html, href, searches } = runRecent([{ q: 'bolt', t: 1 }]);
    expect(html).toContain('Recent search');
    expect(html).not.toContain('Recent search in');
    expect(href).toBe('/search?q=bolt');
    expect(searches[0].sc).toBeUndefined();
});
