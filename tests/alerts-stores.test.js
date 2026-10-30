import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/alerts.js', import.meta.url), 'utf8');

// A stand-in for any element the modal touches, as in
// alerts-open-race.test.js, but keeping the children appended to it.
function element() {
    const classes = new Set();
    const attrs = {};
    const found = {};
    const el = {
        children: [],
        textContent: '', value: '', title: '', className: '', hidden: false, disabled: false,
        classList: {
            add: c => classes.add(c), remove: c => classes.delete(c),
            toggle: (c, on) => { on ? classes.add(c) : classes.delete(c); },
            contains: c => classes.has(c),
        },
        getAttribute: name => (name in attrs ? attrs[name] : null),
        setAttribute: (name, v) => { attrs[name] = String(v); },
        querySelector: sel => found[sel] || (found[sel] = element()),
        querySelectorAll: () => [],
        appendChild: child => { el.children.push(child); },
        focus: () => {}, contains: () => true, addEventListener: () => {},
    };
    Object.defineProperty(el, 'innerHTML', { set: () => { el.children = []; } });
    el.elements = new Proxy({}, { get: (t, name) => t[name] || (t[name] = element()) });
    return el;
}

// Opens the modal over stand-ins with the stores given, answering each
// request in turn, and returns the store list's columns.
async function renderStores(stores) {
    const byId = {};
    const document = {
        addEventListener: () => {},
        getElementById: id => (id.startsWith('alerts-') ? null : byId[id] || (byId[id] = element())),
        querySelector: () => null,
        querySelectorAll: () => [],
        createElement: () => element(),
        body: element(),
    };
    const answers = [{ card: { name: 'Card', set: 'SET', number: '1', finish: 'nonfoil' }, conditions: ['NM'], stores }, [], []];
    const fetch = () => Promise.resolve({
        status: 200, ok: true,
        headers: { get: () => 'application/json' },
        json: () => Promise.resolve(answers.shift()),
    });
    const window = {};
    new Function('window', 'document', 'fetch', source)(window, document, fetch);
    window.openAlertModal({ cardId: 'card-a', side: 'buylist' });
    for (let i = 0; i < 6; i++) await new Promise(r => setTimeout(r, 0));
    return byId['alert-stores'].children;
}

test('picked-only stores get a column of their own with a tooltip', async () => {
    const [main, picked, ...rest] = await renderStores([
        { shorthand: 'TCGDirectNet', name: 'TCG Direct (net)', prices: { NM: 5 }, picked_only: true },
        { shorthand: 'SCG', name: 'Star City Games', prices: { NM: 4 } },
        { shorthand: 'MKMBL', name: 'Cardmarket', prices: {}, picked_only: true },
        { shorthand: 'CK', name: 'Card Kingdom', prices: { NM: 3 } },
    ]);
    expect(rest).toEqual([]);
    expect(main.className).toBe('alert-stores-main');
    expect(main.children.map(r => r.getAttribute('data-shorthand'))).toEqual(['CK', 'SCG']);
    expect(main.children[0].title).toBe('Card Kingdom');
    expect(picked.className).toBe('alert-stores-picked');
    expect(picked.title).toBe('These stores are not enabled unless explicitly selected');
    expect(picked.children.map(r => r.getAttribute('data-shorthand'))).toEqual(['MKMBL', 'TCGDirectNet']);
    expect(picked.children[0].title).toBe('Cardmarket\nThese stores are not enabled unless explicitly selected');
});

test('no picked-only column when no store is picked-only', async () => {
    const [main, ...rest] = await renderStores([
        { shorthand: 'SCG', name: 'Star City Games', prices: { NM: 4 } },
        { shorthand: 'CK', name: 'Card Kingdom', prices: { NM: 3 } },
    ]);
    expect(rest).toEqual([]);
    expect(main.children.map(r => r.getAttribute('data-shorthand'))).toEqual(['CK', 'SCG']);
});
