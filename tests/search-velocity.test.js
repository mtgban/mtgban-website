import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/search-velocity.js', import.meta.url), 'utf8');

// load runs the script over stubs, returning its listeners and the cookies it set.
function load() {
    const listeners = [];
    const cookies = [];
    const document = { addEventListener: (type, fn, capture) => listeners.push({ type, fn, capture }) };
    const setCookie = (...a) => cookies.push(a);
    new Function('document', 'self', 'setCookie', source)(document, {}, setCookie);
    return { listeners, cookies };
}

const details = (classes, open) => ({ open, classList: { contains: (c) => classes.includes(c) } });

test('a toggled sales row saves its state, open and closed', () => {
    const { listeners, cookies } = load();
    expect(listeners).toHaveLength(1);
    expect(listeners[0].type).toBe('toggle');
    expect(listeners[0].capture).toBe(true);
    listeners[0].fn({ target: details(['sales-velocity'], true) });
    listeners[0].fn({ target: details(['m-vendor-row', 'sales-velocity'], false) });
    expect(cookies).toEqual([
        ['SearchVelocityOpen', 'open', 1000],
        ['SearchVelocityOpen', 'closed', 1000],
    ]);
});

test('other details leave the cookie alone', () => {
    const { listeners, cookies } = load();
    listeners[0].fn({ target: details(['m-vendor-row'], true) });
    listeners[0].fn({ target: null });
    expect(cookies).toEqual([]);
});
