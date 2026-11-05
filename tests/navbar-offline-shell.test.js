import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const navbar = readFileSync(join(import.meta.dir, '..', 'js', 'navbar.js'), 'utf8');
const start = navbar.indexOf('// ── Context-aware nav search autocomplete');
const block = navbar.slice(start, navbar.indexOf('// ── Keep search/sealed navigation', start));

// Offline, the service worker answers /search with the shell, so its path says
// nothing. Bound there too, the online autocomplete closes the shell's list
// on every keystroke.
function bound(pathname, hasBanner) {
    const calls = [];
    const input = { focus() {} };
    const form = {};
    const document = {
        getElementById: (id) => ({ 'nav-searchform': form, 'nav-searchbox': input, 'offline-banner': hasBanner ? {} : null })[id],
    };
    const window = { addEventListener() {} };
    new Function('document', 'window', 'location', 'autocomplete', block)(document, window, { pathname }, () => calls.push(pathname));
    return calls.length;
}

test('the online autocomplete stays off the offline shell whatever its path', () => {
    expect(bound('/offline', true)).toBe(0);
    expect(bound('/search', true)).toBe(0);
    expect(bound('/sealed', true)).toBe(0);
});

test('an ordinary page gets the online autocomplete', () => {
    expect(bound('/search', false)).toBe(1);
});
