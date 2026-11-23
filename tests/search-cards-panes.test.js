import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// panes lists a card's columns left to right: its sellers, its picture, then
// its other lists in the page's order (sales before buyers where the
// reader's mode is Sales). The edge buttons and the scroll position both
// read it, so the order is pinned here.
const source = readFileSync(join(import.meta.dir, '..', 'js', 'search-cards.js'), 'utf8');
const start = source.indexOf('    function panes(card) {');
const panes = new Function(source.slice(start, source.indexOf('\n    }\n', start) + 6) + '\nreturn panes;')();

function card(sellers, others) {
    return {
        querySelector: (sel) => (sel === ':scope > [id^="sellers"]' && sellers ? { id: 'sellers-x' } : null),
        querySelectorAll: () => others.map((p) => ({ id: p + '-x' })),
    };
}

test('a card opens on its picture, sellers to the left, buyers then sales to the right', () => {
    expect(panes(card(true, ['buyers', 'sales']))).toEqual(['sellers', 'picture', 'buyers', 'sales']);
});

test('in Sales mode the sales come before the buyers', () => {
    expect(panes(card(true, ['sales', 'buyers']))).toEqual(['sellers', 'picture', 'sales', 'buyers']);
});

test('a card with no sellers starts at its picture', () => {
    expect(panes(card(false, ['buyers']))).toEqual(['picture', 'buyers']);
});
