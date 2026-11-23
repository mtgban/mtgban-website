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

test('a list keeps its overscroll up and down only', () => {
    // Kept sideways too, Chrome on Android drops the swipe that would leave a
    // list long enough to scroll.
    const css = readFileSync(join(import.meta.dir, '..', 'css', 'search-cards-mobile.css'), 'utf8');
    const rule = css.match(/\.m-tab-panel > \.result-col \{([^}]*)\}/)[1];
    expect(rule).toContain('overscroll-behavior-y: contain;');
    expect(rule).not.toMatch(/overscroll-behavior(-x)?:/);
});

test('a flick stops at the next column', () => {
    // The picture, the tools under it and the lists are what a card snaps to;
    // one without the stop lets a hard flick pass the picture by.
    const css = readFileSync(join(import.meta.dir, '..', 'css', 'search-cards-mobile.css'), 'utf8');
    for (const target of ['.m-card > .m-card-img-landscape', '.m-card > .m-tab-panel', '.m-card-tools']) {
        const rule = css.slice(css.indexOf('.m-layout-cards ' + target + ' {'));
        expect(rule.slice(0, rule.indexOf('}'))).toContain('scroll-snap-stop: always;');
    }
});
