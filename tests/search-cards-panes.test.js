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

// tuck is run over a swipe's positions, a card 390 wide with its picture in
// the second of four columns.
const tuckSource = source.slice(source.indexOf('    var STEP = 24;'), source.indexOf('    // A card the deck lands on'));
function swipe(open, from, to) {
    let hidden = open;
    const page = { classList: { contains: () => hidden, toggle: (_, on) => { hidden = on; } } };
    const el = { ...card(true, ['buyers', 'sales']), clientWidth: 390, scrollWidth: 390 * 4, scrollLeft: from };
    const tuck = new Function('panes', 'page', 'pager', tuckSource + '\nturns = new WeakMap(); return tuck;')(panes, page, () => {});
    for (let i = 0; i <= 10; i++) {
        el.scrollLeft = from + (to - from) * i / 10;
        tuck(el);
    }
    return hidden;
}

test('the search bar stays down between two lists', () => {
    expect(swipe(true, 1170, 780)).toBe(true);
    expect(swipe(true, 780, 1170)).toBe(true);
});

test('the search bar comes up onto the picture and goes down leaving it', () => {
    expect(swipe(true, 780, 700)).toBe(false);
    expect(swipe(true, 0, 80)).toBe(false);
    expect(swipe(false, 390, 470)).toBe(true);
});

test('landscape pairs sellers with buyers, and leaves the sales out', () => {
    const read = (f) => readFileSync(join(import.meta.dir, '..', 'css', f), 'utf8');
    for (const css of [read('search-mobile.css'), read('search-cards-mobile.css').split('@media (orientation: portrait)')[0]]) {
        expect(css).not.toContain(':has(.m-tab-panel + .m-tab-panel)');
    }
    // A forced display would show the sales whatever hides them.
    const forced = [...read('search-mobile.css').matchAll(/([^{}]*)\{[^{}]*display: block !important/g)].map((m) => m[1].trim()).filter((s) => s.includes('> .m-tab-panel'));
    expect(forced.length).toBe(2);
    for (const sel of forced) expect(sel).toEndWith('> .m-tab-panel:not([id^="sales"])');
    expect(read('search-cards-mobile.css')).toMatch(/\.m-layout-cards \.m-tab-panel\[id\^="sales"\] \{\n\s+display: none;/);
});

test('a list off screen skips its rows', () => {
    const css = readFileSync(join(import.meta.dir, '..', 'css', 'search-cards-mobile.css'), 'utf8');
    expect(css.match(/\.m-tab-panel > \.result-col \{([^}]*)\}/)[1]).toContain('content-visibility: auto;');
});
