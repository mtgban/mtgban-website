import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// The whole script over a stub deck of n cards, 390x700 upright, firing the
// listeners it adds. The end drawer is up when .m-page has m-pager-open.
// In landscape the page scrolls by scrollY under the 48px nav, each card L
// high, and a card scrolled into view sits under the nav, as its
// scroll-margin-top puts it.
const source = readFileSync(join(import.meta.dir, '..', 'js', 'search-cards.js'), 'utf8');
const W = 390, H = 700, L = 300, NAV = 48;

function target() {
    const on = {};
    return {
        addEventListener: (type, fn) => { (on[type] = on[type] || []).push(fn); },
        removeEventListener: (type, fn) => { on[type] = (on[type] || []).filter((f) => f !== fn); },
        fire: (type, e) => (on[type] || []).slice().forEach((fn) => fn(e)),
    };
}

function phone(n) {
    const classes = new Set();
    const classList = {
        contains: (c) => classes.has(c),
        toggle: (c, on) => { if (on) classes.add(c); else classes.delete(c); },
        remove: (c) => classes.delete(c),
    };
    const stage = target(), page = target(), deck = target(), scrub = target(), win = target(), doc = target(), portrait = target();
    const cards = Array.from({ length: n }, (_, k) => ({
        scrollLeft: W, clientWidth: W, scrollWidth: 3 * W, offsetHeight: H, parentNode: deck, style: {},
        classList: { contains: (c) => c === 'm-card' },
        querySelector: (s) => (s.includes('sellers') ? { id: 'sellers-x' } : null),
        querySelectorAll: () => [{ id: 'buyers-x' }],
        scrollTo(o) { this.scrollLeft = o.left; },
        getBoundingClientRect: () => ({ top: NAV + k * L - win.scrollY, bottom: NAV + (k + 1) * L - win.scrollY }),
        scrollIntoView() { win.scrollY = k * L; },
    }));
    const scrubbing = new Set();
    Object.assign(scrub, {
        style: { setProperty() {} },
        classList: { contains: (c) => scrubbing.has(c), add: (c) => scrubbing.add(c), remove: (c) => scrubbing.delete(c) },
        querySelector: () => ({ style: { setProperty() {} }, setAttribute() {} }),
        getBoundingClientRect: () => ({ top: 100, height: n * 40 }),
        setPointerCapture() {},
    });
    Object.assign(page, { classList, querySelector: (s) => (s === '.m-scrub' ? scrub : s === '.m-results-end' ? {} : null) });
    Object.assign(deck, { scrollTop: 0, clientHeight: H, parentNode: stage, closest: () => page, querySelector: () => cards[0], querySelectorAll: () => cards });
    portrait.matches = true;
    Object.assign(win, { innerWidth: W, innerHeight: H, scrollY: 0, matchMedia: (q) => (q.includes('portrait') ? portrait : { matches: false }) });
    doc.querySelector = (s) => (s === '.m-layout-cards .m-results' ? deck : null);
    const history = { state: null, replaceState(s) { this.state = s; } };
    let t = 0;
    // The debounced scrolls wait here until settle() runs them.
    const due = new Map();
    let id = 0;
    new Function('window', 'document', 'history', 'requestAnimationFrame', 'setTimeout', 'clearTimeout', source)(
        win, doc, history, (fn) => fn(t += 100), (fn) => { due.set(++id, fn); return id; }, (k) => due.delete(k));

    // A finger on the cards, unless it is on one of the page's sheets, whose
    // events reach .m-page and not the deck's stage.
    function touch(type, y, where = {}) {
        const e = {
            touches: type === 'touchend' ? [] : [{ clientX: where.x || 200, clientY: y }], cancelable: true, prevented: false,
            target: { closest: (s) => (where.on && s.includes(where.on) ? {} : null) },
            preventDefault() { this.prevented = true; },
        };
        if (!where.sheet) stage.fire(type, e);
        page.fire(type, e);
        return e;
    }
    function swipeUp(where) {
        touch('touchstart', 600, where);
        touch('touchmove', 500, where);
        touch('touchend', 500, where);
    }
    function turn(upright) {
        portrait.matches = upright;
        win.innerWidth = upright ? W : 844;
        win.innerHeight = upright ? H : W;
        if (!upright) deck.scrollTop = 0;
        win.fire('resize', {});
        portrait.fire('change', {});
    }
    // A scroll of el, the page's own being the document's
    function scroll(el) {
        doc.fire('scroll', { target: el || doc });
    }
    function settle() {
        const fns = [...due.values()];
        due.clear();
        fns.forEach((fn) => fn());
    }
    return { deck, cards, scrub, win, history, touch, swipeUp, turn, scroll, settle, open: () => classes.has('m-pager-open') };
}

test('a swipe up on the last card raises the drawer, and one down lowers it', () => {
    const p = phone(1);
    p.swipeUp();
    expect(p.open()).toBe(true);
    p.touch('touchstart', 500);
    p.touch('touchmove', 600);
    expect(p.open()).toBe(false);
});

test('a swipe in a sheet over the cards leaves the drawer alone', () => {
    const p = phone(1);
    p.swipeUp({ sheet: true });
    expect(p.open()).toBe(false);
    p.swipeUp();
    p.touch('touchstart', 600, { sheet: true });
    expect(p.touch('touchmove', 598, { sheet: true }).prevented).toBe(false);
    p.touch('touchstart', 600);
    expect(p.touch('touchmove', 598).prevented).toBe(true);
});

test('a swipe in an open actions menu or along the scrubber leaves the drawer alone', () => {
    for (const on of ['.m-actions-menu', '.m-scrub']) {
        const p = phone(1);
        p.swipeUp({ on });
        expect(p.open()).toBe(false);
    }
    // Opened over the raised drawer, the menu scrolls
    const p = phone(1);
    p.swipeUp();
    p.touch('touchstart', 600, { on: '.m-actions-menu' });
    expect(p.touch('touchmove', 598, { on: '.m-actions-menu' }).prevented).toBe(false);
});

test('a drag onto the last card does not raise the drawer by itself', () => {
    const p = phone(3);
    p.deck.scrollTop = H;
    p.touch('touchstart', 640);
    p.deck.scrollTop = H + 400;
    p.touch('touchmove', 240);
    expect(p.open()).toBe(false);
});

test('the scrubber and a turn of the phone lower the drawer', () => {
    const scrubbed = phone(5);
    scrubbed.deck.scrollTop = 4 * H;
    scrubbed.swipeUp();
    expect(scrubbed.open()).toBe(true);
    scrubbed.scrub.fire('pointerdown', { preventDefault() {}, clientY: 100 });
    expect([scrubbed.deck.scrollTop, scrubbed.open()]).toEqual([0, false]);

    const turned = phone(1);
    turned.swipeUp();
    turned.turn(false);
    expect(turned.open()).toBe(false);
});

test('a turned phone comes back to its card', () => {
    const p = phone(5);
    p.deck.scrollTop = 3 * H;
    p.win.fire('pagehide', {});
    p.turn(false);
    p.win.fire('pagehide', {});
    expect(p.history.state).toEqual({ cardsIndex: 3 });
    p.turn(true);
    expect(p.deck.scrollTop).toBe(3 * H);
});

test('landscape opens on the card the reader was on upright', () => {
    const p = phone(5);
    p.deck.scrollTop = 3 * H;
    p.scroll(p.deck);
    p.settle();
    p.turn(false);
    expect(p.cards[3].getBoundingClientRect().top).toBe(NAV);

    const css = readFileSync(join(import.meta.dir, '..', 'css', 'search-cards-mobile.css'), 'utf8');
    const landscape = css.slice(css.indexOf('@media (orientation: landscape)'));
    expect(landscape).toMatch(/\.m-layout-cards \.m-card \{\n\s+scroll-margin-top: 48px;/);
});

test('turned back upright, the deck takes the card landscape scrolled to', () => {
    const p = phone(5);
    p.deck.scrollTop = 3 * H;
    p.win.fire('pagehide', {});
    p.turn(false);
    p.win.scrollY = 4 * L + 100;
    p.scroll();
    p.settle();
    p.turn(true);
    expect(p.deck.scrollTop).toBe(4 * H);

    // And left from landscape, Back opens upright on that card
    p.turn(false);
    p.win.scrollY = 1 * L;
    p.win.fire('pagehide', {});
    expect(p.history.state).toEqual({ cardsIndex: 1 });
});
