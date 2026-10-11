import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'search-result-nav.js'), 'utf8');

// A header fake carrying just what stickyOffset/the stuck-header scan
// need: a mutable top so a test can move the "page" between scrolls.
function makeHeader(top) {
    return {
        _top: top,
        getBoundingClientRect() { return { top: this._top }; },
    };
}

// Runs the real js/search-result-nav.js IIFE with a fake document/window.
// opts.pointerTarget is what document.elementFromPoint returns (null for
// "pointer over nothing"); its closest() must resolve to the row under it,
// the way a real descendant element's closest('.result-header, .result-body')
// would. opts.mx/opts.my seed __mx/__my, the globals search-sidebar.js's
// mousemove listener would otherwise maintain.
function load(headers, opts) {
    opts = opts || {};
    const listeners = { document: {}, window: {} };
    const navbar = { getBoundingClientRect: () => ({ height: 0 }) };
    const cover = { getBoundingClientRect: () => ({ height: 0 }) };
    const showHoverCalls = [];

    const document = {
        querySelectorAll: sel => (sel === '.result-header' ? headers : []),
        querySelector: sel => {
            if (sel === '.navbar-v2') return navbar;
            if (sel === '.result-header-cover') return cover;
            return null;
        },
        getElementById: () => null,
        elementFromPoint: () => (opts.pointerTarget === undefined ? null : opts.pointerTarget),
        addEventListener: (ev, fn) => { listeners.document[ev] = fn; },
        body: {},
        activeElement: null,
    };
    const window = {
        addEventListener: (ev, fn) => { listeners.window[ev] = fn; },
        scrollBy: () => {},
        scrollTo: () => {},
        scrollY: 0,
        innerHeight: 800,
        parent: null,
        location: { origin: 'http://localhost' },
        showHoverFor: (el, trusted) => { showHoverCalls.push([el, trusted]); },
    };
    const getComputedStyle = () => ({ getPropertyValue: () => '0' });
    function MouseEvent(type, init) { this.type = type; Object.assign(this, init || {}); }
    const requestAnimationFrame = cb => cb();

    new Function('document', 'window', 'getComputedStyle', 'MouseEvent', 'requestAnimationFrame', '__mx', '__my',
        source)(document, window, getComputedStyle, MouseEvent, requestAnimationFrame, opts.mx, opts.my);

    return { listeners, showHoverCalls };
}

test('a scroll with the pointer over a row calls showHoverFor(row, true) once and not again for the same row', () => {
    const h0 = makeHeader(0);
    const h1 = makeHeader(500);
    const pointerEl = { closest: sel => (sel === '.result-header, .result-body' ? h0 : null) };
    const { listeners, showHoverCalls } = load([h0, h1], { pointerTarget: pointerEl, mx: 10, my: 10 });

    listeners.window.scroll();
    listeners.window.scroll();

    expect(showHoverCalls).toEqual([[h0, true]]);
});

test('a keyboard page calls showHoverFor with trusted=true', () => {
    const h0 = makeHeader(0);
    const h1 = makeHeader(500);
    const { listeners, showHoverCalls } = load([h0, h1], {});

    // search-sidebar.js's own capture-phase keydown listener (not
    // loaded here) would have just set __lastKey; PageDown is a
    // deliberate action on a known header, not that phantom.
    listeners.document.keydown({
        key: 'PageDown',
        target: { tagName: 'BODY' },
        preventDefault: () => {},
    });

    expect(showHoverCalls).toEqual([[h1, true]]);
});

test('a scroll with the pointer over nothing calls showHoverFor(stuckHeader, false) when the stuck header changes', () => {
    const h0 = makeHeader(0);
    const h1 = makeHeader(500);
    const { listeners, showHoverCalls } = load([h0, h1], { pointerTarget: null, mx: 10, my: 10 });

    listeners.window.scroll();
    expect(showHoverCalls).toEqual([[h0, false]]);

    // Same stuck header again: no repeat call.
    listeners.window.scroll();
    expect(showHoverCalls).toEqual([[h0, false]]);

    // The page moved on: the other header is stuck now.
    h0._top = 500;
    h1._top = 0;
    listeners.window.scroll();
    expect(showHoverCalls).toEqual([[h0, false], [h1, false]]);
});
