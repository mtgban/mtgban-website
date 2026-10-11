import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'search-sidebar.js'), 'utf8');
const utilsSource = readFileSync(join(import.meta.dir, '..', 'js', 'utils.js'), 'utf8');

// A minimal DOM mirroring templates/search.html: .result-header and
// .result-body are flat siblings under .search-results (no shared
// wrapper), in result-header-cover, result-header, result-body order
// per result, with nested elements inside the body. Each header holds
// a <template class="result-hover"> as its first child, carrying the
// printings/products HTML the hover panels need.
class FakeElement {
    constructor(cls) {
        this.cls = cls;
        this.attrs = {};
        this.children = [];
        this.parent = null;
        this.nodeType = 1;
        this.classList = { contains: c => this.cls.split(' ').includes(c) };
    }
    get parentElement() { return this.parent; }
    get firstChild() { return this.children[0] || null; }
    get childNodes() { return this.children; }
    get previousElementSibling() {
        if (!this.parent) return null;
        const i = this.parent.children.indexOf(this);
        return i > 0 ? this.parent.children[i - 1] : null;
    }
    append(child) {
        child.parent = this;
        this.children.push(child);
        return child;
    }
    setAttribute(k, v) { this.attrs[k] = v; }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    querySelector(sel) {
        const want = sel.replace(/^\./, '');
        for (const c of this.children) {
            if (c.cls.split(' ').includes(want)) return c;
            const deeper = c.querySelector(sel);
            if (deeper) return deeper;
        }
        return null;
    }
    addEventListener() {}
}

// A fake <template>: content.cloneNode() hands back a fresh fragment
// (itself a FakeElement standing in for a DocumentFragment) each time,
// so two hovers over the same result don't share nodes, and counts them.
class FakeTemplate extends FakeElement {
    constructor(printingsHTML, productsHTML) {
        super('result-hover');
        this.printingsHTML = printingsHTML;
        this.productsHTML = productsHTML;
        this.clones = 0;
        this.content = { cloneNode: () => { this.clones++; return this._buildFragment(); } };
    }
    _buildFragment() {
        const frag = new FakeElement('result-hover-fragment');
        const printings = new FakeElement('hover-printings');
        if (this.printingsHTML) printings.append(new FakeElement('printings-child'));
        const products = new FakeElement('hover-products');
        if (this.productsHTML) products.append(new FakeElement('products-child'));
        frag.append(printings);
        frag.append(products);
        return frag;
    }
}

function fakeDom() {
    const listeners = {};
    const results = new FakeElement('search-results');
    results.addEventListener = (ev, fn) => { listeners[ev] = fn; };

    results.append(new FakeElement('result-header-cover'));
    const h1 = results.append(new FakeElement('result-header'));
    h1.setAttribute('data-hover', JSON.stringify(['img1', true, false, 'LEB', false, 2, '1993', 'Animate Wall']));
    h1.append(new FakeTemplate('<p>p1</p>', '<p>q1</p>'));
    // A variant row (FlavorName/PromoTypes/Flag) sits between header and
    // body for some cards; headerFor must walk past it to reach h1.
    results.append(new FakeElement('result-card-extra'));
    const b1 = results.append(new FakeElement('result-body'));
    const col1 = b1.append(new FakeElement('result-col'));
    const span1 = col1.append(new FakeElement('price'));

    results.append(new FakeElement('result-header-cover'));
    const h2 = results.append(new FakeElement('result-header'));
    // Balance has no products: the template's .hover-products ends up
    // with no children, the 'n/a' path updateSidebar used for "".
    h2.setAttribute('data-hover', JSON.stringify(['img2', false, false, 'LEB', false, 0, '1993', 'Balance']));
    h2.append(new FakeTemplate('', ''));
    results.append(new FakeElement('result-body'));

    return { results, h1, span1, h2, listeners };
}

// No results at all: .search-results exists but holds no .result-header.
function emptyDom() {
    const results = new FakeElement('search-results');
    return { results };
}

// opts.stubHoverSidebar (default true) swaps window.hoverSidebar for a
// recorder after source runs, as every test but the phantom-guard ones
// below wants. false leaves the source's own `window.hoverSidebar =
// hoverSidebar;` in place, so showHoverFor's trusted/untrusted calls
// reach the real guarded function. opts.now overrides performance.now().
function load(dom, opts) {
    opts = opts || {};
    // Enough of #cardImage/#printings/#products for the first-card seed's
    // call into the real updateSidebar to run without touching anything
    // we're not testing here.
    const cardImageStub = { addEventListener() {} };
    const printingsStub = {
        classList: { remove() {} },
        querySelector() { return null; },
        querySelectorAll() { return []; },
        replaceChildren(...nodes) { this.lastReplace = nodes; },
    };
    const productsStub = {
        replaceChildren(...nodes) { this.lastReplace = nodes; },
        set textContent(v) { this._text = v; },
        get textContent() { return this._text; },
    };
    const document = {
        querySelector: sel => (sel === '.search-results' ? dom.results : null),
        getElementById: id => {
            if (id === 'cardImage') return cardImageStub;
            if (id === 'printings') return printingsStub;
            if (id === 'products') return productsStub;
            return null;
        },
        addEventListener: (ev, fn) => { if (ev === 'DOMContentLoaded') fn(); },
    };
    // Recorded from the start (not swapped in after source runs): the
    // seed call fires synchronously during DOMContentLoaded, before any
    // post-source override would be in place.
    const cardArtCalls = [];
    const window = {
        setCardArtSource: (img, src) => cardArtCalls.push(src),
        addEventListener: () => {},
        performance: { now: opts.now || (() => 0) },
        // Without this, httpURL's `new URL(value, window.location.href)`
        // throws on every call (reading .href of undefined) and every
        // src collapses to '', passing tests for the wrong reason.
        location: { href: 'http://localhost/' },
    };
    const stubTail = opts.stubHoverSidebar === false
        ? ';window.__hoverCalls = []; return window;'
        : ';window.__hoverCalls = []; window.hoverSidebar = function(){ window.__hoverCalls.push([].slice.call(arguments)); }; return window;';
    const fn = new Function('document', 'window', 'self', 'performance',
        utilsSource + '\n' + source + '\n' + stubTail);
    const w = fn(document, window, window, window.performance);
    return { w, calls: w.__hoverCalls, cardArtCalls, printingsStub, productsStub };
}

test('hoverDataFor finds the header from a nested body element and parses once', () => {
    const dom = fakeDom();
    const { w } = load(dom);
    const data = w.hoverDataFor(dom.span1);
    expect(data.args.length).toBe(8);
    expect(data.args[0]).toBe('img1');
    expect(data.args[7]).toBe('Animate Wall');
    expect(data.tpl).toBe(dom.h1.children[0]);
    const again = w.hoverDataFor(dom.span1);
    expect(again).toBe(data); // same object: parsed once and cached
    expect(w.hoverDataFor(dom.results)).toBeNull();
});

test('a mouseover inside a result calls hoverSidebar with DOM nodes, not HTML strings', () => {
    const dom = fakeDom();
    const { w, calls } = load(dom);
    // The seed shows the first result, so the second goes first
    dom.listeners.mouseover({ target: dom.h2 });
    expect(calls[0][9]).toBe('Balance');
    // Balance's template carried empty printings/products HTML: the
    // cloned nodes exist but hold no children.
    expect(calls[0][1].children.length).toBe(0);
    expect(calls[0][2].children.length).toBe(0);
    w.updateSidebar.apply(null, calls[0]);

    // dom.span1's result has a .result-card-extra between its header and
    // its body (see fakeDom); this also exercises headerFor walking past it.
    dom.listeners.mouseover({ target: dom.span1 });
    expect(calls.length).toBe(2);
    const [src, printings, products, isFoil, isEtched, setCode, hasWarning, productsCount, releaseDate, cardName] = calls[1];
    expect(typeof printings).not.toBe('string');
    expect(typeof products).not.toBe('string');
    expect(printings.cls).toBe('hover-printings');
    expect(products.cls).toBe('hover-products');
    expect(setCode).toBe('LEB');
    expect(cardName).toBe('Animate Wall');
});

test('a mouseover over the card on show clones nothing and calls nothing', () => {
    const dom = fakeDom();
    const { w, calls } = load(dom);
    const tpl = dom.h1.children[0];
    const seeded = tpl.clones; // the seed shows the first result
    dom.listeners.mouseover({ target: dom.span1 });
    dom.listeners.mouseover({ target: dom.h1 });
    expect(tpl.clones).toBe(seeded);
    expect(calls.length).toBe(0);

    // Another card still updates, and once it shows, the first one does
    dom.listeners.mouseover({ target: dom.h2 });
    expect(calls.length).toBe(1);
    w.updateSidebar.apply(null, calls[0]);
    dom.listeners.mouseover({ target: dom.span1 });
    expect(calls.length).toBe(2);
    expect(tpl.clones).toBe(seeded + 1);
});

test('an empty products node falls back to the n/a text the old "" case used', () => {
    const dom = fakeDom();
    const { w, productsStub } = load(dom);
    dom.listeners.mouseover({ target: dom.h2 });
    w.updateSidebar.apply(null, w.__hoverCalls[0]);
    expect(productsStub.textContent).toBe('n/a');
});

test('the image src is run through httpURL: an https URL passes through, javascript: does not', () => {
    const dom = fakeDom();
    dom.h1.attrs['data-hover'] = JSON.stringify(['https://img.example/card.jpg', true, false, 'LEB', false, 2, '1993', 'Animate Wall']);
    dom.h2.attrs['data-hover'] = JSON.stringify(['javascript:alert(1)', false, false, 'LEB', false, 0, '1993', 'Balance']);
    const { w, cardArtCalls } = load(dom);

    dom.listeners.mouseover({ target: dom.h2 });
    w.updateSidebar.apply(null, w.__hoverCalls[w.__hoverCalls.length - 1]);
    // httpURL rejects non-http(s) schemes, so the javascript: URL never
    // reaches setCardArtSource (and so never reaches img.src).
    expect(cardArtCalls).not.toContain('javascript:alert(1)');
    expect(cardArtCalls[cardArtCalls.length - 1]).toBe('');

    dom.listeners.mouseover({ target: dom.h1 });
    w.updateSidebar.apply(null, w.__hoverCalls[w.__hoverCalls.length - 1]);
    expect(cardArtCalls[cardArtCalls.length - 1]).toBe('https://img.example/card.jpg');
});

test("updateSidebar inserts the template wrapper's children, not the wrapper itself", () => {
    const dom = fakeDom();
    const { w, printingsStub, productsStub } = load(dom);
    // Away from the seeded first result and back
    dom.listeners.mouseover({ target: dom.h2 });
    w.updateSidebar.apply(null, w.__hoverCalls[w.__hoverCalls.length - 1]);
    dom.listeners.mouseover({ target: dom.h1 });
    w.updateSidebar.apply(null, w.__hoverCalls[w.__hoverCalls.length - 1]);

    // The wrapper div (cls 'hover-printings'/'hover-products') never
    // lands in #printings/#products itself - only its children do, so
    // the inline printing symbols and the inline-block "+N" trigger
    // (collapsePrintings) still share a row, as before the <template>.
    expect(printingsStub.lastReplace.some(n => n.cls === 'hover-printings')).toBe(false);
    expect(printingsStub.lastReplace.some(n => n.cls === 'printings-child')).toBe(true);
    expect(productsStub.lastReplace.some(n => n.cls === 'hover-products')).toBe(false);
    expect(productsStub.lastReplace.some(n => n.cls === 'products-child')).toBe(true);
});

test('with no results, the sidebar seed still reaches setCardArtSource with an empty src', () => {
    const dom = emptyDom();
    const { cardArtCalls } = load(dom);
    expect(cardArtCalls).toEqual(['']);
});

// showHoverFor is what search-result-nav.js and search-chart.js now call
// in place of the removed inline onmouseenter. These leave the real
// window.hoverSidebar in place (stubHoverSidebar: false) and push
// performance.now() far from __lastMove/__lastKey (both 0, never touched
// without a mousemove) so the phantom-hover guard would reject an
// untrusted call; trusted must bypass it, untrusted must not.
test('showHoverFor(el, true) bypasses the phantom-hover guard', () => {
    const dom = fakeDom();
    const { w, cardArtCalls } = load(dom, { stubHoverSidebar: false, now: () => 1000 });
    const before = cardArtCalls.length; // after the DOM-ready seed (h1)

    const shown = w.showHoverFor(dom.h2, true);

    expect(shown).toBe(true);
    expect(cardArtCalls.length).toBe(before + 1);
});

test('showHoverFor(el, false) is rejected by the phantom-hover guard under the same conditions', () => {
    const dom = fakeDom();
    const { w, cardArtCalls } = load(dom, { stubHoverSidebar: false, now: () => 1000 });
    const before = cardArtCalls.length; // after the DOM-ready seed (h1)

    const shown = w.showHoverFor(dom.h2, false);

    // showHoverFor still found a result to show...
    expect(shown).toBe(true);
    // ...but hoverSidebar's own guard swallowed the untrusted call.
    expect(cardArtCalls.length).toBe(before);
});
