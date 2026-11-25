import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

const css = read('css/upload.css');

// The rules under every max-width: 560px block, where the results are cards.
function phone() {
    let out = '';
    for (const part of css.split('@media (max-width: 560px) {').slice(1)) out += part.slice(0, part.indexOf('\n}'));
    return out;
}

// A list in a box of its own showed three of eight cards and scrolled apart
// from the page.
test('a phone scrolls the results with the page', () => {
    expect(phone()).toMatch(/\.ures-wrap \{ max-height: none; \}/);
});

// The 640px rules stack the totals; the phone's come later, or lose the tie.
test('a phone sets the totals two to a line', () => {
    const grid = css.indexOf('.res-summary { display: grid; grid-template-columns: 1fr 1fr;');
    expect(grid).toBeGreaterThan(css.indexOf('.res-summary { flex-direction: column;'));
    expect(phone()).toContain('.res-summary { display: grid;');
});

const html = read('templates/upload.html');

// A menu only exists while it is open, so its look must not stop at a width:
// a turned phone leaves the phone rules with the menu still up.
test('an open menu is a menu at any width', () => {
    for (const sel of ['.opt-header-actions', '.upload-store-area']) {
        const open = css.indexOf(sel + '[popover]:popover-open {');
        expect(open).toBeGreaterThan(-1);
        const before = css.slice(0, open);
        // Inside @supports alone: that block opens at the margin
        expect(before.slice(before.lastIndexOf('\n@'))).toMatch(/^\n@supports selector\(:popover-open\) \{/);
    }
});

// Off a phone both are plain boxes: the display they carry outranks a closed popover's none.
test('the menus are laid out in the page on a desktop', () => {
    for (const sel of ['.opt-header-actions', '.upload-store-area']) {
        expect(css).toContain(sel + '[popover] { position: static;');
        expect(css).toContain('        ' + sel + '[popover]');
    }
});

test('every icon button in a store menu has words for the menu', () => {
    const head = html.slice(html.indexOf('id="opt-acts-'), html.indexOf('class="opt-count">{{plural (len $entries)'));
    for (const cls of ['opt-share-btn', 'pack-add-btn', 'pack-take-btn', 'pack-move-btn']) {
        const at = head.indexOf(cls);
        expect(at).toBeGreaterThan(-1);
        expect(head.slice(at, head.indexOf('</button>', at))).toContain('opt-btn-label');
    }
});

// Runs js/upload-optimizer.js far enough to take its document listeners.
function menuClick(btnClasses, attrs = {}, sel = '.opt-header-actions .opt-btn') {
    const handlers = [];
    const document = new Proxy({}, {
        get: (t, k) => {
            if (k === 'addEventListener') return (type, fn, opt) => handlers.push({ type, fn, opt });
            if (k === 'querySelectorAll') return () => [];
            return () => null;
        },
    });
    const window = {};
    new Function('window', 'document', 'sessionStorage', 'wireLoadLists', read('js/upload-optimizer.js'))(window, document, { getItem: () => null, removeItem() {}, setItem() {} }, () => {});
    let closed = 0;
    const menu = { matches: () => true, hidePopover: () => { closed++; } };
    const btn = {
        hasAttribute: (n) => n in attrs,
        classList: { contains: (c) => btnClasses.includes(c) },
        closest: () => menu,
    };
    const target = { closest: (q) => (q.split(', ').includes(sel) ? btn : null) };
    handlers.filter((h) => h.type === 'click' && h.opt === true).forEach((h) => h.fn({ target }));
    return closed;
}

test('a pick closes the store menu', () => {
    expect(menuClick(['opt-btn', 'load'])).toBe(1);
    // A backpack picked in the menu over it too
    expect(menuClick([], {}, '.opt-header-actions .opt-move-menu button')).toBe(1);
});

test('share and the backpack menu keep the store menu open', () => {
    expect(menuClick(['opt-btn', 'opt-share-btn'])).toBe(0);
    expect(menuClick(['opt-btn', 'pack-move-btn'], { popovertarget: 'opt-pack-CK' })).toBe(0);
});

test('the stores button counts the visible grid', () => {
    const count = { textContent: '' };
    const grid = (on, all) => ({ querySelectorAll: (q) => ({ length: q.includes(':checked') ? on : all }) });
    const window = { BAN_UPLOAD_FORM: {} };
    const changes = [];
    const change = (e) => changes.forEach((fn) => fn(e));
    const document = {
        getElementById: (id) => (id === 'upload-store-count' ? count : null),
        querySelector: (q) => (q === '.upload-store-grid:not(.upload-store-hidden)' ? grid(3, 26) : null),
        querySelectorAll: () => [],
        addEventListener: (type, fn) => { if (type === 'change') changes.push(fn); },
    };
    new Function('window', 'document', 'localStorage', 'with (window) {' + read('js/upload-form.js') + '}')(window, document, { getItem: () => null, setItem() {} });
    change({ target: { closest: () => null } });
    expect(count.textContent).toBe('');
    change({ target: { closest: () => ({}) } });
    expect(count.textContent).toBe('3 of 26');
});

// The cog and its word broke apart at the end of a line.
test('the settings link stays on one line', () => {
    expect(css).toMatch(/\n\.upload-share-link \{[^}]*white-space: nowrap;/);
});
