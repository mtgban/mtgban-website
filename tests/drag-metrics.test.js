import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const navbar = readFileSync(new URL('../js/navbar.js', import.meta.url), 'utf8');
const drag = navbar.slice(navbar.indexOf('(function() {', navbar.indexOf('Drag-and-drop: reorder')), navbar.indexOf('Drag hint tile'));
const uploadForm = readFileSync(new URL('../js/upload-form.js', import.meta.url), 'utf8');

// An element with classes, attributes, children and one listener a type.
function element(classes = [], attrs = {}) {
    const cls = new Set(classes);
    const el = {
        attrs, listeners: {}, children: [], parentNode: null, innerHTML: '', textContent: '',
        classList: {
            add: (...c) => c.forEach(x => cls.add(x)), remove: (...c) => c.forEach(x => cls.delete(x)),
            contains: c => cls.has(c), toggle: (c, on) => (on ? cls.add(c) : cls.delete(c)),
        },
        get className() { return Array.from(cls).join(' '); },
        set className(v) { cls.clear(); String(v).split(/\s+/).filter(Boolean).forEach(c => cls.add(c)); },
        getAttribute: k => (k in attrs ? attrs[k] : null),
        setAttribute: (k, v) => { attrs[k] = String(v); },
        addEventListener: (type, fn) => { el.listeners[type] = fn; },
        appendChild(c) { c.remove(); c.parentNode = el; el.children.push(c); },
        insertBefore(c, ref) {
            c.remove();
            c.parentNode = el;
            const at = ref ? el.children.indexOf(ref) : -1;
            el.children.splice(at < 0 ? el.children.length : at, 0, c);
        },
        remove() { if (el.parentNode) { el.parentNode.children.splice(el.parentNode.children.indexOf(el), 1); el.parentNode = null; } },
        get nextSibling() { const s = el.parentNode.children; return s[s.indexOf(el) + 1] || null; },
        closest: sel => (sel === '.tools-quick' ? el.parentNode : (cls.has('tools-tile') || cls.has('nav2-section-btn')) ? el : null),
        querySelector: () => null,
        // By class, as the layout code asks: tiles, section buttons, docked icons.
        querySelectorAll: sel => el.children.filter(c =>
            sel.indexOf('tools-tile') >= 0 ? c.classList.contains('tools-tile')
                : sel.indexOf('nav2-section-btn') >= 0 ? c.classList.contains('nav2-section-btn')
                    : sel === '[data-util]' ? 'data-util' in c.attrs : false),
        getBoundingClientRect: () => ({ left: 0, width: 100 }),
        click() {},
    };
    return el;
}

// A bar with these section buttons, these tools in the grid, and the four icons.
function bar({ sections = ['search'], tiles = ['sets', 'sealed'] } = {}) {
    const tracked = [];
    const made = [];
    const nav = element(['nav2-sections']);
    const grid = element([], { id: 'tools-grid' });
    const utility = element(['nav2-utility']);
    const quick = element(['tools-quick']);
    const dock = element([], { id: 'tools-quick-dock' });
    quick.appendChild(dock);
    const toolsBtn = element([], { 'aria-expanded': 'true' });
    const btns = sections.map(t => { const b = element(['nav2-section-btn'], { 'data-tool': t }); nav.appendChild(b); return b; });
    const tls = tiles.map(t => { const b = element(['tools-tile'], { 'data-tool': t }); grid.appendChild(b); return b; });
    const utils = {};
    ['backpack', 'account', 'guide', 'settings'].forEach(n => { utils[n] = element([], { 'data-util': n }); utility.appendChild(utils[n]); });
    const document = {
        getElementById: id => ({ 'tools-grid': grid, 'tools-quick-dock': dock, 'tools-btn': toolsBtn }[id] || null),
        querySelector: sel => (sel === '.nav2-sections' ? nav : sel === '.nav2-utility' ? utility : null),
        querySelectorAll: sel => (sel === '[data-util]' ? Object.values(utils) : sel.indexOf('.tools-tile, .nav2-section-btn') === 0 ? tls.concat(btns) : []),
        createElement: () => { const e = element(); made.push(e); return e; },
    };
    const window = {
        __BAN_NAV: sections.concat(tiles).map(t => ({ tool: t, icon: '', name: t, desc: '', href: '/' + t })),
        BAN: { track: (...a) => tracked.push(a) },
    };
    new Function('document', 'localStorage', 'window', 'location', 'setTimeout', drag)(
        document, { getItem: () => null, setItem() {} }, window, { pathname: '/search' }, () => {});
    const ev = target => ({ target: target || element(), clientX: 0, preventDefault() {}, stopPropagation() {}, dataTransfer: { setData() {} } });
    // Drags `from` and drops it on `onto`, the event aimed at `target`.
    const drop = (from, onto, target) => {
        from.listeners.dragstart(ev());
        if (onto.listeners.dragover) onto.listeners.dragover(ev(target));
        onto.listeners.drop(ev(target));
        from.listeners.dragend();
    };
    return { tracked, nav, grid, utility, quick, toolsBtn, btns, tls, utils, made, drop, ev };
}

test('each drop that changes the bar is named for what it did', () => {
    const p = bar();
    p.drop(p.tls[1], p.tls[0], p.tls[0]);   // tile onto tile, before it
    p.drop(p.tls[0], p.btns[0], p.btns[0]); // tile onto a section button
    p.drop(p.tls[1], p.nav);                // tile onto the bar
    p.drop(p.btns[0], p.grid);              // section button onto the grid
    p.drop(p.nav.children.find(c => c.classList.contains('nav2-section-btn')), p.toolsBtn); // and onto Tools
    expect(p.tracked).toEqual([
        ['ui.nav.layout', 'reorder'], ['ui.nav.layout', 'swap'], ['ui.nav.layout', 'promote'],
        ['ui.nav.layout', 'demote'], ['ui.nav.layout', 'demote'],
    ]);
});

test('a tile dropped where it already was changes nothing and counts nothing', () => {
    const p = bar();
    p.drop(p.tls[0], p.tls[1], p.tls[1]); // before the tile it already precedes
    expect(p.grid.children).toEqual([p.tls[0], p.tls[1]]);
    expect(p.tracked).toEqual([]);
});

test('the + Add slot promotes too', () => {
    const p = bar();
    p.tls[0].listeners.dragstart(p.ev());
    p.made.find(e => e.className === 'nav2-promote-slot').listeners.drop(p.ev());
    expect(p.tracked).toEqual([['ui.nav.layout', 'promote']]);
});

test('a drop the full bar refuses counts nothing', () => {
    const p = bar({ sections: ['a', 'b', 'c', 'd', 'e'], tiles: ['sets'] });
    p.drop(p.tls[0], p.nav);
    expect(p.tracked).toEqual([]);
});

test('an icon docked and brought back, by the strip, the bar and the Tools button', () => {
    const p = bar();
    p.drop(p.utils.guide, p.quick);
    p.drop(p.utils.guide, p.utility);
    p.drop(p.utils.account, p.toolsBtn);
    p.drop(p.utils.account, p.toolsBtn);
    expect(p.tracked).toEqual([
        ['ui.nav.layout', 'dock'], ['ui.nav.layout', 'undock'], ['ui.nav.layout', 'dock'], ['ui.nav.layout', 'undock'],
    ]);
});

// upload-form.js on a document that keeps its listeners; pressed() is replaced by a count.
function uploadPage(accept) {
    const tracked = [];
    const listeners = {};
    let pressed = 0;
    const stub = () => new Proxy(function () { return stub(); }, { get: (t, k) => (k === Symbol.toPrimitive ? () => '' : stub()), set: () => true });
    const fileInput = { getAttribute: () => accept, files: null, value: '' };
    const document = new Proxy({}, { get: (t, k) => (
        k === 'addEventListener' ? (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); }
            : k === 'getElementById' ? id => (id === 'file' ? fileInput : stub()) : stub()) });
    const window = { BAN: { track: (...a) => tracked.push(a) }, BAN_UPLOAD_FORM: { buylist: false } };
    function DataTransfer() { const files = []; this.files = files; this.items = { add: f => files.push(f) }; }
    new Function('window', 'document', 'localStorage', 'DataTransfer', 'setTimeout', 'with (window) {' + uploadForm + '}')(
        window, document, { getItem: () => null, setItem() {}, removeItem() {} }, DataTransfer, () => {});
    window.pressed = () => { pressed++; };
    const drop = (types, files) => listeners.drop.forEach(fn => fn({ preventDefault() {}, dataTransfer: { types, files } }));
    return { tracked, drop, pressed: () => pressed };
}

test('a file dropped on the upload page is counted once it is taken', () => {
    const p = uploadPage('.csv,.txt');
    p.drop(['Files'], [{ name: 'list.csv', type: 'text/csv' }]);
    expect(p.tracked).toEqual([['ui.upload.file_drop']]);
    expect(p.pressed()).toBe(1);
});

test('a refused file, and a drag that carries no file, count nothing', () => {
    const p = uploadPage('.csv,.txt');
    p.drop(['Files'], [{ name: 'cat.png', type: 'image/png' }]);
    p.drop(['text/plain'], []);
    expect(p.tracked).toEqual([]);
});
