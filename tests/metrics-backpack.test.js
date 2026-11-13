import { test, expect } from 'bun:test';
import { read, fakeBAN } from './metrics-helpers.js';
import { registry } from './track-registry.js';

const source = read('js/backpack.js');
const listStorage = read('js/list-storage.js');

// The stand-in DOM of tests/backpack.test.js, trimmed to what the panel reaches for.
let ids = {};
let submitted = [];
let currentDoc = null;
function el(tag) {
    const node = {
        tag, attrs: {}, classes: new Set(), children: [], listeners: {}, parentNode: null, textContent: '', hidden: false,
        value: '', checked: false, disabled: false, type: '', name: '', style: {},
        get classList() {
            const s = this.classes;
            return { add: (c) => s.add(c), remove: (c) => s.delete(c), toggle: (c, on) => { on ? s.add(c) : s.delete(c); }, contains: (c) => s.has(c) };
        },
        setAttribute(n, v) { this.attrs[n] = String(v); if (n === 'id') ids[v] = this; if (n === 'class') String(v).split(/\s+/).filter(Boolean).forEach((c) => this.classes.add(c)); },
        getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; },
        removeAttribute(n) { delete this.attrs[n]; },
        appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
        append(...cs) { cs.forEach((c) => this.appendChild(c)); },
        remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((c) => c !== this); },
        replaceWith(n) { const p = this.parentNode; if (!p) return; n.parentNode = p; p.children[p.children.indexOf(this)] = n; this.parentNode = null; },
        addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); },
        click() { (this.listeners.click || []).forEach((fn) => fn({ preventDefault() {}, stopPropagation() {} })); },
        focus() { if (currentDoc) currentDoc.activeElement = this; },
        closest(sel) { let n = this; while (n) { if (n.matches(sel)) return n; n = n.parentNode; } return null; },
        matches(sel) { return sel.split(',').some((s) => { s = s.trim(); return s.startsWith('.') ? this.classes.has(s.slice(1)) : s.startsWith('#') ? this.attrs.id === s.slice(1) : this.tag === s; }); },
        querySelector(sel) { return this.querySelectorAll(sel)[0] || null; },
        querySelectorAll(sel) { const out = []; const walk = (n) => { n.children.forEach((c) => { if (c.matches(sel)) out.push(c); walk(c); }); }; walk(this); return out; },
        submit() { submitted.push(this); },
    };
    return node;
}

// page loads backpack.js over a stored backpack; BAN is the fake window.BAN, or none.
function page({ store = [], tabs, tabList, ban, BAN, confirmDialog, navMenu = false, signedIn = true } = {}) {
    ids = {}; submitted = [];
    const m = { mtgban_backpack: JSON.stringify(store) };
    if (tabList) m.mtgban_backpack_tabs = JSON.stringify(tabList);
    const localStorage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const sm = {};
    const sessionStorage = { getItem: (k) => (k in sm ? sm[k] : null), setItem: (k, v) => { sm[k] = String(v); }, removeItem: (k) => { delete sm[k]; } };
    const body = el('body');
    const nav = el('button'); nav.setAttribute('id', 'nav-backpack');
    body.appendChild(nav);
    if (navMenu) { const menu = el('div'); menu.setAttribute('id', 'nav-backpack-menu'); menu.hidden = true; body.appendChild(menu); }
    const window = {
        localStorage, sessionStorage, confirm: () => true, addEventListener() {},
        location: { pathname: '/search', href: '/search' },
    };
    if (BAN) window.BAN = BAN;
    if (ban) window.BAN_BACKPACK = ban;
    if (tabs) window.BAN_BACKPACK_TABS = tabs;
    if (confirmDialog) window.confirmDialog = confirmDialog;
    window.fetch = () => new Promise(() => {});
    const document = {
        body, readyState: 'complete', addEventListener() {},
        documentElement: { dataset: { signedIn: String(signedIn) } },
        getElementById: (id) => ids[id] || null,
        createElement: (tag) => el(tag),
        querySelectorAll: (sel) => body.querySelectorAll(sel),
        activeElement: null,
    };
    currentDoc = document;
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'ListStorage', 'setTimeout',
        listStorage + '; window.ListStorage = ListStorage; ' + source)(
        window, document, localStorage, sessionStorage, undefined, () => {});
    const live = () => JSON.parse(m.mtgban_backpack).filter((e) => !e.del);
    return { window, nav, m, live };
}

const NAMES = ['ui.backpack.panel', 'ui.backpack.card', 'ui.backpack.tab', 'ui.backpack.sort', 'ui.backpack', 'ui.backpack.upload'];
const ours = (calls) => calls.filter((c) => NAMES.includes(c[0]));
const strip = () => ids['backpack-tabs'];
const tabsOf = () => strip().children.filter((b) => b.classes.has('backpack-tab'));
const rowsOf = () => ids['backpack-list'].children;
const pick = (sel, v) => { sel.value = v; (sel.listeners.change || []).forEach((fn) => fn()); };
const keydown = (n, key) => (n.listeners.keydown || []).forEach((fn) => fn({ key, preventDefault() {}, stopPropagation() {} }));
const two = [{ id: 'uuid-1', name: 'One', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'Two', pack: 2, qty: 3, t: 2, m: 2 }];

test('opening the panel counts once', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN });
    p.nav.click();
    p.nav.click(); // closes
    expect(ours(calls)).toEqual([['ui.backpack.panel', 'open', undefined]]);
});

test('plus and minus count by what they did', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN, store: [{ id: 'uuid-1', name: 'One', qty: 2, t: 1, m: 1 }] });
    p.nav.click();
    rowsOf()[0].querySelector('.backpack-plus').click();
    rowsOf()[0].querySelector('.backpack-minus').click();
    rowsOf()[0].querySelector('.backpack-minus').click();
    expect(p.live()[0].qty).toBe(1);
    rowsOf()[0].querySelector('.backpack-minus').click();
    expect(p.live()).toEqual([]);
    expect(ours(calls).slice(1)).toEqual([
        ['ui.backpack.card', 'qty_up', undefined], ['ui.backpack.card', 'qty_down', undefined],
        ['ui.backpack.card', 'qty_down', undefined], ['ui.backpack.card', 'remove', undefined],
    ]);
});

test('a grade change, a second grade and a move are three values', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN, store: [{ id: 'uuid-1', name: 'One', qty: 2, t: 1, m: 1 }], tabs: 2, tabList: [{ pack: 1 }, { pack: 2 }] });
    p.nav.click();
    pick(rowsOf()[0].querySelector('.backpack-cond'), 'SP');
    pick(rowsOf()[0].querySelector('.backpack-cond'), '+NM');
    pick(rowsOf()[0].querySelector('.backpack-cond'), '@2');
    expect(ours(calls).slice(1)).toEqual([
        ['ui.backpack.card', 'condition', undefined], ['ui.backpack.card', 'condition_add', undefined], ['ui.backpack.card', 'move_pack', undefined],
    ]);
});

test('a new tab counts only when one was made', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN, store: two.slice(0, 1), tabs: 2 });
    p.nav.click();
    const add = ids['backpack-tab-add'];
    add.click();
    add.click(); // at the tier's limit: addTab() refuses
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack.tab')).toEqual([['ui.backpack.tab', 'new', undefined]]);
});

test('picking another tab counts switch, and Enter on it is the same pick', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN, store: two, tabs: 3 });
    p.nav.click();
    tabsOf()[1].click();
    keydown(tabsOf()[0], 'Enter');
    keydown(tabsOf()[0], 'ArrowRight'); // the arrow keys are ui.key's
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack.tab')).toEqual([['ui.backpack.tab', 'switch', undefined], ['ui.backpack.tab', 'switch', undefined]]);
});

test('a rename that keeps the name, or blanks it, counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN, store: two, tabs: 2 });
    p.nav.click();
    for (const value of ['  Backpack 1 ', '   ', 'Trades']) {
        tabsOf()[0].click();
        const field = strip().children[0];
        field.value = value;
        keydown(field, 'Enter');
    }
    tabsOf()[0].click();
    const field = strip().children[0];
    field.value = 'Binder';
    keydown(field, 'Escape');
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack.tab')).toEqual([['ui.backpack.tab', 'rename', undefined]]);
});

test('deleting a tab with cards counts on confirm, not on ask', () => {
    const { BAN, calls } = fakeBAN();
    let ok = null;
    const p = page({ BAN, store: two, tabs: 2, confirmDialog: (msg, onOk) => { ok = onOk; } });
    p.nav.click();
    strip().children.find((b) => b.classes.has('backpack-tab-del')).click();
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack.tab')).toEqual([]);
    ok();
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack.tab')).toEqual([['ui.backpack.tab', 'delete', undefined]]);
});

test('the sort reports its key and the direction in scope', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN, store: [{ id: 'uuid-1', name: 'One', qty: 1, t: 1, m: 1 }, { id: 'uuid-2', name: 'Two', qty: 1, t: 2, m: 2 }] });
    p.nav.click();
    pick(ids['backpack-sort-by'], 'retail');
    ids['backpack-sort-dir'].click();
    expect(ours(calls).slice(1)).toEqual([['ui.backpack.sort', 'retail', 'desc'], ['ui.backpack.sort', 'retail', 'asc']]);
});

test('an inherited name in the sort counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN, store: [{ id: 'uuid-1', name: 'One', qty: 1, t: 1, m: 1 }, { id: 'uuid-2', name: 'Two', qty: 1, t: 2, m: 2 }] });
    p.nav.click();
    for (const by of ['constructor', 'toString', '__proto__']) {
        pick(ids['backpack-sort-by'], by);
        p.m.mtgban_backpack_sort = JSON.stringify({ by, dir: 'asc' });
        ids['backpack-sort-dir'].click();
    }
    for (const [name, value, scope] of ours(calls)) {
        if (name !== 'ui.backpack.sort') continue;
        expect(registry['ui.backpack.sort'].enum).toContain(value);
        expect(registry['ui.backpack.sort'].scopes).toContain(scope);
    }
});

test('emptying counts on confirm; undo counts when something came back', () => {
    const { BAN, calls } = fakeBAN();
    let ok = null;
    const p = page({ BAN, store: [{ id: 'uuid-1', name: 'One', qty: 1, t: 1, m: 1 }], confirmDialog: (msg, onOk) => { ok = onOk; } });
    p.nav.click();
    ids['backpack-undo'].click(); // nothing to undo
    ids['backpack-clear'].click();
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack')).toEqual([]);
    ok();
    ids['backpack-undo'].click();
    expect(p.live().length).toBe(1);
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack')).toEqual([['ui.backpack', 'clear', undefined], ['ui.backpack', 'undo', undefined]]);
});

test('the search, the empty-after switch and the navbar pick count under ui.backpack', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN, store: two, tabs: 2, navMenu: true });
    p.nav.click();
    ids['backpack-search'].click();
    const sw = ids['backpack-empty-after'];
    sw.checked = true;
    sw.listeners.change.forEach((fn) => fn());
    sw.checked = false;
    sw.listeners.change.forEach((fn) => fn());
    ids['nav-backpack-menu'].children[1].click();
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack')).toEqual([
        ['ui.backpack', 'search', undefined], ['ui.backpack', 'empty_after_on', undefined],
        ['ui.backpack', 'empty_after_off', undefined], ['ui.backpack', 'switch_menu', undefined],
    ]);
});

test('a send that is refused counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    page({ BAN, store: [{ id: 'uuid-1', name: 'One', qty: 1, t: 1, m: 1 }], ban: { canUpload: false } }).nav.click();
    ids['backpack-send-buylist'].click();
    page({ BAN }).nav.click();
    ids['backpack-send-retail'].click();
    expect(submitted).toEqual([]);
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack.upload')).toEqual([]);
});

test('a send reports its mode', () => {
    const { BAN, calls } = fakeBAN();
    page({ BAN, store: [{ id: 'uuid-1', name: 'One', qty: 1, t: 1, m: 1 }] }).nav.click();
    ids['backpack-send-buylist'].click();
    expect(submitted.length).toBe(1);
    expect(ours(calls).filter((c) => c[0] === 'ui.backpack.upload')).toEqual([['ui.backpack.upload', 'buylist', undefined]]);
});

test('every value and scope sent is registered', () => {
    const { BAN, calls } = fakeBAN();
    const p = page({ BAN, store: [{ id: 'uuid-1', name: 'One', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'Two', qty: 1, t: 2, m: 2 }], tabs: 3, navMenu: true });
    p.nav.click();
    rowsOf()[0].querySelector('.backpack-plus').click();
    pick(ids['backpack-sort-by'], 'edition');
    ids['backpack-tab-add'].click();
    ids['backpack-send-retail'].click();
    expect(ours(calls).length).toBeGreaterThan(3);
    for (const [name, value, scope] of ours(calls)) {
        const n = registry[name];
        expect(n.enum).toContain(value);
        if (scope === undefined) expect(n.scope).toBe('ScopeNone');
        else expect(n.scopes).toContain(scope);
    }
});

test('with no window.BAN the panel still opens and sends', () => {
    const p = page({ store: [{ id: 'uuid-1', name: 'One', qty: 2, t: 1, m: 1 }], tabs: 2 });
    p.nav.click();
    expect(ids['backpack-panel'].classes.has('open')).toBe(true);
    rowsOf()[0].querySelector('.backpack-plus').click();
    pick(ids['backpack-sort-by'], 'name');
    ids['backpack-sort-dir'].click();
    ids['backpack-send-retail'].click();
    expect(submitted.length).toBe(1);
    ids['backpack-tab-add'].click();
    expect(tabsOf().length).toBe(2);
});
