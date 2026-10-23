import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/store-factors.js', import.meta.url), 'utf8');

function fakeStorage(initial = {}) {
    const m = Object.assign({}, initial);
    return {
        getItem: (k) => (k in m ? m[k] : null),
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
        dump: () => m,
    };
}

// Runs the module against fakes: cookies as a map, a path, and a reload counter.
function load(env = {}) {
    const cookies = Object.assign({}, env.cookies || {});
    const reloads = [];
    const window = {
        location: { pathname: env.path || '/search', reload: () => reloads.push(1) },
        addEventListener() {},
    };
    const document = { createElement: () => ({ appendChild() {}, addEventListener() {}, setAttribute() {}, style: {} }), addEventListener() {} };
    const localStorage = env.local || fakeStorage();
    const sessionStorage = env.session || fakeStorage();
    const setCookie = (name, value) => { if (value === '') delete cookies[name]; else cookies[name] = value; };
    const getCookie = (name) => cookies[name] || '';
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'setCookie', 'getCookie', 'Event', source)(
        window, document, localStorage, sessionStorage, setCookie, getCookie, class Event { constructor(t) { this.type = t; } });
    return { SF: window.StoreFactors, cookies, reloads, localStorage, sessionStorage };
}

const STORES = [
    { k: 'CK', n: 'Card Kingdom', r: true, b: true },
    { k: 'TCG', n: 'TCGplayer', r: true, b: false },
    { k: 'ABU', n: 'ABU Games', r: false, b: true },
];

test('normalize keeps integer percents in range on stores that have that side', () => {
    const { SF } = load();
    expect(SF.normalize({ CK: { discount: 10, credit: 85 } }, STORES)).toEqual({ CK: { discount: 10, credit: 85 } });
    expect(SF.normalize({ TCG: { discount: 5, credit: 80 } }, STORES)).toEqual({ TCG: { discount: 5 } });
    expect(SF.normalize({ ABU: { discount: 5, credit: 80 } }, STORES)).toEqual({ ABU: { credit: 80 } });
    expect(SF.normalize({ GONE: { discount: 5 } }, STORES)).toEqual({});
    expect(SF.normalize({ CK: { discount: 12.5, credit: 85 } }, STORES)).toEqual({ CK: { credit: 85 } });
    expect(SF.normalize({ CK: { discount: -3, credit: 500 } }, STORES)).toEqual({});
    expect(SF.normalize({ CK: { discount: 0, credit: 100 } }, STORES)).toEqual({});
    expect(SF.normalize({ CK: { discount: 90, credit: 300 } }, STORES)).toEqual({ CK: { discount: 90, credit: 300 } });
    expect(SF.normalize({ CK: { discount: 91, credit: 9 } }, STORES)).toEqual({});
    expect(SF.normalize({ CK: 'nope', TCG: null }, STORES)).toEqual({});
    expect(SF.normalize(null, STORES)).toEqual({});
});

test('the cookie form round-trips, sorted by store, an empty number for an unset side', () => {
    const { SF } = load();
    const obj = { TCG: { discount: 5 }, CK: { discount: 10, credit: 85 }, ABU: { credit: 80 } };
    expect(SF.toCookie(obj)).toBe('ABU::80,CK:10:85,TCG:5:');
    expect(SF.fromCookie('ABU::80,CK:10:85,TCG:5:')).toEqual(obj);
    expect(SF.fromCookie('')).toEqual({});
    expect(SF.fromCookie('CK:91:,TCG:5:,bad,X:1:2:3')).toEqual({ TCG: { discount: 5 } });
    expect(SF.toCookie({})).toBe('');
});

test('read gives an object, or {} for nothing or garbage', () => {
    expect(load().SF.read()).toEqual({});
    expect(load({ local: fakeStorage({ mtgban_store_factors: '{"CK":{"discount":10}}' }) }).SF.read()).toEqual({ CK: { discount: 10 } });
    expect(load({ local: fakeStorage({ mtgban_store_factors: '[1]' }) }).SF.read()).toEqual({});
    expect(load({ local: fakeStorage({ mtgban_store_factors: 'nope' }) }).SF.read()).toEqual({});
});

test('save writes the preference and the cookie together; empty saves {} and clears the cookie', () => {
    const { SF, cookies, localStorage } = load({ cookies: { SearchStoreFactors: 'CK:10:' } });
    SF.save({ CK: { discount: 10, credit: 85 } });
    expect(localStorage.getItem('mtgban_store_factors')).toBe('{"CK":{"discount":10,"credit":85}}');
    expect(cookies.SearchStoreFactors).toBe('CK:10:85');
    SF.save({});
    expect(localStorage.getItem('mtgban_store_factors')).toBe('{}');
    expect(cookies.SearchStoreFactors).toBeUndefined();
});

test('mirror brings a stale cookie to the preference and reloads once', () => {
    const local = fakeStorage({ mtgban_store_factors: '{"CK":{"discount":10}}' });
    const session = fakeStorage();
    // The load-time mirror reloads; the explicit call is then a no-op
    const first = load({ local, session, cookies: { SearchStoreFactors: 'CK:20:' } });
    first.SF.mirror();
    expect(first.cookies.SearchStoreFactors).toBe('CK:10:');
    expect(first.reloads).toHaveLength(1);
    // The cookie did not take (blocked): the same preference does not reload again
    const second = load({ local, session, cookies: { SearchStoreFactors: 'CK:20:' } });
    second.SF.mirror();
    expect(second.reloads).toHaveLength(0);
    // A new preference value may reload once more
    local.setItem('mtgban_store_factors', '{"CK":{"discount":15}}');
    const third = load({ local, session, cookies: { SearchStoreFactors: 'CK:20:' } });
    third.SF.mirror();
    expect(third.reloads).toHaveLength(1);
});

test('mirror does nothing when the two agree, including both empty', () => {
    const a = load({ local: fakeStorage({ mtgban_store_factors: '{"CK":{"discount":10}}' }), cookies: { SearchStoreFactors: 'CK:10:' } });
    a.SF.mirror();
    expect(a.reloads).toHaveLength(0);
    const b = load();
    b.SF.mirror();
    expect(b.reloads).toHaveLength(0);
    expect(b.localStorage.getItem('mtgban_store_factors')).toBeNull();
});

test('mirror adopts a cookie into a device with no preference yet, without reloading', () => {
    const { SF, reloads, localStorage } = load({ cookies: { SearchStoreFactors: 'CK:10:85' } });
    SF.mirror();
    expect(JSON.parse(localStorage.getItem('mtgban_store_factors'))).toEqual({ CK: { discount: 10, credit: 85 } });
    expect(reloads).toHaveLength(0);
});

test('an emptied preference clears a cookie another device set', () => {
    const { SF, cookies, reloads } = load({ local: fakeStorage({ mtgban_store_factors: '{}' }), cookies: { SearchStoreFactors: 'CK:10:' } });
    SF.mirror();
    expect(cookies.SearchStoreFactors).toBeUndefined();
    expect(reloads).toHaveLength(1);
});

test('mirror writes the cookie on every page but reloads only search and sealed', () => {
    const pref = () => fakeStorage({ mtgban_store_factors: '{"CK":{"discount":10}}' });
    const { SF, reloads, cookies } = load({ path: '/upload', local: pref(), cookies: { SearchStoreFactors: 'CK:20:' } });
    SF.mirror();
    expect(reloads).toHaveLength(0);
    expect(cookies.SearchStoreFactors).toBe('CK:10:');
    const sealed = load({ path: '/sealed', local: pref(), cookies: { SearchStoreFactors: 'CK:20:' } });
    expect(sealed.reloads).toHaveLength(1);
    const foo = load({ path: '/searchfoo', local: pref(), cookies: { SearchStoreFactors: 'CK:20:' } });
    expect(foo.reloads).toHaveLength(0);
    expect(foo.cookies.SearchStoreFactors).toBe('CK:10:');
    const shared = load({ path: '/search/shared', local: pref(), cookies: { SearchStoreFactors: 'CK:20:' } });
    expect(shared.reloads).toHaveLength(1);
});

test('mirror compares normalized forms: an out-of-range preference matches an empty cookie', () => {
    const { SF, reloads, cookies } = load({ local: fakeStorage({ mtgban_store_factors: '{"CK":{"discount":500}}' }) });
    SF.mirror();
    expect(cookies.SearchStoreFactors).toBeUndefined();
    expect(reloads).toHaveLength(0);
});

test('the script runs mirror itself when loaded on a search page', () => {
    const { reloads } = load({ local: fakeStorage({ mtgban_store_factors: '{"CK":{"discount":10}}' }), cookies: { SearchStoreFactors: 'CK:20:' } });
    expect(reloads).toHaveLength(1);
});

// A DOM small enough for the editor: children, class lists, attributes,
// values and listeners.
function fakeElement(tag) {
    const el = {
        tagName: tag.toUpperCase(), className: '', children: [], listeners: {}, attrs: {}, style: {},
        value: '', disabled: false, type: '', parent: null,
        appendChild(c) { c.parent = el; el.children.push(c); return c; },
        remove() { if (el.parent) el.parent.children = el.parent.children.filter((c) => c !== el); },
        addEventListener(ev, fn) { (el.listeners[ev] = el.listeners[ev] || []).push(fn); },
        dispatchEvent(e) { (el.listeners[e.type] || []).forEach((fn) => fn(e)); if (e.bubbles && el.parent) el.parent.dispatchEvent(e); return true; },
        setAttribute(k, v) { el.attrs[k] = String(v); },
        getAttribute(k) { return k in el.attrs ? el.attrs[k] : null; },
        fire(ev) { el.dispatchEvent({ type: ev, bubbles: true }); },
        querySelector(sel) { return el.querySelectorAll(sel)[0] || null; },
        querySelectorAll(sel) {
            const cls = sel.replace(/^\./, '');
            const out = [];
            (function walk(n) { n.children.forEach((c) => { if (c.className.split(' ').includes(cls)) out.push(c); walk(c); }); })(el);
            return out;
        },
    };
    Object.defineProperty(el, 'textContent', {
        get() { return el._text || ''; },
        set(v) { el._text = v; if (v === '') el.children = []; },
    });
    return el;
}

function loadEditor(stores, pref) {
    const local = fakeStorage(pref ? { mtgban_store_factors: JSON.stringify(pref) } : {});
    const cookies = {};
    const window = { location: { pathname: '/upload', reload() {} }, addEventListener() {} };
    const document = { createElement: fakeElement, addEventListener() {} };
    const setCookie = (name, value) => { if (value === '') delete cookies[name]; else cookies[name] = value; };
    const getCookie = (name) => cookies[name] || '';
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'setCookie', 'getCookie', 'Event', source)(
        window, document, local, fakeStorage(), setCookie, getCookie, class Event { constructor(t, o) { this.type = t; this.bubbles = !!(o && o.bubbles); } });
    const container = fakeElement('div');
    container.setAttribute('data-stores', JSON.stringify(stores));
    return { SF: window.StoreFactors, container, local, cookies };
}

function rows(container) { return container.querySelectorAll('.store-factors-row'); }
function selectOf(row) { return row.querySelector('.store-factors-store'); }
function discountOf(row) { return row.querySelector('.store-factors-discount'); }
function creditOf(row) { return row.querySelector('.store-factors-credit'); }

test('render draws one row per saved store, sorted, with the right fields enabled', () => {
    const { SF, container } = loadEditor(STORES, { TCG: { discount: 5 }, CK: { discount: 10, credit: 85 }, GONE: { discount: 1 } });
    SF.render(container, SF.read());
    const r = rows(container);
    expect(r).toHaveLength(2);
    expect(selectOf(r[0]).value).toBe('CK');
    expect(discountOf(r[0]).value).toBe('10');
    expect(creditOf(r[0]).value).toBe('85');
    expect(selectOf(r[1]).value).toBe('TCG');
    expect(discountOf(r[1]).value).toBe('5');
    expect(creditOf(r[1]).disabled).toBe(true);
    expect(creditOf(r[1]).value).toBe('');
    expect(container.querySelector('.store-factors-add')).not.toBeNull();
    expect(discountOf(r[0]).getAttribute('min') || discountOf(r[0]).min).toBeDefined();
});

test('the store list splits into Singles and Sealed groups, sealed names marked, only when a sealed store is listed', () => {
    const labels = (select) => select.children.map((g) => [g.getAttribute('label'), g.children.map((o) => o.value)]);
    const sealed = [STORES[0], STORES[1], { k: 'CKSealed', n: 'Card Kingdom', r: true, b: true, s: true }];
    const { SF, container } = loadEditor(sealed, { CKSealed: { discount: 5 } });
    SF.render(container, SF.read());
    const select = selectOf(rows(container)[0]);
    expect(labels(select)).toEqual([['Singles', ['CK', 'TCG']], ['Sealed', ['CKSealed']]]);
    const selected = select.children.flatMap((g) => g.children.filter((o) => o.selected).map((o) => o.value));
    expect(selected).toEqual(['CKSealed']);
    expect(select.children[1].children[0].textContent).toBe('Card Kingdom (Sealed)');
    expect(select.children[0].children[0].textContent).toBe('Card Kingdom');

    const flat = loadEditor(STORES, { CK: { discount: 5 } });
    flat.SF.render(flat.container, flat.SF.read());
    const options = selectOf(rows(flat.container)[0]).children;
    expect(options.map((o) => o.tagName)).toEqual(['OPTION', 'OPTION', 'OPTION']);
});

test('collect reads the rows back through normalize', () => {
    const { SF, container } = loadEditor(STORES, { CK: { discount: 10, credit: 85 } });
    SF.render(container, SF.read());
    const r = rows(container)[0];
    discountOf(r).value = '12.5';
    creditOf(r).value = '90';
    expect(SF.collect(container)).toEqual({ CK: { credit: 90 } });
    discountOf(r).value = '-3';
    creditOf(r).value = '500';
    expect(SF.collect(container)).toEqual({});
    discountOf(r).value = '20';
    creditOf(r).value = '100';
    expect(SF.collect(container)).toEqual({ CK: { discount: 20 } });
});

test('Add store appends a row; changing its store disables the side it lacks; Remove drops it', () => {
    const { SF, container } = loadEditor(STORES, null);
    SF.render(container, {});
    expect(rows(container)).toHaveLength(0);
    let changes = 0;
    container.addEventListener('change', () => { changes++; });
    container.querySelector('.store-factors-add').fire('click');
    expect(rows(container)).toHaveLength(1);
    expect(changes).toBe(1);
    const r = rows(container)[0];
    expect(selectOf(r).value).toBe('CK');
    discountOf(r).value = '10';
    discountOf(r).fire('input');
    expect(changes).toBe(2);
    creditOf(r).value = '80';
    creditOf(r).fire('input');
    expect(changes).toBe(3);
    selectOf(r).value = 'ABU';
    selectOf(r).fire('change');
    expect(discountOf(r).disabled).toBe(true);
    expect(discountOf(r).value).toBe('');
    expect(creditOf(r).disabled).toBe(false);
    expect(SF.collect(container)).toEqual({ ABU: { credit: 80 } });
    const beforeRemove = changes;
    r.querySelector('.store-factors-remove').fire('click');
    expect(rows(container)).toHaveLength(0);
    expect(SF.collect(container)).toEqual({});
    expect(changes).toBe(beforeRemove + 1);
});

test('two rows for one store: the later one wins', () => {
    const { SF, container } = loadEditor(STORES, null);
    SF.render(container, {});
    container.querySelector('.store-factors-add').fire('click');
    container.querySelector('.store-factors-add').fire('click');
    const r = rows(container);
    selectOf(r[1]).value = 'CK';
    selectOf(r[1]).fire('change');
    discountOf(r[0]).value = '10';
    discountOf(r[1]).value = '20';
    expect(SF.collect(container)).toEqual({ CK: { discount: 20 } });
});

test('the binding loads the saved rows, saves both copies and serializes the current rows', () => {
    const { SF, container, local, cookies } = loadEditor(STORES, { CK: { discount: 10 } });
    const b = SF.binding(container);
    b.load();
    expect(rows(container)).toHaveLength(1);
    const before = b.serialize();
    discountOf(rows(container)[0]).value = '15';
    expect(b.serialize()).not.toBe(before);
    b.save();
    expect(local.getItem('mtgban_store_factors')).toBe('{"CK":{"discount":15}}');
    expect(cookies.SearchStoreFactors).toBe('CK:15:');
});

test('a save keeps entries for stores the editor does not list', () => {
    const { SF, container, local, cookies } = loadEditor(STORES, { CK: { discount: 10 }, GONE: { discount: 5 } });
    const b = SF.binding(container);
    b.load();
    expect(rows(container)).toHaveLength(1);
    b.save();
    expect(JSON.parse(local.getItem('mtgban_store_factors'))).toEqual({ CK: { discount: 10 }, GONE: { discount: 5 } });
    expect(cookies.SearchStoreFactors).toBe('CK:10:,GONE:5:');
    rows(container)[0].querySelector('.store-factors-remove').fire('click');
    b.save();
    expect(JSON.parse(local.getItem('mtgban_store_factors'))).toEqual({ GONE: { discount: 5 } });
    expect(cookies.SearchStoreFactors).toBe('GONE:5:');
});

test('a container with no stores renders a disabled Add button', () => {
    const { SF, container } = loadEditor([], null);
    SF.render(container, { CK: { discount: 10 } });
    expect(rows(container)).toHaveLength(0);
    expect(container.querySelector('.store-factors-add').disabled).toBe(true);
});

test('Add picks the next store without a row and keeps the earlier row', () => {
    const { SF, container } = loadEditor(STORES, { CK: { discount: 10, credit: 85 } });
    SF.render(container, SF.read());
    container.querySelector('.store-factors-add').fire('click');
    const r = rows(container);
    expect(r).toHaveLength(2);
    expect(selectOf(r[1]).value).toBe('TCG');
    expect(SF.collect(container)).toEqual({ CK: { discount: 10, credit: 85 } });
});

test('Add is disabled once every store has a row, and a removal re-enables it', () => {
    const { SF, container } = loadEditor(STORES, null);
    SF.render(container, {});
    const add = container.querySelector('.store-factors-add');
    add.fire('click');
    add.fire('click');
    expect(add.disabled).toBe(false);
    add.fire('click');
    expect(rows(container)).toHaveLength(3);
    expect(add.disabled).toBe(true);
    add.fire('click');
    expect(rows(container)).toHaveLength(3);
    rows(container)[2].querySelector('.store-factors-remove').fire('click');
    expect(add.disabled).toBe(false);
});

test('an untouched row never shadows a filled row for the same store', () => {
    const { SF, container } = loadEditor(STORES, { CK: { discount: 10, credit: 85 } });
    SF.render(container, SF.read());
    container.querySelector('.store-factors-add').fire('click');
    const r = rows(container);
    selectOf(r[1]).value = 'CK';
    selectOf(r[1]).fire('change');
    expect(SF.collect(container)).toEqual({ CK: { discount: 10, credit: 85 } });
});
