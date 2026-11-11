import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-sort.js', import.meta.url), 'utf8');
const html = readFileSync(new URL('../templates/upload.html', import.meta.url), 'utf8');

// An element with the attributes the sorter reads and writes.
function element(attrs) {
    const map = Object.assign({}, attrs);
    return {
        hasAttribute: (n) => Object.prototype.hasOwnProperty.call(map, n),
        getAttribute: (n) => (Object.prototype.hasOwnProperty.call(map, n) ? map[n] : null),
        setAttribute: (n, v) => { map[n] = v; },
        removeAttribute: (n) => { delete map[n]; },
    };
}

// A cell as the template renders it: text, and data-sort where the text is
// not what it sorts by.
function cell(text, sort) {
    const attrs = sort === undefined ? {} : { 'data-sort': sort };
    return Object.assign(element(attrs), { textContent: text });
}

// An entry row carries a hash; the totals row stays put instead.
function row(cells, hash) {
    const attrs = hash === undefined ? { 'data-sort-method': 'none' } : { 'data-hash': hash };
    return Object.assign(element(attrs), { cells });
}

// An optimizer row, which carries its place in the store's lists instead.
function optRow(cells, idx) {
    return Object.assign(element({ 'data-load-idx': String(idx) }), { cells });
}

// A table: its header row, under the rows above it in the head (an
// optimizer table's store header), its rows, and a tbody whose
// appendChild moves a row to the end the way a real one does.
function table(headers, rows, above = [], kind = 'ures-table') {
    const tbody = {
        rows: rows.slice(),
        appendChild(r) {
            this.rows.splice(this.rows.indexOf(r), 1);
            this.rows.push(r);
        },
    };
    const headRow = { cells: headers };
    const t = {
        tBodies: [tbody], tHead: { rows: above.concat([headRow]) }, events: [],
        classList: { contains: (c) => c === kind },
        // The menu asks whether any row has a value for a key
        querySelector: (sel) => {
            const key = (sel.match(/data-k-(\w+)/) || [])[1];
            return tbody.rows.find((r) => r.getAttribute('data-k-' + key)) || null;
        },
    };
    t.dispatchEvent = (e) => t.events.push(e.type + (e.bubbles ? ' bubbles' : ''));
    headers.forEach((th, i) => { th.cellIndex = i; th.closest = () => t; th.parentNode = headRow; });
    return t;
}

function load(document = { addEventListener: () => {} }, localStorage = storage()) {
    return new Function('document', 'localStorage', source +
        '\nreturn {uresSortBy, uresParseChain, uresMenuAct, uresRenderMenu, chains: () => uresChains};')(document, localStorage);
}

// A localStorage that counts its writes
function storage(saved = {}) {
    const map = Object.assign({}, saved);
    return {
        writes: 0,
        getItem: (k) => (k in map ? map[k] : null),
        setItem(k, v) { map[k] = String(v); this.writes++; },
        map,
    };
}

// A page holding tables and Card-header buttons, as the menu reaches them
function page(tables, buttons = []) {
    const listeners = {};
    return {
        listeners,
        body: { appendChild: () => {} },
        addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
        getElementById: () => null,
        createElement: () => Object.assign(element({}), { addEventListener: () => {}, style: {} }),
        querySelectorAll: (sel) => {
            if (sel === '.ures-table, .opt-table') return tables;
            const area = (sel.match(/data-sort-area="(\w+)"/) || [])[1];
            if (area) return buttons.filter((b) => b.getAttribute('data-sort-area') === area);
            return [];
        },
    };
}

// A Card-header button for an area
function button(area) {
    const classes = new Set();
    return Object.assign(element({ 'data-sort-area': area }), {
        addEventListener: () => {},
        classList: { toggle: (c, on) => (on ? classes.add(c) : classes.delete(c)), has: (c) => classes.has(c) },
    });
}

// A row with card-property keys, as the template writes them
function keyed(hash, keys) {
    const attrs = { 'data-hash': hash };
    Object.entries(keys).forEach(([k, v]) => { attrs['data-k-' + k] = v; });
    return Object.assign(element(attrs), { cells: [cell(hash)] });
}

function hashes(t) {
    return t.tBodies[0].rows.map((r) => (r.hasAttribute('data-hash') ? r.getAttribute('data-hash') : 'totals'));
}

function idxs(t) {
    return t.tBodies[0].rows.map((r) => r.getAttribute('data-load-idx'));
}

test('a price column sorts highest first, missing prices last, the totals row at the end', () => {
    const { uresSortBy } = load();
    const price = Object.assign(element({ 'data-sort-method': 'number', 'data-sort-descending': '' }), {});
    const t = table([element({}), price], [
        row([cell('a'), cell('$ 1.50', '1.50')], 'a'),
        row([cell('b'), cell('-', '')], 'b'),
        row([cell('c'), cell('$ 12.00', '12.00')], 'c'),
        row([cell('d'), cell('$ 2.00', '2.00')], 'd'),
        row([cell('Totals'), cell('$ 15.50')]),
    ]);

    uresSortBy(price);
    expect(hashes(t)).toEqual(['c', 'd', 'a', 'b', 'totals']);
    expect(price.getAttribute('aria-sort')).toBe('descending');

    uresSortBy(price);
    expect(hashes(t)).toEqual(['a', 'd', 'c', 'b', 'totals']);
    expect(price.getAttribute('aria-sort')).toBe('ascending');
});

test('a number column reads its text when it has no data-sort', () => {
    const { uresSortBy } = load();
    const qty = element({ 'data-sort-method': 'number', 'data-sort-descending': '' });
    const t = table([element({}), qty], [
        row([cell('a'), cell('2')], 'a'),
        row([cell('b'), cell('10')], 'b'),
        row([cell('c'), cell('$ 3.00')], 'c'),
    ]);
    uresSortBy(qty);
    expect(hashes(t)).toEqual(['b', 'c', 'a']);
});

test('a text column sorts A to Z first, ignoring case, with numbers in order', () => {
    const { uresSortBy } = load();
    const card = element({});
    const t = table([card], [
        row([cell('x', 'Fireball Alpha #10')], 'a'),
        row([cell('x', 'fireball Alpha #9')], 'b'),
        row([cell('x', 'Counterspell Beta #1')], 'c'),
    ]);
    uresSortBy(card);
    expect(hashes(t)).toEqual(['c', 'b', 'a']);
    expect(card.getAttribute('aria-sort')).toBe('ascending');
    uresSortBy(card);
    expect(hashes(t)).toEqual(['a', 'b', 'c']);
});

test('ties keep the order they had, and only the clicked header shows a direction', () => {
    const { uresSortBy } = load();
    const card = element({});
    const cond = element({ 'data-sort-method': 'number' });
    const t = table([card, cond], [
        row([cell('b', 'b'), cell('NM', '0')], 'b'),
        row([cell('a', 'a'), cell('SP', '1')], 'a'),
        row([cell('c', 'c'), cell('NM', '0')], 'c'),
    ]);
    uresSortBy(card);
    expect(hashes(t)).toEqual(['a', 'b', 'c']);
    uresSortBy(cond);
    expect(hashes(t)).toEqual(['b', 'c', 'a']);
    expect(card.hasAttribute('aria-sort')).toBe(false);
    expect(cond.getAttribute('aria-sort')).toBe('ascending');
});

test('optimizer rows move, though they carry no hash', () => {
    const { uresSortBy } = load();
    const offer = element({ 'data-sort-method': 'number', 'data-sort-descending': 'true' });
    const t = table([element({}), offer], [
        optRow([cell('a'), cell('$ 1.00')], 0),
        optRow([cell('b'), cell('$ 5.00')], 1),
        optRow([cell('c'), cell('$ 3.00')], 2),
    ]);
    uresSortBy(offer);
    expect(idxs(t)).toEqual(['1', '2', '0']);
});

test('data-sort-descending="false" sorts ascending first, "true" descending', () => {
    const { uresSortBy } = load();
    const retail = element({ 'data-sort-method': 'number', 'data-sort-descending': 'false' });
    const t = table([retail], [optRow([cell('5')], 0), optRow([cell('1')], 1), optRow([cell('3')], 2)]);
    uresSortBy(retail);
    expect(idxs(t)).toEqual(['1', '2', '0']);
    expect(retail.getAttribute('aria-sort')).toBe('ascending');

    const buylist = element({ 'data-sort-method': 'number', 'data-sort-descending': 'true' });
    const u = table([buylist], [optRow([cell('5')], 0), optRow([cell('1')], 1), optRow([cell('3')], 2)]);
    uresSortBy(buylist);
    expect(idxs(u)).toEqual(['0', '2', '1']);
    expect(buylist.getAttribute('aria-sort')).toBe('descending');
});

test('the direction is cleared on the header row, below the store header', () => {
    const { uresSortBy } = load();
    const store = element({ 'aria-sort': 'ascending' });
    const card = element({});
    const set = element({});
    table([card, set], [optRow([cell('b'), cell('x')], 0), optRow([cell('a'), cell('y')], 1)],
        [{ cells: [store] }]);
    uresSortBy(card);
    uresSortBy(set);
    expect(card.hasAttribute('aria-sort')).toBe(false);
    expect(set.getAttribute('aria-sort')).toBe('ascending');
    expect(store.getAttribute('aria-sort')).toBe('ascending');
});

test('headers marked data-sort-method="none" are not made sortable', () => {
    const listeners = {};
    const ths = [element({}), element({ 'data-sort-method': 'none' }), element({ 'data-sort-method': 'number' })];
    ths.forEach((th) => { th.events = []; th.addEventListener = (type) => th.events.push(type); });
    let asked = '';
    load({
        addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
        querySelectorAll: (sel) => {
            if (!sel.includes('thead th')) return [];
            asked = sel;
            return ths;
        },
    });
    listeners.DOMContentLoaded.forEach((fn) => fn());
    expect(asked).toBe('.ures-table thead th, .opt-table thead th');
    expect(ths.map((th) => th.events.join(','))).toEqual(['click,keydown', '', 'click,keydown']);
    expect(ths.map((th) => th.getAttribute('tabindex'))).toEqual(['0', null, '0']);
});

test('the results totals row is marked to stay at the end', () => {
    expect(html).toContain('<tr class="ures-totals-row" data-sort-method="none">');
});

test('optimizer Loaded and Spread sort by their values, blank with no loaded price', () => {
    expect(html).toContain('<td class="opt-loaded" data-sort="{{if .Price}}{{printf "%.2f" .Price}}{{end}}">');
    expect(html).toContain('<td class="opt-spread {{if gt .Spread 80.0}}hot{{else}}ok{{end}}" data-sort="{{if .Price}}{{printf "%.2f" .Spread}}{{end}}">');
});

test('a sort tells the page its rows moved', () => {
    const { uresSortBy } = load();
    const card = element({});
    const t = table([card], [optRow([cell('b')], 0), optRow([cell('a')], 1)]);
    uresSortBy(card);
    expect(t.events).toEqual(['rowsmoved bubbles']);
});

test('the tie-breakers order rows a column ties on', () => {
    const { uresSortBy, uresMenuAct } = load(page([]));
    const price = element({ 'data-sort-method': 'number', 'data-sort-descending': '' });
    const t = table([element({}), price], [
        Object.assign(keyed('a', { color: '1.04' }), { cells: [cell('a'), cell('$ 2', '2')] }),
        Object.assign(keyed('b', { color: '1.00' }), { cells: [cell('b'), cell('$ 2', '2')] }),
        Object.assign(keyed('c', { color: '3' }), { cells: [cell('c'), cell('$ 9', '9')] }),
    ]);
    uresMenuAct('results', 'color', 'toggle');
    uresSortBy(price);
    expect(hashes(t)).toEqual(['c', 'b', 'a']);
    uresMenuAct('results', 'color', 'dir');
    uresSortBy(price);
    uresSortBy(price);
    expect(hashes(t)).toEqual(['c', 'a', 'b']);
});

test("with no column sorted, the setting's tie groups lead and the chain breaks their ties", () => {
    const t = table([element({})], [
        keyed('a', { lead: '2', set: '1993-08-05 alpha' }),
        keyed('b', { lead: '1', set: '2009-07-17 magic 2010' }),
        keyed('c', { lead: '1', set: '1993-08-05 alpha' }),
        keyed('d', { lead: '2', rarity: '0' }),
    ]);
    const { uresMenuAct } = load(page([t]));
    uresMenuAct('results', 'set', 'toggle');
    // A row missing the key goes last in its group, either way round
    expect(hashes(t)).toEqual(['c', 'b', 'a', 'd']);
    uresMenuAct('results', 'set', 'dir');
    expect(hashes(t)).toEqual(['b', 'c', 'a', 'd']);
    expect(t.events.length).toBe(2);
});

test('with no tie groups, the chain leads, a later key deciding only the ties', () => {
    const t = table([element({})], [
        keyed('a', { color: '1.01', rarity: '3' }),
        keyed('b', { color: '1.00', rarity: '3' }),
        keyed('c', { color: '1.01', rarity: '0' }),
    ]);
    const { uresMenuAct } = load(page([t]));
    uresMenuAct('results', 'color', 'toggle');
    uresMenuAct('results', 'rarity', 'toggle');
    expect(hashes(t)).toEqual(['b', 'c', 'a']);
    // Rarity first now: a number, rarest first
    uresMenuAct('results', 'rarity', 'up');
    expect(hashes(t)).toEqual(['c', 'b', 'a']);
});

test("each area keeps its own chain, and only its own tables follow it", () => {
    const res = table([element({})], [keyed('a', { name: 'zap' }), keyed('b', { name: 'opt' })]);
    const opt = table([element({})], [keyed('x', { name: 'zap' }), keyed('y', { name: 'opt' })], [], 'opt-table');
    const store = storage();
    const { uresMenuAct, chains } = load(page([res, opt]), store);
    uresMenuAct('opt', 'name', 'toggle');
    expect(hashes(opt)).toEqual(['y', 'x']);
    expect(hashes(res)).toEqual(['a', 'b']);
    expect(chains()).toEqual({ results: [], opt: [{ key: 'name', descending: false }] });
    expect(JSON.parse(store.map.mtgban_upload_sort)).toEqual({ results: '', opt: 'name:a' });
    uresMenuAct('opt', '', 'clear');
    expect(chains().opt).toEqual([]);
});

test('a stored chain keeps only known keys, each once', () => {
    const { uresParseChain } = load();
    expect(uresParseChain('color:d,bogus:a,set:a,color:a,')).toEqual([
        { key: 'color', descending: true }, { key: 'set', descending: false },
    ]);
    expect(uresParseChain(undefined)).toEqual([]);
});

test('a saved chain sorts the page on load, lights its buttons, and writes nothing', () => {
    const t = table([element({})], [keyed('a', { cond: '2' }), keyed('b', { cond: '0' })]);
    const btn = button('results');
    const doc = page([t], [btn]);
    const store = storage({ mtgban_upload_sort: JSON.stringify({ results: 'cond:a', opt: '' }) });
    load(doc, store);
    doc.listeners.DOMContentLoaded.forEach((fn) => fn());
    expect(hashes(t)).toEqual(['b', 'a']);
    expect(btn.classList.has('on')).toBe(true);
    expect(btn.getAttribute('title')).toBe(null);
    expect(btn.title).toBe('Sorted by Condition \u25B2');
    expect(store.writes).toBe(0);
});

test('the menu lists the keys some row has, the chain first in its order', () => {
    const t = table([element({})], [keyed('a', { name: 'zap', color: '1.00', rarity: '' }), keyed('b', { name: 'opt' })]);
    const { uresMenuAct, uresRenderMenu } = load(page([t]));
    uresMenuAct('results', 'color', 'toggle');
    const menu = {};
    uresRenderMenu(menu, 'results');
    const keys = [...menu.innerHTML.matchAll(/data-key="(\w+)"/g)].map((m) => m[1]);
    expect(keys).toEqual(['color', 'name']);
    expect(menu.innerHTML).toContain('data-act="up" title="Earlier" disabled');
});

test("an optimizer store's own button sorts that store alone, for this page only", () => {
    const a = table([element({})], [keyed('x', { name: 'zap' }), keyed('y', { name: 'opt' })], [], 'opt-table');
    const b = table([element({})], [keyed('x', { name: 'zap' }), keyed('y', { name: 'opt' })], [], 'opt-table');
    const store = storage();
    const { uresMenuAct, chains } = load(page([a, b]), store);
    uresMenuAct('opt', 'name', 'toggle', a);
    expect(hashes(a)).toEqual(['y', 'x']);
    expect(hashes(b)).toEqual(['x', 'y']);
    expect(chains().opt).toEqual([]);
    expect(store.writes).toBe(0);
});

test("the stores' button sorts every store, replaces their own orders, and is saved", () => {
    const a = table([element({})], [keyed('x', { name: 'zap', color: '1.00' }), keyed('y', { name: 'opt', color: '1.04' })], [], 'opt-table');
    const b = table([element({})], [keyed('x', { name: 'zap', color: '1.00' }), keyed('y', { name: 'opt', color: '1.04' })], [], 'opt-table');
    const store = storage();
    const { uresMenuAct } = load(page([a, b]), store);
    uresMenuAct('opt', 'name', 'toggle', a);
    uresMenuAct('opt', 'color', 'toggle');
    expect(hashes(a)).toEqual(['x', 'y']);
    expect(hashes(b)).toEqual(['x', 'y']);
    expect(JSON.parse(store.map.mtgban_upload_sort).opt).toBe('color:a');
    // A store's own order now starts from the stores' one
    uresMenuAct('opt', 'color', 'dir', b);
    expect(hashes(b)).toEqual(['y', 'x']);
    expect(hashes(a)).toEqual(['x', 'y']);
});

test("a store's own order is made when it is edited, not when it is shown", () => {
    const a = table([element({})], [keyed('x', { name: 'zap' }), keyed('y', { name: 'opt' })], [], 'opt-table');
    const { uresMenuAct, uresRenderMenu, chains } = load(page([a]));
    uresRenderMenu({}, 'opt', a);
    // The stores' order changes under it, with no reset of the stores' own
    chains().opt.push({ key: 'name', descending: false });
    uresMenuAct('opt', 'name', 'none', a);
    expect(hashes(a)).toEqual(['y', 'x']);
});

test("the toolbar's button says it sorts every store", () => {
    const btn = button('opt');
    const store = storage({ mtgban_upload_sort: JSON.stringify({ results: '', opt: 'color:d' }) });
    const doc = page([], [btn]);
    load(doc, store);
    doc.listeners.DOMContentLoaded.forEach((fn) => fn());
    expect(btn.title).toBe('Stores sorted by Color \u25BC');
});
