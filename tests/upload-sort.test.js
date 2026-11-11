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
function table(headers, rows, above = []) {
    const tbody = {
        rows: rows.slice(),
        appendChild(r) {
            this.rows.splice(this.rows.indexOf(r), 1);
            this.rows.push(r);
        },
    };
    const headRow = { cells: headers };
    const t = { tBodies: [tbody], tHead: { rows: above.concat([headRow]) } };
    headers.forEach((th, i) => { th.cellIndex = i; th.closest = () => t; th.parentNode = headRow; });
    return t;
}

function load(document = { addEventListener: () => {} }) {
    return new Function('document', source + '\nreturn {uresSortBy};')(document);
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
        addEventListener: (type, fn) => { listeners[type] = fn; },
        querySelectorAll: (sel) => { asked = sel; return ths; },
    });
    listeners.DOMContentLoaded();
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
