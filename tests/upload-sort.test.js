import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-sort.js', import.meta.url), 'utf8');

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

// An entry row carries a hash; the totals row does not.
function row(cells, hash) {
    const attrs = hash === undefined ? {} : { 'data-hash': hash };
    return Object.assign(element(attrs), { cells });
}

// A results table: its headers, its rows, and a tbody whose appendChild
// moves a row to the end the way a real one does.
function table(headers, rows) {
    const tbody = {
        rows: rows.slice(),
        appendChild(r) {
            this.rows.splice(this.rows.indexOf(r), 1);
            this.rows.push(r);
        },
    };
    const t = { tBodies: [tbody], tHead: { rows: [{ cells: headers }] } };
    headers.forEach((th, i) => { th.cellIndex = i; th.closest = () => t; });
    return t;
}

function load() {
    const document = { addEventListener: () => {} };
    return new Function('document', source + '\nreturn {uresSortBy};')(document);
}

function hashes(t) {
    return t.tBodies[0].rows.map((r) => (r.hasAttribute('data-hash') ? r.getAttribute('data-hash') : 'totals'));
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
