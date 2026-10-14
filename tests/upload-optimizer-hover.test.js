import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-optimizer.js', import.meta.url), 'utf8');

// A node knowing only its parent, enough for contains()
function node(parent = null) {
    return {
        parent,
        contains(other) {
            for (let n = other; n; n = n.parent) {
                if (n === this) return true;
            }
            return false;
        },
    };
}

// An optimizer table as templates/upload.html lays it out: the store header
// and the column labels in its head, a card's cells in its body.
function load() {
    const table = node();
    const head = node(table);
    const body = node(table);
    table.tBodies = [body];
    const header = node(node(head));
    const cell = node(node(body));
    const otherCell = node(node(body));
    const outside = node();

    const shown = [];
    const wrap = { attrs: {}, setAttribute(k, v) { this.attrs[k] = v; } };
    const image = {};
    const window = {
        cardArtPlaceholder: 'placeholder',
        setCardArtSource: (img, src) => shown.push([img, src]),
    };
    const document = {
        querySelectorAll: () => [],
        getElementById: (id) => ({ hoverImage: image, hoverWrap: wrap })[id],
    };
    const optTableOut = new Function('window', 'document', 'wireLoadLists', source + '\nreturn optTableOut;')(
        window, document, () => {});
    return { optTableOut, table, header, cell, otherCell, outside, shown, wrap, image };
}

test('leaving a row for the store header takes the card art down', () => {
    const t = load();
    t.optTableOut(t.table, { relatedTarget: t.header });
    expect(t.shown).toEqual([[t.image, 'placeholder']]);
    expect(t.wrap.attrs).toEqual({ 'data-foil': 'false', 'data-etched': 'false' });
});

test('leaving the table, or the window, takes the card art down', () => {
    for (const to of ['outside', null]) {
        const t = load();
        t.optTableOut(t.table, { relatedTarget: to && t[to] });
        expect(t.shown, String(to)).toEqual([[t.image, 'placeholder']]);
    }
});

test('moving from row to row leaves the card art to the next row', () => {
    const t = load();
    t.optTableOut(t.table, { relatedTarget: t.otherCell });
    t.optTableOut(t.table, { relatedTarget: t.cell });
    expect(t.shown).toEqual([]);
    expect(t.wrap.attrs).toEqual({});
});
