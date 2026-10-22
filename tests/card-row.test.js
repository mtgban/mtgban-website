import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/card-row.js', import.meta.url), 'utf8');

// el builds a stand-in element: attributes, a class list, a parent, and a
// closest()/querySelector() that walk this little tree.
function el(attrs, classes, children) {
    const node = {
        attrs: attrs || {}, classes: classes || [], children: children || [], parentNode: null,
        getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; },
        matches(sel) { return sel.split(',').some((s) => this.classes.includes(s.trim().replace(/^\./, ''))); },
        closest(sel) { let n = this; while (n) { if (n.matches(sel)) return n; n = n.parentNode; } return null; },
        querySelector(sel) {
            const want = sel.replace(/^\./, '');
            const stack = [...this.children];
            while (stack.length) { const c = stack.shift(); if (c.classes.includes(want) || (sel.startsWith('[id^=') && (c.attrs.id || '').startsWith(sel.slice(6, -3)))) return c; stack.push(...c.children); }
            return null;
        },
        textContent: '',
    };
    node.children.forEach((c) => { c.parentNode = node; });
    return node;
}

function load() {
    const window = {};
    new Function('window', source)(window);
    return window.CardRow;
}

const header = (cls) => el({
    'data-card-id': 'uuid-1', 'data-card-name': 'Black Lotus', 'data-set-code': 'LEA',
    'data-edition': 'Limited Edition Alpha', 'data-number': '232', 'data-image-url': 'https://img/lotus.jpg',
    'data-finish-tag': 'Foil', 'data-finish-class': 'foil', 'data-treatments': 'a,b', 'data-has-warning': 'true',
}, [cls]);

test('reads a desktop result header', () => {
    const btn = el({ 'data-card-id': 'uuid-1' }, ['fav-btn']);
    const row = header('result-header');
    row.children.push(btn); btn.parentNode = row;
    const container = el({}, ['result'], [row]);
    const got = load().read(btn);
    expect(got.id).toBe('uuid-1');
    expect(got.name).toBe('Black Lotus');
    expect(got.set).toBe('LEA');
    expect(got.number).toBe('232');
    expect(got.foil).toBe(true);
    expect(got.etched).toBe(false);
    expect(got.treatments).toEqual(['a', 'b']);
    expect(got.cw).toBe(true);
    expect(got.query).toBe('Black Lotus s:LEA cns:232 f:foil');
    expect(got.img).toBe('https://img/lotus.jpg');
    expect(typeof got.t).toBe('number');
    expect(container.children.length).toBe(1);
});

test('reads a button inside the mobile actions menu through the card', () => {
    const btn = el({ 'data-card-id': 'uuid-1' }, ['fav-btn']);
    const menu = el({}, ['m-actions-menu'], [btn]);
    const row = header('m-card-header');
    const card = el({}, ['m-card'], [row, menu]);
    expect(card.children.length).toBe(2);
    const got = load().read(btn);
    expect(got.id).toBe('uuid-1');
    expect(got.edition).toBe('Limited Edition Alpha');
});

test('reads a button inside the mobile card header', () => {
    const btn = el({ 'data-card-id': 'uuid-1' }, ['m-pack-btn', 'pack-btn']);
    const row = header('m-card-header');
    row.children.push(btn); btn.parentNode = row;
    el({}, ['m-card'], [row]);
    const got = load().read(btn);
    expect(got.id).toBe('uuid-1');
    expect(got.name).toBe('Black Lotus');
    expect(got.finishTag).toBe('Foil');
});

// The query searches the name, not the filter its "S:" reads as.
test('quotes a name the search could read a filter out of', () => {
    const btn = el({ 'data-card-id': 'uuid-2' }, ['fav-btn']);
    const row = el({ 'data-card-id': 'uuid-2', 'data-card-name': 'S:P Little Knight', 'data-set-code': 'AGOV', 'data-number': 'AGOV-EN046' }, ['result-header'], [btn]);
    el({}, ['result'], [row]);
    expect(load().read(btn).query).toBe('"S:P Little Knight" s:AGOV cns:AGOV-EN046');
    expect(load().queryName('Dark Ritual')).toBe('Dark Ritual');
});

test('returns null with no row', () => {
    const btn = el({ 'data-card-id': 'uuid-1' }, ['fav-btn']);
    expect(load().read(btn)).toBeNull();
});
