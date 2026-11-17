import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-edit.js', import.meta.url), 'utf8');
// The reload bar's script, whose count the edits join
const printings = readFileSync(new URL('../js/upload-printings.js', import.meta.url), 'utf8');

// A stand-in DOM: elements with attributes, a dataset over the data-*
// ones, classes and children, and compound and descendant selectors.
const camel = (s) => s.replace(/-([a-z])/g, (_, c) => c.toUpperCase());
const kebab = (s) => s.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());

function el(tag, attrs = {}, children = []) {
    const node = {
        tag, attrs: {}, classes: new Set(), children: [], parentNode: null, text: '', style: {}, open: false,
        get textContent() { return this.text + this.children.map((c) => c.textContent).join(''); },
        set textContent(v) { this.text = String(v); this.children = []; },
        get id() { return this.attrs.id; },
        set id(v) { this.attrs.id = String(v); },
        get className() { return [...this.classes].join(' '); },
        set className(v) { this.classes = new Set(String(v).split(/\s+/).filter(Boolean)); },
        get classList() {
            const s = this.classes;
            return { add: (c) => s.add(c), remove: (c) => s.delete(c), contains: (c) => s.has(c), toggle: (c, on) => { if (on === undefined) on = !s.has(c); if (on) s.add(c); else s.delete(c); } };
        },
        get dataset() {
            const a = this.attrs;
            return new Proxy({}, {
                get: (_, k) => a['data-' + kebab(k)],
                set: (_, k, v) => { a['data-' + kebab(k)] = String(v); return true; },
                has: (_, k) => ('data-' + kebab(k)) in a,
                ownKeys: () => Object.keys(a).filter((k) => k.startsWith('data-')).map((k) => camel(k.slice(5))),
                getOwnPropertyDescriptor: () => ({ enumerable: true, configurable: true }),
            });
        },
        setAttribute(n, v) { if (n === 'class') this.className = v; else this.attrs[n] = String(v); },
        getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; },
        hasAttribute(n) { return n in this.attrs; },
        removeAttribute(n) { delete this.attrs[n]; },
        appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
        remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((c) => c !== this); this.parentNode = null; },
        closest(sel) { for (let n = this; n; n = n.parentNode) if (n.matches && n.matches(sel)) return n; return null; },
        matches(sel) { return sel.split(',').some((s) => matchChain(this, s.trim().split(/\s+/))); },
        querySelectorAll(sel) { const out = []; const walk = (n) => n.children.forEach((c) => { if (c.matches(sel)) out.push(c); walk(c); }); walk(this); return out; },
        querySelector(sel) { return this.querySelectorAll(sel)[0] || null; },
        click() { dispatch('click', this); },
        focus() { doc.activeElement = this; },
        getBoundingClientRect() { return { left: 10, top: 10, bottom: 30, right: 40 }; },
        showPopover() { this.open = true; },
        hidePopover() { this.open = false; },
    };
    Object.entries(attrs).forEach(([k, v]) => node.setAttribute(k, v));
    children.forEach((c) => (typeof c === 'string' ? (node.text = c) : node.appendChild(c)));
    return node;
}

function matchOne(n, s) {
    const m = s.match(/^([a-z]+)?(.*)$/);
    if (m[1] && n.tag !== m[1]) return false;
    const parts = m[2].match(/\.[\w-]+|\[[^\]]+\]|:[\w-]+/g) || [];
    return parts.every((p) => {
        if (p[0] === '.') return n.classes.has(p.slice(1));
        if (p === ':popover-open') return n.open;
        const [k, v] = p.slice(1, -1).split('=');
        return v === undefined ? k in n.attrs : n.attrs[k] === v.replace(/"/g, '');
    });
}
function matchChain(n, chain) {
    if (!matchOne(n, chain[chain.length - 1])) return false;
    if (chain.length === 1) return true;
    for (let p = n.parentNode; p; p = p.parentNode) if (p.matches && matchChain(p, chain.slice(0, -1))) return true;
    return false;
}

let doc;
let listeners;
function dispatch(type, target, extra = {}) {
    const e = { type, target, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; }, ...extra };
    (listeners[type] || []).forEach((fn) => fn(e));
    return e;
}

// A results row and the optimizer row of the same card, as upload.html
// draws them; an opened product's row has no buttons.
function resultRow(name, id, cond, qty, { editable = true, grade = true, price = '0' } = {}) {
    const attrs = { 'data-hash': id, 'data-qtys': String(qty), 'data-cond': cond, 'data-price': price, 'data-card-name': name };
    if (grade) attrs['data-grade'] = cond;
    const shown = '$ ' + Number(price).toFixed(2);
    const cells = editable
        ? [el('td', {}, [el('button', { class: 'ures-edit-btn', 'data-edit': 'price' }, [shown])]), el('td', {}, [el('button', { class: 'ures-edit-btn cond-badge', 'data-edit': 'cond' }, [cond])]), el('td', {}, [el('button', { class: 'ures-edit-btn ures-qty-btn', 'data-edit': 'qty' }, [String(qty)])])]
        : [el('td', {}, [shown]), el('td', {}, [cond]), el('td', {}, [String(qty)])];
    return el('tr', attrs, cells);
}
function optRow(id, cond, qty, price = '1.00') {
    return el('tr', { 'data-opt-id': id, 'data-opt-cond': cond, 'data-load-qty': String(qty) }, [
        el('td', {}, [el('button', { class: 'ures-edit-btn opt-cond-btn', 'data-edit': 'cond' }, [cond])]),
        el('td', {}, [el('button', { class: 'ures-edit-btn opt-price-btn', 'data-edit': 'price' }, [price]), el('button', { class: 'ures-edit-btn opt-qty-btn', 'data-edit': 'qty' }, ['×' + qty])]),
    ]);
}

function load({ results, opt = [], sentPack = 0 }) {
    listeners = {};
    const calls = { track: [], pack: [], reprocessed: 0, rendered: 0 };
    // The reload bar as upload.html draws it
    const stat = (kind) => el('span', { id: 'reload-' + kind + '-wrap' }, [el('span', { id: 'reload-' + kind + '-count' }, ['0'])]);
    const bar = el('div', { id: 'reload-bar' }, [stat('fixed'), stat('removed'), el('button', { class: 'opt-btn load' }, ['Reload'])]);
    bar.style.display = 'none';
    const actions = el('div', { class: 'opt-header-actions' }, [el('a', { class: 'opt-btn' }, ['Deck builder'])]);
    const body = el('body', {}, [
        el('table', { class: 'ures-table' }, results),
        el('div', { class: 'opt-store' }, [actions, el('table', {}, opt)]),
        bar,
    ]);
    doc = {
        body, activeElement: null,
        querySelectorAll: (s) => body.querySelectorAll(s),
        querySelector: (s) => body.querySelector(s),
        getElementById: (id) => body.querySelectorAll('[id]').find((n) => n.attrs.id === id) || null,
        createElement: (tag) => el(tag),
        addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
    };
    const window = {
        innerHeight: 800,
        BAN: { track: (name, value) => calls.track.push(name + ':' + value) },
        Backpack: {
            sentPack: () => sentPack,
            setCond: (k, c) => calls.pack.push(['cond', k, c]),
            setQty: (k, q) => calls.pack.push(['qty', k, q]),
        },
        renderBackpack: () => { calls.rendered++; },
        BAN_UPLOAD_PRINTINGS: { cards: {} },
    };
    // The key list-storage.js gives a backpack entry
    window.ListStorage = { backpackKey: (e) => ((e.pack > 1 ? e.pack + '/' : '') + e.id + (e.cond === 'NM' || !e.cond ? '' : '|' + e.cond)) };
    new Function('window', 'document', printings + '\nwindow.updateReloadBar = updateReloadBar;')(window, doc);
    new Function('window', 'document', source)(window, doc);
    dispatch('DOMContentLoaded', doc);
    const menu = () => doc.getElementById('ures-edit-menu');
    const pick = (btn, value) => { btn.click(); menu().querySelector('[data-value="' + value + '"]').click(); };
    // What the bar says, or null while it is hidden
    const shown = () => (bar.style.display === 'none' ? null : doc.getElementById('reload-fixed-count').textContent + ' updated');
    return { calls, bar, actions, menu, pick, shown };
}

const btn = (row, kind) => row.querySelector('.ures-edit-btn[data-edit="' + kind + '"]');

test('a grade picked on a result row rewrites the row the exports pack, and its optimizer row', () => {
    const bolt = resultRow('Bolt', 'a', 'NM', 3);
    const optBolt = optRow('a', 'NM', 3);
    const { calls, menu, pick, shown } = load({ results: [bolt, resultRow('Ring', 'b', 'NM', 1)], opt: [optBolt] });

    btn(bolt, 'cond').click();
    expect(menu().open).toBe(true);
    expect(menu().querySelectorAll('.ures-edit-items button').map((b) => b.textContent)).toEqual(['NM', 'SP', 'MP', 'HP', 'PO', 'None']);
    expect(menu().querySelector('[aria-current]').textContent).toBe('NM');
    menu().querySelector('[data-value="SP"]').click();

    expect(menu().open).toBe(false);
    expect([bolt.dataset.cond, bolt.dataset.grade, bolt.dataset.kCond]).toEqual(['SP', 'SP', '1']);
    expect(btn(bolt, 'cond').textContent).toBe('SP');
    expect(btn(bolt, 'cond').classList.contains('edited')).toBe(true);
    expect(optBolt.dataset.optCond).toBe('SP');
    expect(btn(optBolt, 'cond').classList.contains('edited')).toBe(true);
    expect(shown()).toBe('1 updated');
    expect(doc.body.classList.contains('ures-dirty')).toBe(true);
    expect(calls.track).toEqual(['ui.upload.result:edit_cond']);
    // Not from the backpack, so nothing is taken back there
    expect(calls.pack).toEqual([]);

    // Picking the grade it came with again leaves nothing to reload
    pick(btn(bolt, 'cond'), 'NM');
    expect(btn(bolt, 'cond').classList.contains('edited')).toBe(false);
    expect(btn(optBolt, 'cond').classList.contains('edited')).toBe(false);
    expect(shown()).toBe(null);
    expect(doc.body.classList.contains('ures-dirty')).toBe(false);
});

test('copies picked on an optimizer row set the whole list line', () => {
    const ring = resultRow('Ring', 'b', 'SP', 2);
    const optRing = optRow('b', 'SP', 1);
    const optRing2 = optRow('b', 'SP', 1);
    const { calls, menu, pick, shown } = load({ results: [ring], opt: [optRing, optRing2] });

    btn(optRing, 'qty').click();
    expect(menu().querySelector('[aria-current]').textContent).toBe('2');
    expect(menu().querySelectorAll('.ures-edit-items button').length).toBe(20);
    menu().querySelector('[data-value="5"]').click();

    expect(ring.dataset.qtys).toBe('5');
    expect(btn(ring, 'qty').textContent).toBe('5');
    expect(btn(optRing2, 'qty').classList.contains('edited')).toBe(true);
    expect(btn(optRing2, 'qty').title).toBe('5 in your list; reload to update');
    expect(calls.track).toEqual(['ui.optimizer:edit_qty']);
    expect(shown()).toBe('1 updated');

    // A number past the list is typed in
    btn(ring, 'qty').click();
    const other = menu().querySelector('.ures-edit-input');
    other.value = '40';
    dispatch('keydown', other, { key: 'Enter' });
    expect(ring.dataset.qtys).toBe('40');
    btn(ring, 'qty').click();
    expect(menu().querySelector('[aria-current]').textContent).toBe('40');
    pick(btn(ring, 'qty'), '2');
    expect(shown()).toBe(null);
});

test('copies picked on an optimizer row over several list lines leave each line one at least', () => {
    const ring = resultRow('Ring', 'b', 'SP', 1);
    const ring2 = resultRow('Ring', 'b', 'SP', 2);
    const opt = optRow('b', 'SP', 3);
    const { calls, menu, pick } = load({ results: [ring, ring2], opt: [opt], sentPack: 1 });

    btn(opt, 'qty').click();
    // Two lines can hold no fewer than two copies
    expect(menu().querySelectorAll('.ures-edit-items button')[0].textContent).toBe('2');
    menu().querySelector('[data-value="2"]').click();
    expect([ring.dataset.qtys, ring2.dataset.qtys]).toEqual(['1', '1']);
    expect(btn(ring, 'qty').classList.contains('edited')).toBe(false);
    expect(btn(ring2, 'qty').classList.contains('edited')).toBe(true);

    pick(btn(opt, 'qty'), '5');
    expect([ring.dataset.qtys, ring2.dataset.qtys]).toEqual(['4', '1']);
    expect(btn(opt, 'qty').title).toBe('5 in your list; reload to update');
    expect(calls.pack).toEqual([['qty', 'b|SP', 2], ['qty', 'b|SP', 5]]);
});

test('a list sent from the backpack takes each edit back to the entry it came from', () => {
    const bolt = resultRow('Bolt', 'a', 'NM', 3);
    const ring = resultRow('Ring', 'b', 'SP', 1);
    const ring2 = resultRow('Ring', 'b', 'SP', 2);
    const { calls, pick } = load({ results: [bolt, ring, ring2], sentPack: 2 });

    pick(btn(bolt, 'cond'), 'MP');
    pick(btn(ring, 'qty'), '4');
    expect(calls.pack).toEqual([
        ['cond', '2/a', 'MP'],
        // The backpack holds the card's copies in a grade in one entry
        ['qty', '2/b|SP', 6],
    ]);
    expect(calls.rendered).toBe(2);
});

test('the rows of an opened product edit nothing, from either tab', () => {
    const card = resultRow('Bolt', 'a', 'NM', 3, { editable: false });
    const opt = optRow('a', 'NM', 3);
    load({ results: [card], opt: [opt] });
    expect(opt.querySelectorAll('.ures-edit-btn')).toEqual([]);
});

test('with conditions ignored an optimizer row edits its card whatever the grade', () => {
    const ring = resultRow('Ring', 'b', 'SP', 1, { grade: false });
    const opt = optRow('b', '', 1);
    const { pick } = load({ results: [ring], opt: [opt] });
    pick(btn(opt, 'cond'), 'HP');
    expect(ring.dataset.cond).toBe('HP');
    expect('grade' in ring.dataset).toBe(false);
    expect(opt.dataset.optCond).toBe('');
});

test('the store sends wait for a reload, and the bar nudges', () => {
    const bolt = resultRow('Bolt', 'a', 'NM', 3);
    const { calls, bar, actions, pick } = load({ results: [bolt] });
    const send = actions.querySelector('a');
    expect(dispatch('click', send).defaultPrevented).toBe(false);

    pick(btn(bolt, 'qty'), '1');
    const blocked = dispatch('click', send);
    expect(blocked.defaultPrevented).toBe(true);
    expect(blocked.stopped).toBe(true);
    expect(bar.classList.contains('nudge')).toBe(true);
    expect(calls.track).toEqual(['ui.upload.result:edit_qty']);
});

test('a price set on an optimizer row prices each list line of its card', () => {
    const ring = resultRow('Ring', 'b', 'SP', 1, { price: '1.5' });
    const ring2 = resultRow('Ring', 'b', 'SP', 2, { price: '2' });
    const opt = optRow('b', 'SP', 3, '1.50');
    const { calls, menu, shown } = load({ results: [ring, ring2], opt: [opt] });

    btn(opt, 'price').click();
    const box = menu().querySelector('.ures-edit-input');
    expect(box.value).toBe('1.50');
    expect(doc.activeElement).toBe(box);
    box.value = '3.256';
    menu().querySelector('.ures-edit-set').click();

    expect([ring.dataset.price, ring2.dataset.price]).toEqual(['3.26', '3.26']);
    expect(btn(ring, 'price').textContent).toBe('$ 3.26');
    expect(btn(ring2, 'price').classList.contains('edited')).toBe(true);
    expect(btn(opt, 'price').textContent).toBe('3.26');
    expect(shown()).toBe('2 updated');
    expect(calls.track).toEqual(['ui.optimizer:edit_price']);
    // The backpack keeps no price
    expect(calls.pack).toEqual([]);

    // Back to what one line came with clears only that line
    btn(ring, 'price').click();
    menu().querySelector('.ures-edit-input').value = '1.5';
    dispatch('keydown', menu().querySelector('.ures-edit-input'), { key: 'Enter' });
    expect(btn(ring, 'price').classList.contains('edited')).toBe(false);
    expect(shown()).toBe('1 updated');

    // A price that is no number changes nothing
    btn(ring, 'price').click();
    menu().querySelector('.ures-edit-input').value = '';
    menu().querySelector('.ures-edit-set').click();
    expect(ring.dataset.price).toBe('1.5');
});

test('a grade can be taken back to none, as a list line without one', () => {
    const bolt = resultRow('Bolt', 'a', 'SP', 1);
    const optBolt = optRow('a', 'SP', 1);
    const ring = resultRow('Ring', 'b', '', 2, { grade: false });
    const { calls, menu, pick, shown } = load({ results: [bolt, ring], opt: [optBolt], sentPack: 1 });

    pick(btn(bolt, 'cond'), '');
    expect([bolt.dataset.cond, bolt.dataset.grade, bolt.dataset.kCond]).toEqual(['', '', '']);
    expect(btn(bolt, 'cond').textContent).toBe('');
    // The optimizer prices a line without a grade as NM
    expect(optBolt.dataset.optCond).toBe('');
    expect(btn(optBolt, 'cond').textContent).toBe('NM');
    expect(calls.track).toEqual(['ui.upload.result:edit_cond']);

    // A line that came with none goes back to none
    pick(btn(ring, 'cond'), 'MP');
    expect(shown()).toBe('2 updated');
    btn(ring, 'cond').click();
    expect(menu().querySelector('[aria-current]').textContent).toBe('MP');
    pick(btn(ring, 'cond'), '');
    expect(ring.dataset.cond).toBe('');
    expect(btn(ring, 'cond').classList.contains('edited')).toBe(false);
    expect(shown()).toBe('1 updated');

    // The backpack keeps no grade as NM
    expect(calls.pack).toEqual([['cond', 'a|SP', 'NM'], ['cond', 'b', 'MP'], ['cond', 'b|MP', 'NM']]);
});
