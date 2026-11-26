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
                deleteProperty: (_, k) => delete a['data-' + kebab(k)],
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
        after(n) { const kids = this.parentNode.children; n.parentNode = this.parentNode; kids.splice(kids.indexOf(this) + 1, 0, n); },
        cloneNode() {
            const c = el(this.tag, { ...this.attrs });
            c.className = this.className;
            c.text = this.text;
            this.children.forEach((k) => c.appendChild(k.cloneNode()));
            return c;
        },
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
function resultRow(name, id, cond, qty, { editable = true, grade = cond, price = '0' } = {}) {
    const attrs = { 'data-hash': id, 'data-qtys': String(qty), 'data-cond': cond, 'data-grade': grade, 'data-price': price, 'data-card-name': name };
    const shown = '$ ' + Number(price).toFixed(2);
    const cells = editable
        ? [el('td', {}, [el('button', { class: 'ures-edit-btn', 'data-edit': 'price' }, [shown])]), el('td', {}, [el('button', { class: 'ures-edit-btn cond-badge', 'data-edit': 'cond' }, [cond])]), el('td', {}, [el('button', { class: 'ures-edit-btn ures-qty-btn', 'data-edit': 'qty' }, [String(qty)])])]
        : [el('td', {}, [shown]), el('td', {}, [cond]), el('td', {}, [String(qty)])];
    return el('tr', attrs, cells);
}
// share is the row's loaded price, which pairs it with its results row.
function optRow(id, cond, qty, price = '1.00', share = '0') {
    return el('tr', { 'data-opt-id': id, 'data-opt-cond': cond, 'data-load-qty': String(qty), 'data-share-price': share }, [
        el('td', {}, [el('button', { class: 'ures-edit-btn opt-cond-btn', 'data-edit': 'cond' }, [cond])]),
        el('td', {}, [el('button', { class: 'ures-edit-btn opt-price-btn', 'data-edit': 'price' }, [price]), el('button', { class: 'ures-edit-btn opt-qty-btn', 'data-edit': 'qty' }, ['×' + qty])]),
    ]);
}

function load({ results, opt = [], optB = [], sentPack = 0, packHas = [] }) {
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
        el('div', { class: 'opt-store' }, [el('table', {}, optB)]),
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
            setPaid: (k, v) => calls.pack.push(['paid', k, v]),
            // The backpack refuses a grade it already holds
            addCond: (k, c) => { calls.pack.push(['add', k, c]); return !packHas.includes(c); },
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
    expect(menu().querySelector('.ures-edit-items').querySelectorAll('button').map((b) => b.textContent)).toEqual(['NM', 'SP', 'MP', 'HP', 'PO', 'None']);
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
    expect([optRing.hasAttribute('data-qty-edited'), optRing2.hasAttribute('data-qty-edited')]).toEqual([true, true]);
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
    // A list line edited on its own counts every line of the card and grade
    pick(btn(ring2, 'qty'), '3');
    expect([opt.hasAttribute('data-qty-edited'), btn(opt, 'qty').title]).toEqual([true, '7 in your list; reload to update']);
    expect(calls.pack).toEqual([['qty', 'b|SP', 2], ['qty', 'b|SP', 5], ['qty', 'b|SP', 7]]);
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
    const ring = resultRow('Ring', 'b', 'SP', 1, { grade: '' });
    const opt = optRow('b', '', 1);
    const { pick } = load({ results: [ring], opt: [opt] });
    pick(btn(opt, 'cond'), 'HP');
    expect([ring.dataset.cond, ring.dataset.grade, opt.dataset.optCond]).toEqual(['HP', 'HP', 'HP']);
});

test('a line without a grade gives its optimizer row the grade picked, the key its move is sent by', () => {
    const ring = resultRow('Ring', 'b', '', 1);
    const opt = optRow('b', '', 1);
    const { pick } = load({ results: [ring], opt: [opt] });
    pick(btn(ring, 'cond'), 'MP');
    expect([ring.dataset.cond, ring.dataset.grade, opt.dataset.optCond]).toEqual(['MP', 'MP', 'MP']);
    expect(btn(opt, 'cond').textContent).toBe('MP');
    // And from the optimizer row, which still finds its line
    pick(btn(opt, 'cond'), 'HP');
    expect([ring.dataset.cond, opt.dataset.optCond]).toEqual(['HP', 'HP']);
});

test('copies cut on a card two stores share mark both, a struck line left out', () => {
    const bolt = resultRow('Bolt', 'a', 'NM', 5);
    const struck = resultRow('Bolt', 'a', 'NM', 4);
    struck.classList.add('ures-removed-row');
    const optA = optRow('a', 'NM', 3);
    const optB = optRow('a', 'NM', 2);
    const { pick } = load({ results: [bolt, struck], opt: [optA], optB: [optB] });

    pick(btn(bolt, 'qty'), '2');
    expect([optA.hasAttribute('data-qty-edited'), optB.hasAttribute('data-qty-edited')]).toEqual([true, true]);
    expect(btn(optB, 'qty').title).toBe('2 in your list; reload to update');
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

    // The backpack pair reads the edits, so it is not held back
    const pack = actions.appendChild(el('button', { class: 'opt-btn pack-add-btn' }, [el('svg')]));
    expect(dispatch('click', pack.children[0]).defaultPrevented).toBe(false);
});

test('a price set on an optimizer row prices its own list line, not the card\'s line at another price', () => {
    const ring = resultRow('Ring', 'b', 'SP', 1, { price: '1.5' });
    const ring2 = resultRow('Ring', 'b', 'SP', 2, { price: '2' });
    const opt = optRow('b', 'SP', 1, '1.50', '1.5');
    const opt2 = optRow('b', 'SP', 2, '2.00', '2');
    const { calls, menu, shown } = load({ results: [ring, ring2], opt: [opt, opt2] });

    btn(opt, 'price').click();
    const box = menu().querySelector('.ures-edit-input');
    expect(box.value).toBe('1.50');
    expect(doc.activeElement).toBe(box);
    box.value = '3.256';
    menu().querySelector('.ures-edit-set').click();

    expect([ring.dataset.price, ring2.dataset.price]).toEqual(['3.26', '2']);
    expect(btn(ring, 'price').textContent).toBe('$ 3.26');
    expect(btn(ring2, 'price').classList.contains('edited')).toBe(false);
    expect([btn(opt, 'price').textContent, btn(opt2, 'price').textContent]).toEqual(['3.26', '2.00']);
    expect(shown()).toBe('1 updated');
    expect(calls.track).toEqual(['ui.optimizer:edit_price']);
    expect([opt.dataset.sharePrice, opt2.dataset.sharePrice]).toEqual(['3.26', '2']);
    // Not from the backpack, so nothing is taken back there
    expect(calls.pack).toEqual([]);

    // The row still finds its line at the new price, and back to what the
    // line came with leaves nothing to reload
    btn(opt, 'price').click();
    menu().querySelector('.ures-edit-input').value = '1.5';
    dispatch('keydown', menu().querySelector('.ures-edit-input'), { key: 'Enter' });
    expect([ring.dataset.price, opt.dataset.sharePrice]).toEqual(['1.5', '1.5']);
    expect(btn(ring, 'price').classList.contains('edited')).toBe(false);
    expect(shown()).toBe(null);

    // A price that is no number changes nothing
    btn(ring, 'price').click();
    menu().querySelector('.ures-edit-input').value = '';
    menu().querySelector('.ures-edit-set').click();
    expect(ring.dataset.price).toBe('1.5');
});

test('a grade picked on one of a card\'s lines at two prices moves only its own optimizer row', () => {
    const bolt = resultRow('Bolt', 'a', 'NM', 1, { price: '10' });
    const bolt2 = resultRow('Bolt', 'a', 'NM', 1, { price: '4' });
    const opt = optRow('a', 'NM', 1, '10.00', '10');
    const opt2 = optRow('a', 'NM', 1, '4.00', '4');
    const { pick } = load({ results: [bolt, bolt2], opt: [opt, opt2] });

    pick(btn(bolt2, 'cond'), 'SP');
    expect([opt.dataset.optCond, opt2.dataset.optCond]).toEqual(['NM', 'SP']);
    // And from the optimizer row, which edits its own line alone
    pick(btn(opt, 'cond'), 'MP');
    expect([bolt.dataset.cond, bolt2.dataset.cond]).toEqual(['MP', 'SP']);
});

test('a price set on a list sent from the backpack goes back to it', () => {
    const bolt = resultRow('Bolt', 'a', 'SP', 1, { price: '2' });
    const { calls, menu } = load({ results: [bolt], opt: [], sentPack: 2 });
    btn(bolt, 'price').click();
    menu().querySelector('.ures-edit-input').value = '3.5';
    menu().querySelector('.ures-edit-set').click();
    expect(calls.pack).toEqual([['paid', '2/a|SP', 3.5]]);
    expect(calls.rendered).toBe(1);
});

test('a price set on one of a card\'s lines goes back as the price of all its copies', () => {
    const bolt = resultRow('Bolt', 'a', 'NM', 1, { price: '10' });
    const bolt2 = resultRow('Bolt', 'a', 'NM', 1, { price: '4' });
    const played = resultRow('Bolt', 'a', 'SP', 3, { price: '2' });
    const blank = resultRow('Bolt', 'a', 'SP', 1);
    const { calls, menu } = load({ results: [bolt, bolt2, played, blank], sentPack: 1 });
    const set = (row, value) => {
        btn(row, 'price').click();
        menu().querySelector('.ures-edit-input').value = value;
        menu().querySelector('.ures-edit-set').click();
    };
    set(bolt2, '5');
    expect(calls.pack).toEqual([['paid', 'a', 7.5]]);
    expect([bolt.dataset.price, bolt2.dataset.price]).toEqual(['10', '5']);

    // Copies without a price take the one set, then the lines weigh by theirs
    set(played, '3');
    set(blank, '1');
    expect(calls.pack.slice(1)).toEqual([['paid', 'a|SP', 3], ['paid', 'a|SP', 2.5]]);
});

test('a grade can be taken back to none, as a list line without one', () => {
    const bolt = resultRow('Bolt', 'a', 'SP', 1);
    const optBolt = optRow('a', 'SP', 1);
    const ring = resultRow('Ring', 'b', '', 2);
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

test('a card takes one more line in a grade it has none in, under the row', () => {
    const bolt = resultRow('Bolt', 'a', 'NM', 3, { price: '2' });
    const boltSP = resultRow('Bolt', 'a', 'SP', 1);
    const ring = resultRow('Ring', 'b', 'NM', 1);
    const table = { results: [bolt, boltSP, ring], opt: [optRow('a', 'NM', 3, '2.00', '2')], sentPack: 1 };
    const { calls, menu, pick, shown } = load(table);
    const lines = () => doc.querySelectorAll('.ures-table tr[data-hash]');

    pick(btn(bolt, 'qty'), '5');
    btn(bolt, 'cond').click();
    const adds = menu().querySelectorAll('.ures-edit-items')[1];
    // The grades the card already has a line in are not offered
    expect(adds.querySelectorAll('button').map((b) => b.dataset.value)).toEqual(['+MP', '+HP', '+PO']);
    adds.querySelector('[data-value="+HP"]').click();

    expect(lines().map((tr) => tr.dataset.cardName + ' ' + tr.dataset.cond)).toEqual(['Bolt NM', 'Bolt HP', 'Bolt SP', 'Ring NM']);
    const hp = lines()[1];
    expect([hp.dataset.qtys, hp.dataset.grade, hp.dataset.kCond, hp.dataset.price]).toEqual(['1', 'HP', '3', '2']);
    expect(btn(hp, 'cond').textContent).toBe('HP');
    expect(btn(hp, 'qty').textContent).toBe('1');
    // The new line is the one to reload; the row it came from keeps its own edit
    expect(btn(hp, 'cond').classList.contains('edited')).toBe(true);
    expect(btn(hp, 'qty').classList.contains('edited')).toBe(false);
    expect(bolt.dataset.qtys).toBe('5');
    expect(shown()).toBe('2 updated');
    expect(calls.track).toEqual(['ui.upload.result:edit_qty', 'ui.upload.result:add_cond']);
    expect(calls.pack).toEqual([['qty', 'a', 5], ['add', 'a', 'HP']]);

    // From the optimizer row too, and the line added holds its grade
    btn(doc.querySelector('.opt-store tr[data-opt-id]'), 'cond').click();
    expect(menu().querySelectorAll('.ures-edit-items')[1].querySelectorAll('button').map((b) => b.dataset.value)).toEqual(['+MP', '+PO']);
});

test('a card held in every grade is offered no more lines', () => {
    const rows = ['NM', 'SP', 'MP', 'HP', ''].map((c) => resultRow('Bolt', 'a', c, 1));
    const { menu } = load({ results: rows });
    btn(rows[0], 'cond').click();
    // A line without a grade holds NM, so PO is the one left
    expect(menu().querySelectorAll('.ures-edit-items').length).toBe(2);
    rows[4].attrs['data-cond'] = 'PO';
    btn(rows[0], 'cond').click();
    expect(menu().querySelectorAll('.ures-edit-items').length).toBe(1);
});

test('a grade struck from the page and taken again sets the copies of the backpack entry it left there', () => {
    const bolt = resultRow('Bolt', 'a', 'NM', 3);
    const boltSP = resultRow('Bolt', 'a', 'SP', 4);
    boltSP.classList.add('ures-removed-row');
    const { calls, menu } = load({ results: [bolt, boltSP], sentPack: 1, packHas: ['SP'] });

    btn(bolt, 'cond').click();
    menu().querySelectorAll('.ures-edit-items')[1].querySelector('[data-value="+SP"]').click();
    expect(calls.pack).toEqual([['add', 'a', 'SP'], ['qty', 'a|SP', 1]]);
    expect(calls.rendered).toBe(1);
});
