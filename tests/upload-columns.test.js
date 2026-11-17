import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-columns.js', import.meta.url), 'utf8');

// A stand-in DOM: just enough of tables, rows and cells for the columns to
// be moved and read back.
const kebab = (s) => s.replace(/[A-Z]/g, (c) => '-' + c.toLowerCase());

function el(tag, attrs = {}, children = []) {
    const node = {
        tag, attrs: {}, classes: new Set(), children: [], parentNode: null, text: '',
        get textContent() { return this.text + this.children.map((c) => c.textContent).join(''); },
        get dataset() {
            const a = this.attrs;
            return new Proxy({}, { get: (_, k) => a['data-' + kebab(k)], set: (_, k, v) => { a['data-' + kebab(k)] = String(v); return true; } });
        },
        get classList() {
            const s = this.classes;
            return { add: (...c) => c.forEach((x) => s.add(x)), remove: (...c) => c.forEach((x) => s.delete(x)), contains: (c) => s.has(c), toggle: (c, on) => (on ? s.add(c) : s.delete(c)) };
        },
        get name() { return this.attrs.name; },
        set name(v) { this.attrs.name = String(v); },
        get cells() { return this.children; },
        get rows() { return this.children.flatMap((c) => (c.tag === 'tr' ? [c] : c.children)); },
        get tHead() { return this.children.find((c) => c.tag === 'thead') || null; },
        get nextElementSibling() { const s = this.parentNode.children; return s[s.indexOf(this) + 1] || null; },
        setAttribute(n, v) { this.attrs[n] = String(v); },
        appendChild(c) { if (c.parentNode) c.parentNode.children.splice(c.parentNode.children.indexOf(c), 1); c.parentNode = this; this.children.push(c); return c; },
        insertBefore(c, ref) {
            if (c.parentNode) c.parentNode.children.splice(c.parentNode.children.indexOf(c), 1);
            c.parentNode = this;
            const i = ref ? this.children.indexOf(ref) : this.children.length;
            this.children.splice(i, 0, c);
            return c;
        },
        remove() { if (this.parentNode) this.parentNode.children.splice(this.parentNode.children.indexOf(this), 1); this.parentNode = null; },
        contains(n) { for (; n; n = n.parentNode) if (n === this) return true; return false; },
        closest(sel) { for (let n = this; n; n = n.parentNode) if (n.matches && n.matches(sel)) return n; return null; },
        matches(sel) {
            return sel.split(',').some((s) => {
                const m = s.trim().match(/^([a-z]+)?(.*)$/);
                if (m[1] && this.tag !== m[1]) return false;
                return (m[2].match(/\.[\w-]+|\[[^\]]+\]/g) || []).every((p) => {
                    if (p[0] === '.') return this.classes.has(p.slice(1));
                    const [k, v] = p.slice(1, -1).split('=');
                    return v === undefined ? k in this.attrs : this.attrs[k] === v.replace(/"/g, '');
                });
            });
        },
        querySelectorAll(sel) {
            const out = [];
            const last = sel.split(/\s+/).pop();
            const walk = (n) => n.children.forEach((c) => { if (c.matches(last)) out.push(c); walk(c); });
            walk(this);
            return out;
        },
    };
    Object.entries(attrs).forEach(([k, v]) => (k === 'class' ? String(v).split(' ').forEach((c) => node.classes.add(c)) : node.setAttribute(k, v)));
    children.forEach((c) => (typeof c === 'string' ? (node.text = c) : node.appendChild(c)));
    return node;
}

// A Results table as upload.html draws it: four cells, the stores, the
// custom buylist, which does not move, and a totals row.
function table(stores, kind = 'singles') {
    const head = (k) => el('th', { 'data-store': k, 'data-store-kind': kind, draggable: 'true' }, [k, el('button', { class: 'ures-store-drop' }, ['×'])]);
    const row = (label) => el('tr', {}, ['Card', 'Price', 'Cond', 'Qty'].map((c) => el('td', {}, [label + c])).concat(stores.map((k) => el('td', {}, [label + k])), [el('td', {}, [label + 'custom'])]));
    return el('table', { class: 'ures-table' }, [
        el('thead', {}, [el('tr', {}, ['Card', 'Price', 'Cond', 'Qty'].map((c) => el('th', {}, [c])).concat(stores.map(head), [el('th', {}, ['custom'])]))]),
        el('tbody', {}, [row('a'), row('b'), row('total')]),
    ]);
}

let listeners;
function dispatch(type, target, extra = {}) {
    const e = { type, target, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; }, stopPropagation() { this.stopped = true; }, dataTransfer: { setData() {} }, ...extra };
    (listeners[type] || []).forEach((fn) => fn(e));
    return e;
}

function load(tables) {
    listeners = {};
    const calls = { track: [], reprocessed: 0 };
    const form = el('form', { id: 'upload_form' });
    const body = el('body', {}, tables.concat([form]));
    const doc = {
        querySelectorAll: (s) => body.querySelectorAll(s),
        getElementById: (id) => (id === 'upload_form' ? form : null),
        createElement: (tag) => el(tag),
        addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
    };
    const window = {
        BAN: { track: (n, v) => calls.track.push(n + ':' + v) },
        BAN_OPT_STORES: { stores: ['CK', 'SCG', 'TCG'], sealed: ['CKS', 'TCGS'] },
        reprocessUploadResults: () => { calls.reprocessed++; },
    };
    new Function('window', 'document', source)(window, doc);
    const posted = (name) => form.children.filter((c) => c.attrs.name === name).map((c) => c.value);
    return { calls, window, posted };
}

const order = (t) => t.rows.map((r) => r.cells.map((c) => c.textContent.replace('×', '')).join(','));
const th = (t, k) => t.tHead.rows[0].cells.find((c) => c.attrs['data-store'] === k);

function drag(from, to) {
    dispatch('dragstart', from);
    expect(dispatch('dragover', to).defaultPrevented).toBe(true);
    dispatch('drop', to);
    dispatch('dragend', from);
}

test('a store header dropped on another moves its column, row by row, in every table of its kind', () => {
    const singles = table(['CK', 'SCG', 'TCG']);
    const opened = table(['CK', 'SCG', 'TCG']);
    const sealed = table(['CKS', 'TCGS'], 'sealed');
    const { calls, window, posted } = load([singles, opened, sealed]);

    drag(th(singles, 'TCG'), th(singles, 'CK'));
    const want = [
        'Card,Price,Cond,Qty,TCG,CK,SCG,custom',
        'aCard,aPrice,aCond,aQty,aTCG,aCK,aSCG,acustom',
        'bCard,bPrice,bCond,bQty,bTCG,bCK,bSCG,bcustom',
        'totalCard,totalPrice,totalCond,totalQty,totalTCG,totalCK,totalSCG,totalcustom',
    ];
    expect(order(singles)).toEqual(want);
    expect(order(opened)).toEqual(want);
    expect(order(sealed)[0]).toBe('Card,Price,Cond,Qty,CKS,TCGS,custom');
    // The next re-post prices against the stores in this order
    expect(posted('stores')).toEqual(['TCG', 'CK', 'SCG']);
    expect(posted('sealed_stores')).toEqual([]);
    expect(window.BAN_OPT_STORES.stores).toEqual(['TCG', 'CK', 'SCG']);
    expect(calls.track).toEqual(['ui.upload.result:store_move']);

    // Moved right, it lands after the header it is dropped on
    drag(th(singles, 'TCG'), th(singles, 'SCG'));
    expect(order(singles)[0]).toBe('Card,Price,Cond,Qty,CK,SCG,TCG,custom');
    expect(posted('stores')).toEqual(['CK', 'SCG', 'TCG']);
});

test('a header lands only on another store of its kind in its own table', () => {
    const singles = table(['CK', 'SCG']);
    const opened = table(['CK', 'SCG']);
    const sealed = table(['CKS', 'TCGS'], 'sealed');
    const { calls } = load([singles, opened, sealed]);

    dispatch('dragstart', th(singles, 'CK'));
    expect(dispatch('dragover', th(sealed, 'TCGS')).defaultPrevented).toBe(false);
    expect(dispatch('dragover', th(opened, 'SCG')).defaultPrevented).toBe(false);
    expect(dispatch('dragover', singles.tHead.rows[0].cells[0]).defaultPrevented).toBe(false);
    dispatch('dragend', th(singles, 'CK'));
    expect(calls.track).toEqual([]);
});

test('a column\'s × prices the list again without its store, its sort left alone', () => {
    const singles = table(['CK', 'SCG', 'TCG']);
    const { calls, posted } = load([singles]);

    const e = dispatch('click', th(singles, 'SCG').children[0]);
    expect(e.stopped).toBe(true);
    expect(posted('stores')).toEqual(['CK', 'TCG']);
    expect(calls.reprocessed).toBe(1);
    expect(calls.track).toEqual(['ui.upload.result:store_drop']);
});
