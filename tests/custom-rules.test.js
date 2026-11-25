import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/custom-rules.js', import.meta.url), 'utf8');

function load(cookies = {}, document = {}, window = {}) {
    const setCookie = (name, value) => { if (value === '') delete cookies[name]; else cookies[name] = value; };
    const getCookie = (name) => cookies[name] || '';
    new Function('window', 'document', 'setCookie', 'getCookie', 'Event', source)(
        window, document, setCookie, getCookie, class Event { constructor(t) { this.type = t; } });
    return { R: window.CustomBuylistRules, cookies };
}

const FIELDS = ['rate', 'min', 'seller', 'fallback'];

// A row whose fields hold vals, as querySelector('[data-field="x"]') finds them.
function fakeRow(vals) {
    const fields = {};
    FIELDS.forEach((f, i) => { fields[f] = { value: vals[i], addEventListener() {} }; });
    return { querySelector: (sel) => fields[sel.match(/data-field="([^"]+)"/)[1]] };
}

function fakeContainer(rows, max = 5, rules = 'UploadCustomRules') {
    return {
        getAttribute: (name) => ({ 'data-max': String(max), 'data-rules': rules })[name] ?? null,
        dataset: {},
        querySelector: (sel) => (sel === '.custom-rule' ? fakeRow(rows[0]) : null),
        querySelectorAll: (sel) => (sel === '.custom-rule' ? rows.map(fakeRow) : []),
    };
}

test('parse keeps items of four to six fields at a valid rate, as many as follow the first within the tier', () => {
    const { R } = load();
    expect(R.parse('', 5)).toEqual([]);
    expect(R.parse('0.6:2:TCGLow:', 5)).toEqual([['0.6', '2', 'TCGLow', '']]);
    expect(R.parse('0.6:2:SS::booster_box:collector:x', 5)).toEqual([['0.6', '2', 'SS', '', 'booster_box', 'collector']]);
    expect(R.parse('0.6:2:TCGLow,half:2:TCGLow:,0:2:TCGLow:,0.5::CK:', 5)).toEqual([['0.5', '', 'CK', '']]);
    expect(R.parse(Array(6).fill('0.5::CK:').join(','), 5)).toHaveLength(4);
    expect(R.parse(Array(12).fill('0.5::CK:').join(','), 10)).toHaveLength(9);
    expect(R.parse('0.5::CK:', 1)).toEqual([]);
    expect(R.format(R.parse('0.6:2:TCGLow:,0.5::CK:', 5))).toBe('0.6:2:TCGLow:,0.5::CK:');
});

test('collect skips the first rule, drops a bad rate and writes numbers plainly', () => {
    const { R } = load();
    const container = fakeContainer([
        ['0.8', '7', 'CK', 'TCGLow'],
        ['0.60', '2.50', 'TCGLow', ''],
        ['0,5', '1', 'CK', ''],
        ['0.4', '1,5', 'CK', ''],
    ]);
    expect(R.collect(container)).toEqual([
        ['0.6', '2.5', 'TCGLow', ''],
        ['0.4', '', 'CK', ''],
    ]);
});

test('the binding saves the rows after the first to the cookie, none clearing it', () => {
    const { R, cookies } = load({ UploadCustomRules: '0.5::CK:' });
    const two = R.binding(fakeContainer([['0.8', '7', 'CK', ''], ['0.5', '', 'TCGLow', '']]));
    expect(two.serialize()).toBe('UploadCustomRules=0.5::TCGLow:');
    two.save();
    expect(cookies.UploadCustomRules).toBe('0.5::TCGLow:');
    R.binding(fakeContainer([['0.8', '7', 'CK', '']])).save();
    expect('UploadCustomRules' in cookies).toBe(false);
});

test('the sealed rules save to a cookie of their own', () => {
    const { R, cookies } = load({ UploadCustomRules: '0.5::CK:' });
    R.binding(fakeContainer([['0.8', '7', 'TCGSealed', ''], ['0.6', '20', 'SS', '']], 5, 'UploadCustomSealedRules')).save();
    expect(cookies).toEqual({ UploadCustomRules: '0.5::CK:', UploadCustomSealedRules: '0.6:20:SS:' });
});

// Rows that keep what is written to them, one every 30px from 100 down.
function liveRows(list) {
    return list.map((vals, n) => {
        const fields = {};
        FIELDS.forEach((f, i) => { fields[f] = { value: vals[i], attrs: {}, setAttribute(k, v) { this.attrs[k] = v; }, removeAttribute(k) { delete this.attrs[k]; } }; });
        fields.rate.getBoundingClientRect = () => ({ top: 100 + 30 * n });
        return { querySelector: (sel) => fields[sel.match(/data-field="([^"]+)"/)[1]], fields };
    });
}

test('a move reorders the values over the same rows, the first included', () => {
    const { R } = load();
    const rules = [['0.8', '7', 'CK', 'TCGLow'], ['0.6', '2', 'TCGLow', ''], ['bad', '1', 'SCG', '']];
    const rows = liveRows(rules);
    const container = { querySelectorAll: () => rows };
    const now = () => rows.map((r) => FIELDS.map((f) => r.fields[f].value));
    R.move(container, 0, 2);
    expect(now()).toEqual([rules[1], rules[2], rules[0]]);
    R.move(container, 1, 0);
    expect(now()).toEqual([rules[2], rules[1], rules[0]]);
    // A bad rate is marked where it lands and nowhere else
    expect(rows.map((r) => 'aria-invalid' in r.fields.rate.attrs)).toEqual([true, false, false]);
});

test('a rule with no minimum becomes the first with one of 0', () => {
    const { R } = load();
    const rows = liveRows([['0.8', '7', 'CK', ''], ['0.6', '', 'TCGLow', '']]);
    R.move({ querySelectorAll: () => rows }, 1, 0);
    expect(rows.map((r) => r.fields.min.value)).toEqual(['0', '7']);
});

test('the first rule with its minimum cleared takes 0', () => {
    const ed = editor(['0.8', '7', 'CK', '']);
    load({}, ed.document).R.binding(ed.container).load();
    const min = ed.rows[0].querySelector('[data-field="min"]');
    min.fire('change');
    expect(min.value).toBe('7');
    min.value = '';
    min.fire('change');
    expect(min.value).toBe('0');
});

test('the row under the pointer is found by height, the ends taking what is past them', () => {
    const { R } = load();
    const container = { querySelectorAll: () => liveRows([['1', '', '', ''], ['1', '', '', ''], ['1', '', '', '']]) };
    expect([0, 100, 129, 130, 160, 900].map((y) => R.rowAt(container, y))).toEqual([0, 0, 0, 1, 2, 2]);
});

// An editor of one rule, with just enough of the DOM for binding to wire it.
// Given kinds, its rows have a product and a kind select too; given stores,
// their reference is a select of those.
function editor(vals, kinds, stores) {
    const isA = (c, sel) => c.className.split(' ').includes(sel.slice(1));
    const node = (className) => ({
        className, dataset: {}, attrs: {}, children: [], listeners: {}, hidden: false, focused: 0,
        setAttribute(k, v) { this.attrs[k] = v; },
        removeAttribute(k) { delete this.attrs[k]; },
        addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
        fire(type, e = {}) { (this.listeners[type] || []).forEach((fn) => fn(e)); },
        appendChild(c) { this.children.push(c); c.parent = this; },
        remove() { this.parent.children.splice(this.parent.children.indexOf(this), 1); },
        focus() { this.focused++; },
    });
    // Picks nothing for a value it has no option for, as a select does.
    const select = (cookie, values = ['']) => {
        const n = Object.assign(node('field'), { options: values.map((value) => ({ value, textContent: value || 'Any' })), picked: '' });
        n.dataset.cookie = cookie;
        n.remove = (i) => n.options.splice(i, 1);
        n.appendChild = (o) => n.options.push(o);
        Object.defineProperty(n, 'value', { get: () => n.picked, set(v) { n.picked = n.options.some((o) => o.value === v) ? v : ''; } });
        return n;
    };
    const makeRow = (rowVals) => {
        const row = node('custom-rule');
        const fields = {};
        FIELDS.forEach((f, i) => { fields[f] = Object.assign(node('field'), { value: rowVals[i] }); });
        if (stores) {
            fields.seller = select('UploadCustomBuyer', stores);
            fields.seller.value = rowVals[2];
        }
        if (kinds) ['product', 'kind'].forEach((f) => { fields[f] = select('UploadCustomSealed' + f); });
        row.querySelector = (sel) => {
            const m = sel.match(/data-field="([^"]+)"/);
            return m ? fields[m[1]] : row.children.find((c) => isA(c, sel));
        };
        row.querySelectorAll = (sel) => row.children.filter((c) => isA(c, sel));
        row.cloneNode = () => {
            const copy = makeRow(FIELDS.map((f) => fields[f].value));
            row.children.forEach((c) => copy.appendChild(node(c.className)));
            return copy;
        };
        return row;
    };
    const rows = [makeRow(vals)];
    const add = node('custom-rules-add');
    const container = {
        changes: 0,
        dataset: {},
        getAttribute: (name) => ({ 'data-max': '5', 'data-rules': 'UploadCustomRules', 'data-kinds': JSON.stringify(kinds) })[name] ?? null,
        dispatchEvent(e) { if (e.type === 'change') this.changes++; },
        insertBefore(row) { row.parent = { children: rows }; rows.push(row); },
        querySelector: (sel) => (sel === '.custom-rule' ? rows[0] : add),
        querySelectorAll: (sel) => ({
            '.custom-rule': rows, '.custom-rule ~ .custom-rule': rows.slice(1),
            '.custom-rule-grip': rows.flatMap((r) => r.querySelectorAll('.custom-rule-grip')),
        })[sel],
    };
    return { container, rows, add, document: { createElement: () => node('') } };
}

test('grips show from two rules, and the arrows move a rule as far as the ends', () => {
    const ed = editor(['0.8', '7', 'CK', '']);
    const tracked = [];
    const { R } = load({}, ed.document, { BAN: { track: (...a) => tracked.push(a) } });
    R.binding(ed.container).load();
    const grips = () => ed.container.querySelectorAll('.custom-rule-grip');
    const rates = () => ed.rows.map((r) => r.querySelector('[data-field="rate"]').value);
    const press = (row, key) => {
        let prevented = false;
        grips()[row].fire('keydown', { key, preventDefault() { prevented = true; } });
        return prevented;
    };
    expect(grips().map((g) => g.hidden)).toEqual([true]);

    ed.add.fire('click');
    ed.rows[1].querySelector('[data-field="rate"]').value = '0.5';
    expect(grips().map((g) => g.hidden)).toEqual([false, false]);
    ed.container.changes = 0;

    press(0, 'ArrowUp');
    press(1, 'ArrowDown');
    expect(press(0, 'Tab')).toBe(false);
    expect(rates()).toEqual(['0.8', '0.5']);
    expect([ed.container.changes, tracked.length]).toEqual([0, 0]);

    expect(press(0, 'ArrowDown')).toBe(true);
    expect(rates()).toEqual(['0.5', '0.8']);
    expect(grips().map((g) => g.focused)).toEqual([0, 1]);
    expect(ed.container.changes).toBe(1);
    expect(tracked).toEqual([['ui.settings.custom_rule', 'move']]);

    // Back to one rule, nothing is left to order
    ed.rows[1].querySelector('.custom-rule-remove').fire('click');
    expect(grips().map((g) => g.hidden)).toEqual([true]);
});

test('a sealed rule lists the products, and the kinds of the one picked', () => {
    const ed = editor(['0.8', '7', 'SS', ''], { booster_box: ['collector', 'draft'], deck: ['intro'] });
    const cookies = {
        UploadCustomSealedproduct: 'booster_box', UploadCustomSealedkind: 'collector',
        UploadCustomRules: '0.5:1:SS:,0.4:1:SS::booster_crate:gone',
    };
    const { R } = load(cookies, ed.document);
    const binding = R.binding(ed.container);
    binding.load();
    const at = (row, f) => ed.rows[row].querySelector('[data-field="' + f + '"]');
    const shown = (row, f) => at(row, f).options.map((o) => o.textContent);
    const picks = () => ed.rows.map((r, i) => [at(i, 'product').value, at(i, 'kind').value]);

    expect(picks()).toEqual([['booster_box', 'collector'], ['', ''], ['booster_crate', 'gone']]);
    expect(shown(0, 'product')).toEqual(['Any', 'Booster box', 'Deck']);
    expect(shown(0, 'kind')).toEqual(['Any', 'Collector', 'Draft']);
    expect(shown(1, 'kind')).toEqual(['Any', 'Collector', 'Draft', 'Intro']);
    // A label the datastore lost stays, so a save does not widen the rule to Any
    expect(shown(2, 'product')).toEqual(['Any', 'Booster box', 'Deck', 'Booster crate']);
    binding.save();
    expect(cookies.UploadCustomRules).toBe('0.5:1:SS:::,0.4:1:SS::booster_crate:gone');

    // Kinds travel with their product to a row that listed others
    R.move(ed.container, 0, 1);
    expect(picks()).toEqual([['', ''], ['booster_box', 'collector'], ['booster_crate', 'gone']]);

    // Another product drops a kind it has not, and keeps one it has
    at(1, 'product').value = 'deck';
    at(1, 'product').fire('change');
    expect([picks()[1], shown(1, 'kind')]).toEqual([['deck', ''], ['Any', 'Intro']]);
    at(0, 'kind').value = 'intro';
    at(0, 'product').value = 'deck';
    at(0, 'product').fire('change');
    expect(picks()[0]).toEqual(['deck', 'intro']);
});

test('a reference store missing from this load survives a save', () => {
    const ed = editor(['0.8', '7', 'CK', ''], undefined, ['TCGLow', 'CK']);
    const cookies = { UploadCustomBuyer: 'GONE', UploadCustomRules: '0.6:2:SCG:' };
    const { R } = load(cookies, ed.document);
    const binding = R.binding(ed.container);
    binding.load();
    const sellers = () => ed.rows.map((r) => r.querySelector('[data-field="seller"]'));
    expect(sellers().map((s) => s.value)).toEqual(['GONE', 'SCG']);
    binding.save();
    expect(cookies.UploadCustomRules).toBe('0.6:2:SCG:');

    // It travels with its rule, and no list names a store twice
    R.move(ed.container, 1, 0);
    expect(sellers().map((s) => s.value)).toEqual(['SCG', 'GONE']);
    R.move(ed.container, 1, 0);
    expect(sellers()[0].options.map((o) => o.value)).toEqual(['TCGLow', 'CK', 'GONE', 'SCG']);
});
