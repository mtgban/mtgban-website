import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const optimizer = readFileSync(new URL('../js/upload-optimizer.js', import.meta.url), 'utf8');
const template = readFileSync(new URL('../templates/upload.html', import.meta.url), 'utf8');

test('the start view hands its reload decision to the optimizer before the script loads', () => {
    const flag = template.indexOf('window.BAN_UPLOAD_RELOAD = isReload;');
    expect(flag).toBeGreaterThan(template.indexOf('var isReload ='));
    expect(flag).toBeLessThan(template.indexOf('/js/upload-optimizer.js'));
});

function classes() {
    const set = new Set();
    return { add: (c) => set.add(c), remove: (c) => set.delete(c), contains: (c) => set.has(c) };
}

// A store section as templates/upload.html draws it: its rows, each with
// its box, and the box in its head that toggles them all.
function section(store, rows) {
    const s = {
        id: 'opt-' + store, dispatched: [], all: { checked: true },
        rows: rows.map(([id, cond]) => {
            const tr = { dataset: { optId: id, optCond: cond }, classList: classes() };
            tr.cb = { checked: true, closest: () => tr };
            tr.querySelector = () => tr.cb;
            tr.closest = (sel) => (sel === '.opt-store' ? s : null);
            return tr;
        }),
        querySelectorAll: (sel) => (sel === 'tr[data-opt-id]' ? s.rows : []),
        querySelector: (sel) => (sel === 'thead input[type="checkbox"]' ? s.all : null),
        dispatchEvent: (e) => { s.dispatched.push(e.type); },
    };
    return s;
}

function loadOptimizer(sections, stored, reload) {
    const store = { ...stored };
    const sessionStorage = {
        getItem: (k) => (k in store ? store[k] : null),
        setItem: (k, v) => { store[k] = v; },
        removeItem: (k) => { delete store[k]; },
    };
    const handlers = {};
    const rows = () => sections.flatMap((s) => s.rows);
    const document = {
        addEventListener: (type, fn) => { (handlers[type] = handlers[type] || []).push(fn); },
        querySelectorAll: (sel) => {
            if (sel === '.opt-store') return sections;
            if (sel === '.opt-store tr.opt-removed[data-opt-id]') return rows().filter((tr) => tr.classList.contains('opt-removed'));
            return [];
        },
    };
    const window = { BAN_UPLOAD_RELOAD: reload };
    class Event { constructor(type) { this.type = type; } }
    new Function('window', 'document', 'wireLoadLists', 'sessionStorage', 'Event', optimizer)(
        window, document, () => {}, sessionStorage, Event);
    const fire = (type, e) => (handlers[type] || []).forEach((fn) => fn(e));
    return { store, fire };
}

test('the unticked rows are kept by card, condition and store', () => {
    const ck = section('CK', [['a', 'NM'], ['b', '']]);
    const scg = section('SCG', [['a', 'NM']]);
    const { store, fire } = loadOptimizer([ck, scg], {}, false);

    ck.rows[1].classList.add('opt-removed');
    scg.rows[0].classList.add('opt-removed');
    fire('change', { target: { closest: () => ck } });
    expect(JSON.parse(store.uploadOptUnticked)).toEqual(['b\t\tCK', 'a\tNM\tSCG']);

    ck.rows[1].classList.remove('opt-removed');
    scg.rows[0].classList.remove('opt-removed');
    fire('change', { target: { closest: () => scg } });
    expect('uploadOptUnticked' in store).toBe(false);
});

test('a reload unticks them again and recounts their sections', () => {
    const ck = section('CK', [['a', 'NM'], ['b', '']]);
    const scg = section('SCG', [['a', 'NM']]);
    const abu = section('ABU', [['c', 'NM']]);
    const kept = JSON.stringify(['b\t\tCK', 'a\tNM\tSCG', 'gone\tNM\tCK']);
    const { fire } = loadOptimizer([ck, scg, abu], { uploadOptUnticked: kept }, true);
    fire('DOMContentLoaded');

    expect(ck.rows.map((tr) => [tr.cb.checked, tr.classList.contains('opt-removed')])).toEqual([[true, false], [false, true]]);
    expect(ck.all.checked).toBe(true);
    expect(ck.dispatched).toEqual(['change']);
    expect(scg.rows[0].cb.checked).toBe(false);
    expect(scg.all.checked).toBe(false);
    expect(abu.rows[0].cb.checked).toBe(true);
    expect(abu.dispatched).toEqual([]);
});

test('a new list starts ticked and forgets the old one', () => {
    const ck = section('CK', [['b', '']]);
    const { store, fire } = loadOptimizer([ck], { uploadOptUnticked: JSON.stringify(['b\t\tCK']) }, false);
    fire('DOMContentLoaded');

    expect(ck.rows[0].cb.checked).toBe(true);
    expect(ck.dispatched).toEqual([]);
    expect('uploadOptUnticked' in store).toBe(false);
});
