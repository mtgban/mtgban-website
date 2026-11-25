import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

const source = read('js/arbit-rows.js');
const KEY = 'mtgban_arbit_unticked:arbit:SZ';

// A store section as templates/arbit.html draws it: its rows, each with its
// box, and the box in its head that toggles them all.
function section(store, rows) {
    const s = {
        dataset: { store }, dispatched: [], all: { checked: true }, getAttribute: () => store,
        querySelectorAll: () => s.rows,
        querySelector: () => s.all,
        dispatchEvent: (e) => { s.dispatched.push(e.type); },
    };
    s.rows = rows.map(([arbId, arbListing]) => {
        const classes = new Set();
        const tr = {
            dataset: { arbId, arbListing }, cb: { checked: true },
            classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c), contains: (c) => classes.has(c) },
            querySelector: () => tr.cb, closest: () => s,
        };
        return tr;
    });
    return s;
}

function load(sections, store, arbit = { mode: 'arbit', source: 'SZ' }) {
    const handlers = {};
    const document = {
        addEventListener: (type, fn) => { (handlers[type] = handlers[type] || []).push(fn); },
        querySelectorAll: () => sections,
    };
    const sessionStorage = {
        getItem: (k) => (k in store ? store[k] : null),
        setItem: (k, v) => { store[k] = v; },
        removeItem: (k) => { delete store[k]; },
    };
    class Event { constructor(type) { this.type = type; } }
    new Function('window', 'document', 'sessionStorage', 'Event', source)({ BAN_ARBIT: arbit }, document, sessionStorage, Event);
    const fire = (type, e) => handlers[type].forEach((fn) => fn(e));
    return { fire, change: (s) => fire('change', { target: { closest: (sel) => (sel === '.arb-section' ? s : null) } }) };
}

const rayne = [['rayne', 'NM 1'], ['rayne', 'SP 2'], ['nihil', 'NM 3']];
const shown = (s) => s.rows.map((tr) => tr.cb.checked && !tr.classList.contains('arb-removed'));

test('the rows unticked stay so when a sort loads the page again, in any order', () => {
    const store = {};
    const before = section('CK', rayne);
    const page = load([before], store);
    before.rows[0].classList.add('arb-removed');
    before.rows[1].classList.add('arb-removed');
    page.change(before);
    expect(JSON.parse(store[KEY])).toEqual(['rayne\tNM 1\tCK', 'rayne\tSP 2\tCK']);

    const after = section('CK', rayne.toReversed());
    const other = section('SCG', rayne);
    load([after, other], store).fire('DOMContentLoaded');
    expect(shown(after)).toEqual([true, false, false]);
    expect(after.all.checked).toBe(true);
    expect(after.dispatched).toEqual(['change']);
    expect(shown(other)).toEqual([true, true, true]);
    expect(other.dispatched).toEqual([]);
});

test('a section with every row unticked shows its head box unticked', () => {
    const s = section('CK', [['a', 'NM 1']]);
    load([s], { [KEY]: JSON.stringify(['a\tNM 1\tCK']) }).fire('DOMContentLoaded');
    expect(s.all.checked).toBe(false);
});

test('a kept row a filter took off the page stays kept; one ticked again does not', () => {
    const store = { [KEY]: JSON.stringify(['gone\tNM 9\tCK', 'rayne\tNM 1\tCK']) };
    const s = section('CK', rayne);
    load([s], store).change(s);
    expect(JSON.parse(store[KEY])).toEqual(['gone\tNM 9\tCK']);
});

test('each mode and source keeps its own', () => {
    const store = { [KEY]: JSON.stringify(['rayne\tNM 1\tCK']) };
    for (const arbit of [{ mode: 'reverse', source: 'SZ' }, { mode: 'arbit', source: 'ABU' }]) {
        const s = section('CK', rayne);
        load([s], store, arbit).fire('DOMContentLoaded');
        expect(shown(s)).toEqual([true, true, true]);
    }
});

// The listing a row is kept by, as templates/arbit.html prints it for a copy
// of the source and, on Global, the reference's listing it is set against.
const listingAttr = read('templates/arbit.html').match(/<tr data-arb-id="\{\{\.CardID\}\}" data-arb-listing="([^"]*)"/)[1];
function listing(mode, copy, ref) {
    return listingAttr
        .replace(/\{\{if \$\.GlobalMode\}\}(.*?)\{\{end\}\}/, mode === 'global' ? '$1' : '')
        .replace(/\{\{\.(InventoryEntry|ReferenceEntry)\.(Conditions|InstanceID)\}\}/g, (_, side, field) => (side === 'InventoryEntry' ? copy : ref)[field]);
}

const copy = { Conditions: 'NM', InstanceID: '1' };
const refs = [{ Conditions: 'NM', InstanceID: '7' }, { Conditions: 'SP', InstanceID: '8' }];

test('the rows carry the listing they are kept by', () => {
    expect(listing('arbit', copy, refs[0])).toBe('NM 1');
    expect(listing('reverse', copy, refs[1])).toBe('NM 1');
    expect(listing('global', copy, refs[1])).toBe('NM 1 SP 8');
});

test('one copy against two of the reference\'s listings on Global is two rows, kept apart', () => {
    const arbit = { mode: 'global', source: 'TCGLow' };
    const rows = refs.map((ref) => ['bolt', listing('global', copy, ref)]);
    for (const unticked of [0, 1]) {
        const store = {};
        const before = section('CK', rows);
        const page = load([before], store, arbit);
        before.rows[unticked].classList.add('arb-removed');
        page.change(before);

        const after = section('CK', rows);
        load([after], store, arbit).fire('DOMContentLoaded');
        expect(shown(after)).toEqual([unticked !== 0, unticked !== 1]);
    }
});
