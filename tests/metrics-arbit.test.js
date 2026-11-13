import { test, expect } from 'bun:test';
import { read, tagsWith, expectTrack, fakeBAN } from './metrics-helpers.js';
import { trackProblems } from './track-registry.js';

const arbit = read('templates/arbit.html');

// The opening tag a marker after its end closes.
function tagBefore(src, marker) {
    const out = [];
    for (let i = src.indexOf(marker); i >= 0; i = src.indexOf(marker, i + 1)) out.push(src.slice(src.lastIndexOf('<', i), i + 1));
    return out;
}

test.each([
    ['title="Previous"', 'ui.arbit.row', 'section_nav', undefined],
    ['title="Next"', 'ui.arbit.row', 'section_nav', undefined],
    ['class="arb-section-name"', 'ui.arbit.row', 'section_nav', undefined],
    ['class="section-fold"', 'ui.arbit.row', 'fold', undefined],
    ['id="arbFilterReset"', 'ui.arbit.filters', 'reset', undefined],
    ['class="arb-filter-clear"', 'ui.arbit.filters', 'clear_saved', undefined],
])('%# the tag with %s tracks %s:%s', (marker, name, value, scope) => {
    const found = tagsWith(arbit, marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], name, value, scope);
});

test.each([
    ['>Deck builder at {{$sourceKey}}</a>', 2, 'deck_builder', '{{$sourceKey}}'],
    ['>Mass entry at TCGplayer</a>', 1, 'mass_entry', '{{$sourceKey}}'],
    ['>Mass entry at Mana Pool</a>', 1, 'mass_entry', '{{$sourceKey}}'],
    ['>Load at {{$sourceKey}}</a>', 1, 'load_at', '{{$sourceKey}}'],
    ['>Load buylist at {{$scraperKey}}</a>', 1, 'sellcart', '{{$scraperKey}}'],
    ['>Download {{$scraperKey}} CSV</a>', 1, 'csv', '{{$scraperKey}}'],
])('the send link ending %s tracks ui.arbit.send:%s', (marker, count, value, scope) => {
    const found = tagBefore(arbit, marker);
    expect(found.length).toBe(count);
    found.forEach((t) => expectTrack(t, 'ui.arbit.send', value, scope));
});

test('both landing card lists count landing_card', () => {
    const found = tagsWith(arbit, 'class="card arb-store-card"');
    expect(found.length).toBe(2);
    found.forEach((t) => expectTrack(t, 'ui.arbit.store_select', 'landing_card', undefined));
});

test('the selects, the section, the reference link and the contents link carry what the scripts read', () => {
    expect(tagsWith(arbit, 'onchange="goToStore(this.value)"')[0]).toContain('data-pick="store"');
    expect(tagsWith(arbit, 'location.hash = this.value')[0]).toContain('data-pick="jump"');
    expect(tagsWith(arbit, 'id="arbPresetSelect"')[0]).not.toContain('data-pick');
    expect(arbit).toContain('<div class="arb-section" data-fold data-store="{{$arb.Key}}">');
    expect(tagsWith(arbit, 'href="{{.ReferenceEntry.URL}}"')[0]).toContain('class="arb-qlink buy ref"');
    expect(tagsWith(arbit, 'href="{{.InventoryEntry.URL}}"')[0]).toContain('class="arb-qlink buy"');
    expect(tagsWith(arbit, 'title="Search what can be found in this product"')[0]).toContain('class="arb-contents"');
    expect(arbit).toContain('<script type="text/javascript" src="/js/arbit-rows.js?hash={{$.Hash}}" defer></script>');
});

test('every literal mark on the arbitrage pages is in the registry', () => {
    expect(trackProblems(arbit).filter((p) => !p.includes('{{'))).toEqual([]);
});

// arbit-presets.js, as tests/arbit-presets.test.js loads it, with window.BAN added.
const presetsSource = read('js/arbit-presets.js');
function fakeStorage(initial = {}) {
    const m = Object.assign({}, initial);
    return {
        getItem: (k) => (k in m ? m[k] : null),
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
    };
}
const ARBIT = {
    source: 'CK', query: 'f=1', cookie: 'ArbitFilters', sort: '',
    ignored: ['syp', 'stocks', 'legit', 'stable', 'tradable', 'decklists'],
    defaults: { minsell: '0', minbuy: '0', minspread: '10', mindiff: '0', minqty: '0', minprof: '0', rl: '0', abu4h: '0', nocollector: '0', nooversize: '0', notoken: '0' },
};
const sameSite = (v) => (v.charAt(0) === '?' ? v : '');

function loadPresets(cfg, { local = fakeStorage(), elements = {}, search = '', ban = true, prompt = null, confirm = null } = {}) {
    const f = fakeBAN();
    const window = {
        addEventListener() {},
        BAN_ARBIT: Object.assign({}, ARBIT, cfg),
        location: { href: '', search, replace: (u) => { window.location.replaced = u; } },
        ArbitFilters: { save() {}, formQuery: (form) => form.query },
        prompt, confirm,
    };
    if (ban) window.BAN = f.BAN;
    const document = {
        getElementById: (id) => elements[id] || null,
        createElement: () => ({ value: '', textContent: '', selected: false }),
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'sameSiteURL', presetsSource)(window, document, local, fakeStorage(), sameSite);
    return { P: window.ArbitPresets, window, calls: f.calls };
}

// The preset row's elements, as fakePage in tests/arbit-presets.test.js builds them.
function fakePage(formQuery) {
    const listeners = {};
    const on = (name) => (ev, fn) => { listeners[name + ':' + ev] = fn; };
    const options = [];
    const select = {
        value: '',
        set innerHTML(v) { options.length = 0; },
        appendChild: (o) => { options.push(o); if (o.selected) select.value = o.value; },
        addEventListener: on('select'),
    };
    const button = (name) => ({ disabled: false, textContent: '', setAttribute() {}, focus() {}, addEventListener: on(name), click: () => listeners[name + ':click']() });
    const attrs = {};
    const pin = {
        attrs, addEventListener: on('pin'),
        getAttribute: (k) => (k in attrs ? attrs[k] : null),
        setAttribute: (k, v) => { attrs[k] = String(v); },
        classList: { toggle() {}, contains: () => false },
    };
    // One number field, minsell, whose value the form's state reads
    const minsell = { type: 'number', name: 'minsell', value: new URLSearchParams(formQuery).get('minsell') || '' };
    const form = {
        query: formQuery, addEventListener: on('form'), submits: 0, requestSubmit: () => { form.submits++; }, minsell,
        querySelectorAll: (sel) => (sel === 'input[type=number]' ? [minsell] : []),
        querySelector: (sel) => (sel === 'input[name=toggles_on]' ? { value: '' } : sel.startsWith('input[type=number]') && sel.includes('"minsell"') ? minsell : null),
    };
    const elements = {
        arbPresetBox: { hidden: true }, arbPresetSelect: select, arbPresetControls: { hidden: true }, arbPresetNote: { textContent: '' },
        arbPresetSaveToggle: button('toggle'), arbPresetSaveRow: { hidden: true },
        arbPresetName: { value: '', focus() {}, addEventListener: on('name') },
        arbPresetSave: button('save'), arbPresetCancel: button('cancel'), arbPresetRename: button('rename'), arbPresetDelete: button('delete'),
        arbPresetPin: pin, arbFilters: form,
    };
    return { elements, options, listeners, form };
}

const pinTo = (local, id) => local.setItem('mtgban_arbit_pins', JSON.stringify({ 'arbit:CK': { id, t: 1 } }));

test('a store reached with no filters opens on its pin and counts pin_auto', () => {
    const local = fakeStorage();
    const four = loadPresets({}, { local }).P.store.save({ name: 'Four', q: 'f=1&minsell=4' }).preset;
    pinTo(local, four.id);
    const { window, calls } = loadPresets({ query: 'f=1&minsell=2' }, { local, search: '?source=CK' });
    expect(window.location.replaced).toBe('?source=CK&f=1&minsell=4');
    expect(calls).toEqual([['ui.arbit.pin_auto', undefined, undefined]]);
});

test('a store with no pin, or a URL that already carries f, counts nothing on arrival', () => {
    const local = fakeStorage();
    expect(loadPresets({ query: 'f=1&minsell=2' }, { local, search: '?source=CK' }).calls).toEqual([]);
    const four = loadPresets({}, { local }).P.store.save({ name: 'Four', q: 'f=1&minsell=4' }).preset;
    pinTo(local, four.id);
    const marked = loadPresets({ query: 'f=1&minsell=2' }, { local, search: '?source=CK&f=1&minsell=2' });
    expect(marked.window.location.replaced).toBeUndefined();
    expect(marked.calls).toEqual([]);
});

test('pinnedStore is true exactly when storeURL would land on a pin', () => {
    const local = fakeStorage();
    const four = loadPresets({}, { local }).P.store.save({ name: 'Four', q: 'f=1&minsell=4' }).preset;
    pinTo(local, four.id);
    const { P } = loadPresets({ source: 'SCG' }, { local });
    expect(P.pinnedStore('/arbit?source=CK')).toBe(true);
    expect(P.storeURL('/arbit?source=CK')).toBe('/arbit?source=CK&f=1&minsell=4');
    expect(P.pinnedStore('/arbit?source=SCG')).toBe(false);
    expect(P.pinnedStore('/arbit')).toBe(false);
});

const presetCalls = (calls) => calls.filter((c) => c[0] === 'ui.arbit.preset');

test('picking a preset, pinning it, saving and deleting are four values', () => {
    const local = fakeStorage();
    const two = loadPresets({}, { local }).P.store.save({ name: 'Two', q: 'f=1&minsell=2' }).preset;
    const page = fakePage('f=1&minsell=2');
    const { calls } = loadPresets({ query: 'f=1&minsell=2' }, { local, elements: page.elements, search: '?f=1', confirm: () => true });
    page.elements.arbPresetSelect.value = two.id;
    page.listeners['select:change']();
    page.listeners['pin:click']();
    page.listeners['toggle:click']();
    page.elements.arbPresetName.value = 'Other';
    page.form.query = 'f=1&minsell=3';
    page.form.minsell.value = '3';
    page.listeners['save:click']();
    page.listeners['delete:click']();
    expect(presetCalls(calls).map((c) => c[1])).toEqual(['apply', 'pin', 'save_as', 'delete']);
});

test('a save over the selected preset is save, a new name is save_as', () => {
    const local = fakeStorage();
    const page = fakePage('f=1&minsell=2');
    const { calls } = loadPresets({ query: 'f=1&minsell=2' }, { local, elements: page.elements });
    page.listeners['toggle:click']();
    page.elements.arbPresetName.value = 'Two';
    page.listeners['save:click']();
    page.form.query = 'f=1&minsell=5';
    page.form.minsell.value = '5';
    page.listeners['toggle:click']();
    page.elements.arbPresetName.value = 'Two';
    page.listeners['save:click']();
    expect(page.elements.arbPresetNote.textContent).toBe('Updated Two');
    expect(presetCalls(calls).map((c) => c[1])).toEqual(['save_as', 'save']);
});

test('a pin that storage refuses counts nothing, nor a refused save or a cancelled rename', () => {
    const local = fakeStorage();
    loadPresets({}, { local }).P.store.save({ name: 'Two', q: 'f=1&minsell=2' });
    const page = fakePage('f=1&minsell=2');
    const { calls } = loadPresets({ query: 'f=1&minsell=2' }, { local, elements: page.elements, search: '?f=1', prompt: () => null });
    local.setItem = () => { throw new Error('quota'); };
    page.listeners['pin:click']();
    expect(page.elements.arbPresetNote.textContent).toBe('Could not pin: browser storage is unavailable');
    page.listeners['toggle:click']();
    page.elements.arbPresetName.value = 'Default';
    page.listeners['save:click']();
    page.listeners['rename:click']();
    expect(presetCalls(calls)).toEqual([]);
});

// store-picker.js and arbit-rows.js on a document that keeps its listeners.
function loadListeners(file, window) {
    const listeners = {};
    const document = { addEventListener: (ev, fn) => { (listeners[ev] = listeners[ev] || []).push(fn); } };
    new Function('window', 'document', read(file))(window, document);
    return (ev, target) => (listeners[ev] || []).forEach((fn) => fn({ target }));
}
const select = (pick, value) => ({ value, getAttribute: (k) => (k === 'data-pick' ? pick : null) });

test('the store picker reports the page it is on', () => {
    for (const [mode, value] of [['arbit', 'buying'], ['reverse', 'selling'], ['global', 'index']]) {
        const { BAN, calls } = fakeBAN();
        const fire = loadListeners('js/store-picker.js', { BAN, BAN_ARBIT: { mode } });
        fire('change', select('store', '/arbit?source=SCG'));
        expect(calls).toEqual([['ui.arbit.store_select', value, undefined]]);
    }
});

test('a mode outside the three, inherited names included, counts no store pick', () => {
    for (const mode of ['sleepers', 'constructor', 'toString', '__proto__', undefined]) {
        const { BAN, calls } = fakeBAN();
        const fire = loadListeners('js/store-picker.js', { BAN, BAN_ARBIT: { mode } });
        fire('change', select('store', '/arbit?source=SCG'));
        expect(calls).toEqual([]);
    }
});

test('the picker landing on a pinned store also counts pin_auto', () => {
    const { BAN, calls } = fakeBAN();
    const fire = loadListeners('js/store-picker.js', {
        BAN, BAN_ARBIT: { mode: 'arbit' }, ArbitPresets: { pinnedStore: (link) => link === '/arbit?source=CK' },
    });
    fire('change', select('store', '/arbit?source=CK'));
    fire('change', select('store', '/arbit?source=SCG'));
    expect(calls).toEqual([
        ['ui.arbit.store_select', 'buying', undefined], ['ui.arbit.pin_auto', undefined, undefined],
        ['ui.arbit.store_select', 'buying', undefined],
    ]);
});

test('the picker with the active store (empty value) counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    const fire = loadListeners('js/store-picker.js', { BAN, BAN_ARBIT: { mode: 'arbit' } });
    fire('change', select('store', ''));
    fire('change', select(null, 'x'));
    expect(calls).toEqual([]);
});

test('jump counts with no value', () => {
    const { BAN, calls } = fakeBAN();
    const fire = loadListeners('js/store-picker.js', { BAN, BAN_ARBIT: { mode: 'arbit' } });
    fire('change', select('jump', 'Store'));
    expect(calls).toEqual([['ui.arbit.jump', undefined, undefined]]);
});

// An element of an arbit section: its classes, and the section and thead it sits in.
function inSection(classes, { store = 'CK', section = true, thead = false, type = '' } = {}) {
    const sec = { getAttribute: (k) => (k === 'data-store' ? store : null) };
    const el = {
        type,
        classList: { contains: (c) => classes.includes(c) },
        closest: (sel) => {
            if (sel === '.arb-section') return section ? sec : null;
            if (sel === '.arb-section thead') return section && thead ? {} : null;
            return classes.includes(sel.slice(1)) ? el : null;
        },
    };
    return el;
}

test('a row link is told apart by its classes and carries the section store', () => {
    const { BAN, calls } = fakeBAN();
    const fire = loadListeners('js/arbit-rows.js', { BAN });
    fire('click', inSection(['arb-qlink', 'buy']));
    fire('click', inSection(['arb-qlink', 'sell']));
    fire('click', inSection(['arb-qlink', 'buy', 'ref'], { store: 'SCG' }));
    fire('click', inSection(['arb-qlink', 'buy'], { store: 'a b' }));
    expect(calls).toEqual([
        ['ui.arbit.quick_link', 'buy', 'CK'], ['ui.arbit.quick_link', 'sell', 'CK'],
        ['ui.arbit.quick_link', 'buy_reference', 'SCG'], ['ui.arbit.quick_link', 'buy', 'other'],
    ]);
});

test('a section store takes every shorthand the server accepts, and nothing else', () => {
    const { BAN, calls } = fakeBAN();
    const fire = loadListeners('js/arbit-rows.js', { BAN });
    for (const store of ['TCG+SI', 'A.B', 'x-y', 'a,b', 'a b', '<b>', '']) fire('click', inSection(['arb-qlink', 'buy'], { store }));
    expect(calls.map((c) => c[2])).toEqual(['TCG+SI', 'A.B', 'x-y', 'a,b', 'other', 'other', 'other']);
});

test('a row link outside any section counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    const fire = loadListeners('js/arbit-rows.js', { BAN });
    fire('click', inSection(['arb-qlink', 'buy'], { section: false }));
    expect(calls).toEqual([]);
});

test('a row box is check; the header box is check_all', () => {
    const { BAN, calls } = fakeBAN();
    const fire = loadListeners('js/arbit-rows.js', { BAN });
    fire('change', inSection(['arb-row-check'], { type: 'checkbox' }));
    fire('change', inSection([], { type: 'checkbox', thead: true }));
    fire('change', inSection([], { type: 'checkbox' }));
    expect(calls).toEqual([['ui.arbit.row', 'check', undefined], ['ui.arbit.row', 'check_all', undefined]]);
});

test('the contents link counts with no value', () => {
    const { BAN, calls } = fakeBAN();
    const fire = loadListeners('js/arbit-rows.js', { BAN });
    fire('click', inSection(['arb-contents']));
    fire('click', inSection(['emoji']));
    expect(calls).toEqual([['ui.arbit.contents', undefined, undefined]]);
});

// arbit-filters.js, as tests/arbit-filters.test.js loads it.
const filtersSource = read('js/arbit-filters.js');
function loadFilters(ban = true) {
    const f = fakeBAN();
    const listeners = {};
    const on = (name) => (ev, fn) => { listeners[name + ':' + ev] = fn; };
    const panel = { hidden: true };
    const toggle = { addEventListener: on('toggle'), setAttribute() {} };
    const form = { addEventListener: on('form'), querySelectorAll: () => [] };
    const window = { BAN_ARBIT: { source: 'CK', query: 'f=1', cookie: 'ArbitFilters' }, location: { href: '', search: '?f=1', reload() {} }, addEventListener() {} };
    if (ban) window.BAN = f.BAN;
    const elements = { arbFilterToggle: toggle, arbFilterPanel: panel, arbFilters: form };
    class FormData { [Symbol.iterator]() { return [][Symbol.iterator](); } }
    new Function('window', 'document', 'writeCookie', 'getCookie', 'FormData', 'localStorage', 'sessionStorage', filtersSource)(
        window, { getElementById: (id) => elements[id] || null }, () => {}, () => '', FormData, fakeStorage(), fakeStorage());
    return { window, listeners, panel, calls: f.calls };
}

test('the filter toggle reports the state it moves to', () => {
    const t = loadFilters();
    t.listeners['toggle:click']();
    expect(t.panel.hidden).toBe(false);
    t.listeners['toggle:click']();
    expect(t.panel.hidden).toBe(true);
    expect(t.calls).toEqual([['ui.arbit.filters', 'open', undefined], ['ui.arbit.filters', 'close', undefined]]);
});

test('a filter submit counts apply', () => {
    const t = loadFilters();
    t.listeners['form:submit']();
    expect(t.calls).toEqual([['ui.arbit.filters', 'apply', undefined]]);
});

test('sortBy counts its key before it navigates', () => {
    const t = loadFilters();
    t.window.sortBy('spread', 'Store');
    expect(t.window.location.href).toContain('sort=spread');
    t.window.sortBy('ratio', 'Store');
    expect(t.calls).toEqual([['ui.arbit.sort', 'spread', undefined]]);
});

// filtering.js over one table and the edition box.
function loadFiltering(window) {
    const input = { value: '' };
    const document = { getElementById: () => input, getElementsByClassName: () => [] };
    const fns = new Function('window', 'document', read('js/filtering.js') + '\nreturn {filterTableByEdition};')(window, document);
    return { input, filter: fns.filterTableByEdition };
}

test('the edition filter counts once however much is typed', () => {
    const { BAN, calls } = fakeBAN();
    const p = loadFiltering({ BAN });
    p.filter();
    expect(calls).toEqual([]);
    for (const v of ['m', 'mo', 'mod']) { p.input.value = v; p.filter(); }
    expect(calls).toEqual([['ui.arbit.edition_filter', 'used', undefined]]);
});

test('with no window.BAN every one of these still runs', () => {
    expect(() => loadPresets({ query: 'f=1&minsell=2' }, { search: '?source=CK', ban: false })).not.toThrow();
    const picker = loadListeners('js/store-picker.js', { BAN_ARBIT: { mode: 'arbit' } });
    expect(() => { picker('change', select('store', '/arbit?source=SCG')); picker('change', select('jump', 'x')); }).not.toThrow();
    const rows = loadListeners('js/arbit-rows.js', {});
    expect(() => { rows('click', inSection(['arb-qlink', 'buy'])); rows('change', inSection(['arb-row-check'])); }).not.toThrow();
    const t = loadFilters(false);
    t.listeners['toggle:click']();
    expect(t.panel.hidden).toBe(false);
    const p = loadFiltering({});
    p.input.value = 'x';
    expect(() => p.filter()).not.toThrow();
});
