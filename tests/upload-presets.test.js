import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-presets.js', import.meta.url), 'utf8');

export function loadPresets({ cookies = {}, storage = null, document = null, win = {} } = {}) {
    const window = Object.assign({}, win);
    const getCookie = (n) => (n in cookies ? cookies[n] : null);
    const written = [];
    const setCookie = (n, v, d) => { written.push([n, v, d]); cookies[n] = v; };
    const localStorage = storage || fakeStorage();
    const sessionStorage = fakeStorage();
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'getCookie', 'setCookie', source)(
        window, document, localStorage, sessionStorage, getCookie, setCookie);
    return { P: window.UploadPresets, written, cookies, localStorage, window };
}

export function fakeStorage(initial = {}) {
    const m = Object.assign({}, initial);
    return {
        getItem: (k) => (k in m ? m[k] : null),
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
        _map: m,
    };
}

function fakeDoc({ mode = 'false', tab = 'singles', canChange = true, canBuylist = true, boxes } = {}) {
    const grid = (names, checked) => names.map(v => ({ type: 'checkbox', name: null, value: v, checked: checked.indexOf(v) >= 0, disabled: !canChange }));
    boxes = boxes || {
        singlesBox: grid(['CK', 'SCG', 'CSI'], ['SCG']),
        sealedBox: grid(['CK'], []),
        singlesIndexRow: grid(['TCGLow', 'TCGMarket'], ['TCGLow']),
        sealedIndexRow: grid(['TCGSealed'], []),
    };
    boxes.singlesBox.forEach(b => b.name = 'stores'); boxes.sealedBox.forEach(b => b.name = 'sealed_stores');
    boxes.singlesIndexRow.forEach(b => b.name = 'index_stores'); boxes.sealedIndexRow.forEach(b => b.name = 'sealed_index_stores');
    const radios = [{ type: 'radio', name: 'mode', value: 'false', checked: mode === 'false' }, { type: 'radio', name: 'mode', value: 'true', checked: mode === 'true', disabled: !canBuylist }];
    const st = { tab };
    const tabs = { 'tab-singles': { classList: { contains: (c) => c === 'active' && st.tab === 'singles' } }, 'tab-sealed': { classList: { contains: (c) => c === 'active' && st.tab === 'sealed' } } };
    const form = Object.assign(fakeEl(), {
        dataset: { canChangeStores: String(canChange) },
        querySelectorAll: (sel) => sel.indexOf('mode') >= 0 ? radios : [],
    });
    const byId = Object.assign({ upload_form: form }, tabs);
    Object.keys(boxes).forEach(id => { byId[id] = { querySelectorAll: (sel) => sel.indexOf('checkbox') >= 0 ? boxes[id] : [] }; });
    return { getElementById: (id) => byId[id] || null, _boxes: boxes, _radios: radios, _byId: byId, _st: st };
}

// fakeEl records listeners so a test can fire them and count them.
function fakeEl(props = {}) {
    const on = {};
    return Object.assign({
        hidden: false, disabled: false, textContent: '', value: '',
        addEventListener: (t, f) => { (on[t] = on[t] || []).push(f); },
        _fire: (t, e) => (on[t] || []).forEach(f => f(e || {})),
        _count: (t) => (on[t] || []).length,
        setAttribute() {}, focus() {},
    }, props);
}

// fakeSelect keeps options like a <select>: no selected option means the first.
function fakeSelect() {
    const s = fakeEl();
    s.options = [];
    s._rebuilds = 0;
    Object.defineProperty(s, 'innerHTML', { set() { s.options = []; s._rebuilds++; } });
    Object.defineProperty(s, 'value', {
        get() { const o = s.options.filter(x => x.selected).pop() || s.options[0]; return o ? o.value : ''; },
        set(v) { s.options.forEach(o => { o.selected = o.value === v; }); },
    });
    s.appendChild = (o) => { s.options.push(o); };
    s._text = () => { const v = s.value; const o = s.options.find(x => x.value === v); return o ? o.textContent : ''; };
    return s;
}

// mountDoc is fakeDoc plus the preset row, with selectTab firing the form's
// change listeners the way upload-form.js's dispatchFormChange does.
function mountDoc(opts = {}) {
    const doc = fakeDoc(opts);
    const form = doc._byId.upload_form;
    Object.assign(doc._byId, {
        'preset-select': fakeSelect(), 'preset-note': fakeEl(), 'preset-name': fakeEl(),
        'preset-save-row': fakeEl({ hidden: true }), 'preset-save': fakeEl(), 'preset-rename': fakeEl(),
        'preset-delete': fakeEl(), 'preset-save-toggle': fakeEl(), 'preset-cancel': fakeEl(),
    });
    doc.createElement = () => ({ value: '', textContent: '', selected: false });
    const win = {
        reloadSelect() {},
        selectTab: (t) => { doc._st.tab = t; form._fire('change', { target: form }); },
    };
    return { doc, win, select: doc._byId['preset-select'], note: doc._byId['preset-note'], form };
}

const OFFERED = { stores: ['CK', 'SCG', 'CSI'], sealed_stores: ['CK'], index_stores: ['TCGLow', 'TCGMarket'], sealed_index_stores: ['TCGSealed'] };
const CTX = { canChangeStores: true, offered: OFFERED };
const STATE = { mode: 'false', tab: 'singles', stores: ['SCG', 'CK'], sealed_stores: [], index_stores: ['TCGLow'], sealed_index_stores: [] };

test('fromState fills every settings default when no cookie is set', () => {
    const { P } = loadPresets();
    const o = P.fromState(STATE, () => null, CTX);
    expect(o.percspread).toBe('60');
    expect(o.margin).toBe('10');
    expect(o.lowval).toBe('true');
    expect(o.customperc).toBe('true');
    expect(o.highval).toBeUndefined();
    expect(o.custombuylist).toBeUndefined();
    expect(o.stores).toEqual(['CK', 'SCG']);
    expect(Object.keys(o)).toEqual(Object.keys(o).slice().sort());
});

test('fromState reads cookies and the custom buylist block', () => {
    const cookies = { UploadOptimizerOpts: 'highval,noresults,', UploadPercSpread: '075', UploadCustomOpts: 'enabled,', UploadCustomRate: '0.9' };
    const { P } = loadPresets({ cookies });
    const o = P.fromState(STATE, (n) => cookies[n] ?? null, CTX);
    expect(o.highval).toBe('true');
    expect(o.lowval).toBeUndefined();
    expect(o.percspread).toBe('75');
    expect(o.custombuylist).toBe('true');
    expect(o.customrate).toBe('0.9');
    expect(o.customseller).toBe('TCGLow');
});

test('canonical normalises numbers, sorts and dedupes stores, drops unknown stores', () => {
    const { P } = loadPresets();
    const a = P.canonical({ percspread: '60.0', stores: ['SCG', 'CK', 'CK', 'NOPE'], mode: 'false' }, CTX);
    expect(a.percspread).toBe('60');
    expect(a.stores).toEqual(['CK', 'SCG']);
});

test('equal ignores key order and treats a mode difference as different', () => {
    const { P } = loadPresets();
    const a = P.fromState(STATE, () => null, CTX);
    const b = P.fromState(Object.assign({}, STATE, { stores: ['CK', 'SCG'] }), () => null, CTX);
    const c = P.fromState(Object.assign({}, STATE, { mode: 'true' }), () => null, CTX);
    expect(P.equal(a, b)).toBe(true);
    expect(P.equal(a, c)).toBe(false);
});

test('findMatch returns the preset with equal opts or null', () => {
    const { P } = loadPresets();
    const a = P.fromState(STATE, () => null, CTX);
    const presets = [{ id: 'p1', name: 'x', opts: P.fromState(Object.assign({}, STATE, { mode: 'true' }), () => null, CTX) },
                     { id: 'p2', name: 'y', opts: a }];
    expect(P.findMatch(a, presets).id).toBe('p2');
    expect(P.findMatch(Object.assign({}, a, { margin: '11' }), presets)).toBeNull();
});

test('a user who cannot change stores gets no store lists', () => {
    const { P } = loadPresets();
    const o = P.fromState(STATE, () => null, { canChangeStores: false, offered: OFFERED });
    expect(o.stores).toBeUndefined();
    expect(o.index_stores).toBeUndefined();
    expect(o.mode).toBe('false');
});

test('store round-trips, sorts by name case-insensitive and keeps ids on rename', () => {
    const { P, localStorage } = loadPresets();
    const r1 = P.store.save({ name: 'Banana', opts: { mode: 'false' } });
    const r2 = P.store.save({ name: 'apple', opts: { mode: 'true' } });
    const r3 = P.store.save({ name: 'cherry', opts: { mode: 'true' } });
    expect(r1.ok && r2.ok && r3.ok).toBe(true);
    expect(P.store.list().map(p => p.name)).toEqual(['apple', 'Banana', 'cherry']);
    expect(P.store.rename(r1.preset.id, 'beta')).toBe(true);
    expect(P.store.list().map(p => p.name)).toEqual(['apple', 'beta', 'cherry']);
    expect(JSON.parse(localStorage.getItem('mtgban_upload_presets')).length).toBe(3);
    expect(P.store.remove(r2.preset.id)).toBe(true);
    expect(P.store.list().length).toBe(2);
});

test('save with an existing id replaces opts and savedAt and keeps the id', () => {
    const { P } = loadPresets();
    const r = P.store.save({ name: 'a', opts: { mode: 'false' } });
    const again = P.store.save({ id: r.preset.id, name: 'a', opts: { mode: 'true' } });
    expect(again.preset.id).toBe(r.preset.id);
    expect(P.store.list()[0].opts.mode).toBe('true');
});

test('the 11th preset is refused and nothing is evicted', () => {
    const { P } = loadPresets();
    for (let i = 0; i < 10; i++) expect(P.store.save({ name: 'p' + i, opts: { margin: String(i) } }).ok).toBe(true);
    const r = P.store.save({ name: 'p10', opts: { margin: '10' } });
    expect(r).toEqual({ ok: false, reason: 'cap' });
    expect(P.store.list().length).toBe(10);
});

test('corrupt storage reads as empty and is overwritten on save', () => {
    const { P, localStorage } = loadPresets({ storage: fakeStorage({ mtgban_upload_presets: '{not json' }) });
    expect(P.store.list()).toEqual([]);
    expect(P.store.save({ name: 'a', opts: {} }).ok).toBe(true);
    expect(JSON.parse(localStorage.getItem('mtgban_upload_presets')).length).toBe(1);
});

test('a storage that throws on write keeps nothing, like list-storage.js', () => {
    const s = fakeStorage({ mtgban_upload_presets: JSON.stringify([{ id: 'p_old', name: 'old', opts: {} }]) });
    s.setItem = () => { throw new Error('quota'); };
    const { P } = loadPresets({ storage: s });
    expect(P.store.save({ name: 'a', opts: {} })).toEqual({ ok: false, reason: 'storage' });
    expect(P.store.list().map(p => p.name)).toEqual(['old']);
    expect(P.store.rename('p_old', 'new')).toBe(false);
    expect(P.store.remove('p_old')).toBe(false);
    expect(P.store.list().map(p => p.name)).toEqual(['old']);
});

test('a preset the browser could not store is not listed after "Could not save"', () => {
    const { doc, win, select, note, form } = mountDoc();
    const s = fakeStorage();
    s.setItem = () => { throw new Error('quota'); };
    const { P } = loadPresets({ win, storage: s });
    P.mount(doc);
    doc._byId['preset-name'].value = 'Mine';
    doc._byId['preset-save']._fire('click');
    expect(note.textContent).toBe('Could not save: browser storage is unavailable');
    form._fire('change', { target: form });
    expect(select.options.map(o => o.textContent)).toEqual(['No presets yet']);
});

test('readState reads mode, tab and the four store lists from the page', () => {
    const { P } = loadPresets();
    const s = P.readState(fakeDoc({ mode: 'true', tab: 'sealed' }));
    expect(s).toEqual({ mode: 'true', tab: 'sealed', stores: ['SCG'], sealed_stores: [], index_stores: ['TCGLow'], sealed_index_stores: [] });
});

test('persistStores writes the cookies the handler reads, joined with a bar', () => {
    const { P, written } = loadPresets();
    const doc = fakeDoc({ mode: 'false' });
    doc._boxes.singlesBox[0].checked = true; // CK and SCG
    const out = P.persistStores(doc);
    expect(out.enabledSellers).toBe('CK|SCG');
    expect(out.enabledIndexes).toBe('TCGLow');
    expect(written.find(w => w[0] === 'enabledSellers')[2]).toBe(3650);
    expect(out.enabledVendors).toBeUndefined();
});

test('persistStores writes the vendor cookies in buylist mode', () => {
    const { P } = loadPresets();
    const out = P.persistStores(fakeDoc({ mode: 'true' }));
    expect(out.enabledVendors).toBe('SCG');
    expect(out.enabledSealedVendors).toBe('');
});

test('apply writes the settings cookies, sets mode and tab, ticks stores and reports unknown ones', () => {
    const doc = fakeDoc({ mode: 'false', tab: 'singles' });
    const calls = [];
    const resetGrid = (list) => list.map(b => ({ type: 'checkbox', name: b.name, value: b.value, checked: false, disabled: b.disabled }));
    const win = {
        reloadSelect: (m) => {
            calls.push(['mode', m]);
            doc._boxes.singlesBox = resetGrid(doc._boxes.singlesBox);
            doc._boxes.sealedBox = resetGrid(doc._boxes.sealedBox);
        },
        selectTab: (t) => calls.push(['tab', t]),
    };
    const { P, cookies } = loadPresets({ win });
    const preset = { id: 'p', name: 'n', opts: P.canonical({ mode: 'true', tab: 'sealed', highval: 'true', percspread: '75', custombuylist: 'true', customrate: '0.9', stores: ['CK', 'GONE'], sealed_stores: ['CK'], index_stores: [], sealed_index_stores: [] }) };
    const res = P.apply(preset, doc);
    expect(cookies.UploadOptimizerOpts).toBe('highval,');
    expect(cookies.UploadPercSpread).toBe('75');
    expect(cookies.UploadCustomOpts).toBe('enabled,');
    expect(cookies.UploadCustomRate).toBe('0.9');
    expect(calls).toEqual([['mode', 'buylist'], ['tab', 'sealed']]);
    expect(doc._radios[1].checked).toBe(true);
    expect(doc._boxes.singlesBox.map(b => b.checked)).toEqual([true, false, false]);
    expect(doc._boxes.sealedBox[0].checked).toBe(true);
    expect(res.unavailableStores).toEqual(['GONE']);
    expect(cookies.enabledVendors).toBe('CK');
});

test('apply treats the mode as retail when the buylist radio is disabled, and leaves stores alone', () => {
    const doc = fakeDoc({ mode: 'false', tab: 'singles', canBuylist: false });
    const calls = [];
    const win = { reloadSelect: (m) => calls.push(['mode', m]), selectTab: (t) => calls.push(['tab', t]) };
    const { P, cookies } = loadPresets({ win });
    const preset = { id: 'p', name: 'n', opts: P.canonical({ mode: 'true', tab: 'singles', stores: ['CK'] }) };
    P.apply(preset, doc);
    expect(doc._radios[0].checked).toBe(true);
    expect(doc._radios[1].checked).toBe(false);
    expect(calls[0]).toEqual(['mode', 'retail']);
    // The preset's vendor-flavored pick does not apply under a forced retail
    // fallback: the seller grid is untouched (still its original SCG tick)
    // and nothing overwrites enabledSellers/enabledVendors.
    expect(doc._boxes.singlesBox.map(b => b.checked)).toEqual([false, true, false]);
    expect(cookies.enabledSellers).toBeUndefined();
    expect(cookies.enabledVendors).toBeUndefined();
});

test('decideSave picks empty, duplicate, update or create in that order', () => {
    const { P } = loadPresets();
    const a = { id: 'a', name: 'Alpha', opts: P.canonical({ mode: 'false', margin: '10' }) };
    const b = { id: 'b', name: 'Beta', opts: P.canonical({ mode: 'true', margin: '10' }) };
    const presets = [a, b];
    expect(P.decideSave({ name: '  ', current: a.opts, presets })).toEqual({ action: 'empty' });
    expect(P.decideSave({ name: 'New', current: a.opts, presets })).toEqual({ action: 'duplicate', preset: a });
    expect(P.decideSave({ name: 'alpha', current: P.canonical({ mode: 'false', margin: '12' }), presets })).toEqual({ action: 'update', preset: a });
    expect(P.decideSave({ name: 'Gamma', current: P.canonical({ mode: 'false', margin: '12' }), presets })).toEqual({ action: 'create' });
    // Re-saving a preset under its own name with its own opts is an update, not a duplicate.
    expect(P.decideSave({ name: 'Alpha', current: a.opts, presets })).toEqual({ action: 'update', preset: a });
});

test('apply skips store lists for a user who cannot change stores', () => {
    const { P, cookies } = loadPresets({ win: { reloadSelect() {}, selectTab() {} } });
    const doc = fakeDoc({ canChange: false });
    const res = P.apply({ id: 'p', name: 'n', opts: P.canonical({ mode: 'false', tab: 'singles', stores: ['CK'] }) }, doc);
    expect(doc._boxes.singlesBox[0].checked).toBe(false);
    expect(cookies.enabledSellers).toBeUndefined();
    expect(res.storesSkipped).toBe(true);

    const doc2 = fakeDoc({ canChange: false });
    const res2 = P.apply({ id: 'p', name: 'n', opts: P.canonical({ mode: 'false', tab: 'singles' }) }, doc2);
    expect(res2.storesSkipped).toBe(false);
});

// Picks a preset in the dropdown the way a reader does.
function pick(select, id) { select.value = id; select._fire('change'); }

test('apply with a missing store shows the chosen preset unmodified until a real tick', () => {
    const { doc, win, select, note, form } = mountDoc();
    const { P } = loadPresets({ win });
    const cur = P.current(doc); // SCG ticked
    const b = P.store.save({ name: 'B', opts: cur }).preset;
    const a = P.store.save({ name: 'A', opts: Object.assign({}, cur, { stores: ['CK', 'GONE'] }) }).preset;
    P.mount(doc);
    expect(select.value).toBe(b.id);
    pick(select, a.id);
    expect(doc._boxes.singlesBox.map(x => x.checked)).toEqual([true, false, false]);
    expect(note.textContent).toBe('1 store unavailable on this page');
    expect(select.value).toBe(a.id);
    expect(select._text()).toBe('A');
    expect(select.options.find(o => o.value === b.id).textContent).toBe('B');
    doc._boxes.singlesBox[2].checked = true; // CSI
    form._fire('change', { target: form });
    expect(select._text()).toBe('A (modified)');
    doc._boxes.singlesBox[2].checked = false;
    form._fire('change', { target: form });
    expect(select._text()).toBe('A');
});

test('apply keeps the chosen preset selected and unmodified when the buylist radio is disabled', () => {
    const { doc, win, select } = mountDoc({ canBuylist: false });
    const { P } = loadPresets({ win });
    const cur = P.current(doc); // retail, SCG, TCGLow
    const b = P.store.save({ name: 'B', opts: cur }).preset;
    const a = P.store.save({ name: 'A', opts: Object.assign({}, cur, { mode: 'true', stores: ['CK'], index_stores: ['TCGMarket'] }) }).preset;
    P.mount(doc);
    expect(select.value).toBe(b.id);
    pick(select, a.id);
    expect(doc._radios[0].checked).toBe(true);
    expect(doc._boxes.singlesIndexRow.map(x => x.checked)).toEqual([false, true]);
    expect(select.value).toBe(a.id);
    expect(select._text()).toBe('A');
});

test('apply selects the chosen preset when it matches the page exactly', () => {
    const { doc, win, select } = mountDoc();
    const { P } = loadPresets({ win });
    const cur = P.current(doc);
    const b = P.store.save({ name: 'B', opts: cur }).preset;
    const a = P.store.save({ name: 'A', opts: Object.assign({}, cur, { stores: ['CK'] }) }).preset;
    P.mount(doc);
    pick(select, a.id);
    expect(select.value).toBe(a.id);
    expect(select._text()).toBe('A');
    pick(select, b.id);
    expect(select._text()).toBe('B');
});

test('refresh shows presets synced into storage without rebinding the form', () => {
    const { doc, win, select, form } = mountDoc();
    const { P, localStorage } = loadPresets({ win });
    P.mount(doc);
    expect(select._text()).toBe('No presets yet');
    const counts = () => [form._count('change'), form._count('input'), select._count('change')];
    const before = counts();
    const synced = [{ id: 'p_sync', name: 'Synced', savedAt: 1, opts: P.current(doc) }];
    localStorage.setItem('mtgban_upload_presets', JSON.stringify(synced));
    expect(select.options.length).toBe(1);
    P.refresh();
    expect(select.options.map(o => o.textContent)).toEqual(['Presets', 'Synced']);
    expect(select.value).toBe('p_sync');
    expect(counts()).toEqual(before);
});

test('refresh before mount does nothing', () => {
    const { P } = loadPresets();
    expect(() => P.refresh()).not.toThrow();
});

test('a delete the browser could not store says so and keeps the preset', () => {
    const { doc, win, select, note } = mountDoc();
    const s = fakeStorage();
    const { P } = loadPresets({ win, storage: s });
    const p = P.store.save({ name: 'Kept', opts: P.current(doc) }).preset;
    P.mount(doc);
    expect(select.value).toBe(p.id);
    s.setItem = () => { throw new Error('quota'); };
    doc._byId['preset-delete']._fire('click');
    expect(note.textContent).toBe('Could not delete: browser storage is unavailable');
    expect(select.options.map(o => o.textContent)).toEqual(['Presets', 'Kept']);
});

// Saves under name the way the save row does; an existing name updates.
function saveAs(doc, name) {
    doc._byId['preset-name'].value = name;
    doc._byId['preset-save']._fire('click');
}
const stored = (P, id) => P.store.list().find(p => p.id === id).opts;

test('update keeps a store the page does not offer and drops one the reader unticked', () => {
    const { doc, win, select } = mountDoc();
    const { P } = loadPresets({ win });
    const a = P.store.save({ name: 'A', opts: Object.assign({}, P.current(doc), { stores: ['CK', 'GONE', 'SCG'] }) }).preset;
    P.mount(doc);
    pick(select, a.id);
    doc._boxes.singlesBox[1].checked = false; // SCG
    doc._boxes.singlesBox[2].checked = true; // CSI
    saveAs(doc, 'A');
    expect(doc._byId['preset-note'].textContent).toBe('Updated A');
    expect(stored(P, a.id).stores).toEqual(['CK', 'CSI', 'GONE']);
});

test('update keeps every store list when the tier cannot change stores', () => {
    const { doc, win, select } = mountDoc({ canChange: false });
    const { P, cookies } = loadPresets({ win });
    const lists = { stores: ['CK'], sealed_stores: ['CK'], index_stores: ['TCGMarket'], sealed_index_stores: ['TCGSealed'] };
    const a = P.store.save({ name: 'A', opts: Object.assign({}, P.current(doc), lists) }).preset;
    P.mount(doc);
    pick(select, a.id);
    cookies.UploadMargin = '12';
    saveAs(doc, 'A');
    const o = stored(P, a.id);
    expect(o.margin).toBe('12');
    expect([o.stores, o.sealed_stores, o.index_stores, o.sealed_index_stores]).toEqual([['CK'], ['CK'], ['TCGMarket'], ['TCGSealed']]);
});

test('update keeps a buylist preset buylist when the buylist radio is disabled', () => {
    const { doc, win, select } = mountDoc({ canBuylist: false });
    const { P, cookies } = loadPresets({ win });
    const a = P.store.save({ name: 'A', opts: Object.assign({}, P.current(doc), { mode: 'true', stores: ['CK'], sealed_stores: ['CK'], index_stores: ['TCGMarket'] }) }).preset;
    P.mount(doc);
    pick(select, a.id);
    cookies.UploadMargin = '12';
    saveAs(doc, 'A');
    const o = stored(P, a.id);
    expect(o.margin).toBe('12');
    expect(o.mode).toBe('true');
    expect(o.stores).toEqual(['CK']);
    expect(o.sealed_stores).toEqual(['CK']);
    expect(o.index_stores).toEqual(['TCGMarket']);
});

test('rename and remove say missing for an id that is gone', () => {
    const { P } = loadPresets();
    expect(P.store.rename('p_gone', 'x')).toBe('missing');
    expect(P.store.remove('p_gone')).toBe('missing');
});

// A preset another tab deletes while a prompt or confirm is open.
function vanishing(dialog) {
    const s = fakeStorage();
    const { doc, win, select, note } = mountDoc();
    win[dialog] = () => { s.setItem('mtgban_upload_presets', '[]'); return 'Renamed'; };
    const { P } = loadPresets({ win, storage: s });
    P.store.save({ name: 'Gone', opts: P.current(doc) });
    P.mount(doc);
    return { doc, select, note };
}

test('renaming a preset another tab deleted says it no longer exists', () => {
    const { doc, select, note } = vanishing('prompt');
    doc._byId['preset-rename']._fire('click');
    expect(note.textContent).toBe('That preset no longer exists');
    expect(select.options.map(o => o.textContent)).toEqual(['No presets yet']);
});

test('deleting a preset another tab deleted says it no longer exists', () => {
    const { doc, select, note } = vanishing('confirm');
    doc._byId['preset-delete']._fire('click');
    expect(note.textContent).toBe('That preset no longer exists');
    expect(select.options.map(o => o.textContent)).toEqual(['No presets yet']);
});

test('refresh leaves the options alone when nothing changed, so an open dropdown stays open', () => {
    const { doc, win, select, form } = mountDoc();
    const { P, localStorage } = loadPresets({ win });
    P.store.save({ name: 'A', opts: P.current(doc) });
    P.mount(doc);
    const n = select._rebuilds;
    P.refresh();
    form._fire('change', { target: form });
    expect(select._rebuilds).toBe(n);
    const list = JSON.parse(localStorage.getItem('mtgban_upload_presets'));
    list.push({ id: 'p_b', name: 'B', opts: Object.assign({}, list[0].opts, { margin: '99' }) });
    localStorage.setItem('mtgban_upload_presets', JSON.stringify(list));
    P.refresh();
    expect(select._rebuilds).toBe(n + 1);
    expect(select.options.map(o => o.textContent)).toEqual(['Presets', 'A', 'B']);
});

test('the dropdown follows the match even when the option list is unchanged', () => {
    const { doc, win, select } = mountDoc();
    const { P } = loadPresets({ win });
    const b = P.store.save({ name: 'B', opts: P.current(doc) }).preset;
    P.mount(doc);
    pick(select, ''); // the placeholder; the form still matches B
    expect(select.value).toBe(b.id);
    expect(select._text()).toBe('B');
});

test('a preset with store lists matches unmodified on a page that cannot change stores', () => {
    const { doc, win, select, form } = mountDoc({ canChange: false });
    const { P, cookies } = loadPresets({ win });
    const lists = { stores: ['CK'], sealed_stores: ['CK'], index_stores: ['TCGMarket'], sealed_index_stores: [] };
    const a = P.store.save({ name: 'A', opts: Object.assign({}, P.current(doc), lists, { margin: '12' }) }).preset;
    P.mount(doc);
    expect(select._text()).toBe('Presets');
    pick(select, a.id);
    expect(select._text()).toBe('A');
    cookies.UploadMargin = '13';
    form._fire('change', { target: form });
    expect(select._text()).toBe('A (modified)');
});

test('picking one of two presets that differ only in what the page cannot show keeps the pick', () => {
    const { doc, win, select } = mountDoc();
    const { P } = loadPresets({ win });
    const cur = P.current(doc);
    const a = P.store.save({ name: 'A', opts: Object.assign({}, cur, { stores: ['CK'] }) }).preset;
    const b = P.store.save({ name: 'B', opts: Object.assign({}, cur, { stores: ['CK', 'GONE'] }) }).preset;
    P.mount(doc);
    pick(select, b.id);
    expect(select.value).toBe(b.id);
    expect(select._text()).toBe('B');
    pick(select, a.id);
    expect(select._text()).toBe('A');
});

test('update after a mode switch does not carry the other mode\'s stores', () => {
    const { doc, win, select } = mountDoc();
    const { P } = loadPresets({ win });
    const a = P.store.save({ name: 'A', opts: Object.assign({}, P.current(doc), { stores: ['CSI', 'SCG'] }) }).preset;
    P.mount(doc);
    pick(select, a.id);
    // Switching to Buylist swaps the singles grid to the vendors, as reloadSelect does.
    doc._radios[0].checked = false;
    doc._radios[1].checked = true;
    doc._boxes.singlesBox = ['CK', 'ABU'].map(v => ({ type: 'checkbox', name: 'stores', value: v, checked: v === 'CK' }));
    saveAs(doc, 'A');
    const o = stored(P, a.id);
    expect(o.mode).toBe('true');
    expect(o.stores).toEqual(['CK']);
});

test('a new retail preset saves under forced retail next to a buylist preset', () => {
    const { doc, win, note } = mountDoc({ canBuylist: false });
    const { P } = loadPresets({ win });
    P.store.save({ name: 'BP', opts: Object.assign({}, P.current(doc), { mode: 'true', stores: ['CK'] }) });
    P.mount(doc);
    doc._boxes.singlesBox[2].checked = true; // CSI
    saveAs(doc, 'My retail');
    expect(note.textContent).toBe('Saved My retail');
    expect(P.store.list().map(p => p.name)).toEqual(['BP', 'My retail']);
});

test('a new preset with stores saves next to a preset without store lists', () => {
    const { doc, win, note } = mountDoc();
    const { P } = loadPresets({ win });
    const bare = P.current(doc);
    P.STORE_LISTS.forEach(k => { delete bare[k]; });
    P.store.save({ name: 'X', opts: bare });
    P.mount(doc);
    doc._boxes.singlesBox[0].checked = true; // CK
    saveAs(doc, 'CK too');
    expect(note.textContent).toBe('Saved CK too');
    expect(P.store.list().map(p => p.name)).toEqual(['CK too', 'X']);
});
