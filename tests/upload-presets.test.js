import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-presets.js', import.meta.url), 'utf8');

export function loadPresets({ cookies = {}, storage = null, document = null, win = {} } = {}) {
    const window = Object.assign({}, win);
    const getCookie = (n) => (n in cookies ? cookies[n] : null);
    const written = [];
    const setCookie = (n, v, d) => { written.push([n, v, d]); cookies[n] = v; };
    const localStorage = storage || fakeStorage();
    new Function('window', 'document', 'localStorage', 'getCookie', 'setCookie', source)(
        window, document, localStorage, getCookie, setCookie);
    return { P: window.UploadPresets, written, cookies, localStorage };
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
    const tabs = { 'tab-singles': { classList: { contains: (c) => c === 'active' && tab === 'singles' } }, 'tab-sealed': { classList: { contains: (c) => c === 'active' && tab === 'sealed' } } };
    const form = {
        dataset: { canChangeStores: String(canChange) },
        querySelectorAll: (sel) => sel.indexOf('mode') >= 0 ? radios : [],
    };
    const byId = Object.assign({ upload_form: form }, tabs);
    Object.keys(boxes).forEach(id => { byId[id] = { querySelectorAll: (sel) => sel.indexOf('checkbox') >= 0 ? boxes[id] : [] }; });
    return { getElementById: (id) => byId[id] || null, _boxes: boxes, _radios: radios };
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

test('a storage that throws on write keeps presets in memory for the page', () => {
    const s = fakeStorage();
    s.setItem = () => { throw new Error('quota'); };
    const { P } = loadPresets({ storage: s });
    const r1 = P.store.save({ name: 'a', opts: {} });
    expect(r1).toEqual({ ok: false, reason: 'storage' });
    expect(P.store.list().length).toBe(1);
    const r2 = P.store.save({ name: 'b', opts: {} });
    expect(r2).toEqual({ ok: false, reason: 'storage' });
    expect(P.store.list().length).toBe(2);
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
