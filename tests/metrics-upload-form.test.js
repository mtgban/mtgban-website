import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { read, tagsWith, expectTrack, fakeBAN } from './metrics-helpers.js';
import { trackProblems } from './track-registry.js';

const upload = read('templates/upload.html');
const presetsSource = readFileSync(new URL('../js/upload-presets.js', import.meta.url), 'utf8');
const formSource = readFileSync(new URL('../js/upload-form.js', import.meta.url), 'utf8');

test.each([
    ['id="tab-singles"', 'ui.upload.tab', 'singles', undefined],
    ['id="tab-sealed"', 'ui.upload.tab', 'sealed', undefined],
    ['id="src-btn-file"', 'ui.upload.source_pick', 'file', undefined],
    ['id="src-btn-url"', 'ui.upload.source_pick', 'url', undefined],
    ['id="src-btn-text"', 'ui.upload.source_pick', 'text', undefined],
    ['id="clearFileBtn"', 'ui.upload.file', 'clear', undefined],
    ['setVisibleStores(true)', 'ui.upload.stores', 'select_all', undefined],
    ['setVisibleStores(false)', 'ui.upload.stores', 'clear', undefined],
    ['id="submit_default"', 'ui.upload.submit', 'upload', 'form'],
    ['id="submit_download"', 'ui.upload.submit', 'download', 'form'],
    ['id="submit_estimate"', 'ui.upload.submit', 'estimate', 'form'],
    ['id="submit_deckbox"', 'ui.upload.submit', 'deckbox', 'form'],
    ['id="submit_tcgplayer_csv"', 'ui.upload.submit', 'tcgplayer_csv', 'form'],
])('%# the tag with %s tracks %s:%s', (marker, name, value, scope) => {
    const found = tagsWith(upload, marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], name, value, scope);
});

// A templated store scope is held by the Go render tests instead.
test('every mark on the upload form is in the registry', () => {
    expect(trackProblems(upload).filter((p) => !p.includes('{{'))).toEqual([]);
});

test('the mode radios carry no mark', () => {
    for (const marker of ['id="retail"', 'id="buylist"']) {
        for (const tag of tagsWith(upload, marker)) expect(tag).not.toContain('data-track');
    }
});

// Presets: the fakes of tests/upload-presets.test.js, with window.BAN added.

function fakeStorage(initial = {}) {
    const m = Object.assign({}, initial);
    return {
        getItem: (k) => (k in m ? m[k] : null),
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
    };
}

function fakeEl(props = {}) {
    const on = {};
    return Object.assign({
        hidden: false, disabled: false, textContent: '', value: '',
        addEventListener: (t, f) => { (on[t] = on[t] || []).push(f); },
        _fire: (t, e) => (on[t] || []).forEach(f => f(e || {})),
        setAttribute() {}, focus() {},
    }, props);
}

function fakeSelect() {
    const s = fakeEl();
    s.options = [];
    Object.defineProperty(s, 'innerHTML', { set() { s.options = []; } });
    Object.defineProperty(s, 'value', {
        get() { const o = s.options.filter(x => x.selected).pop() || s.options[0]; return o ? o.value : ''; },
        set(v) { s.options.forEach(o => { o.selected = o.value === v; }); },
    });
    s.appendChild = (o) => { s.options.push(o); };
    return s;
}

function mountDoc() {
    const grid = (names, checked) => names.map(v => ({ type: 'checkbox', name: null, value: v, checked: checked.indexOf(v) >= 0, disabled: false }));
    const boxes = {
        singlesBox: grid(['CK', 'SCG', 'CSI'], ['SCG']),
        sealedBox: grid(['CK'], []),
        singlesIndexRow: grid(['TCGLow'], ['TCGLow']),
        sealedIndexRow: grid(['TCGSealed'], []),
    };
    boxes.singlesBox.forEach(b => b.name = 'stores'); boxes.sealedBox.forEach(b => b.name = 'sealed_stores');
    boxes.singlesIndexRow.forEach(b => b.name = 'index_stores'); boxes.sealedIndexRow.forEach(b => b.name = 'sealed_index_stores');
    const radios = [{ type: 'radio', name: 'mode', value: 'false', checked: true }, { type: 'radio', name: 'mode', value: 'true', checked: false }];
    const st = { tab: 'singles' };
    const form = Object.assign(fakeEl(), {
        dataset: { canChangeStores: 'true' },
        querySelectorAll: (sel) => sel.indexOf('mode') >= 0 ? radios : [],
    });
    const byId = {
        upload_form: form,
        'tab-singles': { classList: { contains: (c) => c === 'active' && st.tab === 'singles' } },
        'tab-sealed': { classList: { contains: (c) => c === 'active' && st.tab === 'sealed' } },
        'preset-select': fakeSelect(), 'preset-note': fakeEl(), 'preset-name': fakeEl(),
        'preset-save-row': fakeEl({ hidden: true }), 'preset-save': fakeEl(), 'preset-rename': fakeEl(),
        'preset-delete': fakeEl(), 'preset-save-toggle': fakeEl(), 'preset-cancel': fakeEl(),
    };
    Object.keys(boxes).forEach(id => { byId[id] = { querySelectorAll: (sel) => sel.indexOf('checkbox') >= 0 ? boxes[id] : [] }; });
    const doc = { getElementById: (id) => byId[id] || null, createElement: () => ({ value: '', textContent: '', selected: false }), _byId: byId, _boxes: boxes };
    return { doc, select: byId['preset-select'], note: byId['preset-note'], form };
}

function loadPresets({ storage = fakeStorage(), win = {}, ban = true } = {}) {
    const f = fakeBAN();
    const { doc, select, note, form } = mountDoc();
    const window = Object.assign({ reloadSelect() {}, selectTab() {} }, win);
    if (ban) window.BAN = f.BAN;
    const cookies = {};
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'getCookie', 'setCookie', presetsSource)(
        window, doc, storage, fakeStorage(), (n) => (n in cookies ? cookies[n] : null), (n, v) => { cookies[n] = v; });
    const P = window.UploadPresets;
    return { P, doc, select, note, form, window, calls: f.calls, cookies };
}

const presetCalls = (calls) => calls.filter(c => c[0] === 'ui.upload.preset');
function saveAs(doc, name) {
    doc._byId['preset-name'].value = name;
    doc._byId['preset-save']._fire('click');
}

test('picking a preset counts apply; picking the empty option does not', () => {
    const { P, doc, select, calls } = loadPresets();
    const p = P.store.save({ name: 'A', opts: Object.assign({}, P.current(doc), { margin: '12' }) }).preset;
    P.mount(doc);
    select.value = p.id;
    select._fire('change');
    expect(presetCalls(calls)).toEqual([['ui.upload.preset', 'apply', undefined]]);
    select.options.forEach(o => { o.selected = false; });
    select.options.push({ value: '', selected: true });
    select._fire('change');
    expect(presetCalls(calls).length).toBe(1);
});

test('a first save is save_as, a save over the selected preset is save', () => {
    const { P, doc, calls, cookies } = loadPresets();
    P.mount(doc);
    saveAs(doc, 'Mine');
    expect(doc._byId['preset-note'].textContent).toBe('Saved Mine');
    cookies.UploadMargin = '12';
    saveAs(doc, 'Mine');
    expect(doc._byId['preset-note'].textContent).toBe('Updated Mine');
    expect(presetCalls(calls)).toEqual([['ui.upload.preset', 'save_as', undefined], ['ui.upload.preset', 'save', undefined]]);
});

test('a save refused at the cap of 10, a duplicate and an empty name count nothing', () => {
    const { P, doc, calls, cookies } = loadPresets();
    for (let i = 0; i < 10; i++) P.store.save({ name: 'p' + i, opts: { margin: String(i) } });
    P.mount(doc);
    cookies.UploadMargin = '77';
    saveAs(doc, 'eleventh');
    expect(doc._byId['preset-note'].textContent).toBe('You can keep 10 presets; delete one first');
    saveAs(doc, '   ');
    expect(doc._byId['preset-note'].textContent).toBe('Give the preset a name');

    const second = loadPresets();
    second.P.store.save({ name: 'Same', opts: second.P.current(second.doc) });
    second.P.mount(second.doc);
    saveAs(second.doc, 'Other');
    expect(second.doc._byId['preset-note'].textContent).toBe('These settings are already saved as Same');

    const s = fakeStorage();
    const third = loadPresets({ storage: s });
    third.P.mount(third.doc);
    s.setItem = () => { throw new Error('quota'); };
    saveAs(third.doc, 'Mine');
    expect(third.doc._byId['preset-note'].textContent).toBe('Could not save: browser storage is unavailable');

    expect(presetCalls(calls)).toEqual([]);
    expect(presetCalls(second.calls)).toEqual([]);
    expect(presetCalls(third.calls)).toEqual([]);
});

test('rename and delete count only once the store did them', () => {
    const answers = { prompt: null, confirm: false };
    const { P, doc, calls } = loadPresets({ win: { prompt: () => answers.prompt, confirm: () => answers.confirm } });
    P.store.save({ name: 'A', opts: P.current(doc) });
    P.mount(doc);
    doc._byId['preset-rename']._fire('click');
    doc._byId['preset-delete']._fire('click');
    expect(presetCalls(calls)).toEqual([]);
    answers.prompt = 'B';
    doc._byId['preset-rename']._fire('click');
    expect(P.store.list().map(p => p.name)).toEqual(['B']);
    answers.confirm = true;
    doc._byId['preset-delete']._fire('click');
    expect(P.store.list()).toEqual([]);
    expect(presetCalls(calls)).toEqual([['ui.upload.preset', 'rename', undefined], ['ui.upload.preset', 'delete', undefined]]);
});

test('presets work with no window.BAN', () => {
    const { P, doc, select, calls } = loadPresets({ ban: false });
    P.mount(doc);
    saveAs(doc, 'Mine');
    expect(doc._byId['preset-note'].textContent).toBe('Saved Mine');
    select._fire('change');
    expect(calls).toEqual([]);
});

// upload-form.js on a document that keeps its listeners, as tests/drag-metrics.test.js loads it.
function stub() {
    return new Proxy(function () { return stub(); }, { get: (t, k) => (k === Symbol.toPrimitive ? () => '' : stub()), set: () => true });
}

function loadForm({ ban = true, storage = {} } = {}) {
    const f = fakeBAN();
    const listeners = {};
    const fileInput = {
        id: 'file', value: '', _files: null,
        getAttribute: () => '.csv,.txt',
        get files() { return this._files; },
        set files(v) { this._files = v; this.value = v && v[0] ? 'C:\\fakepath\\' + v[0].name : ''; },
    };
    const byId = {
        file: fileInput,
        fileLabel: { textContent: '', innerHTML: '' },
        textArea: { value: 'x', style: {}, addEventListener() {} },
    };
    const document = new Proxy({}, { get: (t, k) => (
        k === 'addEventListener' ? (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); }
            : k === 'getElementById' ? (id) => (id in byId ? byId[id] : stub()) : stub()) });
    const window = { BAN_UPLOAD_FORM: { buylist: false } };
    if (ban) window.BAN = f.BAN;
    const store = Object.assign({}, storage);
    const localStorage = { getItem: (k) => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = v; }, removeItem() {} };
    function DataTransfer() { const files = []; this.files = files; this.items = { add: (x) => files.push(x) }; }
    new Function('window', 'document', 'localStorage', 'DataTransfer', 'setTimeout', 'with (window) {' + formSource + '}')(
        window, document, localStorage, DataTransfer, () => {});
    const fire = (type, e) => (listeners[type] || []).forEach(fn => fn(e));
    return { window, fire, fileInput, byId, calls: f.calls };
}

// A store grid row with its "only" control.
function storeRow(disabled) {
    const boxes = [{ checked: false, disabled: false }, { checked: false, disabled: false }];
    const target = { checked: false, disabled };
    boxes.push(target);
    const item = { dataset: {}, querySelector: () => target, addEventListener() {} };
    const box = { querySelectorAll: () => boxes };
    const only = { dataset: {}, textContent: 'only', title: '' };
    only.closest = (sel) => (sel === '.upload-store-only' ? only : sel === '.upload-store-item' ? item : sel === '.upload-store-grid' ? box : null);
    return only;
}

const click = (target) => ({ target, preventDefault() {}, stopPropagation() {} });

test('only then exclude on the same row are two values', () => {
    const { fire, calls } = loadForm();
    const only = storeRow(false);
    fire('click', click(only));
    fire('click', click(only));
    expect(calls.filter(c => c[0] === 'ui.upload.stores')).toEqual([['ui.upload.stores', 'only', undefined], ['ui.upload.stores', 'exclude', undefined]]);
});

test('only on a disabled store counts nothing', () => {
    const { fire, calls } = loadForm();
    fire('click', click(storeRow(true)));
    expect(calls).toEqual([]);
});

test('a file picked through the input counts pick; an empty change does not', () => {
    const { fire, fileInput, calls } = loadForm();
    fire('change', { target: fileInput });
    expect(calls).toEqual([]);
    fileInput.value = 'C:\\fakepath\\list.csv';
    fire('change', { target: fileInput });
    fire('change', { target: { id: 'gdocURL', value: 'x' } });
    expect(calls).toEqual([['ui.upload.file', 'pick', undefined]]);
});

test('a dropped file counts no pick', () => {
    const { fire, byId, calls } = loadForm();
    fire('drop', { preventDefault() {}, dataTransfer: { types: ['Files'], files: [{ name: 'list.csv', type: 'text/csv' }] } });
    expect(byId.fileLabel.textContent).toBe('list.csv');
    expect(calls.filter(c => c[0] === 'ui.upload.file')).toEqual([]);
});

test('pressed() itself makes no call', () => {
    const { window, fileInput, byId, calls } = loadForm();
    fileInput.value = 'C:\\fakepath\\list.csv';
    window.pressed();
    expect(byId.fileLabel.textContent).toBe('list.csv');
    expect(calls).toEqual([]);
});

test('restoring the saved tab and source at load counts nothing', () => {
    const { window, calls } = loadForm({ storage: { uploadTab: 'sealed', uploadSourceMode: 'url', uploadMode: 'retail' } });
    window.onload();
    expect(calls).toEqual([]);
});

test('the form listeners run with no window.BAN', () => {
    const { fire, fileInput } = loadForm({ ban: false });
    const only = storeRow(false);
    fileInput.value = 'C:\\fakepath\\list.csv';
    expect(() => {
        fire('change', { target: fileInput });
        fire('click', click(only));
    }).not.toThrow();
    expect(only.dataset.mode).toBe('exclude');
});
