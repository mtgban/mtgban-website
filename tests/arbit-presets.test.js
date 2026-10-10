import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/arbit-presets.js', import.meta.url), 'utf8');

function fakeStorage(initial = {}) {
    const m = Object.assign({}, initial);
    return {
        getItem: (k) => (k in m ? m[k] : null),
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
        _map: m,
    };
}

// Arbit's ignored keys and defaults, as presetNorms answers them
const ARBIT = {
    source: 'CK', query: 'f=1', cookie: 'ArbitFilters', sort: '',
    ignored: ['syp', 'stocks', 'legit', 'stable', 'tradable', 'decklists'],
    defaults: { minsell: '0', minbuy: '0', minspread: '10', mindiff: '0', minqty: '0', minprof: '0', rl: '0', abu4h: '0' },
};

// sameSiteURL (utils.js) as it answers for this site's own query URLs
const sameSite = (v) => (v.charAt(0) === '?' ? v : '');

function load(cfg, { local = fakeStorage(), session = fakeStorage(), elements = {}, filters = null, sameSiteURL = sameSite } = {}) {
    const saves = [];
    const listeners = {};
    const window = {
        addEventListener: (ev, fn) => { listeners[ev] = fn; },
        BAN_ARBIT: Object.assign({}, ARBIT, cfg),
        location: { href: '' },
        ArbitFilters: filters || { save: (q) => saves.push(q), formQuery: (f) => f.query },
        prompt: null,
        confirm: null,
    };
    const document = {
        getElementById: (id) => elements[id] || null,
        createElement: () => ({ value: '', textContent: '', selected: false }),
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'sameSiteURL', source)(window, document, local, session, sameSiteURL);
    return { P: window.ArbitPresets, window, saves, local, session, listeners };
}

const stored = (local) => JSON.parse(local.getItem('mtgban_arbit_presets'));

test('the store creates, updates in place, renames and deletes with a tombstone', () => {
    const { P, local } = load({});
    const a = P.store.save({ name: 'Cheap', q: 'f=1&maxsell=5' });
    expect(a.ok).toBe(true);
    const b = P.store.save({ id: a.preset.id, name: 'Cheap', q: 'f=1&maxsell=4' });
    expect(b.preset.id).toBe(a.preset.id);
    expect(P.store.list().map((p) => p.q)).toEqual(['f=1&maxsell=4']);
    expect(P.store.rename(a.preset.id, 'Cheaper')).toBe(true);
    expect(P.store.list()[0].name).toBe('Cheaper');
    expect(P.store.remove(a.preset.id)).toBe(true);
    expect(P.store.list()).toEqual([]);
    expect(stored(local)).toEqual([{ id: a.preset.id, del: true, savedAt: expect.any(Number) }]);
    expect(P.store.remove(a.preset.id)).toBe('missing');
});

test('a tombstone older than 30 days is dropped on the next write', () => {
    const old = { id: 'p_old', del: true, savedAt: Date.now() - 31 * 24 * 60 * 60 * 1000 };
    const fresh = { id: 'p_new', del: true, savedAt: Date.now() };
    const local = fakeStorage({ mtgban_arbit_presets: JSON.stringify([old, fresh]) });
    const { P } = load({}, { local });
    P.store.save({ name: 'A', q: 'f=1' });
    expect(stored(local).filter((p) => p.del).map((p) => p.id)).toEqual(['p_new']);
});

test('each page group keeps its own presets and its own cap of 10', () => {
    const local = fakeStorage();
    const arbit = load({}, { local }).P;
    for (let i = 0; i < 10; i++) expect(arbit.store.save({ name: 'A' + i, q: 'f=1&minsell=' + i }).ok).toBe(true);
    expect(arbit.store.save({ name: 'A10', q: 'f=1' })).toEqual({ ok: false, reason: 'cap' });
    const global = load({ cookie: 'GlobalFilters' }, { local }).P;
    expect(global.store.list()).toEqual([]);
    expect(global.store.save({ name: 'G', q: 'f=1' }).ok).toBe(true);
    expect(global.store.list().map((p) => p.group)).toEqual(['global']);
    expect(arbit.store.list().length).toBe(10);
});

test('normalizing drops what the page does not apply and what is at its default', () => {
    const { P } = load({});
    expect(P.normalize('f=1&minsell=0&rl=0&tradable=1&sort=spread&t=5')).toBe('');
    expect(P.normalize('minspread=10&cond=NM%2CSP&f=1')).toBe('cond=NM%2CSP');
    expect(P.normalize('minsell=2&cond=NM')).toBe(P.normalize('cond=NM&f=1&minsell=2'));
    expect(P.normalize('minsell=2')).not.toBe(P.normalize('minsell=3'));
    // An empty pick is a real selection, kept
    expect(P.normalize('f=1&cond=')).toBe('cond=');
});

test('on reverse, Tradable on is its default and off is a change', () => {
    const { P } = load({ ignored: ['syp', 'stocks', 'legit', 'stable', 'decklists'], defaults: Object.assign({}, ARBIT.defaults, { tradable: '1' }) });
    expect(P.normalize('f=1&tradable=1')).toBe('');
    expect(P.normalize('f=1&tradable=0')).toBe('tradable=0');
});

test('save decisions: empty, duplicate, update, create', () => {
    const local = fakeStorage();
    const { P } = load({ query: 'f=1&minsell=2' }, { local });
    P.store.save({ name: 'Two', q: 'f=1&minsell=2&rl=0' });
    P.store.save({ name: 'Five', q: 'f=1&minsell=5' });
    const presets = P.store.list();
    expect(P.decideSave('  ', presets).action).toBe('empty');
    expect(P.decideSave('Another', presets)).toEqual({ action: 'duplicate', preset: presets.find((p) => p.name === 'Two') });
    expect(P.decideSave('two', presets).action).toBe('update');
    expect(P.decideSave('five', presets).action).toBe('duplicate');
    const fresh = load({ query: 'f=1&minsell=9' }, { local }).P;
    expect(fresh.decideSave('Nine', fresh.store.list()).action).toBe('create');
    expect(fresh.decideSave('five', fresh.store.list()).action).toBe('update');
});

test('applying a preset opens it with the page\'s sort and saves both', () => {
    const { P, window, saves } = load({ source: 'SCG', sort: 'spread' });
    P.apply({ q: 'cond=NM&f=1&minsell=2' });
    expect(window.location.href).toBe('?source=SCG&cond=NM&f=1&minsell=2&sort=spread');
    expect(saves).toEqual(['cond=NM&f=1&minsell=2&sort=spread']);
    const plain = load({ source: 'SCG' });
    plain.P.apply({ q: 'f=1&minsell=2' });
    expect(plain.window.location.href).toBe('?source=SCG&f=1&minsell=2');
    expect(plain.saves).toEqual(['f=1&minsell=2']);
});

// A filter form, as arbit.html lays it out: picker groups of boxes, number
// fields, and the toggles the bar lists in toggles_on.
function fakeFormDOM({ picks = {}, numbers = {}, toggles = {} } = {}) {
    const box = (name, value, checked) => ({ type: 'checkbox', name, value, checked });
    const groups = Object.keys(picks).map((name) => {
        const boxes = picks[name].map(([v, on]) => box(name, v, on));
        return { boxes, querySelectorAll: () => boxes };
    });
    const nums = Object.keys(numbers).map((name) => ({ type: 'number', name, value: numbers[name] }));
    const toggleBoxes = Object.keys(toggles).map((name) => box(name, '1', toggles[name]));
    return {
        groups, nums, toggleBoxes,
        querySelectorAll: (sel) => (sel === '[data-pick]' ? groups : sel === 'input[type=number]' ? nums : []),
        querySelector: (sel) => {
            if (sel === 'input[name=toggles_on]') return { value: Object.keys(toggles).join(',') };
            const m = sel.match(/name="([^"]+)"/);
            return m ? toggleBoxes.find((b) => b.name === m[1]) || null : null;
        },
    };
}

test('the form reads as the query the server would write for it', () => {
    const { P } = load({});
    const dom = fakeFormDOM({
        picks: { cond: [['NM', true], ['SP', true], ['MP', false], ['HP', false]], finish: [['nonfoil', true], ['foil', true]], rarity: [['rare', false], ['common', false]] },
        numbers: { minsell: '2.50', maxsell: '', minspread: '10' },
        toggles: { rl: true, abu4h: false },
    });
    expect(P.formState(dom)).toBe('abu4h=0&cond=NM%2CSP&f=1&minsell=2.5&minspread=10&rarity=&rl=1');
    // The page's own canonical query for the same filters matches it
    expect(P.normalize(P.formState(dom))).toBe(P.normalize('cond=NM%2CSP&f=1&minsell=2.5&rarity=&rl=1'));
});

// The preset row's elements, as arbit.html has them
function fakePage(formQuery, dom = fakeFormDOM()) {
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
    const form = Object.assign(dom, { query: formQuery, addEventListener: on('form'), submits: 0, requestSubmit: () => { form.submits++; } });
    const elements = {
        arbPresetBox: { hidden: true },
        arbPresetSelect: select,
        arbPresetControls: { hidden: true },
        arbPresetNote: { textContent: '' },
        arbPresetSaveToggle: button('toggle'),
        arbPresetSaveRow: { hidden: true },
        arbPresetName: { value: '', focus() {}, addEventListener: on('name') },
        arbPresetSave: button('save'),
        arbPresetCancel: button('cancel'),
        arbPresetRename: button('rename'),
        arbPresetDelete: button('delete'),
        arbFilters: form,
    };
    return { elements, options, listeners, form };
}

test('the select shows the matching preset, and a changed page reads modified', () => {
    const local = fakeStorage();
    const session = fakeStorage();
    load({}, { local }).P.store.save({ name: 'Two', q: 'f=1&minsell=2' });

    const page = fakePage('f=1&minsell=2');
    load({ query: 'f=1&minsell=2&rl=0' }, { local, session, elements: page.elements });
    expect(page.elements.arbPresetBox.hidden).toBe(false);
    expect(page.options.map((o) => o.textContent)).toEqual(['Presets', 'Default', 'Two']);
    expect(page.options.map((o) => !!o.disabled)).toEqual([true, false, false]);
    expect(page.elements.arbPresetSelect.value).toBe(page.options[2].value);

    const changed = fakePage('f=1&minsell=3');
    load({ query: 'f=1&minsell=3' }, { local, session, elements: changed.elements });
    expect(changed.options.map((o) => o.textContent)).toEqual(['Presets', 'Default', 'Two (modified)']);
});

test('saving the page as it stands saves its own state and stays put', () => {
    const local = fakeStorage();
    const page = fakePage('f=1&minsell=2');
    const { P } = load({ query: 'f=1&minsell=2' }, { local, elements: page.elements });
    expect(page.elements.arbPresetSaveToggle.disabled).toBe(false);
    page.listeners['toggle:click']();
    page.elements.arbPresetName.value = 'Two';
    page.listeners['save:click']();
    expect(P.store.list().map((p) => [p.name, p.q])).toEqual([['Two', 'f=1&minsell=2']]);
    expect(page.elements.arbPresetNote.textContent).toBe('Saved Two');
    expect(page.form.submits).toBe(0);
});

test('saving edits not yet applied saves them as the form holds them, then applies them', () => {
    const local = fakeStorage();
    const page = fakePage('f=1&minsell=2', fakeFormDOM({ numbers: { minsell: '7' }, toggles: { rl: false } }));
    const { P } = load({ query: 'f=1&minsell=2' }, { local, elements: page.elements });
    page.form.query = 'f=1&minsell=7';
    page.listeners['form:input']();
    expect(page.elements.arbPresetSaveToggle.disabled).toBe(false);
    page.listeners['toggle:click']();
    page.elements.arbPresetName.value = 'Seven';
    page.listeners['save:click']();
    expect(P.store.list().map((p) => [p.name, p.q])).toEqual([['Seven', 'f=1&minsell=7&rl=0']]);
    expect(page.form.submits).toBe(1);
});

test('edits that match a saved preset are a duplicate, not a new one', () => {
    const local = fakeStorage();
    load({}, { local }).P.store.save({ name: 'Seven', q: 'f=1&minsell=7' });
    const page = fakePage('f=1&minsell=2', fakeFormDOM({ numbers: { minsell: '7' } }));
    const { P } = load({ query: 'f=1&minsell=2' }, { local, elements: page.elements });
    page.form.query = 'f=1&minsell=7';
    page.listeners['toggle:click']();
    page.elements.arbPresetName.value = 'Again';
    page.listeners['save:click']();
    expect(page.elements.arbPresetNote.textContent).toBe('Already saved as Seven');
    expect(P.store.list().length).toBe(1);
    // Applied, so the page shows Seven itself rather than modified
    expect(page.form.submits).toBe(1);
});

test('a preset synced in from another device appears on refresh', () => {
    const local = fakeStorage();
    const page = fakePage('f=1');
    const { P } = load({}, { local, elements: page.elements });
    expect(page.options.map((o) => o.textContent)).toEqual(['Presets', 'Default']);
    local.setItem('mtgban_arbit_presets', JSON.stringify([{ id: 'p_x', name: 'Synced', savedAt: 1, group: 'arbit', q: 'f=1&minsell=4' }]));
    P.refresh();
    expect(page.options.map((o) => o.textContent)).toEqual(['Presets', 'Default', 'Synced']);
});

test('choosing a preset applies it', () => {
    const local = fakeStorage();
    load({}, { local }).P.store.save({ name: 'Four', q: 'f=1&minsell=4' });
    const page = fakePage('f=1');
    const { window, saves } = load({}, { local, elements: page.elements });
    page.elements.arbPresetSelect.value = page.options[2].value;
    page.listeners['select:change']();
    expect(window.location.href).toBe('?source=CK&f=1&minsell=4');
    expect(saves).toEqual(['f=1&minsell=4']);
});

test('a preset whose URL is not this site\'s goes nowhere and saves nothing', () => {
    const { P, window, saves } = load({}, { sameSiteURL: () => '' });
    P.apply({ q: 'f=1&minsell=2' });
    expect(window.location.href).toBe('');
    expect(saves).toEqual([]);
});

test('back from a picked preset, a page the browser kept redraws for its own filters', () => {
    const local = fakeStorage();
    const session = fakeStorage();
    load({}, { local }).P.store.save({ name: 'Four', q: 'f=1&minsell=4' });
    const page = fakePage('f=1');
    const { listeners } = load({}, { local, session, elements: page.elements });
    // Picked on this page, then navigated away and back
    page.elements.arbPresetSelect.value = page.options[2].value;
    session.setItem('mtgban_arbit_selected_preset', page.options[2].value);
    listeners.pageshow({ persisted: true });
    // This page is at its defaults, so the built-in preset is the one shown
    expect(page.elements.arbPresetSelect.value).toBe('default');
    expect(page.options.map((o) => o.textContent)).toEqual(['Presets', 'Default', 'Four']);
    expect(session.getItem('mtgban_arbit_selected_preset')).toBe(null);
});

test('the built-in Default shows for a page at its defaults and applies them with the sort', () => {
    const page = fakePage('f=1');
    const { window, saves } = load({ query: 'abu4h=0&f=1&rl=0', sort: 'spread' }, { elements: page.elements });
    expect(page.elements.arbPresetSelect.value).toBe('default');
    const changed = fakePage('f=1&minsell=2');
    load({ query: 'f=1&minsell=2' }, { elements: changed.elements });
    expect(changed.elements.arbPresetSelect.value).toBe('');

    page.elements.arbPresetSelect.value = 'default';
    page.listeners['select:change']();
    expect(window.location.href).toBe('?source=CK&f=1&sort=spread');
    expect(saves).toEqual(['f=1&sort=spread']);
});

test('Default cannot be saved over or renamed to, and the defaults are already saved as it', () => {
    const local = fakeStorage();
    const { P } = load({ query: 'f=1' }, { local });
    expect(P.decideSave('default', [])).toEqual({ action: 'reserved' });
    expect(P.decideSave('Anything', [])).toEqual({ action: 'duplicate', preset: { id: 'default', name: 'Default', q: 'f=1' } });

    const page = fakePage('f=1&minsell=2');
    const { P: Q, window } = load({ query: 'f=1&minsell=2' }, { local, elements: page.elements });
    page.listeners['toggle:click']();
    page.elements.arbPresetName.value = 'Default';
    page.listeners['save:click']();
    expect(page.elements.arbPresetNote.textContent).toBe('Default is built in; pick another name');
    expect(Q.store.list()).toEqual([]);

    Q.store.save({ name: 'Two', q: 'f=1&minsell=2' });
    Q.refresh();
    window.prompt = () => 'DEFAULT';
    page.elements.arbPresetSelect.value = page.options[2].value;
    page.listeners['select:change']();
    page.listeners['rename:click']();
    expect(page.elements.arbPresetNote.textContent).toBe('Default is built in; pick another name');
    expect(Q.store.list().map((p) => p.name)).toEqual(['Two']);
});
