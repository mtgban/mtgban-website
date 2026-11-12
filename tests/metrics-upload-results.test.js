import { test, expect } from 'bun:test';
import { read, tagsWith, expectTrack, fakeBAN } from './metrics-helpers.js';
import { trackProblems } from './track-registry.js';

const upload = read('templates/upload.html');

test.each([
    ["showResTab('results'", 'ui.upload.result_tab', 'results', undefined],
    ["showResTab('optimizer'", 'ui.upload.result_tab', 'optimizer', undefined],
    ["showUresView('all'", 'ui.upload.result_tab', 'all', undefined],
    ["showUresView('singles'", 'ui.upload.result_tab', 'singles', undefined],
    ["showUresView('sealed'", 'ui.upload.result_tab', 'sealed', undefined],
    ["showUresView('notfound'", 'ui.upload.result_tab', 'not_found', undefined],
    ['class="upload-btn upload-btn-secondary res-mode-btn"', 'ui.upload.result', 'switch_mode', undefined],
    ['<button class="opt-btn load" onclick="window.reprocessUploadResults', 'ui.upload.result', 'reload', undefined],
    ['runUnpack()', 'ui.upload.result', 'unpack', undefined],
    ['class="back-link"', 'ui.upload.result', 'back', undefined],
    ['class="res-mode-upsell-btn"', 'ui.upload.upsell', undefined, undefined],
    ["submitExport('download'", 'ui.upload.submit', 'download', 'results'],
    ["submitExport('estimate'", 'ui.upload.submit', 'estimate', 'results'],
    ["submitExport('deckbox'", 'ui.upload.submit', 'deckbox', 'results'],
    ["submitExport('tcgplayer_csv'", 'ui.upload.submit', 'tcgplayer_csv', 'results'],
    ['openStorePrompt()', 'ui.upload.publish', 'open', undefined],
    ['class="opt-toc-item"', 'ui.optimizer', 'toc_jump', undefined],
    ['title="Previous"', 'ui.optimizer', 'section_nav', undefined],
    ['title="Next"', 'ui.optimizer', 'section_nav', undefined],
    ['class="section-fold"', 'ui.optimizer', 'fold', undefined],
    ['>Load buylist at {{$scraperKey}}', 'ui.optimizer.send', 'sellcart', '{{$scraperKey}}'],
    ['>Download {{$scraperKey}} CSV</a>', 'ui.optimizer.send', 'csv', '{{$scraperKey}}'],
    ['>Remove from TCG CSV</a>', 'ui.optimizer.send', 'tcg_csv', '{{$scraperKey}}'],
    ['class="opt-send-btn"', 'ui.optimizer.send', 'row_popover', '{{$scraperKey}}'],
    ['>Mass entry at TCGplayer</a>', 'ui.optimizer.send', 'mass_entry', '{{$sourceKey}}'],
    ['>Mass entry at Mana Pool</a>', 'ui.optimizer.send', 'mass_entry', '{{$sourceKey}}'],
    ['>Load at {{$sourceKey}}</a>', 'ui.optimizer.send', 'load_at', '{{$sourceKey}}'],
])('%# the tag with %s tracks %s:%s', (marker, name, value, scope) => {
    // A marker after the tag's end names the tag it closes.
    const at = upload.indexOf(marker);
    const found = marker.startsWith('>') ? [upload.slice(upload.lastIndexOf('<', at), at + 1)] : tagsWith(upload, marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], name, value, scope);
});

test('both deck builder links name their store', () => {
    const tags = [];
    for (let i = upload.indexOf('>Deck builder at {{$sourceKey}}</a>'); i >= 0; i = upload.indexOf('>Deck builder at {{$sourceKey}}</a>', i + 1)) {
        tags.push(upload.slice(upload.lastIndexOf('<', i), i + 1));
    }
    expect(tags.length).toBe(2);
    tags.forEach((t) => expectTrack(t, 'ui.optimizer.send', 'deck_builder', '{{$sourceKey}}'));
});

test('the copy icon is found by class, and the Publish button counts from its script', () => {
    expect(tagsWith(upload, 'copyAndBlink(this')[0]).toContain('class="emoji opt-copy"');
    expect(tagsWith(upload, 'runPublishStore()')[0]).not.toContain('data-track');
});

test('no tag sends upsell as a value', () => {
    expect(upload).not.toContain('data-track-value="upsell"');
});

test('every literal mark on the upload page is in the registry', () => {
    expect(trackProblems(upload).filter((p) => !p.includes('{{'))).toEqual([]);
});

// upload-sort.js, as tests/upload-sort.test.js loads it.
const sortSource = read('js/upload-sort.js');
const noStorage = { getItem: () => null, setItem() {} };
// emptyTable is a results table with no rows.
const emptyTable = () => ({ tBodies: [{ rows: [], appendChild() {} }], dispatchEvent() {}, classList: { contains: (c) => c === 'ures-table' } });
function sortable(window) {
    const { uresSortBy } = new Function('document', 'localStorage', 'window', sortSource + '\nreturn {uresSortBy};')({ addEventListener() {} }, noStorage, window);
    const attrs = {};
    const th = {
        cellIndex: 0, getAttribute: (n) => (n in attrs ? attrs[n] : null), setAttribute: (n, v) => { attrs[n] = v; }, removeAttribute: (n) => { delete attrs[n]; },
    };
    const table = emptyTable();
    th.closest = () => table;
    th.parentNode = { cells: [th] };
    const sort = (repeated) => uresSortBy(th, repeated);
    sort.th = th;
    return sort;
}

test('a header sort counts once per click', () => {
    const { BAN, calls } = fakeBAN();
    const sort = sortable({ BAN });
    sort();
    sort();
    expect(calls).toEqual([['ui.upload.result', 'sort', undefined], ['ui.upload.result', 'sort', undefined]]);
});

test('a held key sorts on each repeat and counts only the first press', () => {
    const { BAN, calls } = fakeBAN();
    const sort = sortable({ BAN });
    sort(true);
    expect(sort.th.getAttribute('aria-sort')).toBe('ascending');
    expect(calls).toEqual([]);
});

// wired loads upload-sort.js and fires DOMContentLoaded, returning one header's listeners.
function wired(BAN) {
    const listeners = {};
    const attrs = {};
    const th = {
        cellIndex: 0, getAttribute: (n) => (n in attrs ? attrs[n] : null), setAttribute: (n, v) => { attrs[n] = v; }, removeAttribute: (n) => { delete attrs[n]; },
        addEventListener: (type, fn) => { listeners[type] = fn; },
    };
    const table = emptyTable();
    th.closest = () => table;
    th.parentNode = { cells: [th] };
    const ready = [];
    const document = {
        addEventListener: (type, fn) => { if (type === 'DOMContentLoaded') ready.push(fn); },
        querySelectorAll: (sel) => (sel.indexOf('thead th') >= 0 ? [th] : []),
    };
    new Function('document', 'localStorage', 'window', sortSource)(document, noStorage, { BAN });
    ready.forEach((fn) => fn());
    return { listeners, th };
}

test('a wired header counts a keydown only when it is not a repeat', () => {
    const { BAN, calls } = fakeBAN();
    const { listeners, th } = wired(BAN);
    listeners.keydown({ key: 'Enter', repeat: true, preventDefault() {} });
    expect(th.getAttribute('aria-sort')).toBe('ascending');
    expect(calls).toEqual([]);
    listeners.keydown({ key: 'Enter', repeat: false, preventDefault() {} });
    expect(calls).toEqual([['ui.upload.result', 'sort', undefined]]);
});

// upload-printings.js over a row, its picker and the reload bar.
const printingsSource = read('js/upload-printings.js');
function printings(window) {
    const byId = {};
    const node = () => ({ style: {}, textContent: '', classList: { add() {}, remove() {} } });
    const document = {
        getElementById: (id) => (byId[id] = byId[id] || node()),
        createElement: () => {
            const on = {};
            return { appendChild() {}, addEventListener: (t, f) => { on[t] = f; }, _click: () => on.click() };
        },
        addEventListener() {},
    };
    const grid = { cards: [], appendChild(c) { this.cards.push(c); } };
    byId['printing-picker-grid'] = Object.defineProperty(grid, 'innerHTML', { set() {} });
    const fns = new Function('window', 'document', 'ensureHashesLoaded', printingsSource + '\nreturn {toggleRemoveRow, openPrintingPicker};')(
        Object.assign(window, { BAN_UPLOAD_PRINTINGS: { cards: { u1: { image: 'a', edition: 'E', number: '1' } } }, setCardArtSource() {} }), document, () => {});
    const classes = new Set();
    const row = { dataset: { hash: 'u0' }, classList: { contains: (c) => classes.has(c), add: (c) => classes.add(c), remove: (c) => classes.delete(c) }, querySelector: () => null };
    const btn = { dataset: { hash: 'u0', aliases: 'u1' }, closest: () => row };
    return { fns, btn, grid };
}

test('removing a row counts; putting it back does not', () => {
    const { BAN, calls } = fakeBAN();
    const { fns, btn } = printings({ BAN });
    fns.toggleRemoveRow(btn);
    fns.toggleRemoveRow(btn);
    expect(calls).toEqual([['ui.upload.result', 'remove_row', undefined]]);
});

test('picking a printing counts printing_swap', () => {
    const { BAN, calls } = fakeBAN();
    const { fns, btn, grid } = printings({ BAN });
    fns.openPrintingPicker(btn);
    expect(calls).toEqual([]);
    grid.cards[0]._click();
    expect(btn.dataset.hash).toBe('u1');
    expect(calls).toEqual([['ui.upload.result', 'printing_swap', undefined]]);
});

// upload-optimizer.js, as tests/upload-optimizer-totals.test.js loads it.
const optimizerSource = read('js/upload-optimizer.js');
function optimizer(window) {
    const listeners = {};
    const document = {
        querySelectorAll: () => [],
        addEventListener: (t, f) => { listeners[t] = f; },
    };
    const section = { id: 'opt-CK', querySelectorAll: () => [], querySelector: () => null };
    const thead = {};
    const fns = new Function('window', 'document', 'wireLoadLists', optimizerSource + '\nreturn {toggleAllOptRows};')(window, document, () => {});
    const rowBox = (n) => ({ checked: true, closest: (sel) => (sel === 'tr' ? { classList: { add() {}, remove() {} } } : null), n });
    const rows = [rowBox(0), rowBox(1), rowBox(2)];
    const box = (cls) => ({
        type: 'checkbox', checked: false,
        classList: { contains: (c) => c === cls },
        closest: (sel) => (sel === '.opt-store' ? section : sel === '.opt-store thead' && !cls ? thead : sel === 'table' ? { querySelectorAll: () => rows } : null),
    });
    return {
        fns, rows,
        change: (target) => listeners.change({ target }),
        click: (target) => listeners.click({ target }),
        rowCheck: box('opt-row-check'),
        master: box(''),
    };
}

test('a row box counts row_check; the header box counts check_all once, whatever the row count', () => {
    const { BAN, calls } = fakeBAN();
    const o = optimizer({ BAN });
    o.change(o.rowCheck);
    o.fns.toggleAllOptRows(o.master);
    o.change(o.master);
    expect(o.rows.every((r) => r.checked === false)).toBe(true);
    expect(calls).toEqual([['ui.optimizer', 'row_check', undefined], ['ui.optimizer', 'check_all', undefined]]);
});

test('a change outside a store section counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    const o = optimizer({ BAN });
    o.change({ type: 'checkbox', classList: { contains: () => true }, closest: () => null });
    expect(calls).toEqual([]);
});

test('the copy icon counts copy_name', () => {
    const { BAN, calls } = fakeBAN();
    const o = optimizer({ BAN });
    const icon = {};
    o.click({ closest: (sel) => (sel === '.opt-copy' ? icon : null) });
    o.click({ closest: () => null });
    expect(calls).toEqual([['ui.optimizer', 'copy_name', undefined]]);
});

// backpack.js over optimizer sections, the stand-in DOM of tests/backpack.test.js trimmed.
const backpackSource = read('js/backpack.js');
const listStorage = read('js/list-storage.js');
let ids = {};
function el(tag) {
    const node = {
        tag, attrs: {}, classes: new Set(), children: [], listeners: {}, parentNode: null, textContent: '', hidden: false,
        value: '', checked: false, disabled: false, type: '', name: '', style: {},
        get classList() {
            const s = this.classes;
            return { add: (c) => s.add(c), remove: (c) => s.delete(c), toggle: (c, on) => { on ? s.add(c) : s.delete(c); }, contains: (c) => s.has(c) };
        },
        setAttribute(n, v) { this.attrs[n] = String(v); if (n === 'id') ids[v] = this; if (n === 'class') String(v).split(/\s+/).filter(Boolean).forEach((c) => this.classes.add(c)); },
        getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; },
        removeAttribute(n) { delete this.attrs[n]; },
        appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
        append(...cs) { cs.forEach((c) => this.appendChild(c)); },
        remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((c) => c !== this); },
        replaceWith(n) { const p = this.parentNode; if (!p) return; n.parentNode = p; p.children[p.children.indexOf(this)] = n; this.parentNode = null; },
        addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); },
        click() { (this.listeners.click || []).forEach((fn) => fn({ preventDefault() {}, stopPropagation() {} })); },
        focus() {},
        closest(sel) { let n = this; while (n) { if (n.matches(sel)) return n; n = n.parentNode; } return null; },
        matches(sel) { return sel.split(',').some((s) => { s = s.trim(); return s.startsWith('.') ? this.classes.has(s.slice(1)) : s.startsWith('#') ? this.attrs.id === s.slice(1) : s.includes('[') ? this.tag === s.split('[')[0] && s.slice(s.indexOf('[') + 1, -1) in this.attrs : this.tag === s; }); },
        querySelector(sel) { return this.querySelectorAll(sel)[0] || null; },
        querySelectorAll(sel) { const out = []; const walk = (n) => { n.children.forEach((c) => { if (c.matches(sel)) out.push(c); walk(c); }); }; walk(this); return out; },
        submit() {},
    };
    return node;
}

// pack loads backpack.js over a stored backpack and one optimizer section of [id, qty] rows,
// with results also a results toolbar pair over the same cards as result rows.
function pack({ store = [], rows, max, BAN, confirm = () => true, results = false } = {}) {
    ids = {};
    const m = { mtgban_backpack: JSON.stringify(store) };
    const localStorage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const sm = {};
    const sessionStorage = { getItem: (k) => (k in sm ? sm[k] : null), setItem: (k, v) => { sm[k] = String(v); }, removeItem: (k) => { delete sm[k]; } };
    const body = el('body');
    const nav = el('button'); nav.setAttribute('id', 'nav-backpack');
    body.appendChild(nav);
    const section = el('div'); section.classes.add('opt-store');
    const add = el('button'); add.classes.add('pack-add-btn');
    const take = el('button'); take.classes.add('pack-take-btn');
    section.append(add, take);
    rows.forEach(([id, qty]) => {
        const tr = el('tr'); tr.setAttribute('data-opt-id', id); tr.setAttribute('data-opt-cond', ''); tr.setAttribute('data-load-qty', String(qty));
        Object.entries({ 'data-load-name': 'Card ' + id, 'data-load-set': 'S', 'data-load-number': '7', 'data-opt-edition': 'Set', 'data-opt-img': '', 'data-opt-finish-tag': '', 'data-opt-finish-class': '', 'data-opt-cw': 'false' }).forEach(([k, v]) => tr.setAttribute(k, v));
        section.appendChild(tr);
    });
    body.appendChild(section);
    const window = { localStorage, sessionStorage, confirm, addEventListener() {}, location: { pathname: '/upload' } };
    const toolbar = {};
    if (results) {
        const bar = el('div');
        toolbar.add = el('button'); toolbar.add.classes.add('pack-add-btn'); toolbar.add.setAttribute('data-pack-rows', 'results');
        toolbar.take = el('button'); toolbar.take.classes.add('pack-take-btn'); toolbar.take.setAttribute('data-pack-rows', 'results');
        bar.append(toolbar.add, toolbar.take);
        body.appendChild(bar);
        const resultRows = rows.map(([id, qty]) => {
            const tr = el('tr');
            Object.entries({ 'data-hash': id, 'data-grade': '', 'data-qtys': String(qty), 'data-card-name': 'Card ' + id, 'data-set-code': 'S', 'data-number': '7', 'data-edition': 'Set' }).forEach(([k, v]) => tr.setAttribute(k, v));
            return tr;
        });
        window.exportRows = () => resultRows;
        window.currentExportView = () => 'all';
    }
    if (BAN) window.BAN = BAN;
    if (max) window.BAN_BACKPACK_MAX = max;
    window.fetch = () => new Promise(() => {});
    const document = {
        body, readyState: 'complete', addEventListener() {},
        documentElement: { dataset: { signedIn: 'false' } },
        getElementById: (id) => ids[id] || null,
        createElement: (tag) => el(tag),
        querySelectorAll: (sel) => body.querySelectorAll(sel),
        activeElement: null,
    };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'ListStorage', 'setTimeout',
        listStorage + '; window.ListStorage = ListStorage; ' + backpackSource)(
        window, document, localStorage, sessionStorage, undefined, () => {});
    return { window, add, take, toolbar };
}

const optimizerCalls = (calls) => calls.filter((c) => c[0] === 'ui.optimizer');

test('rows added to the backpack count pack_add only when a copy went in', () => {
    const { BAN, calls } = fakeBAN();
    const p = pack({ rows: [['a', 1]], BAN });
    p.window.addRowsToBackpack(p.add);
    expect(optimizerCalls(calls)).toEqual([['ui.optimizer', 'pack_add', undefined]]);

    const full = fakeBAN();
    const q = pack({ max: 1, store: [{ id: 'z', name: 'Z', qty: 1, t: 1, m: 1 }], rows: [['b', 1]], BAN: full.BAN });
    q.window.addRowsToBackpack(q.add);
    expect(ids['backpack-toast'].textContent).toBe('Backpack is full (1 products)');
    expect(optimizerCalls(full.calls)).toEqual([]);
});

test('rows taken count pack_take on confirm', () => {
    const answer = { yes: false };
    const { BAN, calls } = fakeBAN();
    const p = pack({ store: [{ id: 'a', name: 'A', qty: 2, t: 1, m: 1 }], rows: [['a', 1]], BAN, confirm: () => answer.yes });
    p.window.takeRowsFromBackpack(p.take);
    expect(optimizerCalls(calls)).toEqual([]);
    answer.yes = true;
    p.window.takeRowsFromBackpack(p.take);
    expect(optimizerCalls(calls)).toEqual([['ui.optimizer', 'pack_take', undefined]]);
});

test('the results toolbar pair counts under ui.upload.result, the optimizer pair under ui.optimizer', () => {
    const { BAN, calls } = fakeBAN();
    const p = pack({ rows: [['a', 1]], BAN, results: true });
    p.window.addRowsToBackpack(p.toolbar.add);
    p.window.takeRowsFromBackpack(p.toolbar.take);
    p.window.addRowsToBackpack(p.add);
    const counted = calls.filter((c) => c[0] === 'ui.upload.result' || c[0] === 'ui.optimizer');
    expect(counted).toEqual([['ui.upload.result', 'pack_add', undefined], ['ui.upload.result', 'pack_take', undefined], ['ui.optimizer', 'pack_add', undefined]]);
});

test('the sort menu buttons and the results backpack pair carry no mark: the scripts count them', () => {
    const tags = tagsWith(upload, 'data-sort-area=').concat(tagsWith(upload, 'data-pack-rows="results"'));
    expect(tags.length).toBe(5);
    tags.forEach((t) => expect(t).not.toContain('data-track'));
});

// sortMenu loads upload-sort.js over one results table and its Card-header button, past DOMContentLoaded.
function sortMenu(window) {
    const docListeners = {};
    let menu = null;
    const table = Object.assign(emptyTable(), { tHead: { rows: [{ cells: [] }] }, querySelector: () => null });
    const btnAttrs = { 'data-sort-area': 'results' };
    const btnListeners = {};
    const btn = {
        getAttribute: (n) => (n in btnAttrs ? btnAttrs[n] : null), setAttribute: (n, v) => { btnAttrs[n] = v; },
        addEventListener: (type, fn) => { btnListeners[type] = fn; },
        classList: { toggle() {} },
        getBoundingClientRect: () => ({ top: 0, bottom: 10, left: 0 }),
    };
    const document = {
        body: { appendChild() {} },
        addEventListener: (type, fn) => { (docListeners[type] = docListeners[type] || []).push(fn); },
        getElementById: () => menu,
        createElement: () => {
            const listeners = {};
            menu = {
                className: '', style: {}, listeners, innerHTML: '',
                classList: { contains: (c) => menu.className.split(' ').indexOf(c) >= 0 },
                setAttribute() {}, addEventListener: (type, fn) => { listeners[type] = fn; }, querySelector: () => null, hidePopover() {},
            };
            return menu;
        },
        querySelectorAll: (sel) => {
            if (sel === '.ures-table, .opt-table') return [table];
            if (sel === '[data-sort-area="results"]') return [btn];
            return [];
        },
    };
    new Function('document', 'localStorage', 'window', sortSource)(document, noStorage, Object.assign(window, { innerHeight: 800, innerWidth: 1000 }));
    docListeners.DOMContentLoaded.forEach((fn) => fn());
    const toggle = (state) => docListeners.beforetoggle.forEach((fn) => fn({ target: menu, newState: state }));
    const act = (name) => {
        const row = { getAttribute: () => 'name' };
        const control = { disabled: false, getAttribute: () => name, closest: () => row };
        menu.listeners.click({ target: { closest: () => control } });
    };
    return {
        open: () => { btnListeners.click({ stopPropagation() {} }); toggle('open'); },
        close: () => toggle('closed'),
        act,
    };
}

test('the sort menu counts each open, and each pick by a closed word', () => {
    const { BAN, calls } = fakeBAN();
    const m = sortMenu({ BAN });
    m.open();
    m.close();
    ['toggle', 'dir', 'up', 'down', 'clear', 'constructor', 'toString'].forEach(m.act);
    expect(calls).toEqual(['sort_menu', 'sort_key', 'sort_dir', 'sort_move', 'sort_move', 'sort_clear'].map((v) => ['ui.upload.result', v, undefined]));
});

test('with no window.BAN every one of these still runs', () => {
    expect(() => sortable({})()).not.toThrow();
    expect(() => { const m = sortMenu({}); m.open(); m.act('toggle'); m.act('clear'); }).not.toThrow();
    const r = pack({ rows: [['a', 1]], results: true });
    r.window.addRowsToBackpack(r.toolbar.add);
    expect(ids['backpack-toast'].textContent).toBe('Added 1 copy to the backpack');
    const { fns, btn } = printings({});
    fns.toggleRemoveRow(btn);
    expect(btn.closest().classList.contains('ures-removed-row')).toBe(true);
    const o = optimizer({});
    expect(() => { o.change(o.rowCheck); o.change(o.master); o.click({ closest: (sel) => (sel === '.opt-copy' ? {} : null) }); }).not.toThrow();
    const p = pack({ rows: [['a', 1]] });
    p.window.addRowsToBackpack(p.add);
    expect(ids['backpack-toast'].textContent).toBe('Added 1 copy to the backpack');
});

// upload-store-prompt.js: Publish counts only once its required fields let it post.
const promptSource = read('js/upload-store-prompt.js');
function storePrompt(window, name) {
    const fields = { store_name: { value: name, focus() {} }, store_shorthand: { value: 'BOB', focus() {} } };
    const overlay = {
        classList: { add() {}, remove() {} },
        querySelector: (sel) => fields[sel.match(/name="([^"]+)"/)[1]],
        querySelectorAll: () => [],
    };
    let posted = 0;
    const form = { querySelectorAll: () => [], appendChild() {}, submit() { posted++; } };
    const document = {
        getElementById: (id) => (id === 'store-overlay' ? overlay : id === 'upload_form' ? form : { value: '' }),
        addEventListener() {},
        createElement: () => ({}),
    };
    const { runPublishStore } = new Function('window', 'document', 'ensureHashesLoaded', 'resExportFields', promptSource + '\nreturn {runPublishStore};')(
        window, document, () => {}, []);
    runPublishStore();
    return () => posted;
}

test('Publish counts submit once it posts; a missing name counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    expect(storePrompt({ BAN }, '  ')()).toBe(0);
    expect(calls).toEqual([]);
    expect(storePrompt({ BAN }, 'Bob')()).toBe(1);
    expect(calls).toEqual([['ui.upload.publish', 'submit', undefined]]);
    expect(storePrompt({}, 'Bob')()).toBe(1);
});

// upload-share.js over a stub fetch and clipboard; flushes settle by microtasks alone.
const shareSource = read('js/upload-share.js');
function sharing({ status = 201, body = { url: '/upload/shared/abc' }, clipboard = () => Promise.resolve() } = {}) {
    const { BAN, calls } = fakeBAN();
    const window = { BAN, location: { origin: 'https://example.test' }, packRows: () => 'rows' };
    const fetch = () => Promise.resolve({ status, json: () => Promise.resolve(body) });
    const document = { getElementById: () => null };
    new Function('window', 'document', 'fetch', 'navigator', 'setTimeout', 'packRows', shareSource)(
        window, document, fetch, { clipboard: { writeText: clipboard } }, () => {}, window.packRows);
    const link = () => ({ innerHTML: 'Share', title: '', closest: () => ({ querySelectorAll: () => [] }) });
    return { window, calls, link };
}
const settle = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };

test('a share counts once the link is copied, by list or section', async () => {
    const s = sharing();
    s.window.copyShareLink(s.link());
    s.window.copySectionShareLink(s.link());
    await settle();
    expect(s.calls).toEqual([['ui.upload.share', 'list', undefined], ['ui.upload.share', 'section', undefined]]);
});

test('a refused share counts nothing', async () => {
    const s = sharing({ status: 429, body: { error: 'too many' } });
    s.window.copyShareLink(s.link());
    await settle();
    expect(s.calls).toEqual([]);
});

test('a refused clipboard write counts nothing', async () => {
    const s = sharing({ clipboard: () => Promise.reject(new Error('denied')) });
    s.window.copyShareLink(s.link());
    await settle();
    expect(s.calls).toEqual([]);
});

test('a second click while the first is pending counts nothing', async () => {
    const s = sharing();
    const el = s.link();
    s.window.copyShareLink(el);
    s.window.copyShareLink(el);
    await settle();
    expect(s.calls).toEqual([['ui.upload.share', 'list', undefined]]);
});

test('the upload page carries no share mark: the script counts a copied link', () => {
    expect(upload).not.toContain('data-track="ui.upload.share"');
});
