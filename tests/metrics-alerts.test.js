import { test, expect } from 'bun:test';
import { read, fakeBAN } from './metrics-helpers.js';
import { registry } from './track-registry.js';

const source = read('js/alerts.js');

// A stand-in element, as tests/alerts-open-race.test.js builds it.
function element() {
    const classes = new Set();
    const attrs = {};
    const children = {};
    const listeners = {};
    const el = {
        listeners,
        textContent: '', innerHTML: '', value: '', hidden: false, disabled: false,
        classList: {
            add: c => classes.add(c), remove: c => classes.delete(c),
            toggle: (c, on) => { on ? classes.add(c) : classes.delete(c); },
            contains: c => classes.has(c),
        },
        getAttribute: name => (name in attrs ? attrs[name] : null),
        setAttribute: (name, v) => { attrs[name] = String(v); },
        removeAttribute: name => { delete attrs[name]; },
        querySelector: sel => children[sel] || (children[sel] = element()),
        querySelectorAll: () => [],
        closest: () => element(),
        appendChild: () => {}, focus: () => {}, contains: () => true,
        addEventListener: (type, fn) => { listeners[type] = fn; },
    };
    el.elements = new Proxy({}, { get: (t, name) => t[name] || (t[name] = element()) });
    return el;
}

// Loads js/alerts.js as tests/alerts-open-race.test.js does, with window.BAN added.
// ids names the alerts-* elements the page has; select answers document.querySelector.
function load({ ids = [], select = {}, selectAll = {}, ban = true, confirmDialog } = {}) {
    const byId = {};
    const el = id => ((id.startsWith('alerts-') && !ids.includes(id)) ? null : byId[id] || (byId[id] = element()));
    const listeners = {};
    const document = {
        addEventListener: (type, fn) => { listeners[type] = fn; },
        getElementById: el,
        querySelector: sel => select[sel] || null,
        querySelectorAll: sel => selectAll[sel] || [],
        createElement: () => element(),
        body: element(),
    };
    const f = fakeBAN();
    const reloads = [];
    const window = { localStorage: { getItem: () => null, setItem() {} }, location: { reload: () => reloads.push(f.calls.length) } };
    if (ban) window.BAN = f.BAN;
    if (confirmDialog) window.confirmDialog = confirmDialog;
    const calls = [];
    const fetch = (path, opts) => new Promise(resolve => {
        calls.push({ path, method: opts && opts.method, answer: data => resolve({
            status: 200, ok: true,
            headers: { get: () => 'application/json' },
            json: () => Promise.resolve(data),
        }), refuse: () => resolve({
            status: 500, ok: false,
            headers: { get: () => 'application/json' },
            json: () => Promise.resolve({ error: 'refused' }),
        }) });
    });
    new Function('window', 'document', 'fetch', source)(window, document, fetch);
    return { window, el, calls, reloads, track: f.calls, ready: () => listeners.DOMContentLoaded(), key: e => listeners.keydown(e) };
}

const settle = () => new Promise(r => setTimeout(r, 0));
const mine = (track, name) => track.filter(c => c[0] === name);
const options = { card: { name: 'Card', set: 'SET', number: '1', finish: 'nonfoil' }, conditions: ['NM'], stores: [{ shorthand: 'X', name: 'X', prices: { NM: 10 } }] };

async function openLoaded(a) {
    a.window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    a.calls[0].answer(options);
    await settle();
    a.calls[1].answer([]);
    await settle();
    a.calls[2].answer([]);
    await settle();
}
const modalClick = (a, closest) => a.el('alert-modal').listeners.click({ target: { closest } });
const role = name => sel => (sel === '[data-role]' ? { getAttribute: () => name } : null);

test('the modal counts open with where it is', () => {
    const search = load();
    search.window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    expect(mine(search.track, 'ui.alerts.modal')).toEqual([['ui.alerts.modal', 'open', 'search']]);
    const page = load({ ids: ['alerts-page'] });
    page.window.openAlertModal({ alertId: '7' });
    expect(mine(page.track, 'ui.alerts.modal')).toEqual([['ui.alerts.modal', 'open', 'alerts_page']]);
});

test('a save counts save and not cancel', async () => {
    const a = load();
    a.ready();
    await openLoaded(a);
    modalClick(a, sel => (sel === '.settings-pill[data-value]' ? { getAttribute: () => 'abs', parentNode: { getAttribute: () => 'above_kind' } } : null));
    a.el('alert-form').elements.above_value.value = '5';
    modalClick(a, role('save'));
    expect(a.calls[3].method).toBe('POST');
    a.calls[3].answer({});
    await settle();
    expect(mine(a.track, 'ui.alerts.modal')).toEqual([['ui.alerts.modal', 'open', 'search'], ['ui.alerts.modal', 'save', 'search']]);
    expect(a.el('alert-modal').classList.contains('open')).toBe(false);
});

test('a save the form refuses counts nothing and the modal stays open', async () => {
    const a = load();
    a.ready();
    await openLoaded(a);
    modalClick(a, role('save'));
    expect(a.calls.length).toBe(3);
    expect(mine(a.track, 'ui.alerts.modal')).toEqual([['ui.alerts.modal', 'open', 'search']]);
});

test('Cancel, the backdrop and Escape each count one cancel', async () => {
    const a = load({ ids: ['alerts-page'] });
    a.ready();
    a.window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    modalClick(a, role('cancel'));
    a.window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    a.el('alert-modal-backdrop').listeners.click({});
    a.window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    a.key({ key: 'Escape', preventDefault() {} });
    expect(mine(a.track, 'ui.alerts.modal').filter(c => c[1] === 'cancel')).toEqual([
        ['ui.alerts.modal', 'cancel', 'alerts_page'], ['ui.alerts.modal', 'cancel', 'alerts_page'], ['ui.alerts.modal', 'cancel', 'alerts_page'],
    ]);
});

test('closing a modal that is not open counts nothing', () => {
    const a = load();
    a.ready();
    a.window.closeAlertModal();
    a.window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    a.window.closeAlertModal();
    a.window.closeAlertModal();
    expect(mine(a.track, 'ui.alerts.modal').filter(c => c[1] === 'cancel').length).toBe(1);
});

// A table whose buttons each name an action on alert 7.
function rowClick(table, action) {
    const row = { getAttribute: k => ({ 'data-id': '7', 'data-card-id': 'card-a', 'data-side': 'retail' })[k] || null };
    const btn = { getAttribute: () => action, closest: () => row };
    table.listeners.click({ target: { closest: sel => (sel === 'button[data-action]' ? btn : null) } });
}

test('pause and resume count once the server answers; delete once it answers after the confirm', async () => {
    const table = element();
    let confirmed = null;
    const a = load({ ids: ['alerts-page'], select: { '.alerts-table': table }, confirmDialog: (msg, run) => { confirmed = run; } });
    a.ready();
    rowClick(table, 'pause');
    rowClick(table, 'resume');
    rowClick(table, 'delete');
    expect(mine(a.track, 'ui.alerts.row')).toEqual([]);
    a.calls[0].answer({});
    a.calls[1].answer({});
    await settle();
    expect(mine(a.track, 'ui.alerts.row')).toEqual([['ui.alerts.row', 'pause', undefined], ['ui.alerts.row', 'resume', undefined]]);
    confirmed();
    expect(mine(a.track, 'ui.alerts.row').map(c => c[1])).toEqual(['pause', 'resume']);
    a.calls[2].answer({});
    await settle();
    expect(mine(a.track, 'ui.alerts.row').map(c => c[1])).toEqual(['pause', 'resume', 'delete']);
    // Each count lands before its reload.
    expect(a.reloads).toEqual([1, 2, 3]);
    rowClick(table, 'edit');
    expect(mine(a.track, 'ui.alerts.row').map(c => c[1])).toEqual(['pause', 'resume', 'delete', 'edit']);
    expect(mine(a.track, 'ui.alerts.modal')).toEqual([['ui.alerts.modal', 'open', 'alerts_page']]);
});

test('a delete whose confirm never answers counts nothing', () => {
    const table = element();
    const a = load({ select: { '.alerts-table': table }, confirmDialog: () => {} });
    a.ready();
    rowClick(table, 'delete');
    expect(mine(a.track, 'ui.alerts.row')).toEqual([]);
});

test('delete all counts once, when the server answers after the confirm', async () => {
    const button = element();
    let confirmed = null;
    const a = load({ select: { '.alerts-delete-all': button }, confirmDialog: (msg, run) => { confirmed = run; } });
    a.ready();
    button.listeners.click();
    expect(mine(a.track, 'ui.alerts.row')).toEqual([]);
    confirmed();
    expect(mine(a.track, 'ui.alerts.row')).toEqual([]);
    a.calls[0].answer({ deleted: 0 });
    await settle();
    expect(mine(a.track, 'ui.alerts.row')).toEqual([['ui.alerts.row', 'delete_all', undefined]]);
    expect(a.reloads).toEqual([1]);
});

test('a refused row action or delete all toasts and counts nothing', async () => {
    const table = element();
    const button = element();
    const a = load({ ids: ['alerts-page', 'alerts-toast'], select: { '.alerts-table': table, '.alerts-delete-all': button }, confirmDialog: (msg, run) => run() });
    a.ready();
    rowClick(table, 'pause');
    rowClick(table, 'delete');
    button.listeners.click();
    a.calls.forEach(c => c.refuse());
    await settle();
    expect(a.calls.length).toBe(3);
    expect(mine(a.track, 'ui.alerts.row')).toEqual([]);
    expect(a.reloads).toEqual([]);
    expect(a.el('alerts-toast').textContent).toBe('refused');
});

test('the sort reports its field and direction from the menu and from a header', () => {
    const th = element();
    th.setAttribute('data-sort', 'now');
    const a = load({ ids: ['alerts-sort'], selectAll: { '.alerts-table th[data-sort]': [th] } });
    const pick = a.el('alerts-sort');
    a.ready();
    expect(mine(a.track, 'ui.alerts.sort')).toEqual([]);
    pick.value = 'now:desc';
    pick.listeners.change();
    expect(mine(a.track, 'ui.alerts.sort')).toEqual([['ui.alerts.sort', 'now', 'desc']]);
    th.listeners.click();
    expect(mine(a.track, 'ui.alerts.sort')[1]).toEqual(['ui.alerts.sort', 'now', 'asc']);
    th.listeners.keydown({ key: 'Enter', preventDefault() {} });
    expect(mine(a.track, 'ui.alerts.sort')[2]).toEqual(['ui.alerts.sort', 'now', 'desc']);
});

test('a held key flips the header sort on each repeat and counts only a fresh press', () => {
    const th = element();
    th.setAttribute('data-sort', 'now');
    const a = load({ selectAll: { '.alerts-table th[data-sort]': [th] }, ids: ['alerts-sort'] });
    a.ready();
    const pick = a.el('alerts-sort');
    th.listeners.keydown({ key: 'Enter', repeat: false, preventDefault() {} });
    expect(mine(a.track, 'ui.alerts.sort')).toEqual([['ui.alerts.sort', 'now', 'desc']]);
    th.listeners.keydown({ key: 'Enter', repeat: true, preventDefault() {} });
    expect(pick.value).toBe('now:asc');
    expect(mine(a.track, 'ui.alerts.sort').length).toBe(1);
});

test('each channel button counts its action; a click outside a button counts nothing', () => {
    const a = load({ ids: ['alerts-channels'] });
    a.ready();
    const box = a.el('alerts-channels');
    const press = action => {
        try {
            box.listeners.click({ target: { closest: () => (action ? { getAttribute: () => action, closest: () => null } : null) } });
        } catch (e) { /* the stand-ins do not draw the channels box */ }
    };
    press(null);
    press('bogus');
    press('constructor');
    const actions = ['change', 'cancel', 'add', 'save', 'resend', 'remove', 'enable'];
    actions.forEach(press);
    expect(mine(a.track, 'ui.alerts.channel').map(c => c[1])).toEqual(actions);
    expect(registry['ui.alerts.channel'].enum).toEqual(actions);
});

test('with no BAN the modal opens, cancels and saves', async () => {
    const a = load({ ban: false });
    a.ready();
    await openLoaded(a);
    modalClick(a, role('cancel'));
    expect(a.el('alert-modal').classList.contains('open')).toBe(false);
});

test('every value and scope the script sends is registered', () => {
    expect(registry['ui.alerts.modal'].enum).toEqual(['open', 'save', 'cancel']);
    expect(registry['ui.alerts.modal'].scopes).toEqual(['alerts_page', 'search']);
    expect(registry['ui.alerts.row'].enum).toEqual(['edit', 'pause', 'resume', 'delete', 'delete_all']);
    expect(registry['ui.alerts.sort'].enum).toEqual(['created', 'name', 'now', 'fired', 'status', 'side']);
});
