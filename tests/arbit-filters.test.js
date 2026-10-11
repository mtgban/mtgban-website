import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/arbit-filters.js', import.meta.url), 'utf8');

function load(cfg, form = null, elements = {}, saved = {}, env = {}) {
    const listeners = {};
    const reloads = [];
    const window = {
        BAN_ARBIT: cfg,
        location: { href: '', search: env.search || '', reload: () => reloads.push(1) },
        addEventListener: (ev, fn) => { listeners['window:' + ev] = fn; },
        UserState: env.userState,
    };
    const localStorage = env.local || fakeStorage();
    const sessionStorage = env.session || fakeStorage();
    const document = { getElementById: (id) => (id === 'arbFilters' ? form : elements[id] || null) };
    const cookies = [];
    const writeCookie = (...args) => {
        cookies.push(args);
        saved[args[0]] = decodeURIComponent(args[1]);
    };
    // What the form would submit, as pairs, standing in for a real form's
    class FormData {
        constructor(f) { this.pairs = (f && f.pairs) || []; }
        [Symbol.iterator]() { return this.pairs[Symbol.iterator](); }
    }
    // getCookie hands back the value decoded, as cookies.js does
    const getCookie = (name) => (name in saved ? saved[name] : '');
    new Function('window', 'document', 'writeCookie', 'getCookie', 'FormData', 'localStorage', 'sessionStorage', source)(
        window, document, writeCookie, getCookie, FormData, localStorage, sessionStorage);
    return { window, listeners, cookies, reloads, localStorage };
}

function fakeStorage(initial = {}) {
    const m = Object.assign({}, initial);
    return {
        getItem: (k) => (k in m ? m[k] : null),
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
        _map: m,
    };
}

// The saved query a writeCookie call carries, less its time.
function savedQuery(call) {
    const value = decodeURIComponent(call[1]);
    expect(value).toMatch(/(^|&)t=\d+$/);
    return value.replace(/&?t=\d+$/, '');
}

function fakeGroup(checked) {
    const boxes = checked.map((c) => ({ checked: c, disabled: false }));
    const marker = { disabled: false };
    return {
        boxes,
        marker,
        querySelectorAll: (sel) => (sel === 'input[type=checkbox]' ? boxes : boxes.concat([marker])),
    };
}

// values are the number fields in order, named n0, n1...; carries are the
// saved values carried beside them, by field name.
function fakeForm(values, groups = [], carries = {}) {
    const inputs = values.map((value, i) => ({ name: 'n' + i, value, disabled: false }));
    const carried = [];
    const parent = { removeChild: (c) => carried.splice(carried.indexOf(c), 1) };
    Object.keys(carries).forEach((name) => carried.push({ name, value: carries[name], disabled: false, parentNode: parent }));
    // Each carry's clear button, its click listener kept as click
    const clears = Object.keys(carries).map((name) => ({
        parentNode: { hidden: false },
        getAttribute: () => name,
        addEventListener(ev, fn) { this[ev] = fn; },
    }));
    const listeners = {};
    const all = () => inputs.concat(...groups.map((g) => g.querySelectorAll('input')));
    return {
        inputs,
        carried,
        clears,
        listeners,
        querySelectorAll: (sel) => (sel === 'input[type=number]' ? inputs : sel === '[data-pick]' ? groups
            : sel === 'input[data-limit]' ? carried.slice() : sel === '[data-limit-clear]' ? clears : all()),
        querySelector: (sel) => inputs.concat(carried).find((i) => sel === 'input[type=number][name="' + i.name + '"]' && inputs.includes(i)
            || sel === 'input[data-limit][name="' + i.name + '"]' && carried.includes(i)) || null,
        addEventListener: (ev, fn) => { listeners[ev] = fn; },
    };
}

test('a sort link keeps the source and the filters, lands on the table, and saves the sort', () => {
    const saved = { ArbitFilters: 'cond=NM%2CSP&f=1&minsell=2&t=1' };
    const { window, cookies } = load({ source: 'CK', query: 'cond=NM%2CSP&f=1&minsell=2', cookie: 'ArbitFilters' }, null, {}, saved);
    window.sortBy('spread', 'Star City Games');
    expect(window.location.href).toBe('?source=CK&cond=NM%2CSP&f=1&minsell=2&sort=spread#Star City Games');
    expect(cookies.length).toBe(1);
    expect(cookies[0][0]).toBe('ArbitFilters');
    expect(cookies[0].slice(2)).toEqual([1000, '/']);
    expect(savedQuery(cookies[0])).toBe('cond=NM%2CSP&f=1&minsell=2&sort=spread');
});

test('sorting a page opened from someone else\'s link saves only the sort', () => {
    const saved = { ArbitFilters: 'f=1&minsell=2&sort=diff&t=1' };
    const { window, cookies } = load({ source: 'CK', query: 'f=1&minsell=9', cookie: 'ArbitFilters' }, null, {}, saved);
    window.sortBy('spread', 'X');
    expect(window.location.href).toBe('?source=CK&f=1&minsell=9&sort=spread#X');
    expect(savedQuery(cookies[0])).toBe('f=1&minsell=2&sort=spread');
});

test('sorting with nothing saved saves the sort alone', () => {
    const { window, cookies } = load({ source: 'CK', query: 'f=1&minsell=9', cookie: 'ArbitFilters' });
    window.sortBy('alpha', 'X');
    expect(savedQuery(cookies[0])).toBe('f=1&sort=alpha');
});

test('a sort link with no filters carries the source alone', () => {
    const { window } = load({ source: 'CK', query: '' });
    expect(window.ArbitFilters.sortURL('alpha', 'X')).toBe('?source=CK&sort=alpha#X');
});

test('submitting leaves empty limits out, and coming back re-enables them', () => {
    const form = fakeForm(['', '5', '']);
    const { listeners } = load({ source: 'CK', query: '' }, form);
    form.listeners.submit();
    expect(form.inputs.map((i) => i.disabled)).toEqual([true, false, true]);
    listeners['window:pageshow']();
    expect(form.inputs.map((i) => i.disabled)).toEqual([false, false, false]);
});

test('a field left empty posts the saved value carried beside it, and a typed one replaces it', () => {
    const form = fakeForm(['', '7'], [], { n0: '-50', n1: '-3' });
    const { listeners } = load({ source: 'CK', query: '' }, form);
    form.listeners.submit();
    expect(form.inputs.map((i) => i.disabled)).toEqual([true, false]);
    expect(form.carried.map((i) => i.disabled)).toEqual([false, true]);
    listeners['window:pageshow']();
    expect(form.carried.map((i) => i.disabled)).toEqual([false, false]);
});

test('clearing a carried limit drops it from the form and hides its note', () => {
    const form = fakeForm(['', ''], [], { n0: '-50', n1: '-3' });
    load({ source: 'CK', query: '' }, form);
    form.clears[0].click();
    expect(form.carried.map((c) => c.name)).toEqual(['n1']);
    expect(form.clears.map((b) => b.parentNode.hidden)).toEqual([true, false]);
});

test('a picker with every box ticked posts nothing, one with a box unticked posts all of it', () => {
    const full = fakeGroup([true, true, true]);
    const partial = fakeGroup([true, false, true]);
    const form = fakeForm([], [full, partial]);
    const { listeners } = load({ source: 'CK', query: '' }, form);
    form.listeners.submit();
    expect(full.boxes.every((b) => b.disabled) && full.marker.disabled).toBe(true);
    expect(partial.boxes.some((b) => b.disabled) || partial.marker.disabled).toBe(false);
    listeners['window:pageshow']();
    expect(full.boxes.some((b) => b.disabled) || full.marker.disabled).toBe(false);
});

test('the toggle opens and closes the bar, and remembers it site-wide', () => {
    const attrs = {};
    let onClick;
    const toggle = { setAttribute: (k, v) => { attrs[k] = v; }, addEventListener: (ev, fn) => { onClick = fn; } };
    const panel = { hidden: true };
    const { cookies } = load({ source: 'CK', query: '' }, null, { arbFilterToggle: toggle, arbFilterPanel: panel });
    onClick();
    expect(panel.hidden).toBe(false);
    expect(attrs['aria-expanded']).toBe('true');
    onClick();
    expect(panel.hidden).toBe(true);
    expect(attrs['aria-expanded']).toBe('false');
    expect(cookies).toEqual([['ArbitFiltersOpen', '1', 1000, '/'], ['ArbitFiltersOpen', '', 1000, '/']]);
});

test('applying saves what the form submits, less the source', () => {
    const form = fakeForm([]);
    form.pairs = [['source', 'CK'], ['f', '1'], ['cond_on', '1'], ['cond', 'NM'], ['cond', 'SP'], ['minsell', '2']];
    const { cookies } = load({ source: 'CK', query: '', cookie: 'GlobalFilters' }, form);
    form.listeners.submit();
    expect(cookies.length).toBe(1);
    expect(cookies[0][0]).toBe('GlobalFilters');
    expect(savedQuery(cookies[0])).toBe('f=1&cond_on=1&cond=NM&cond=SP&minsell=2');
});

test('restoring the defaults saves them as the latest state', () => {
    let onClick;
    const reset = { addEventListener: (ev, fn) => { onClick = fn; } };
    const { cookies } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, { arbFilterReset: reset });
    onClick();
    expect(savedQuery(cookies[0])).toBe('f=1');
});

test('a page with no cookie to save in saves nothing', () => {
    const { window, cookies } = load({ source: 'CK', query: 'f=1' });
    window.sortBy('alpha', 'X');
    expect(cookies).toEqual([]);
});

test('a save keeps the synced copy with the same time as the cookie', () => {
    const local = fakeStorage({ mtgban_arbit_filters: JSON.stringify({ global: { q: 'f=1&minsell=7', t: 5 } }) });
    const { window, cookies, localStorage } = load({ source: 'CK', query: 'f=1', cookie: 'ArbitFilters' }, null, {}, {}, { local });
    window.ArbitFilters.save('f=1&minsell=2');
    const stored = JSON.parse(localStorage.getItem('mtgban_arbit_filters'));
    expect(stored.global).toEqual({ q: 'f=1&minsell=7', t: 5 });
    expect(stored.arbit.q).toBe('f=1&minsell=2');
    expect(decodeURIComponent(cookies[cookies.length - 1][1])).toBe('f=1&minsell=2&t=' + stored.arbit.t);
});

test('a save is stamped on the server\'s clock where a sync has read it', () => {
    const local = fakeStorage();
    const { window, cookies, localStorage } = load({ source: 'CK', query: 'f=1', cookie: 'ArbitFilters' }, null, {}, {},
        { local, userState: { now: () => 4242, clamp: (t) => t, later: (a, b) => a > b } });
    window.ArbitFilters.save('f=1&minsell=2');
    expect(decodeURIComponent(cookies[0][1])).toBe('f=1&minsell=2&t=4242');
    expect(JSON.parse(localStorage.getItem('mtgban_arbit_filters')).arbit.t).toBe(4242);
});

test('filters applied later on another device reach the cookies, and the page reloads once', () => {
    const synced = { arbit: { q: 'f=1&minsell=9', t: 200 }, global: { q: 'f=1&minsell=7', t: 50 } };
    const local = fakeStorage({ mtgban_arbit_filters: JSON.stringify(synced) });
    const session = fakeStorage();
    const saved = { ArbitFilters: 'f=1&minsell=2&t=100', GlobalFilters: 'f=1&minsell=3&t=60' };
    const { cookies, reloads } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {}, saved, { local, session });
    expect(cookies.map((c) => [c[0], decodeURIComponent(c[1])])).toEqual([['ArbitFilters', 'f=1&minsell=9&t=200']]);
    expect(reloads.length).toBe(1);

    // Drawn again from the same older cookie, as when cookies are blocked
    const again = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {}, { ArbitFilters: 'f=1&minsell=2&t=100' }, { local, session });
    expect(again.reloads.length).toBe(0);
});

test('a page opened from a link, or drawn from the newest state, does not reload', () => {
    const local = fakeStorage({ mtgban_arbit_filters: JSON.stringify({ arbit: { q: 'f=1&minsell=9', t: 200 } }) });
    const linked = load({ source: 'CK', query: 'f=1&minsell=4', cookie: 'ArbitFilters' }, null, {}, {}, { local, search: '?source=CK&f=1&minsell=4' });
    expect(linked.reloads.length).toBe(0);
    expect(linked.cookies.map((c) => c[0])).toEqual(['ArbitFilters']);
    const current = load({ source: 'CK', query: 'f=1&minsell=9', cookie: 'ArbitFilters' }, null, {}, { ArbitFilters: 'f=1&minsell=9&t=200' }, { local });
    expect(current.reloads.length).toBe(0);
    expect(current.cookies.length).toBe(0);
});

test('a cookie the synced copy never held is copied into it, without a reload', () => {
    const local = fakeStorage({ mtgban_arbit_filters: JSON.stringify({ global: { q: 'f=1&minsell=7', t: 300 } }) });
    const saved = { ArbitFilters: 'cond=NM%2CSP&f=1&minsell=2&t=100', GlobalFilters: 'f=1&minsell=3&t=50' };
    const { cookies, reloads, localStorage } = load({ source: 'CK', query: 'cond=NM%2CSP&f=1&minsell=2', cookie: 'ArbitFilters' }, null, {}, saved, { local });
    const stored = JSON.parse(localStorage.getItem('mtgban_arbit_filters'));
    expect(stored.arbit).toEqual({ q: 'cond=NM%2CSP&f=1&minsell=2', t: 100 });
    expect(stored.global).toEqual({ q: 'f=1&minsell=7', t: 300 });
    // The older Global cookie still comes up to the synced copy
    expect(cookies.map((c) => [c[0], decodeURIComponent(c[1])])).toEqual([['GlobalFilters', 'f=1&minsell=7&t=300']]);
    expect(reloads.length).toBe(0);
});

test('nothing is copied either way where the two agree', () => {
    const local = fakeStorage({ mtgban_arbit_filters: JSON.stringify({ arbit: { q: 'f=1&minsell=2', t: 100 } }) });
    let writes = 0;
    const counting = Object.assign({}, local, { setItem: (k, v) => { writes++; local.setItem(k, v); } });
    const { cookies } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {}, { ArbitFilters: 'f=1&minsell=2&t=100' }, { local: counting });
    expect(cookies.length).toBe(0);
    expect(writes).toBe(0);
});

// The clock user-state.js keeps, loaded signed out so that it reads the
// device's own
function deviceUserState() {
    const window = { addEventListener() {} };
    const source = readFileSync(new URL('../js/user-state.js', import.meta.url), 'utf8');
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        window, { cookie: '', readyState: 'complete', addEventListener() {} }, fakeStorage(), fakeStorage(), null, { mtime: () => 0 });
    return window.UserState;
}

test('a cookie stamped ahead of the clock loses to synced filters on it, which a merge settled', () => {
    const hour = 60 * 60 * 1000, onTime = Date.now() - 60 * 1000, ahead = Date.now() + hour;
    const local = fakeStorage({ mtgban_arbit_filters: JSON.stringify({ arbit: { q: 'f=1&minsell=9', t: onTime } }) });
    const saved = { ArbitFilters: 'f=1&minsell=2&t=' + ahead };
    const { cookies, localStorage, reloads } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {}, saved,
        { local, userState: deviceUserState() });
    expect(JSON.parse(localStorage.getItem('mtgban_arbit_filters')).arbit).toEqual({ q: 'f=1&minsell=9', t: onTime });
    expect(cookies.map((c) => [c[0], decodeURIComponent(c[1])])).toEqual([['ArbitFilters', 'f=1&minsell=9&t=' + onTime]]);
    expect(reloads.length).toBe(1);
});

// Runs user-state.js's sync of a device's saved filters with the server's,
// a dirty device's merge or a clean one's hydrate, and returns its storage
// and clock for the page to load with.
async function mergedFilters(local, server, dirty = true) {
    const source = readFileSync(new URL('../js/user-state.js', import.meta.url), 'utf8');
    const storage = fakeStorage(Object.assign({ mtgban_arbit_filters: JSON.stringify(local) }, dirty ? { mtgban_userstate_dirty: '1' } : {}));
    const state = { version: 3, favorites: [], recents: [], preferences: { mtgban_arbit_filters: JSON.stringify(server) } };
    const window = { addEventListener() {} };
    const fetch = () => Promise.resolve({ status: 200, ok: true, json: () => Promise.resolve(state) });
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', source)(
        window, { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} }, storage, fakeStorage(), fetch,
        { mtime: (x) => x.m || x.t || 0, tombstones: () => [] }, () => 0, () => {});
    for (let i = 0; i < 20; i++) await Promise.resolve();
    return { local: storage, userState: window.UserState };
}

test('filters applied signed out on a fast clock survive signing in', async () => {
    const ahead = Date.now() + 60 * 60 * 1000;
    // Signed out, a save writes the cookie and the saved copy but marks nothing to sync
    const { local, userState } = await mergedFilters(
        { arbit: { q: 'f=1&minsell=2', t: ahead } },
        { arbit: { q: 'f=1&minsell=9', t: Date.now() - 60 * 1000 } }, false);
    const { cookies, localStorage, reloads } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {},
        { ArbitFilters: 'f=1&minsell=2&t=' + ahead }, { local, userState });
    expect(JSON.parse(localStorage.getItem('mtgban_arbit_filters')).arbit.q).toBe('f=1&minsell=2');
    expect(savedQuery(cookies[cookies.length - 1])).toBe('f=1&minsell=2');
    expect(reloads.length).toBe(0);
});

test('filters a merge picked between two copies ahead of the clock hold against the losing cookie', async () => {
    const hour = 60 * 60 * 1000, mine = Date.now() + hour;
    const { local, userState } = await mergedFilters(
        { arbit: { q: 'f=1&minsell=2', t: mine } },
        { arbit: { q: 'f=1&minsell=9', t: mine + 5000 } });
    const { cookies, localStorage, reloads } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {},
        { ArbitFilters: 'f=1&minsell=2&t=' + mine }, { local, userState });
    const stored = JSON.parse(localStorage.getItem('mtgban_arbit_filters')).arbit;
    expect(stored.q).toBe('f=1&minsell=9');
    expect(Math.abs(stored.t - Date.now())).toBeLessThan(1000);
    expect(decodeURIComponent(cookies[cookies.length - 1][1])).toBe('f=1&minsell=9&t=' + stored.t);
    expect(reloads.length).toBe(1);
});

test('a cookie and a synced copy tied ahead of the clock both come back to it', () => {
    const ahead = Date.now() + 60 * 60 * 1000;
    const local = fakeStorage({ mtgban_arbit_filters: JSON.stringify({ arbit: { q: 'f=1&minsell=2', t: ahead } }) });
    const { cookies, localStorage, reloads } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {},
        { ArbitFilters: 'f=1&minsell=2&t=' + ahead }, { local, userState: deviceUserState() });
    const stored = JSON.parse(localStorage.getItem('mtgban_arbit_filters')).arbit;
    expect(stored.q).toBe('f=1&minsell=2');
    expect(Math.abs(stored.t - Date.now())).toBeLessThan(1000);
    expect(cookies.map((c) => [c[0], decodeURIComponent(c[1])])).toEqual([['ArbitFilters', 'f=1&minsell=2&t=' + stored.t]]);
    expect(reloads.length).toBe(0);
});

test('synced filters that beat the cookie both ahead of the clock reload the page to them', () => {
    const hour = 60 * 60 * 1000;
    const local = fakeStorage({ mtgban_arbit_filters: JSON.stringify({ arbit: { q: 'f=1&minsell=9', t: Date.now() + 2 * hour } }) });
    const cookieAt = Date.now() + hour;
    const { cookies, reloads } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {},
        { ArbitFilters: 'f=1&minsell=2&t=' + cookieAt }, { local, userState: deviceUserState() });
    expect(savedQuery(cookies[cookies.length - 1])).toBe('f=1&minsell=9');
    expect(reloads.length).toBe(1);
});

test('newer synced filters that read as the page\'s own restamp the cookie without a reload', () => {
    const local = fakeStorage({ mtgban_arbit_filters: JSON.stringify({ arbit: { q: 'f=1&minsell=2', t: 200 } }) });
    const { cookies, reloads } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {},
        { ArbitFilters: 'f=1&minsell=2&t=100' }, { local });
    expect(cookies.map((c) => [c[0], decodeURIComponent(c[1])])).toEqual([['ArbitFilters', 'f=1&minsell=2&t=200']]);
    expect(reloads.length).toBe(0);
});

test('a cookie stamped ahead of the clock, alone, is kept as made now', () => {
    const ahead = Date.now() + 60 * 60 * 1000;
    const { cookies, localStorage, reloads } = load({ source: 'CK', query: 'f=1&minsell=2', cookie: 'ArbitFilters' }, null, {},
        { ArbitFilters: 'f=1&minsell=2&t=' + ahead }, { userState: deviceUserState() });
    const stored = JSON.parse(localStorage.getItem('mtgban_arbit_filters')).arbit;
    expect(stored.q).toBe('f=1&minsell=2');
    expect(Math.abs(stored.t - Date.now())).toBeLessThan(1000);
    expect(cookies.map((c) => [c[0], decodeURIComponent(c[1])])).toEqual([['ArbitFilters', 'f=1&minsell=2&t=' + stored.t]]);
    expect(reloads.length).toBe(0);
});
