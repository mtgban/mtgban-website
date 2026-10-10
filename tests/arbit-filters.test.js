import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/arbit-filters.js', import.meta.url), 'utf8');

function load(cfg, form = null, elements = {}, saved = {}) {
    const listeners = {};
    const window = {
        BAN_ARBIT: cfg,
        location: { href: '' },
        addEventListener: (ev, fn) => { listeners['window:' + ev] = fn; },
    };
    const document = { getElementById: (id) => (id === 'arbFilters' ? form : elements[id] || null) };
    const cookies = [];
    const writeCookie = (...args) => cookies.push(args);
    // What the form would submit, as pairs, standing in for a real form's
    class FormData {
        constructor(f) { this.pairs = (f && f.pairs) || []; }
        [Symbol.iterator]() { return this.pairs[Symbol.iterator](); }
    }
    // getCookie hands back the value decoded, as cookies.js does
    const getCookie = (name) => (name in saved ? saved[name] : '');
    new Function('window', 'document', 'writeCookie', 'getCookie', 'FormData', source)(window, document, writeCookie, getCookie, FormData);
    return { window, listeners, cookies };
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

function fakeForm(values, groups = []) {
    const inputs = values.map((value) => ({ value, disabled: false }));
    const listeners = {};
    const all = () => inputs.concat(...groups.map((g) => g.querySelectorAll('input')));
    return {
        inputs,
        listeners,
        querySelectorAll: (sel) => (sel === 'input[type=number]' ? inputs : sel === '[data-pick]' ? groups : all()),
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
