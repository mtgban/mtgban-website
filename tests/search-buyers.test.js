import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/search-buyers.js', import.meta.url), 'utf8');

// load runs the script over stubs, returning what it exports, its click
// listener and the cookies it set.
function load() {
    const listeners = [];
    const cookies = [];
    const document = { addEventListener: (type, fn) => listeners.push({ type, fn }) };
    const self = {};
    const setCookie = (...a) => cookies.push(a);
    new Function('document', 'self', 'setCookie', source)(document, self, setCookie);
    return { api: self.SearchBuyers, listeners, cookies };
}

// el is an element stub with attributes, classes and markup.
function el(attrs = {}, classes = []) {
    const a = { ...attrs };
    const c = new Set(classes);
    return {
        attrs: a,
        innerHTML: '',
        textContent: '',
        getAttribute: (k) => (k in a ? a[k] : null),
        setAttribute: (k, v) => { a[k] = String(v); },
        removeAttribute: (k) => { delete a[k]; },
        classList: { toggle: (k, on) => (on ? c.add(k) : c.delete(k)), has: (k) => c.has(k) },
    };
}

// page is a root holding columns, switch buttons and Sales panes, and the
// log-in prompt when prompt is given.
function page(panes, prompt) {
    const cols = [el({ 'data-buyers-mode': 'buylist' }), el({ 'data-buyers-mode': 'buylist' })];
    const buttons = [el({ 'data-buyers-set': 'buylist' }, ['on']), el({ 'data-buyers-set': 'sales' })];
    return {
        cols, buttons, panes,
        getElementById: (id) => (id === 'sales-login' && prompt ? { innerHTML: prompt } : null),
        querySelector: (sel) => (sel === '[data-buyers-mode="sales"]' ? cols.find((c) => c.attrs['data-buyers-mode'] === 'sales') || null : null),
        querySelectorAll: (sel) => {
            if (sel === '[data-buyers-mode]') return cols;
            if (sel === '[data-buyers-set]') return buttons;
            if (sel === '.sales-pane[data-pending], .sales-pane[data-failed]') {
                return panes.filter((p) => 'data-pending' in p.attrs || 'data-failed' in p.attrs);
            }
            return [];
        },
    };
}

const pending = (id) => el({ 'data-card': id, 'data-pending': '' });

test('a switch sets every column and button and remembers the mode', async () => {
    const { api, cookies } = load();
    const root = page([]);
    await api.choose(root, 'sales', () => { throw new Error('nothing to fetch'); });
    expect(root.cols.map((c) => c.attrs['data-buyers-mode'])).toEqual(['sales', 'sales']);
    expect(root.buttons.map((b) => b.classList.has('on'))).toEqual([false, true]);
    expect(root.buttons.map((b) => b.attrs['aria-pressed'])).toEqual(['false', 'true']);
    expect(cookies).toEqual([['SearchBuyersMode', 'sales', 1000]]);
});

test('the first switch to Sales fetches every pending card once, and fills it', async () => {
    const { api } = load();
    const root = page([pending('a'), pending('b'), pending('a'), el({ 'data-card': 'c' })]);
    const asked = [];
    const fetchFn = (url) => {
        asked.push(url);
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ a: '<i>A</i>', b: '<i>B</i>' }) });
    };
    await api.choose(root, 'sales', fetchFn);
    expect(asked).toEqual(['/data/sales/a,b']);
    expect(root.panes.map((p) => p.innerHTML)).toEqual(['<i>A</i>', '<i>B</i>', '<i>A</i>', '']);
    expect(root.panes.filter((p) => 'data-pending' in p.attrs)).toHaveLength(0);

    // Drawn already: switching back and again fetches nothing.
    await api.choose(root, 'buylist', fetchFn);
    await api.choose(root, 'sales', fetchFn);
    expect(asked).toHaveLength(1);
});

test('a failed fetch says so in each waiting pane, stops loading, and is asked again', async () => {
    const { api } = load();
    const root = page([pending('a')]);
    await api.choose(root, 'sales', () => Promise.resolve({ ok: false, status: 503 }));
    expect(root.panes[0].textContent).toBe('Recent sales could not be loaded.');
    // No longer pending, so the "Loading" line is gone.
    expect('data-pending' in root.panes[0].attrs).toBe(false);
    expect('data-failed' in root.panes[0].attrs).toBe(true);

    const asked = [];
    await api.choose(root, 'sales', (url) => {
        asked.push(url);
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ a: '<i>A</i>' }) });
    });
    expect(asked).toEqual(['/data/sales/a']);
    expect(root.panes[0].innerHTML).toBe('<i>A</i>');
    expect('data-failed' in root.panes[0].attrs).toBe(false);
});

test('a second switch while the fetch is under way waits on it', async () => {
    const { api } = load();
    const root = page([pending('a')]);
    const asked = [];
    let answer;
    const fetchFn = (url) => {
        asked.push(url);
        return new Promise((resolve) => { answer = resolve; });
    };
    const first = api.choose(root, 'sales', fetchFn);
    await api.choose(root, 'buylist', fetchFn);
    const second = api.choose(root, 'sales', fetchFn);
    expect(asked).toHaveLength(1);
    answer({ ok: true, json: () => Promise.resolve({ a: '<i>A</i>' }) });
    await Promise.all([first, second]);
    expect(root.panes[0].innerHTML).toBe('<i>A</i>');
});

test('the buylist and unknown modes fetch nothing', async () => {
    const { api, cookies } = load();
    const root = page([pending('a')]);
    const fetchFn = () => { throw new Error('fetched'); };
    await api.choose(root, 'buylist', fetchFn);
    await api.choose(root, 'bogus', fetchFn);
    expect(cookies).toEqual([['SearchBuyersMode', 'buylist', 1000]]);
});

test('a click on a switch button chooses its mode', () => {
    const { listeners } = load();
    expect(listeners.map((l) => l.type)).toEqual(['click']);
    const target = { closest: () => null };
    // A click elsewhere is left alone.
    listeners[0].fn({ target, preventDefault: () => { throw new Error('prevented'); } });
});

test('a reader not logged in gets the one prompt in each pane, and no fetch', async () => {
    const { api } = load();
    const root = page([pending('a'), pending('b')], '<div>Log in</div>');
    await api.choose(root, 'sales', () => { throw new Error('fetched'); });
    expect(root.panes.map((p) => p.innerHTML)).toEqual(['<div>Log in</div>', '<div>Log in</div>']);
    expect(root.panes.filter((p) => 'data-pending' in p.attrs)).toHaveLength(0);
});

test('a page that opens in Sales fills its panes, one in Buylist waits', async () => {
    const { api } = load();
    const asked = [];
    const fetchFn = (url) => {
        asked.push(url);
        return Promise.resolve({ ok: true, json: () => Promise.resolve({ a: '<i>A</i>' }) });
    };
    const buylist = page([pending('a')]);
    await api.start(buylist, fetchFn);
    expect(asked).toEqual([]);

    const sales = page([pending('a')]);
    sales.cols[0].attrs['data-buyers-mode'] = 'sales';
    await api.start(sales, fetchFn);
    expect(asked).toEqual(['/data/sales/a']);
    expect(sales.panes[0].innerHTML).toBe('<i>A</i>');
});
