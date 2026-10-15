import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const exportsSrc = readFileSync(new URL('../js/upload-exports.js', import.meta.url), 'utf8');
const shareSrc = readFileSync(new URL('../js/upload-share.js', import.meta.url), 'utf8');

// A results row as the page carries it: data-* on the <tr>, a class for a
// row the reader removed.
function row(data, removed) {
    return { dataset: data, classList: { contains: (c) => removed && c === 'ures-removed-row' } };
}

function pageWith(rows) {
    const document = {
        addEventListener: () => {},
        querySelector: () => null,
        querySelectorAll: () => rows,
        getElementById: (id) => (id === 'res_mode' ? { value: 'true' } : null),
    };
    const window = {};
    const packRows = new Function('window', 'document', 'with (window) {' + exportsSrc + '}\nreturn packRows;')(window, document);
    window.packRows = packRows;
    return { window, document, packRows };
}

test('packRows packs seven fields a row and skips removed rows and rows without a hash', () => {
    const { packRows } = pageWith([
        row({ hash: 'uuid-1', qtys: '2', cond: 'NM', price: '1.50', notes: 'a\tb\nc', from: 'box', fromqty: '1' }),
        row({ hash: '', qtys: '1' }),
        row({ hash: 'uuid-2', qtys: '1' }, true),
        row({ hash: 'uuid-3', qtys: '3' }),
    ]);
    expect(packRows('all')).toBe('uuid-1\t2\tNM\t1.50\ta b c\tbox\t1\nuuid-3\t3\t\t\t\t\t');
});

function share(status, body, rows) {
    const { window, document } = pageWith(rows || [row({ hash: 'uuid-1', qtys: '1' })]);
    const calls = [];
    const fetch = (url, init) => {
        calls.push({ url, init });
        return Promise.resolve({ status, json: () => Promise.resolve(body) });
    };
    const copied = [];
    const navigator = { clipboard: { writeText: (s) => { copied.push(s); return Promise.resolve(); } } };
    window.location = { origin: 'https://example.test' };
    window.fetch = fetch;
    window.navigator = navigator;
    const timers = [];
    window.setTimeout = (fn) => { timers.push(fn); return 0; };
    const el = { innerHTML: '<svg></svg> Share', title: 'Copy a link to this list, kept for 7 days' };
    new Function('window', 'document', 'navigator', 'fetch', 'setTimeout', 'with (window) {' + shareSrc + '}')(window, document, navigator, fetch, window.setTimeout);
    return { window, calls, copied, el, timers };
}

test('a share posts the packed rows and copies the link', async () => {
    const { window, calls, copied, el } = share(201, { key: 'k', url: '/upload?share=k' });
    await window.copyShareLink(el);
    expect(calls.length).toBe(1);
    expect(calls[0].url).toBe('/api/upload/share');
    expect(calls[0].init.method).toBe('POST');
    expect(calls[0].init.headers['X-Requested-With']).toBe('fetch');
    expect(JSON.parse(calls[0].init.body)).toEqual({ rows: 'uuid-1\t1\t\t\t\t\t', buylist: true });
    expect(copied).toEqual(['https://example.test/upload?share=k']);
    expect(el.innerHTML).toContain('Copied!');
});

test('a refused share says so and copies nothing', async () => {
    const { window, copied, el } = share(400, { error: 'a row has no card id' });
    await window.copyShareLink(el);
    expect(copied).toEqual([]);
    expect(el.innerHTML).toBe('Could not share');
    expect(el.title).toBe('a row has no card id');
});

test('a second click while in flight is ignored', async () => {
    const { window, calls, el } = share(201, { key: 'k', url: '/upload?share=k' });
    const first = window.copyShareLink(el);
    const second = window.copyShareLink(el);
    expect(second).toBeUndefined();
    await first;
    expect(calls.length).toBe(1);
});

test('a click during the flash is ignored, and the timer restores the link', async () => {
    const { window, calls, el, timers } = share(201, { key: 'k', url: '/upload?share=k' });
    const origHTML = el.innerHTML;
    const origTitle = el.title;
    await window.copyShareLink(el);
    expect(el.innerHTML).toContain('Copied!');
    expect(window.copyShareLink(el)).toBeUndefined();
    expect(calls.length).toBe(1);
    expect(timers.length).toBe(1);
    timers[0]();
    expect(el.innerHTML).toBe(origHTML);
    expect(el.title).toBe(origTitle);
    await window.copyShareLink(el);
    expect(calls.length).toBe(2);
});
