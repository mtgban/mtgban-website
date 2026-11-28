import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/sleepers-gap.js', import.meta.url), 'utf8');

function fakeStorage(initial = {}) {
    const m = Object.assign({}, initial);
    return {
        getItem: (k) => (k in m ? m[k] : null),
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
        _map: m,
    };
}

// el is a node answering the few selectors sleepers-gap.js asks for.
function el(props = {}, kids = {}) {
    const listeners = {};
    const node = Object.assign({
        dataset: {}, attrs: {}, children: [], hidden: false, disabled: false, textContent: '', title: '', value: '',
        setAttribute(k, v) { this.attrs[k] = v; },
        addEventListener(ev, fn) { listeners[ev] = fn; },
        fire(ev, e) { listeners[ev](e); },
        querySelector: (sel) => kids[sel] || null,
        querySelectorAll: (sel) => (kids[sel + '*'] || []),
        appendChild(c) { this.children.push(c); },
        get firstElementChild() { return this.children[0] || null; },
    }, props);
    return node;
}

// A row as the templates' <template data-gap-row> clones it.
function rowNode() {
    const parts = { '[data-gap-link]': el(), '[data-gap-ref]': el(), '[data-gap-target]': el(), '[data-gap-remove]': el() };
    const row = el({}, parts);
    row.parts = parts;
    return row;
}

const STORES = [['', 'Pick a reference...'], ['TCGLow', 'TCG Low'], ['CK', 'Card Kingdom'], ['SCG', 'Star City Games']];

function page({ game = 'magic', local = fakeStorage(), stores = STORES, userState } = {}) {
    const ref = el({ options: stores.map(([value, text]) => ({ value, textContent: text })) });
    const target = el();
    const go = el({ disabled: true });
    const save = el({ disabled: true });
    const form = el({}, {
        'select[name="ref"]': ref, 'select[name="target"]': target,
        '[data-gap-go]': go, '[data-gap-save]': save, 'select*': [ref, target],
    });
    const box = el({ hidden: true });
    box.textContent = '';
    Object.defineProperty(box, 'textContent', { set() { box.children = []; }, get() { return ''; } });
    const rows = [];
    const tpl = { content: { firstElementChild: { cloneNode: () => { const r = rowNode(); rows.push(r); return r; } } } };
    const sel = { '[data-gap-form]': form, '[data-gap-form] select[name="ref"]': ref, '[data-gap-saved]': box, 'template[data-gap-row]': tpl };
    const document = {
        body: { dataset: { game } },
        readyState: 'complete',
        querySelector: (s) => sel[s] || null,
        addEventListener() {},
    };
    const window = { UserState: userState };
    new Function('window', 'document', 'localStorage', source)(window, document, local);
    const pick = (r, t) => { ref.value = r; target.value = t; ref.fire('change'); };
    return { G: window.SleepersGap, local, box, ref, target, go, save, pick };
}

const stored = (local) => JSON.parse(local.getItem('mtgban_sleepers_gap_pairs'));

test('a saved pair is stored under its game, with an id both devices agree on', () => {
    const { G, local } = page();
    expect(G.store.save('TCGLow', 'CK')).toBe(true);
    expect(stored(local)).toEqual([{ id: 'magic:TCGLow>CK', game: 'magic', ref: 'TCGLow', target: 'CK', savedAt: expect.any(Number) }]);
    expect(G.store.save('TCGLow', 'CK')).toBe('saved');
    expect(G.store.save('CK', 'CK')).toBe('invalid');
    expect(G.store.save('', 'CK')).toBe('invalid');
});

test('the list is newest first, and only this game\'s', () => {
    const local = fakeStorage({ mtgban_sleepers_gap_pairs: JSON.stringify([
        { id: 'magic:TCGLow>CK', game: 'magic', ref: 'TCGLow', target: 'CK', savedAt: 1 },
        { id: 'lorcana:TCGLow>CK', game: 'lorcana', ref: 'TCGLow', target: 'CK', savedAt: 3 },
        { id: 'magic:CK>SCG', game: 'magic', ref: 'CK', target: 'SCG', savedAt: 2 },
        { id: 'magic:SCG>CK', del: true, savedAt: 4 },
    ]) });
    const { G } = page({ local });
    expect(G.store.list().map((p) => p.id)).toEqual(['magic:CK>SCG', 'magic:TCGLow>CK']);
});

test('a game keeps 10 pairs, other games not counting', () => {
    const others = Array.from({ length: 10 }, (_, i) => ({ id: 'lorcana:A' + i + '>B', game: 'lorcana', ref: 'A' + i, target: 'B', savedAt: 1 }));
    const { G } = page({ local: fakeStorage({ mtgban_sleepers_gap_pairs: JSON.stringify(others) }) });
    for (let i = 0; i < 10; i++) expect(G.store.save('S' + i, 'CK')).toBe(true);
    expect(G.store.save('TCGLow', 'CK')).toBe('full');
    expect(G.store.list().length).toBe(10);
});

test('a removal leaves a tombstone, and saving the pair again outdates it', () => {
    let clock = 1000;
    const { G, local } = page({ userState: { now: () => clock, later: (a, b) => (a || 0) > (b || 0) } });
    G.store.save('TCGLow', 'CK');
    expect(G.store.remove('magic:TCGLow>CK')).toBe(true);
    expect(stored(local)).toEqual([{ id: 'magic:TCGLow>CK', del: true, savedAt: 1001 }]);
    expect(G.store.remove('magic:TCGLow>CK')).toBe(false);
    // Saved again on the same clock tick: still later than the removal
    expect(G.store.save('TCGLow', 'CK')).toBe(true);
    expect(stored(local)).toEqual([{ id: 'magic:TCGLow>CK', game: 'magic', ref: 'TCGLow', target: 'CK', savedAt: 1002 }]);
});

test('a tombstone past 30 days is dropped on the next write', () => {
    const now = Date.now();
    const local = fakeStorage({ mtgban_sleepers_gap_pairs: JSON.stringify([
        { id: 'magic:A>B', del: true, savedAt: now - 31 * 24 * 3600 * 1000 },
        { id: 'magic:C>D', del: true, savedAt: now - 1000 },
    ]) });
    const { G } = page({ local });
    G.store.save('TCGLow', 'CK');
    expect(stored(local).map((p) => p.id)).toEqual(['magic:C>D', 'magic:TCGLow>CK']);
});

test('rows draw each pair, with its link and names', () => {
    const local = fakeStorage({ mtgban_sleepers_gap_pairs: JSON.stringify([
        { id: 'magic:TCGLow>CK', game: 'magic', ref: 'TCGLow', target: 'CK', savedAt: 2 },
        { id: 'magic:TCGLow>GONE', game: 'magic', ref: 'TCGLow', target: 'GONE', savedAt: 3 },
    ]) });
    const { box } = page({ local });
    expect(box.hidden).toBe(false);
    expect(box.children.map((r) => r.dataset.gapId)).toEqual(['magic:TCGLow>GONE', 'magic:TCGLow>CK']);
    const row = box.children[1];
    expect(row.parts['[data-gap-link]'].href).toBe('?page=gap&ref=TCGLow&target=CK');
    expect(row.parts['[data-gap-ref]'].textContent).toBe('TCG Low');
    expect(row.parts['[data-gap-target]'].textContent).toBe('Card Kingdom');
    expect(row.parts['[data-gap-remove]'].attrs['aria-label']).toBe('Remove TCG Low vs Card Kingdom');
});

test('a pair naming a store the page does not offer keeps a row to remove it by', () => {
    const local = fakeStorage({ mtgban_sleepers_gap_pairs: JSON.stringify([
        { id: 'magic:TCGLow>GONE', game: 'magic', ref: 'TCGLow', target: 'GONE', savedAt: 3 },
    ]) });
    const { G, box } = page({ local });
    const row = box.children[0];
    expect(row.parts['[data-gap-ref]'].textContent).toBe('TCG Low');
    expect(row.parts['[data-gap-target]'].textContent).toBe('GONE');
    const btn = { closest: (s) => (s === '[data-gap-remove]' ? btn : row) };
    box.fire('click', { target: btn, preventDefault() {} });
    expect(G.store.list()).toEqual([]);
    expect(box.hidden).toBe(true);
});

test('no pairs leaves the list hidden', () => {
    const { box } = page();
    expect(box.hidden).toBe(true);
});

test('Compare and Save follow the picked pair', () => {
    const { G, go, save, pick, box } = page();
    expect(go.disabled).toBe(true);
    expect(save.disabled).toBe(true);
    pick('TCGLow', 'TCGLow');
    expect(go.disabled).toBe(true);
    expect(save.disabled).toBe(true);
    pick('TCGLow', 'CK');
    expect(go.disabled).toBe(false);
    expect(save.disabled).toBe(false);
    save.fire('click');
    expect(G.store.has('TCGLow', 'CK')).toBe(true);
    expect(save.disabled).toBe(true);
    expect(save.textContent).toBe('★ Saved');
    expect(box.children.length).toBe(1);
    pick('CK', 'SCG');
    expect(save.disabled).toBe(false);
    expect(save.textContent).toBe('☆ Save');
});

test('Save is off at the cap, saying why', () => {
    const { G, save, pick } = page();
    for (let i = 0; i < 10; i++) G.store.save('S' + i, 'CK');
    pick('TCGLow', 'CK');
    expect(save.disabled).toBe(true);
    expect(save.title).toBe('10 saved — remove one');
});

test('the remove button removes its own row', () => {
    const { G, box } = page();
    G.store.save('TCGLow', 'CK');
    G.store.save('CK', 'SCG');
    G.refresh();
    expect(box.children.length).toBe(2);
    const row = box.children.find((r) => r.dataset.gapId === 'magic:TCGLow>CK');
    const btn = { closest: (s) => (s === '[data-gap-remove]' ? btn : row) };
    box.fire('click', { target: btn, preventDefault() {} });
    expect(G.store.list().map((p) => p.id)).toEqual(['magic:CK>SCG']);
    expect(box.children.length).toBe(1);
});
