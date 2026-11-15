import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const optimizer = readFileSync(new URL('../js/upload-optimizer.js', import.meta.url), 'utf8');
const exportsSource = readFileSync(new URL('../js/upload-exports.js', import.meta.url), 'utf8');

// An optimizer row as templates/upload.html draws it: its card, condition,
// the stores it can move to and, when moved, the store it was moved to.
function row(id, cond, move, moved) {
    const attrs = moved ? { 'data-opt-moved': moved } : {};
    return {
        dataset: {
            optId: id, optCond: cond, move,
            get optMoved() { return attrs['data-opt-moved']; },
        },
        hasAttribute: (name) => name in attrs,
        setAttribute: (name, value) => { attrs[name] = value; },
        removeAttribute: (name) => { delete attrs[name]; },
    };
}

function element(tag) {
    return {
        tag, className: '', dataset: {}, children: [], text: '',
        set textContent(v) { this.text = v; this.children = []; },
        appendChild(child) { this.children.push(child); return child; },
    };
}

function fakeDocument(rows, mode) {
    return {
        querySelectorAll: (sel) => sel === '.opt-store tr[data-opt-moved]'
            ? rows.filter((r) => r.hasAttribute('data-opt-moved'))
            : [],
        getElementById: (id) => (id === 'res_mode' ? { value: mode } : null),
        createElement: element,
        createTextNode: (text) => ({ text }),
        addEventListener() {},
    };
}

function loadOptimizer(rows) {
    const calls = { track: [], stored: {}, reprocessed: 0 };
    const window = { BAN: { track: (name, value) => calls.track.push(name + ':' + value) }, BAN_OPT_STORE_NAMES: { SCG: 'Star City Games' } };
    const sessionStorage = { setItem: (k, v) => { calls.stored[k] = v; } };
    const fns = new Function('window', 'document', 'wireLoadLists', 'sessionStorage', 'reprocessUploadResults',
        optimizer + '\nreturn {moveOptRow, fillMoveMenu};')(
        window, fakeDocument(rows, 'true'), () => {}, sessionStorage, () => { calls.reprocessed++; });
    window.reprocessUploadResults = true;
    return { ...fns, calls };
}

function packOptMoves(rows, mode) {
    const window = {};
    return new Function('window', 'document', exportsSource + '\nreturn packOptMoves;')(window, fakeDocument(rows, mode))();
}

test('the moves go with the mode they were made in, one line a card', () => {
    const rows = [row('a', 'NM', '', 'SCG'), row('a', 'NM', '', 'SCG'), row('b', '', '', 'CK'), row('c', 'NM', '', undefined)];
    expect(packOptMoves(rows, 'true')).toBe('buylist\na\tNM\tSCG\nb\t\tCK');
    expect(packOptMoves(rows, 'false')).toBe('retail\na\tNM\tSCG\nb\t\tCK');
    expect(packOptMoves([row('c', 'NM', '', undefined)], 'true')).toBe('');
});

test('a move marks the row alone for its card and prices the list again on the card', () => {
    const elsewhere = row('a', 'NM', '', 'CK');
    const other = row('b', 'NM', '', 'CK');
    const picked = row('a', 'NM', 'SCG:4.00');
    const { moveOptRow, calls } = loadOptimizer([elsewhere, other, picked]);

    moveOptRow(picked, 'SCG');
    expect(picked.dataset.optMoved).toBe('SCG');
    expect(elsewhere.hasAttribute('data-opt-moved')).toBe(false);
    expect(other.dataset.optMoved).toBe('CK');
    expect(calls.track).toEqual(['ui.optimizer:row_move']);
    expect(calls.stored).toEqual({ uploadOptFocus: 'a\tNM', uploadResView: 'optimizer' });
    expect(calls.reprocessed).toBe(1);

    moveOptRow(picked, '');
    expect(picked.hasAttribute('data-opt-moved')).toBe(false);
    expect(calls.track).toEqual(['ui.optimizer:row_move', 'ui.optimizer:row_unmove']);
});

test('the menu lists the row\'s stores by name with their offer, and a way back once moved', () => {
    const { fillMoveMenu } = loadOptimizer([]);
    const menu = element('div');
    const items = (r) => {
        fillMoveMenu(menu, r);
        return menu.children.slice(1).map((b) => [b.children[0].text, b.children[1] ? b.children[1].text : '', b.dataset.store]);
    };
    expect(items(row('a', 'NM', 'SCG:4.00,ABU:3.50'))).toEqual([
        ['Star City Games', '$ 4.00', 'SCG'],
        ['ABU', '$ 3.50', 'ABU'],
    ]);
    expect(menu.children[0].text).toBe('Move to');
    expect(items(row('a', 'NM', '', 'CK'))).toEqual([['Let the optimizer place it', '', '']]);
});
