import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const optimizer = readFileSync(new URL('../js/upload-optimizer.js', import.meta.url), 'utf8');
const exportsSource = readFileSync(new URL('../js/upload-exports.js', import.meta.url), 'utf8');

// An optimizer row as templates/upload.html draws it: its card, condition,
// the stores it can move to, when moved, the store it was moved to, and
// the price its line carries.
function row(id, cond, move, moved, price) {
    const attrs = moved ? { 'data-opt-moved': moved } : {};
    const dataset = {
        optId: id, optCond: cond, move,
        get optMoved() { return attrs['data-opt-moved']; },
    };
    if (price !== undefined) dataset.sharePrice = price;
    return {
        dataset,
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

function loadOptimizer(rows, mode = 'true') {
    const calls = { track: [], stored: {}, reprocessed: 0 };
    const window = { BAN: { track: (name, value) => calls.track.push(name + ':' + value) }, BAN_OPT_STORE_NAMES: { SCG: 'Star City Games' } };
    const sessionStorage = { setItem: (k, v) => { calls.stored[k] = v; } };
    const fns = new Function('window', 'document', 'wireLoadLists', 'sessionStorage', 'reprocessUploadResults',
        optimizer + '\nreturn {moveOptRow, fillMoveMenu};')(
        window, fakeDocument(rows, mode), () => {}, sessionStorage, () => { calls.reprocessed++; });
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

test('a card\'s lines at two prices move apart, each naming its price', () => {
    const rows = [row('a', 'NM', '', 'SCG', '4'), row('a', 'NM', '', 'CK', '10m'), row('a', 'NM', '', 'SCG', '4')];
    expect(packOptMoves(rows, 'true')).toBe('buylist\na\tNM\tSCG\t4\na\tNM\tCK\t10m');
});

test('a move on one of a card\'s price lines leaves the other line\'s move', () => {
    const ten = row('a', 'NM', '', 'CK', '10');
    const four = row('a', 'NM', 'SCG:4.00', 'CK', '4');
    const { moveOptRow } = loadOptimizer([ten, four]);

    moveOptRow(four, 'SCG');
    expect(four.dataset.optMoved).toBe('SCG');
    expect(ten.dataset.optMoved).toBe('CK');
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
    const { fillMoveMenu } = loadOptimizer([], 'false');
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

test('on a buylist the menu leads to Not bought, and out of it once there', () => {
    const { fillMoveMenu } = loadOptimizer([]);
    const menu = element('div');
    const items = (r) => {
        fillMoveMenu(menu, r);
        return menu.children.slice(1).map((b) => [b.children[0].text, b.dataset.store]);
    };
    expect(items(row('a', 'NM', 'SCG:4.00'))).toEqual([
        ['Star City Games', 'SCG'],
        ['Not bought', '-'],
    ]);
    expect(items(row('a', 'NM', 'SCG:4.00', 'CK'))).toEqual([
        ['Star City Games', 'SCG'],
        ['Not bought', '-'],
        ['Let the optimizer place it', ''],
    ]);
    expect(items(row('a', 'NM', 'SCG:4.00', '-'))).toEqual([
        ['Star City Games', 'SCG'],
        ['Let the optimizer place it', ''],
    ]);
});

test('a move to Not bought goes with the others', () => {
    const picked = row('a', 'NM', 'SCG:4.00');
    const { moveOptRow, calls } = loadOptimizer([picked]);
    moveOptRow(picked, '-');
    expect(picked.dataset.optMoved).toBe('-');
    expect(calls.track).toEqual(['ui.optimizer:row_move']);
    expect(packOptMoves([picked], 'true')).toBe('buylist\na\tNM\t-');
});

test('an added store takes its place by name, and a dragged order stays', () => {
    const source = optimizer.match(/function addByName\([\s\S]*?\n}/)[0];
    const window = { BAN_OPT_STORE_NAMES: { CK: 'Card Kingdom', MP: 'Mana Pool', MS: 'MTGSeattle', SCG: 'Star City Games' } };
    const addByName = new Function('window', source + '\nreturn addByName;')(window);
    const added = (list, key) => { addByName(list, key); return list; };
    expect(added(['MS', 'SCG'], 'CK')).toEqual(['CK', 'MS', 'SCG']);
    expect(added(['CK', 'MS'], 'MP')).toEqual(['CK', 'MP', 'MS']);
    expect(added(['CK', 'MS'], 'SCG')).toEqual(['CK', 'MS', 'SCG']);
    expect(added([], 'CK')).toEqual(['CK']);
    expect(added(['SCG', 'CK', 'MS'], 'MP')).toEqual(['SCG', 'CK', 'MP', 'MS']);
    expect(added(['CK', 'SCG', 'MP'], 'MS')).toEqual(['CK', 'SCG', 'MP', 'MS']);
    expect(added(['SCG', 'MS', 'MP'], 'CK')).toEqual(['SCG', 'MS', 'CK', 'MP']);
});
