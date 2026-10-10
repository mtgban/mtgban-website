import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/load-lists.js', import.meta.url), 'utf8');

const ROWS = [
    {qty: '2', name: 'Lightning Bolt', ckid: '11', tcgid: '101', set: 'M10', number: '146'},
    {qty: '1', name: 'Counterspell', ckid: '12', tcgid: '102', set: 'MH2', number: '267'},
    {qty: '3', name: 'Lim-Dûl\'s Vault', ckid: '13', tcgid: '103', set: 'ALL', number: '48'},
];

// loadPage runs the script against a stand-in for one section of a page:
// its rows, shown in reverse as a sorted table would, and the lists and forms
// its load buttons send. untick and tick mark a row as the page's own
// checkbox handler does, then fire the change event that follows.
function loadPage({lists = [], forms = []}) {
    const trs = ROWS.map((r, idx) => {
        const tr = {
            removed: false,
            dataset: {
                loadIdx: String(idx),
                loadQty: r.qty,
                loadName: r.name,
                loadCkid: r.ckid,
                loadTcgid: r.tcgid,
                loadSet: r.set,
                loadNumber: r.number,
            },
        };
        tr.classList = {contains: (name) => name === 'opt-removed' && tr.removed};
        return tr;
    });
    const shown = [...trs].reverse();
    const section = {
        querySelectorAll: (selector) => ({
            'tr[data-load-idx]': shown,
            '[data-load-list]': lists,
            'form': forms,
        })[selector] || [],
    };
    const checkbox = {closest: (selector) => (selector === '.opt-store' ? section : null)};

    let onChange;
    const document = {
        addEventListener: (type, handler) => {
            if (type === 'change') onChange = handler;
        },
    };
    const wire = new Function('document', source + '\nreturn wireLoadLists;')(document);
    wire({section: '.opt-store', removed: 'opt-removed'});

    const toggle = (idx, removed) => {
        trs[idx].removed = removed;
        onChange({target: checkbox});
    };
    return {
        untick: (idx) => toggle(idx, true),
        tick: (idx) => toggle(idx, false),
    };
}

// A list input in format, with value as the server wrote it
function listInput(format, value) {
    return {dataset: {loadList: format}, value};
}

describe('load lists', () => {
    test('a TCGplayer list keeps its product ids in the server order', () => {
        const input = listInput('tcg', '2-101||1-102||3-103||');
        const page = loadPage({lists: [input]});
        page.untick(1);
        expect(input.value).toBe('2-101||3-103||');
    });

    test('a Card Kingdom list keeps its names', () => {
        const input = listInput('ck', '2 Lightning Bolt||1 Counterspell||3 Lim-Dûl\'s Vault||');
        const page = loadPage({lists: [input]});
        page.untick(0);
        expect(input.value).toBe('1 Counterspell||3 Lim-Dûl\'s Vault||');
    });

    test('a Cool Stuff Inc list drops the unticked row', () => {
        const input = listInput('csi', '2 Lightning Bolt|1 Counterspell|3 Lim-Dûl\'s Vault|');
        const page = loadPage({lists: [input]});
        page.untick(2);
        expect(input.value).toBe('2 Lightning Bolt|1 Counterspell|');
    });

    test('a Card Kingdom buylist keeps its ids', () => {
        const input = listInput('ckbuylist', '{"contents":[]}');
        const page = loadPage({lists: [input]});
        page.untick(1);
        expect(JSON.parse(input.value)).toEqual({contents: [{id: 11, qty: 2}, {id: 13, qty: 3}, {}]});
    });

    test('a Manapool deck keeps sets and numbers, encoded as UTF-8', () => {
        const input = listInput('manapool', 'server');
        const page = loadPage({lists: [input]});
        page.untick(1);
        const deck = '2 Lightning Bolt [M10] 146\n3 Lim-Dûl\'s Vault [ALL] 48';
        expect(input.value).toBe(Buffer.from(deck, 'utf8').toString('base64'));
    });

    test('ticking every row again sends the list as the server built it', () => {
        const input = listInput('tcg', '2-101||1-102||3-103||');
        const page = loadPage({lists: [input]});
        page.untick(1);
        page.tick(1);
        expect(input.value).toBe('2-101||1-102||3-103||');
    });

    test('a cart link keeps only the ticked rows, adding up shared ids', () => {
        const href = 'https://abugames.com/cartview/shop#ban=301:5&v=abc&side=retail';
        const link = {dataset: {loadList: 'cart', loadItems: '301,,301'}, href};
        const page = loadPage({lists: [link]});
        page.untick(1);
        expect(link.href).toBe(href);
        page.untick(0);
        expect(link.href).toBe('https://abugames.com/cartview/shop#ban=301:3&v=abc&side=retail');
        page.tick(0);
        page.tick(1);
        expect(link.href).toBe(href);
    });

    test('a hashes form disables only the unticked row, even for a repeated card', () => {
        const inputs = [
            {name: 'tag', value: 'SCGRetail'},
            {name: 'mode', value: 'false'},
        ];
        // The same card twice, in two conditions
        for (const [id, cond] of [['card-a', 'NM'], ['card-a', 'SP'], ['card-b', 'NM']]) {
            inputs.push({name: 'SCGRetailhashes', value: id});
            inputs.push({name: 'SCGRetailhashesQtys', value: '1'});
            inputs.push({name: 'SCGRetailhashesCond', value: cond});
        }
        const form = {
            querySelectorAll: (selector) => (selector === 'input[type="hidden"]' ? inputs : []),
        };
        const page = loadPage({forms: [form]});
        page.untick(1);
        expect(inputs.filter((i) => !i.disabled).map((i) => i.value))
            .toEqual(['SCGRetail', 'false', 'card-a', '1', 'NM', 'card-b', '1', 'NM']);
        page.tick(1);
        expect(inputs.every((i) => !i.disabled)).toBe(true);
    });
});
