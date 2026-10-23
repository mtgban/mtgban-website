import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-optimizer.js', import.meta.url), 'utf8');

function text() {
    return { textContent: '' };
}

// A store's optimizer section as templates/upload.html lays it out: its rows
// with their offer and quantity, the count and total in its header, and its
// entry in the list above the stores.
function load(rows) {
    const trs = rows.map(([price, qty]) => ({
        dataset: { optPrice: String(price), loadQty: String(qty) },
        classList: {
            removed: false,
            contains(c) { return c === 'opt-removed' && this.removed; },
        },
    }));
    const count = text();
    const total = text();
    const section = {
        id: 'opt-CK',
        querySelectorAll: () => trs,
        querySelector: (sel) => ({ '.opt-count': count, '.opt-total': total })[sel],
    };
    const tocStats = text();
    const tocTotal = text();
    const toc = (href, stats, sum) => ({
        getAttribute: () => href,
        querySelector: (sel) => ({ '.toc-stats': stats, '.toc-total': sum })[sel],
    });
    const otherStats = text();
    const document = {
        querySelectorAll: (sel) => sel === '.opt-toc-item'
            ? [toc('#opt-SCG', otherStats, text()), toc('#opt-CK', tocStats, tocTotal)]
            : [],
        listeners: {},
        addEventListener(type, fn) { this.listeners[type] = fn; },
    };
    const updateOptTotals = new Function('window', 'document', 'Tablesort', 'wireLoadLists',
        source + '\nreturn updateOptTotals;')({}, document, function() {}, () => {});
    const untick = (n) => { trs[n].classList.removed = true; };
    // A tick change as the page sends it, from a checkbox in a section or not
    const change = (inSection) => document.listeners.change({
        target: { closest: (sel) => (inSection && sel === '.opt-store' ? section : null) },
    });
    return { update: () => updateOptTotals(section), change, untick, count, total, tocStats, tocTotal, otherStats };
}

test('unticking a row takes its copies and offer off the store', () => {
    const t = load([[2.5, 4], [1.25, 1], [10, 1]]);
    t.update();
    expect([t.count.textContent, t.total.textContent]).toEqual(['3 cards (6 total)', '$ 21.25']);
    t.untick(0);
    t.update();
    expect([t.count.textContent, t.total.textContent]).toEqual(['2 cards', '$ 11.25']);
    expect([t.tocStats.textContent, t.tocTotal.textContent]).toEqual(['2 cards', '$ 11.25']);
    expect(t.otherStats.textContent).toBe('');
});

test('a store left with one card, or none, says so', () => {
    const t = load([[3, 2], [1, 1]]);
    t.untick(1);
    t.update();
    expect([t.count.textContent, t.total.textContent]).toEqual(['1 card (2 total)', '$ 6.00']);
    t.untick(0);
    t.update();
    expect([t.count.textContent, t.total.textContent]).toEqual(['0 cards', '$ 0.00']);
});

test('a tick change in a store recounts it, and one elsewhere does not', () => {
    const t = load([[2.5, 4], [1.25, 1]]);
    t.untick(1);
    t.change(false);
    expect(t.count.textContent).toBe('');
    t.change(true);
    expect([t.count.textContent, t.total.textContent]).toEqual(['1 card (4 total)', '$ 10.00']);
    expect([t.tocStats.textContent, t.tocTotal.textContent]).toEqual(['1 card (4 total)', '$ 10.00']);
});
