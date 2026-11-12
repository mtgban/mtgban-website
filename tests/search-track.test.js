import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/search-track.js', import.meta.url), 'utf8');

// node is a plain element: closest walks parentNode, matching a tag, a tag.class or a .class.
function node(tag, classes = [], props = {}) {
    const n = {
        tag, classes, parentNode: null,
        classList: { contains: (c) => classes.includes(c) },
        closest(sel) {
            const [t, c] = sel.split('.');
            for (let x = n; x; x = x.parentNode) {
                if ((!t || x.tag === t) && (!c || x.classes.includes(c))) return x;
            }
            return null;
        },
        ...props,
    };
    return n;
}

function summaryIn({ classes, open }) {
    const details = node('details', classes, { open });
    const summary = node('summary');
    summary.parentNode = details;
    const span = node('span', ['m-vendor-name']);
    span.parentNode = summary;
    return span;
}

function linkIn(target) {
    const a = node('a', ['m-vendor-link']);
    a.parentNode = target;
    return a;
}

function anchor(cls) {
    const header = node('div', ['result-header']);
    const a = node('a', [cls]);
    a.parentNode = header;
    return a;
}

// load runs the script over stubs, returning what it registered and set on self.
function load(window) {
    const listeners = [];
    const document = { addEventListener: (type, fn, capture) => listeners.push({ type, fn, capture }) };
    const self = {};
    new Function('window', 'document', 'self', source)(window, document, self);
    return { listeners, SearchTrack: self.SearchTrack };
}

const { SearchTrack } = load({});

test.each([
    ['a closed sales row', summaryIn({ classes: ['price-row', 'sales-velocity'], open: false }), false, 'velocity'],
    ['an open sales row', summaryIn({ classes: ['sales-velocity'], open: true }), false, ''],
    ['the mobile sales row, which is also an offer row', summaryIn({ classes: ['m-vendor-row', 'sales-velocity'], open: false }), false, 'velocity'],
    ['a closed offer row', summaryIn({ classes: ['m-vendor-row'], open: false }), false, 'detail'],
    ['an open offer row', summaryIn({ classes: ['m-vendor-row'], open: true }), false, ''],
    ['the store link inside an offer row', linkIn(summaryIn({ classes: ['m-vendor-row'], open: false })), false, ''],
    ['a summary of some other details', summaryIn({ classes: ['faq'], open: false }), false, ''],
    ['an add link on the chart page', anchor('chart-add-link'), false, 'roster_add'],
    ['a remove link on the chart page', anchor('chart-remove-link'), false, 'roster_remove'],
    ['an add link inside the modal', anchor('chart-add-link'), true, ''],
    ['anything else', { tag: 'div', classes: [], closest: () => null }, false, ''],
    ['no target at all', null, false, ''],
])('%s', (_, target, modal, want) => {
    expect(SearchTrack.classify(target, modal)).toBe(want);
});

test('the listener is capture phase and makes one call for a click', () => {
    const calls = [];
    const { listeners } = load({ BAN: { track: (...a) => calls.push(a) } });
    expect(listeners).toHaveLength(1);
    expect(listeners[0].type).toBe('click');
    expect(listeners[0].capture).toBe(true);
    listeners[0].fn({ target: summaryIn({ classes: ['price-row', 'sales-velocity'], open: false }) });
    listeners[0].fn({ target: summaryIn({ classes: ['m-vendor-row'], open: false }) });
    listeners[0].fn({ target: anchor('chart-remove-link') });
    listeners[0].fn({ target: summaryIn({ classes: ['m-vendor-row'], open: true }) });
    expect(calls).toEqual([['ui.row.velocity', 'open'], ['ui.row.detail', 'open'], ['ui.chart.roster', 'remove', 'page']]);
});

test('inside the chart modal a roster link is left to search-modal.js', () => {
    const calls = [];
    const { listeners } = load({ BAN: { track: (...a) => calls.push(a) }, BAN_SEARCH_MODAL: { ids: 'a', maxCards: 2 } });
    listeners[0].fn({ target: anchor('chart-add-link') });
    expect(calls).toEqual([]);
});

test('with no BAN the listener does nothing and does not throw', () => {
    const { listeners } = load({});
    expect(() => listeners[0].fn({ target: summaryIn({ classes: ['sales-velocity'], open: false }) })).not.toThrow();
    expect(() => listeners[0].fn({ target: anchor('chart-add-link') })).not.toThrow();
});
