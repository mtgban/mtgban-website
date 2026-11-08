import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/store-picker.js', import.meta.url), 'utf8');

// A click on the pill around a picker, landing on the element whose
// ancestors (itself first) are given by selector, and how often it
// opened the picker.
function click(ancestors) {
    let handler = null;
    const document = { addEventListener: (ev, fn) => { if (ev === 'click') handler = fn; } };
    new Function('document', source)(document);
    let opened = 0;
    const select = { showPicker: () => { opened++; }, contains: () => false, focus() {} };
    const wrapper = { querySelector: (sel) => (sel === '.arb-store-select' ? select : null) };
    const target = {
        closest: (sel) => {
            if (sel === '.arb-current-store') return wrapper;
            return ancestors.includes(sel) ? {} : null;
        },
    };
    handler({ target });
    return opened;
}

test('a click on the pill around the picker opens it', () => {
    expect(click([])).toBe(1);
});

test('a click on a button in the pill, as the preset\'s pin, leaves the picker shut', () => {
    expect(click(['button'])).toBe(0);
});
