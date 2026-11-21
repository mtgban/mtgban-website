import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// The arbitrage pages' phone rules: the 640px block of arbit.css.
function phoneBlock() {
    const css = read('css/arbit.css');
    const start = css.indexOf('@media (max-width: 640px) {');
    expect(start, 'expected the 640px block').toBeGreaterThan(-1);
    let depth = 0;
    for (let i = css.indexOf('{', start); i < css.length; i++) {
        if (css[i] === '{') depth++;
        if (css[i] === '}' && --depth === 0) return css.slice(start, i);
    }
    throw new Error('unclosed 640px block');
}

// On a phone a section header holds its name and two rows of load buttons;
// stuck to the top it would cover a fifth of the screen.
test('a section header scrolls with the page on phones', () => {
    expect(phoneBlock()).toMatch(/\.arb-section-header \{ position: static; \}/);
});

// Stacked one per row, the store, jump and preset pickers start at one x and
// fill their row, so none pushes the page wider.
test('the stacked pickers line up and fit their row', () => {
    const block = phoneBlock();
    expect(block).toMatch(/\.arb-current-store \.store-type \{ min-width: 8em; \}/);
    // The preset select's 190px floor is an ID rule; the phone rule names it
    // too, or it outranks the reset and a 360px phone overflows.
    expect(block).toMatch(/\.arb-current-store \.arb-store-select,\n\s+#arbPresetSelect \{ flex: 1 1 0; width: 0; min-width: 0; \}/);
    expect(block).not.toMatch(/\.arb-current-store \{ justify-content: center;/);
});
