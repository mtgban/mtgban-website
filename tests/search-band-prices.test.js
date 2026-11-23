import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// In the tight two-column band (a 560-720px results area: iPads in landscape,
// 1250-1366px laptops with the sidebar) and in a list at phone width the price
// columns close up to one, so store names are not cut: what follows a price
// stacks under it, none hidden.
function bandBlock() {
    const css = read('css/search-rows.css');
    const subgrid = css.indexOf('@supports (grid-template-columns: subgrid)');
    const start = css.indexOf('@container search-results (560px < width <= 720px) or (width <= 480px) {\n    .rows-main {');
    expect(subgrid).toBeGreaterThan(-1);
    // After the subgrid rules, which it overrides at the same specificity.
    expect(start).toBeGreaterThan(subgrid);
    return css.slice(start, css.indexOf('\n}\n', start));
}

test('the band stacks a row\'s quantity and second price under its price', () => {
    const block = bandBlock();
    expect(block).toMatch(/\.rows-main \{\n\s+grid-template-columns: 1fr auto;/);
    expect(block).toMatch(/\.rows-main \.price-right \{[^}]*flex-direction: column;/);
    expect(block).toMatch(/\.rows-main \.price-right > \.qty \{[^}]*font-size/);
    expect(block).not.toMatch(/\.qty[^{]*\{[^}]*display: none/);
});

test('the band puts a sealed index\'s Sim median under its name and spread under its EV', () => {
    const block = bandBlock();
    expect(block).toMatch(/\.rows-index \{\n\s+grid-template-columns: 1fr auto;/);
    expect(block).toMatch(/\.index-label-2,\n\s+\.rows-index \.price-row > \.index-label-3 \{ display: none; \}/);
    // The prices join the row's grid, so the price column is only as wide as EV.
    expect(block).toMatch(/\.rows-index \.price-right\.index-cols \{ display: contents; \}/);
    expect(block).toMatch(/\.index-cols > \.price:first-child \{ grid-column: 2; grid-row: 1; \}/);
    expect(block).toMatch(/\.index-cols > \.price:nth-child\(2\) \{ grid-column: 1; grid-row: 2; \}/);
    expect(block).toMatch(/\.index-cols > \.price:nth-child\(3\) \{ grid-column: 2; grid-row: 2; \}/);
    // Labelled only under the EV header: a section without one is not simulated.
    expect(block).toMatch(/\.rows-index:has\(\.index-label\) \.index-cols > \.price:nth-child\(2\)::before \{ content: "Sim"; \}/);
    expect(block).toMatch(/\.rows-index:has\(\.index-label\) \.index-cols > \.price:nth-child\(3\)::before \{ content: "±"; \}/);
});

test('a phone\'s list pane is a results area, so it folds at phone width', () => {
    const css = read('css/search-cards-mobile.css');
    expect(css).toMatch(/\.m-layout-cards \.m-tab-panel \{\n\s+container: search-results \/ inline-size;/);
});

// A buyer's ratio, credit, quantity and CK pause sit in .buylist-extra and
// .qty. Desktop's band hides them behind the row's hover tooltip; a phone
// has no hover, so its list keeps them, stacked under the price.
test('only desktop\'s band hides a buyer\'s ratio, credit and quantity', () => {
    const css = read('css/search-rows.css');
    const hides = [...css.matchAll(/@container search-results ([^{]+)\{\n\s+\.price-right\.has-buylist-extra \{[^}]*\}\n\s+\.price-right\.has-buylist-extra \.buylist-extra,\n\s+\.price-right\.has-buylist-extra \.qty \{ display: none; \}/g)];
    expect(hides.map(m => m[1].trim())).toEqual(['(560px < width <= 720px)']);
});

test('a phone\'s list stacks a buyer\'s credit under the price, in a row that grows', () => {
    expect(bandBlock()).toMatch(/\.rows-main \.price-right > \.buylist-extra,/);
    // Any results area that narrow, desktop's too, lets the row grow.
    expect(read('css/search-rows.css')).toMatch(/@container search-results \(width <= 480px\) \{\n\s+\.rows-main > \.price-row \{\n\s+height: auto;\n\s+min-height: var\(--price-row-h, 42px\);/);
    const cards = read('css/search-cards-mobile.css');
    expect(cards).toMatch(/\.m-layout-cards \.m-tab-panel \.price-row \{\n\s+height: auto;\n\s+min-height: var\(--price-row-h, 42px\);/);
});

// A sealed index's EV row on a phone stacks EV, Sim median and spread in the
// price column, with the store's name centred beside them.
test('a phone\'s sealed index row centres its name beside the stacked prices', () => {
    const all = read('css/search-cards-mobile.css');
    // Inside the phone-width query: a wider pane keeps the index's subgrid.
    const start = all.indexOf('@container search-results (width <= 480px) {\n    .m-layout-cards .m-tab-panel .rows-index');
    expect(start).toBeGreaterThan(-1);
    const cards = all.slice(start, all.indexOf('\n}\n', start));
    expect(all.match(/\.rows-index \.index-cols > \.price:nth-child/g)).toHaveLength(2);
    expect(cards).toMatch(/\.m-tab-panel \.rows-index \.price-row > \.store-name \{\n\s+grid-row: 1 \/ span 3;\n\s+align-self: center;/);
    expect(cards).toMatch(/\.m-tab-panel \.rows-index \.index-cols > \.price:nth-child\(2\) \{\n\s+grid-column: 2;\n\s+grid-row: 2;/);
    expect(cards).toMatch(/\.m-tab-panel \.rows-index \.index-cols > \.price:nth-child\(3\) \{\n\s+grid-column: 2;\n\s+grid-row: 3;/);
});
