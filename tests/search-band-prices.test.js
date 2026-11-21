import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// In the tight two-column band (a 560-720px results area: iPads in landscape,
// 1250-1366px laptops with the sidebar) the price columns close up to one, so
// store names are not cut: what follows a price stacks under it, none hidden.
function bandBlock() {
    const css = read('css/search.css');
    const subgrid = css.indexOf('@supports (grid-template-columns: subgrid)');
    const start = css.indexOf('@container search-results (560px < width <= 720px) {\n    .rows-main {');
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

test('the band stacks a sealed index\'s Sim median and spread under its EV', () => {
    const block = bandBlock();
    expect(block).toMatch(/\.rows-index \{\n\s+grid-template-columns: 1fr auto;/);
    expect(block).toMatch(/\.index-label-2,\n\s+\.rows-index \.price-row > \.index-label-3 \{ display: none; \}/);
    expect(block).toMatch(/\.index-cols > \.price:first-child \{ grid-column: 1 \/ -1; \}/);
    // Labelled only under the EV header: a section without one is not simulated.
    expect(block).toMatch(/\.rows-index:has\(\.index-label\) \.index-cols > \.price:nth-child\(2\)::before \{ content: "Sim"; \}/);
    expect(block).toMatch(/\.rows-index:has\(\.index-label\) \.index-cols > \.price:nth-child\(3\)::before \{ content: "±"; \}/);
});
