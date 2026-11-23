import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// The orders folded in a Sales list (templates/partials/sales-pane.html).
test('the fold follows the rows it carries on the shading of', () => {
    expect(read('templates/partials/sales-pane.html')).toMatch(/\{\{range \.Shown\}\}\{\{template "sales-row"[^}]*\}\}\{\{end\}\}\n\{\{with \.More\}\}<details class="sales-more">/);
    const css = read('css/search-rows.css');
    for (const parity of ['even', 'odd']) {
        expect(css).toContain(`:where(.sales-pane > .price-row:nth-child(${parity} of .price-row)) + .sales-more > .price-row:where(:nth-child(${parity} of .price-row))`);
    }
});

test('the fold\'s row is as tall as the others to a finger, at every width', () => {
    expect(read('css/search-rows.css')).toMatch(/@media \(pointer: coarse\) \{[^@]*\.sales-more > summary \{[^}]*min-height: var\(--price-row-h, 42px\);/);
    // Each width that sets the rows' height sets the fold's beside it.
    const css = read('css/search.css');
    const rows = [...css.matchAll(/^ *\.price-row \{ --price-row-h: (\d+px);.*\n(.*)$/gm)];
    expect(rows).toHaveLength(2);
    for (const [, height, next] of rows) {
        expect(next.trim()).toBe(`.sales-more > summary { --price-row-h: ${height}; }`);
    }
});
