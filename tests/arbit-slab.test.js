import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// A span's line box is shorter than its glyphs (main.css), so a label ending
// in an ellipsis clips only sideways or loses its descenders.
test("a slab's label keeps its descenders", () => {
    const rule = read('css/arbit.css').match(/^\.arb-slab \{([^}]*)\}/m)[1];
    expect(rule).toMatch(/overflow: hidden;\s+overflow: clip visible;/);
});
