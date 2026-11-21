import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// Global's reference price can be flagged (red, with a caution on hover)
// inside its buy link; the pointer still says it is a link.
test('a flagged price inside a Global buy link keeps the link cursor', () => {
    const css = read('css/arbit.css');
    expect(css).toMatch(/^\.arb-table \.arb-price-link \.arb-price-warn \{ cursor: pointer; \}/m);
});
