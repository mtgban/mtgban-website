import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

const css = read('css/upload.css');

// The rules under every max-width: 560px block, where the results are cards.
function phone() {
    let out = '';
    for (const part of css.split('@media (max-width: 560px) {').slice(1)) out += part.slice(0, part.indexOf('\n}'));
    return out;
}

// A list in a box of its own showed three of eight cards and scrolled apart
// from the page.
test('a phone scrolls the results with the page', () => {
    expect(phone()).toMatch(/\.ures-wrap \{ max-height: none; \}/);
});

// The 640px rules stack the totals; the phone's come later, or lose the tie.
test('a phone sets the totals two to a line', () => {
    const grid = css.indexOf('.res-summary { display: grid; grid-template-columns: 1fr 1fr;');
    expect(grid).toBeGreaterThan(css.indexOf('.res-summary { flex-direction: column;'));
    expect(phone()).toContain('.res-summary { display: grid;');
});
