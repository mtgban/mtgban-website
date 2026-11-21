import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// At 640px and under the desktop Sets table fits a 375px phone: its finish
// tags stack and its cells keep 6px sides, so Released stays in view.
test('the sets table fits a phone without scrolling', () => {
    const css = read('css/sets.css');
    const start = css.indexOf('@media (max-width: 640px) {');
    expect(start).toBeGreaterThan(-1);
    const block = css.slice(start, css.indexOf('\n}', start));
    expect(block).toContain('.sets-finish { flex-wrap: wrap; }');
    expect(block).toContain('.sets-table th, .sets-table td { padding: 5px 6px; }');
});

// A 360px phone still had 8px too many; 4px cell sides at 380 and under fit it.
test('the sets table fits a 360px phone', () => {
    const css = read('css/sets.css');
    const start = css.indexOf('@media (max-width: 380px) {');
    expect(start).toBeGreaterThan(-1);
    expect(css.slice(start, css.indexOf('\n}', start))).toContain('.sets-table th, .sets-table td { padding: 5px 4px; }');
});
