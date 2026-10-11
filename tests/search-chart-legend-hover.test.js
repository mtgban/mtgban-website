import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'search-chart.js'), 'utf8');

// The legend's hover replays the row's own hover (image, printings and
// products together) rather than driving img.src directly. It used to do
// that via the row's inline onmouseenter, removed along with the other
// inline hover handlers; it now goes through search-sidebar.js's shared
// window.showHoverFor, trusted the way the scroll hit-test's hover is.
test('the chart legend hover calls showHoverFor and has dropped onmouseenter', () => {
    expect(source).toContain('window.showHoverFor(row, true)');
    expect(source).not.toContain('onmouseenter');
});
