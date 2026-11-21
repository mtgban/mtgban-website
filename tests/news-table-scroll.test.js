import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const css = readFileSync(join(import.meta.dir, '..', 'css', 'news.css'), 'utf8');

// The report table is wider than an iPad or a small laptop, so its box
// scrolls at every width: a clip there hides the right-hand columns.
test('the newspaper table scrolls sideways at every width', () => {
    const base = css.match(/^\.news-table-wrap \{([^}]*)\}/m);
    expect(base, 'expected a top-level .news-table-wrap rule').toBeTruthy();
    expect(base[1]).toMatch(/overflow-x:\s*auto;/);
    expect(base[1]).not.toMatch(/overflow:\s*hidden/);

    // No media query takes the scroll back for some widths.
    const nested = [...css.matchAll(/^\s+\.news-table-wrap \{([^}]*)\}/gm)];
    for (const m of nested) expect(m[1]).not.toMatch(/overflow/);
});
