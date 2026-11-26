import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const css = readFileSync(join(import.meta.dir, '..', 'css', 'search-mobile.css'), 'utf8');

test('the upright landing clips its page, so a category jump scrolls only the list', () => {
    // iPhone Safari scrolls an overflow: hidden root on a jump to
    // #m-sealed-..., which hides the heading under the nav.
    const portrait = css.slice(css.indexOf('@media (orientation: portrait)'));
    const rule = portrait.match(/html:has\(\.m-landing\),\s*html:has\(\.m-landing\) body \{([^}]*)\}/)[1];
    expect(rule).toMatch(/overflow: hidden;[\s\S]*overflow: clip;/);
});
