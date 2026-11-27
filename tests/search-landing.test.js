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

test('the landscape nav opens the sealed category jump the hidden bar holds', () => {
    // Landscape hides the bar with the landing's Jump button, so the nav's
    // button shows for the category sheet and falls back to opening it.
    const landscape = css.slice(css.indexOf('@media (orientation: landscape)'));
    expect(landscape).toMatch(/body:has\(#m-sealed-cat-overlay\) \.m-nav-filter-btn[^{]*\{\s*display: flex;/);
    const nav = readFileSync(join(import.meta.dir, '..', 'templates', 'mobile', 'partials', 'navbar.html'), 'utf8');
    const btn = nav.match(/<button[^>]*m-nav-filter-btn[^>]*>/)[0];
    expect(btn).toContain("getElementById('m-filter-overlay')||document.getElementById('m-sealed-cat-overlay')");
    expect(btn).toContain("getElementById('m-filter-sheet')||document.getElementById('m-sealed-cat-sheet')");
});
