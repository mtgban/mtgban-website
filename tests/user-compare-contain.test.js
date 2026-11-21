import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// The compare table's "Not included" text is positioned absolute. On a phone
// the table scrolls inside .user-compare, so that box has to hold the text,
// or the text widens the page and the whole page pans sideways.
test('the tier table holds its screen-reader text inside its scroll box', () => {
    const css = read('css/user.css');
    expect(css).toMatch(/\.user-hidden \{[^}]*position:\s*absolute;/);
    const box = css.match(/^\.user-compare \{([^}]*)\}/m);
    expect(box, 'expected a top-level .user-compare rule').toBeTruthy();
    expect(box[1]).toMatch(/position:\s*relative;/);
    // Every hidden label sits in the box, between its opening and </table>.
    const tpl = read('templates/user.html');
    const start = tpl.indexOf('<div class="user-compare">');
    expect(start).toBeGreaterThan(-1);
    const inBox = tpl.slice(start, tpl.indexOf('</table>', start));
    const count = (s) => (s.match(/class="user-hidden"/g) || []).length;
    expect(count(inBox)).toBeGreaterThan(0);
    expect(count(inBox)).toBe(count(tpl));
});
