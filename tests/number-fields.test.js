import { test, expect } from 'bun:test';
import { read, tagsWith } from './metrics-helpers.js';

// A price or percent field asks a phone for its number keypad, not letters.
test('the price and percent filters open the decimal keypad', () => {
    const fields = {
        'templates/screener.html': ['Now $', 'Was $', 'Min %', 'Max %'],
        'templates/news.html': ['Min $', 'Max $'],
        'templates/mobile/news.html': ['Min $', 'Max $'],
    };
    for (const [file, placeholders] of Object.entries(fields)) {
        const src = read(file);
        for (const ph of placeholders) {
            const tags = tagsWith(src, `placeholder="${ph}"`);
            expect(tags.length, `${file} ${ph}`).toBe(1);
            expect(tags[0], `${file} ${ph}`).toContain('inputmode="decimal"');
        }
    }
});

// The Newspaper's change bounds are signed (a fall is stored as -18.4), and
// the iPhone's decimal pad has no minus key: those fields keep the keyboard.
test('the newspaper change filters keep a keyboard with a minus key', () => {
    for (const file of ['templates/news.html', 'templates/mobile/news.html']) {
        const src = read(file);
        for (const ph of ['Min %', 'Max %']) {
            const tags = tagsWith(src, `placeholder="${ph}"`);
            expect(tags.length, `${file} ${ph}`).toBe(1);
            expect(tags[0], `${file} ${ph}`).not.toContain('inputmode="decimal"');
        }
    }
});

// The Screener's columns are fixed fractions, so a header too wide for its
// column has to wrap its sort arrows at every width, not only on phones.
test('the screener headers wrap at every width', () => {
    const css = read('css/screener.css');
    const base = css.match(/^#screenerTable th \{([^}]*)\}/m);
    expect(base, 'expected a top-level #screenerTable th rule').toBeTruthy();
    expect(base[1]).toMatch(/white-space:\s*normal;/);
});
