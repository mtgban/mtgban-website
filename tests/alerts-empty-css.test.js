import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

// The favorites empty-state rules serve the Alerts page too, so they live
// in main.css, which every page loads, and nowhere else.
test('the landing-empty rules live in main.css alone', () => {
    const main = readFileSync(new URL('../css/main.css', import.meta.url), 'utf8');
    const search = readFileSync(new URL('../css/search.css', import.meta.url), 'utf8');
    for (const sel of ['.landing-empty-fav {', '.landing-empty-mini-result {', '.landing-empty-tooltip {', '@keyframes landing-empty-pulse', '@keyframes landing-empty-fade']) {
        expect(main).toContain(sel);
        expect(search).not.toContain(sel);
    }
    expect(search).not.toMatch(/landing-empty-/);
    // search.css alone defines --search-link, so the moved rules carry a fallback.
    expect(main).not.toMatch(/var\(--search-link\)/);
    expect(main).toContain('var(--search-link, var(--ainfo))');
});
