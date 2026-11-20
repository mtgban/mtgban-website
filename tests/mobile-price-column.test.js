import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const css = readFileSync(join(import.meta.dir, '..', 'css', 'search-mobile.css'), 'utf8');

// A row that widens its own count track moves only its own price, so the
// width is set once per card and every row's grid reads it.
test('a card with TCGplayer counts gives every row the same count track', () => {
    const card = css.match(/^\.m-card:has\(\.tcg-listings\) \{([^}]*)\}/m);
    expect(card, 'expected .m-card:has(.tcg-listings) to set the width').toBeTruthy();
    expect(card[1]).toMatch(/--m-vendor-qty-width:\s*[\d.]+em;/);

    const tracks = [...css.matchAll(/^\s*\.m-vendor-right \{([^}]*)\}/gm)]
        .map(m => m[1].match(/grid-template-columns:\s*([^;]+);/))
        .filter(Boolean)
        .map(m => m[1].trim().split(/\s+(?![^(]*\))/));
    // One rule for both orientations, so a phone's price column has one width.
    expect(tracks.length).toBe(1);
    expect(tracks[0][0]).toBe('5em');
    for (const columns of tracks) expect(columns[1]).toBe('var(--m-vendor-qty-width, 2em)');

    expect(css).not.toMatch(/\.m-vendor-right:has\(\.tcg-listings\)[^{]*\{[^}]*grid-template-columns/);
});
