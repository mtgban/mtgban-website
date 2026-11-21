import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const css = readFileSync(join(import.meta.dir, '..', 'css', 'search-mobile.css'), 'utf8');

// A row that widens its own count track moves only its own price. A flat
// row's count takes the empty chevron track instead, and only a count under
// a chevron widens the track, once per card, so every row's grid reads it.
test('a card with TCGplayer counts keeps its prices in one column', () => {
    const flat = css.match(/^\.m-vendor-flat \.m-vendor-qty:has\(\.tcg-listings\) \{([^}]*)\}/m);
    expect(flat, 'expected a flat row\'s count to take the chevron track').toBeTruthy();
    expect(flat[1]).toMatch(/grid-column:\s*span 2;/);

    const card = css.match(/^\.m-card:has\(summary \.tcg-listings\) \{([^}]*)\}/m);
    expect(card, 'expected a count under a chevron to widen the card\'s track').toBeTruthy();
    expect(card[1]).toMatch(/--m-vendor-qty-width:\s*[\d.]+em;/);
    // Every card with counts making the room squeezed the store names.
    expect(css).not.toMatch(/^\.m-card:has\(\.tcg-listings\)/m);

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
