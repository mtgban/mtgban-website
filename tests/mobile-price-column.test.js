import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const css = readFileSync(join(import.meta.dir, '..', 'css', 'search-mobile.css'), 'utf8');

// The offline phone page's rows keep their prices in one column: one track
// rule for both orientations, so a phone's price column has one width.
test('a phone row keeps its prices in one column', () => {
    const tracks = [...css.matchAll(/^\s*\.m-vendor-right \{([^}]*)\}/gm)]
        .map(m => m[1].match(/grid-template-columns:\s*([^;]+);/))
        .filter(Boolean)
        .map(m => m[1].trim().split(/\s+(?![^(]*\))/));
    expect(tracks.length).toBe(1);
    expect(tracks[0][0]).toBe('5em');
    for (const columns of tracks) expect(columns[1]).toBe('var(--m-vendor-qty-width, 2em)');
});
