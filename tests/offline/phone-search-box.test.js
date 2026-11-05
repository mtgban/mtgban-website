import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const root = join(import.meta.dir, '..', '..');
const read = (file) => readFileSync(join(root, file), 'utf8');

// The navbar's box shows only in landscape anywhere else (search-mobile.css), and
// the offline page has no other, so without this rule an upright phone can't search.
test('the offline page shows the navbar box on an upright phone', () => {
    expect(read('templates/mobile/offline.html')).not.toContain('<input');
    expect(read('templates/mobile/partials/navbar.html')).toContain('id="navsearchbox"');
    expect(read('js/offline/offline-page-mobile.js')).toContain("boxId: 'navsearchbox'");

    // Not indented, so outside any orientation's media query.
    const rule = read('css/offline.css').match(/^body:has\(#m-offline-results\) \.m-nav-search \{([^}]*)\}/m);
    expect(rule[1]).toContain('display: flex');
});

// The suggestions live in the nav, so the nav has to stack above the bar holding
// the Singles and Sealed pills, or they open underneath it.
test('the suggestions open over the Singles and Sealed pills', () => {
    const zIndex = (file, selector) => {
        const rule = read(file).match(new RegExp('^' + selector + ' \\{([^}]*)\\}', 'm'));
        return Number(rule[1].match(/z-index: (\d+)/)[1]);
    };
    const nav = zIndex('css/offline.css', 'body:has\\(#m-offline-results\\) \\.m-nav');
    expect(nav).toBeGreaterThan(zIndex('css/search-mobile.css', '\\.m-search-bar-sticky'));
});
