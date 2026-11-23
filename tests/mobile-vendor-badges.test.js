import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// A long store name on the offline phone page gives way to the ellipsis,
// never the Best badge after it: the name has an element of its own, and
// only that element shrinks.
test('a store name truncates alone and its badges stay whole', () => {
    const css = read('css/search-mobile.css');
    const box = css.match(/^\.m-vendor-name:has\(> \.m-vendor-label\) \{([^}]*)\}/m);
    expect(box, 'expected the name box to lay out its children').toBeTruthy();
    expect(box[1]).toMatch(/display:\s*flex;/);
    const name = css.match(/^\.m-vendor-name > \.m-vendor-label \{([^}]*)\}/m);
    expect(name, 'expected the name to take the ellipsis').toBeTruthy();
    expect(name[1]).toMatch(/min-width:\s*0;/);
    expect(name[1]).toMatch(/text-overflow:\s*ellipsis;/);
    expect(css).toMatch(/^\.m-vendor-name > :not\(\.m-vendor-label\) \{\s*flex:\s*none;/m);

    const offline = read('js/offline/offline-render-mobile.js');
    expect(offline.match(/<span class="m-vendor-label">' \+ escapeHtml\(r\.name\) \+ '<\/span>' \+ \(i === 0 \? '<span class="m-best-badge">/g).length).toBe(2);
});
