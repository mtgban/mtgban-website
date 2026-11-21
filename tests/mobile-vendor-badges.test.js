import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// A long store name gives way to the ellipsis, never the badges after it
// (Best, Paused, the wait arrow): the name has an element of its own, and
// only that element shrinks.
test('a store name truncates alone and its badges stay whole', () => {
    const tpl = read('templates/mobile/search.html');
    const bare = tpl.match(/\{\{else\}\}[^<{]*\{\{\$entry\.ScraperName\}\}[^<]*?\{\{end\}\}/g) || [];
    expect(bare, 'a store name with no link of its own').toEqual([]);
    expect(tpl.match(/\{\{else\}\}<span class="m-vendor-label">\{\{\$entry\.ScraperName\}\}/g).length).toBe(6);

    const css = read('css/search-mobile.css');
    const box = css.match(/^\.m-vendor-name:has\(> \.m-vendor-link, > \.m-vendor-label\) \{([^}]*)\}/m);
    expect(box, 'expected the name box to lay out its children').toBeTruthy();
    expect(box[1]).toMatch(/display:\s*flex;/);
    const name = css.match(/^\.m-vendor-name > \.m-vendor-link,\n\.m-vendor-name > \.m-vendor-label \{([^}]*)\}/m);
    expect(name, 'expected the name to take the ellipsis').toBeTruthy();
    expect(name[1]).toMatch(/min-width:\s*0;/);
    expect(name[1]).toMatch(/text-overflow:\s*ellipsis;/);
    expect(css).toMatch(/^\.m-vendor-name > :not\(\.m-vendor-link, \.m-vendor-label\) \{\s*flex:\s*none;/m);
    // A restricted store's name stays italic once wrapped.
    expect(css).toContain('.m-vendor-restricted > :not(.m-vendor-link, .m-vendor-label) {');

    const offline = read('js/offline/offline-render-mobile.js');
    expect(offline.match(/<span class="m-vendor-label">' \+ escapeHtml\(r\.name\) \+ '<\/span>' \+ \(i === 0 \? '<span class="m-best-badge">/g).length).toBe(2);
});

// Under 375px a state pill and Best together leave a store's name about two
// letters, so Best steps aside there: the highlighted row still says it.
test('Best gives way to a state pill on the narrowest phones', () => {
    const css = read('css/search-mobile.css');
    const block = css.match(/@media \(max-width: 374px\) \{\s*\.m-vendor-name:has\(> \.bl-pill\) > \.m-best-badge \{([^}]*)\}/);
    expect(block, 'expected the narrow-phone rule').toBeTruthy();
    // Out of sight and out of the layout, but still read aloud.
    expect(block[1]).not.toMatch(/display:\s*none/);
    expect(block[1]).toMatch(/position:\s*absolute;/);
    expect(block[1]).toMatch(/width:\s*1px;/);
    expect(block[1]).toMatch(/clip-path:\s*inset\(50%\);/);
});
