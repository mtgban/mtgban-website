import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const root = join(import.meta.dir, '..', '..');
const read = (file) => readFileSync(join(root, file), 'utf8');
const page = read('templates/mobile/offline.html');
const search = read('templates/mobile/search.html');

// The search box is at the foot of an upright phone and in the navbar of a
// landscape one, as on the search page.
test('the offline page searches from the foot and, in landscape, from the navbar', () => {
    expect(page).toContain('id="searchbox"');
    expect(read('templates/mobile/partials/navbar.html')).toContain('id="navsearchbox"');
    expect(read('js/offline/offline-page-mobile.js')).toContain("boxes: [['searchbox', 'searchform'], ['navsearchbox', 'navsearchform']]");
});

// The deck is the search's: its script, its styles and the templates of what
// moves a card between its panes.
test('the offline page shares the search\'s deck', () => {
    for (const shared of ['/js/search-cards.js', '/css/search-cards-mobile.css', '/css/search-rows.css',
        '{{template "m-edge-sell"', '{{template "m-edge-buy"', '{{template "m-pane-head"']) {
        expect(page).toContain(shared);
        expect(search).toContain(shared);
    }
    // The renderer fills in, or drops, exactly this price.
    expect(read('js/offline/offline-render-mobile.js')).toContain('\'<span class="m-edge-price">{price}</span>\'');
    expect(read('templates/partials/card-panes.html')).toContain('{{with .Price}}<span class="m-edge-price">{{.}}</span>{{end}}');
});

// Every script and stylesheet the page loads has to be in the shell cache, or
// it draws nothing with the network gone.
test('the service worker precaches what the phone\'s offline page loads', () => {
    const sw = read('sw.js');
    const assets = [...page.matchAll(/(?:src|href)="(\/(?:js|css)\/[^"?]+)\?/g)].map((m) => m[1]);
    expect(assets).toContain('/js/search-cards.js');
    for (const asset of assets) expect(sw).toContain("'" + asset + "?hash='");
});
