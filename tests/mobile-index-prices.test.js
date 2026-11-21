import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// An index row with two prices (CM Low / Trend, TCG Low / Market) shows both
// on a phone, the second under the first, in sellers and buyers alike. A
// sealed EV row's Secondary is its Sim median, which desktop shows in a
// column of its own with a tooltip; it gets no unlabelled figure here.
test('mobile index rows show their second price', () => {
    const tpl = read('templates/mobile/search.html');
    const shown = '{{if and $entry.Secondary (not $entry.IsEV)}}<span class="m-vendor-secondary">$ {{printf "%.2f" $entry.Secondary}}</span>{{end}}</span>';
    expect(tpl.split(shown).length - 1).toBe(2);
    const css = read('css/search-mobile.css');
    const rule = css.match(/^\.m-vendor-secondary \{([^}]*)\}/m);
    expect(rule, 'expected a .m-vendor-secondary rule').toBeTruthy();
    expect(rule[1]).toMatch(/display:\s*block;/);
});
