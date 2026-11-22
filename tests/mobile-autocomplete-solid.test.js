import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// Every mobile page's search dropdown is solid, not a blurred layer redrawn
// on each keystroke; mobile.css loads only in the mobile templates.
test('the mobile search dropdown is opaque on every page', () => {
    const css = read('css/mobile.css');
    for (const theme of ['dark', 'light']) {
        const rule = new RegExp('\\n\\.' + theme + '-theme \\.autocomplete-items \\{[^}]*backdrop-filter: none;');
        expect(css).toMatch(rule);
    }
    expect(read('templates/mobile/base-mobile.html')).toContain('/css/mobile.css');
    expect(read('templates/base.html')).not.toContain('/css/mobile.css');
});
