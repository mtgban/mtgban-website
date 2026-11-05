import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const root = join(import.meta.dir, '..', '..');
const shell = readFileSync(join(root, 'js', 'offline', 'offline-page-desktop.js'), 'utf8');
const sw = readFileSync(join(root, 'sw.js'), 'utf8');

// The sidebar image starts as src="", which trips the card-art fallback once
// and latches its guard; only setCardArtSource re-arms it, so a bare
// img.src assignment here would leave a never-synced card as a hole.
test('the shell sets the sidebar image through setCardArtSource', () => {
    const start = shell.indexOf('function showImage(');
    expect(start).toBeGreaterThan(-1);
    const end = shell.indexOf('\n    var page', start);
    expect(end).toBeGreaterThan(start);
    const body = shell.slice(start, end);
    expect(body).toContain("setCardArtSource(document.getElementById('cardImage')");
    expect(body).not.toMatch(/\.src\s*=/);
});

// What that fallback shows has to be in the shell cache, or offline it
// fails the same way the image did.
test('the service worker precaches the game card back', () => {
    expect(sw).toContain("SHELL_URLS.push('/img/backs/' + GAME + '.webp')");
    expect(sw).toContain("var GAME = self.__GAME || ''");
});

// An empty count collapses its line, and the sidebar image rides on it.
test('the shell counts an empty result as well', () => {
    expect(shell).toContain("n + ' result' + (n === 1 ? '' : 's') + ' found'");
});
