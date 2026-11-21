import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

// A report shows one page of its rows, so only the server can sort it: a
// client sort would order the page alone, beside the links that order it all.
test('the newspaper sorts through its links alone', () => {
    for (const file of ['templates/news.html', 'templates/mobile/news.html']) {
        expect(read(file), file).not.toMatch(/tablesort[^"]*\.js|new Tablesort/);
    }
    const desktop = read('templates/news.html');
    expect(desktop).toContain('&dir=desc&');
    expect(desktop).toContain('&dir=asc&');
});
