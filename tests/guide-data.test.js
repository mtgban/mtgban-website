import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/guide-data.js', import.meta.url), 'utf8');

// The query parser reads one operator, :, < or >, so r>=rare compares
// against "=rare", which no game ranks: a guide example must not show it.
test('no guide example uses >= or <=', () => {
    // Whichever quote a string uses: the examples are single-quoted, the
    // summaries double-quoted.
    expect(source.match(/(['"`])(?:(?!\1)[^\n])*\w[<>]=(?:(?!\1)[^\n])*\1/g)).toBeNull();
});
