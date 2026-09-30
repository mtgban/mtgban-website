import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

// utils.js is a plain script the page loads, so its helpers are globals.
(0, eval)(readFileSync(new URL('../js/utils.js', import.meta.url), 'utf8'));

test('escapeHtml escapes text and both quote styles', () => {
    expect(escapeHtml(`<a href="x" title='y'>R&D</a>`))
        .toBe('&lt;a href=&quot;x&quot; title=&#39;y&#39;&gt;R&amp;D&lt;/a&gt;');
    expect(escapeHtml(42)).toBe('42');
});

test('escapeHtml writes nothing for a missing value', () => {
    expect(escapeHtml(null)).toBe('');
    expect(escapeHtml(undefined)).toBe('');
});
