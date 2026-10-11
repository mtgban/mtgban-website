import { test, expect } from 'bun:test';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

// --dodgerblue is a text colour; white text sits on --dodgerblue-fill,
// which keeps 4.5:1 in both themes.
test('no white-text rule takes --dodgerblue as its background', () => {
    const dir = join(import.meta.dir, '..', 'css');
    const bad = [];
    for (const f of readdirSync(dir).filter((n) => n.endsWith('.css'))) {
        for (const m of readFileSync(join(dir, f), 'utf8').matchAll(/([^{}]+)\{([^{}]*)\}/g)) {
            const body = m[2];
            if (/background(-color)?:\s*var\(--dodgerblue\)/.test(body) && /(^|[\s;])color:\s*(#fff(fff)?|white)\b/i.test(body)) {
                bad.push(f + ': ' + m[1].trim());
            }
        }
    }
    expect(bad).toEqual([]);
});
