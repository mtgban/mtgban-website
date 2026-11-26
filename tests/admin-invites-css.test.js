import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const css = readFileSync(join(import.meta.dir, '..', 'css', 'admin-invites.css'), 'utf8');

test('the invites rows wrap so the link and revoke fit the admin column', () => {
    // admin.css keeps every admin cell on one line; this table opts out,
    // all but the link and its Copy.
    expect(css).toMatch(/\.admin-table\.admin-invites td \{\s*white-space: normal;/);
    expect(css).toMatch(/\.admin-table\.admin-invites td\.admin-invite-link \{\s*white-space: nowrap;/);
    expect(css).toMatch(/\.admin-invite-link input \{\s*width: 10em;/);
});

test('the invite form is 16px on a touch screen, so iOS does not zoom into it', () => {
    const coarse = css.slice(css.indexOf('@media (pointer: coarse)'));
    const rule = coarse.match(/\{([\s\S]*?)\{([^}]*)\}/);
    for (const field of ['.admin-invite-form input[type]', '.admin-invite-form select', '.admin-invite-link input[type]']) {
        expect(rule[1]).toContain(field);
    }
    expect(rule[2]).toContain('font-size: 16px;');
});
