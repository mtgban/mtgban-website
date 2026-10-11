import { test, expect } from 'bun:test';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

const root = join(import.meta.dir, '..', 'templates');
const SYNC = ['/js/cookies.js', '/js/utils.js', '/js/card-art-fallback.js'];

function templates(dir) {
    return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? templates(join(dir, e.name)) : e.name.endsWith('.html') ? [join(dir, e.name)] : []);
}

test('every local script tag is deferred, except the three head helpers', () => {
    const bad = [];
    for (const f of templates(root)) {
        const html = readFileSync(f, 'utf8');
        for (const m of html.matchAll(/<script\b([^>]*\bsrc="(\/js\/[^"?]+)[^"]*"[^>]*)>/g)) {
            const attrs = m[1], path = m[2];
            const deferred = /\bdefer\b/.test(attrs);
            if (SYNC.includes(path) ? deferred : !deferred) bad.push(f.replace(root, '') + ': ' + path);
        }
    }
    expect(bad).toEqual([]);
});

test('the lucide tag is deferred and icons.js follows it in every base', () => {
    for (const f of ['base.html', 'mobile/base-mobile.html', 'base-landing.html']) {
        const html = readFileSync(join(root, f), 'utf8');
        const lucide = html.indexOf('unpkg.com/lucide@1.47.0/dist/umd/lucide.js');
        expect(lucide).toBeGreaterThan(-1);
        const tagStart = html.lastIndexOf('<script', lucide);
        const tagEnd = html.indexOf('>', lucide);
        const tag = html.slice(tagStart, tagEnd);
        expect(tag).toContain('defer');
        const after = html.slice(tagEnd + 1);
        const nextScript = after.indexOf('<script');
        const nextTag = after.slice(nextScript, after.indexOf('>', nextScript));
        expect(nextTag).toContain('/js/icons.js');
        expect(html).not.toContain('lucide.createIcons();</script>');
    }
});

test('the phone base guards the theme inline before the navbar', () => {
    const html = readFileSync(join(root, 'mobile', 'base-mobile.html'), 'utf8');
    const guard = html.indexOf("localStorage.getItem('theme')");
    const navbar = html.indexOf('{{template "navbar" .}}');
    expect(guard).toBeGreaterThan(-1);
    expect(guard).toBeLessThan(navbar);
});
