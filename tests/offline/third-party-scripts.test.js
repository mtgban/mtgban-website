const { test, expect } = require('bun:test');
const fs = require('fs');
const path = require('path');

// Scripts we load from a CDN run on the reader's page with the same reach as
// our own. A floating tag means whatever that project publishes next is in
// production on the first cold load after it lands, reviewed by nobody - and
// it costs a redirect through the registry's version resolver every time.
// Scripts only. The one floating stylesheet, keyrune@latest, is deliberate:
// it is the set-symbol font, so a float is how a new set's symbol appears
// without a deploy, and pinning it would freeze the symbols to whatever
// shipped last. A stylesheet also cannot execute, which is most of why the
// tag matters for the scripts below.
const templates = path.join(__dirname, '../../templates');

function htmlFiles(dir) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
        const full = path.join(dir, e.name);
        return e.isDirectory() ? htmlFiles(full) : e.name.endsWith('.html') ? [full] : [];
    });
}

test('no template loads a third-party script from a floating version tag', () => {
    const floating = [];
    for (const file of htmlFiles(templates)) {
        const src = fs.readFileSync(file, 'utf8');
        // <script src="…"> pointing at a package CDN, with a tag rather than
        // a version: @latest, @next, @canary, or a bare package with no @ at
        // all (which those CDNs resolve to latest just the same).
        const re = /<script[^>]+src="(https?:\/\/(?:unpkg\.com|cdn\.jsdelivr\.net|esm\.sh|cdnjs\.cloudflare\.com)\/[^"]+)"/g;
        let m;
        while ((m = re.exec(src)) !== null) {
            const url = m[1];
            // unpkg and jsdelivr carry the version after an @; cdnjs puts it
            // in the path (…/libs/codemirror/5.65.18/…). Either is a pin as
            // long as it is an exact three-part version - a bare major like
            // chart.js@4 is a range, and ranges move.
            const pinned = /@\d+\.\d+\.\d+(?:[/@]|$)/.test(url)
                || /cdnjs\.cloudflare\.com\/ajax\/libs\/[^/]+\/\d+\.\d+\.\d+\//.test(url);
            if (!pinned) floating.push(`${path.relative(templates, file)}: ${url}`);
        }
    }
    expect(
        floating,
        `pin these to an exact version:\n  ${floating.join('\n  ')}`,
    ).toEqual([]);
});

function jsFiles(dir) {
    return fs.readdirSync(dir, { withFileTypes: true }).flatMap(e => {
        const full = path.join(dir, e.name);
        return e.isDirectory() ? jsFiles(full) : e.name.endsWith('.js') ? [full] : [];
    });
}

// A script injected from js, preloaded by a template or precached by the
// service worker runs just the same, so it is held to the same pin. Lucide is
// also asked for by URL from three places, and the offline cache answers
// only the one it stored: they have to be the same URL.
test('scripts from js, preloads and the service worker are pinned too', () => {
    const root = path.join(__dirname, '../..');
    const files = [...htmlFiles(templates), ...jsFiles(path.join(root, 'js')), path.join(root, 'sw.js')];
    const floating = [];
    const lucide = new Set();
    for (const file of files) {
        const src = fs.readFileSync(file, 'utf8');
        const re = /https?:\/\/(?:unpkg\.com|cdn\.jsdelivr\.net\/npm)\/[^'"\s)]+\.js\b/g;
        let m;
        while ((m = re.exec(src)) !== null) {
            const url = m[0];
            if (!/@\d+\.\d+\.\d+\//.test(url)) floating.push(`${path.relative(root, file)}: ${url}`);
            if (url.includes('/lucide@')) lucide.add(url);
        }
    }
    expect(floating, `pin these to an exact version:\n  ${floating.join('\n  ')}`).toEqual([]);
    expect([...lucide]).toHaveLength(1);
});
