const { test, expect } = require('bun:test');
const fs = require('fs');
const path = require('path');

// The server (and a handful of scripts) write `<i data-lucide="…">`, and the
// lucide bundle swaps each one for an `<svg>` a frame later. An unsized
// placeholder is a 0x0 box, so every row whose size depends on the icon lays
// out wrong on first paint and jumps when the bundle lands.
//
// css/search.css was paired first and is guarded next door, in
// search-sticky-offsets.test.js. This is the same assertion for the rest of
// the stylesheets, and it is about which selectors appear in which rule
// rather than about any particular number - that is what drifts.
//
// Measured before pairing (see the PR): the guide grew 49.5px and moved 648
// elements, /'s action strip slid 40px sideways, and the search page's image
// button - right-aligned - slid its strip 24px at 860px wide.

// Every base below holds a plain `<i data-lucide>` reached through the parent,
// so the rule that sizes the icon has to size the placeholder too. Bases whose
// placeholder carries its own class (.settings-section-chevron, .group-chevron,
// .m-settings-chevron, .m-sort-dir) are deliberately absent: there the one
// selector already sizes both states, and there is no `X svg` rule to pair.
const BASES = {
    'css/landing.css': ['.landing-action-btn'],
    'css/guide.css': ['.guide-nav-link', '.guide-section-header', '.guide-example-copy'],
    'css/screener.css': ['.screener-reset'],
    'css/command-palette.css': [
        '.cp-category-header', '.cp-result-icon', '.cp-result-delete',
        '.cp-chip-icon', '.cp-chip-delete',
    ],
    'css/mobile.css': ['.m-pin-btn'],
    'css/search-mobile.css': [
        '.m-search-btn', '.m-sort-pill', '.m-fav-btn', '.m-chart-btn',
        '.m-actions-btn', '.m-actions-item', '.m-setpicker-close',
        '.m-setpicker-search', '.m-fav-sort .fav-sort-pill',
    ],
};

// Walk a stylesheet and hand back every style rule. At-rules are descended
// into rather than reported, so a rule inside `@media (max-width: 900px)` is
// found with the same selector it is written with - which matters, since
// several of these icons are only sized in a media block.
function eachRule(css, fn) {
    const src = css.replace(/\/\*[\s\S]*?\*\//g, m => m.replace(/[^\n]/g, ' '));
    let start = 0;
    for (let i = 0; i < src.length; i++) {
        if (src[i] === '}') { start = i + 1; continue; }
        if (src[i] !== '{') continue;
        const selector = src.slice(start, i).trim();
        let depth = 1, j = i + 1, nested = false;
        for (; j < src.length && depth > 0; j++) {
            if (src[j] === '{') { depth++; nested = true; }
            else if (src[j] === '}') depth--;
        }
        if (selector.startsWith('@')) { start = i + 1; continue; }   // descend
        if (!nested) fn({ selector, body: src.slice(i + 1, j - 1) });
        i = j - 1;
        start = j;
    }
}

function read(file) {
    return fs.readFileSync(path.join(__dirname, '../..', file), 'utf8');
}

// The rules that give `<base> svg` a box, as opposed to the ones that only
// paint it a colour.
function sizingRules(css, base) {
    const esc = base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(^|,)\\s*${esc}\\s+svg\\s*(,|$)`);
    const out = [];
    eachRule(css, r => {
        if (!re.test(r.selector.replace(/\s+/g, ' '))) return;
        if (!/(^|[;{\s])(width|height)\s*:/.test(r.body)) return;
        out.push(r.selector.replace(/\s+/g, ' '));
    });
    return out;
}

for (const [file, bases] of Object.entries(BASES)) {
    const css = read(file);
    for (const base of bases) {
        test(`${file}: "${base}" sizes its icon placeholder alongside the icon`, () => {
            const rules = sizingRules(css, base);
            expect(
                rules.length,
                `expected a rule sizing "${base} svg" in ${file}; without one the icon `
                + `arrives at lucide's own 24 against a 0x0 placeholder`,
            ).toBeGreaterThan(0);
            for (const selector of rules) {
                // Either spelling reserves the box. `i[data-lucide]` names
                // exactly the element being reserved and is what new rules
                // here use; a bare `i` is kept where raising the specificity
                // would change which rule wins - `.m-sort-pill i[data-lucide]`
                // (0,2,1) beats `.m-sort-pill .m-sort-dir` (0,2,0) and pinned
                // that placeholder to 18px against a 20px icon.
                const esc = base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
                const paired = new RegExp(`(^|,)\\s*${esc}\\s+i(\\[data-lucide\\])?\\s*(,|$)`);
                expect(
                    paired.test(selector),
                    `"${selector}" in ${file} sizes the icon without its placeholder; `
                    + `the row will jump when lucide paints`,
                ).toBe(true);
            }
        });
    }
}

// Not every `X svg { width }` in the tree wants a placeholder: three files
// draw the lucide markup themselves rather than letting the bundle do it, and
// a blanket scan reads those as unpaired. Pin why they are exempt, so the
// exemption survives someone converting one of them to a placeholder.
test('the stylesheets that size a drawn svg have no placeholder to pair', () => {
    // templates/upload.html defines "upload-icon", which emits the markup
    // lucide would have produced minus the data-lucide attribute, so the
    // icons arrive with the page.
    expect(read('templates/upload.html')).toContain('{{define "upload-icon"}}');
    expect(read('templates/upload.html')).not.toContain('{{define "upload-icon"}}<i');

    // templates/offline.html inlines the same way - the offline shell cannot
    // reach the cdn by definition.
    const offline = read('templates/offline.html');
    expect(offline).toContain('class="lucide lucide-clock"');
    expect(offline).not.toContain('data-lucide');

    // .news-toc-icon holds $page.Icon, which is an emoji or an index number.
    expect(read('templates/news.html')).toContain('<span class="news-toc-icon">{{if $page.Icon}}');
});
