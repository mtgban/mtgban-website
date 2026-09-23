const { test, expect } = require('bun:test');
const fs = require('fs');
const path = require('path');

// Every vertical offset in the search column comes down to one line: the line a
// result header pins to. The results column starts on it, the fixed sidebar
// starts on it, and the first header's own static position sits on it. Each of
// those has been broken at least once by a change that read as locally
// reasonable, and the symptoms are quiet rather than obvious - a column that
// drifts a little before its headers catch, a footer creeping up over the
// sidebar, a variant row that looks permanently half-scrolled.
//
// These assert the arithmetic in the stylesheet rather than rendered pixels, so
// they run without a browser. They are deliberately about which tokens appear
// in which declaration: that is what drifts.
const css = fs.readFileSync(path.join(__dirname, '../../css/search.css'), 'utf8');

// A selector can be styled more than once - a base rule plus one inside the
// desktop @media block - so collect every body and look through all of them
// rather than trusting whichever comes first.
function rules(selector) {
    const esc = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(?:^|[};{]|\\*/)\\s*${esc}\\s*\\{([^{}]*)\\}`, 'g');
    const out = [];
    let m;
    while ((m = re.exec(css)) !== null) out.push(m[1]);
    expect(out.length, `expected at least one ${selector} rule in css/search.css`).toBeGreaterThan(0);
    return out;
}

// Every value a selector gives a property, in source order. A selector styled
// twice can set the same property twice - .search-layout floors min-height at 0
// in the shared rule and again with the real calc in the desktop one - so a
// helper that stopped at the first match would assert against the wrong half.
function declarations(selector, prop) {
    const out = [];
    for (const body of rules(selector)) {
        const m = body.match(new RegExp(`(?:^|[;{\\s])${prop}\\s*:\\s*([^;]+);`));
        if (m) out.push(m[1].trim());
    }
    return out;
}

function declaration(selector, prop) {
    const all = declarations(selector, prop);
    return all.length ? all[all.length - 1] : null;
}

test('the results column starts on the line its headers pin to', () => {
    // .page-content pads by --nav-height plus --content-padding-slack; this
    // negative margin takes the slack back off so the column begins at
    // --nav-height. Drop it and every header starts a slack below its own
    // sticky top, so the column visibly drifts before the first one catches.
    const margin = declaration('.search-layout', 'margin-top');
    expect(margin, 'expected .search-layout to declare margin-top').toBeTruthy();
    expect(margin).toContain('-1');
    expect(margin).toContain('--content-padding-slack');
});

test('a header pins exactly one cover below the navbar', () => {
    // The cover masks the band between the navbar and a pinned header, so the
    // header has to pin exactly its height lower - they are one stack.
    const coverTop = declaration('.result-header-cover', 'top');
    const coverHeight = declaration('.result-header-cover', 'height');
    const headerTop = declaration('.result-header', 'top');

    expect(coverTop).toContain('--nav-height');
    expect(coverHeight).toContain('--result-cover-height');
    expect(headerTop).toContain('--nav-height');
    expect(headerTop).toContain('--result-cover-height');
});

test('the first header starts on the line it pins to, not above it', () => {
    // A sticky offset never moves anything else. A header whose static
    // position sits above its own sticky top is therefore painted lower than
    // the space it left behind, and covers what follows it - the variant row
    // - by exactly that difference, permanently, from the moment the page
    // loads. This column's top padding is what closes that gap, so it has to
    // read the same token the header's sticky offset does.
    // Narrow viewports override this padding with their own flat value; there
    // the sidebar has collapsed and none of this stack applies, so it is the
    // rule that governs the sticky column we care about here.
    const tops = declarations('.search-results', 'padding').map(v => v.split(/\s+/)[0]);
    expect(
        tops.some(top => top.includes('--result-cover-height')),
        `expected .search-results' top padding to be the cover height, saw: ${tops.join(' | ')}`,
    ).toBe(true);
});

test('the cover gives back exactly the height it takes', () => {
    // The cover contributes no flow height - it is pulled back over the
    // header it masks. If these two ever stop matching, the header's static
    // position moves and the fold above comes back.
    const height = declaration('.result-header-cover', 'height');
    const pullback = declaration('.result-header-cover', 'margin-bottom');
    expect(height).toContain('--result-cover-height');
    expect(pullback).toContain('--result-cover-height');
    expect(pullback).toContain('-1');
});

test('the fixed sidebar starts on that same line', () => {
    const top = declaration('.search-sidebar', '--search-sidebar-top');
    expect(top, 'expected --search-sidebar-top to be declared').toBeTruthy();
    expect(top).toContain('--nav-height');
    // Adding the slack here is the tempting fix for the two columns not
    // lining up. It lines them up by pushing the results column down into
    // that drift instead - bring the sidebar up to the line, never the other
    // way round.
    expect(top).not.toContain('--content-padding-slack');
});

test('the layout floors its height at that same line', () => {
    // The fixed sidebar contributes no height to this grid, so a short
    // result list would otherwise end the document - and the site footer
    // after it - well above the sidebar's own fixed bottom edge.
    const min = declarations('.search-layout', 'min-height').find(v => v.includes('100dvh'));
    expect(min, 'expected .search-layout to floor its height against the viewport').toBeTruthy();
    expect(min).toContain('--nav-height');
    // Subtracting the slack as well ends the document a slack short, which
    // pulls the site footer up past where the sidebar's bottom edge sits.
    expect(min).not.toContain('--content-padding-slack');
});
