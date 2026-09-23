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
    // ...and the footer comes after this grid, so flooring it at the whole
    // viewport pushes the footer past the bottom of it by the footer's own
    // height - every time, on a page with room to spare, which is a page
    // that then scrolls for nothing. This is not the sidebar's old reserve
    // (that was this column keeping clear of a footer crossing it, and the
    // test below pins that it is gone); this one is where the document ends.
    expect(min).toContain('--search-footer-reserve');
    // Subtracting the slack as well ends the document a slack short, which
    // pulls the site footer up past where the sidebar's bottom edge sits.
    expect(min).not.toContain('--content-padding-slack');
});

test('the footer starts where the results column does, not under the sidebar', () => {
    // The sidebar is fixed and reaches the viewport bottom, so a full-bleed
    // footer crosses it at the end of every page. That used to be paid for
    // with a reserved strip the sidebar had to stop short of - 90px given up
    // at every scroll position to protect one. Indenting the footer past the
    // sidebar column instead is what lets the sidebar own its full height,
    // so these two go together: if the footer ever goes full-bleed again,
    // the height below has to give the strip back.
    const left = declaration('body:has(.search-layout) .site-footer', 'margin-left');
    expect(left, 'expected the search page footer to clear the sidebar column').toBeTruthy();
    expect(left).toContain('--search-sidebar-left');
    expect(left).toContain('--search-sidebar-width');

    const height = declaration('.search-sidebar', 'height');
    expect(height).toContain('100dvh');
    expect(height).toContain('--search-sidebar-top');
    expect(height).not.toContain('reserve');
});

test('the sidebar column and the footer read one definition of where it sits', () => {
    // Three places used to carry the same centring arithmetic: the grid's
    // track, the fixed sidebar's left edge, and now the footer's indent.
    // They can only drift apart if one of them spells it out again.
    const bodyRule = rules('body:has(.search-layout)')[0];
    expect(bodyRule).toContain('--search-sidebar-left');
    expect(bodyRule).toContain('--search-sidebar-width');
    expect(declaration('.search-sidebar', 'left')).toBe('var(--search-sidebar-left)');
    expect(declaration('.search-sidebar', 'width')).toBe('var(--search-sidebar-width)');
    // Narrow viewports drop to a single column, so it is the two-column
    // track that has to read the token, not whichever rule comes last.
    const tracks = declarations('.search-layout', 'grid-template-columns');
    expect(
        tracks.some(t => t.includes('--search-sidebar-width')),
        `expected the two-column track to read the sidebar width, saw: ${tracks.join(' | ')}`,
    ).toBe(true);
});

test('Available In has a floor wherever it is showing a list', () => {
    // It is the box that gives when the column runs short, but only down to
    // a point: with min-height:0 it kept shrinking past its own content to
    // the 2px of border left over, which is the "clipped sliver" the
    // collapse exists to prevent, reached by the other road. Neither `auto`
    // nor `min-content` can express the floor - both floor a flex item at
    // its WHOLE content, every product the card knows - and `auto` is
    // collapsed to zero anyway by this box's own overflow: hidden.
    //
    // A floor of 0 is correct in exactly one place: the collapsed state,
    // where the box IS its title bar and has no list to keep room for. So
    // this asserts a real floor exists rather than that every rule carries
    // one.
    const floors = declarations('.search-sidebar .sidebar-products-card', 'min-height');
    expect(floors.length, 'expected the desktop Available In card to declare a floor').toBeGreaterThan(0);
    const real = floors.filter(v => /^[1-9]\d*px$/.test(v));
    expect(
        real.length,
        `expected a non-zero px floor among: ${floors.join(' | ')}`,
    ).toBeGreaterThan(0);
    // ...and the pressed-open state has to keep one, because that is the
    // state whose whole job is holding a list.
    const expanded = declarations('.search-sidebar .sidebar-products-card[data-expanded="true"]', 'min-height');
    expect(expanded.some(v => /^[1-9]\d*px$/.test(v)),
        `expected the expanded card to keep a floor, saw: ${expanded.join(' | ')}`).toBe(true);
});

test('running short collapses Available In to its title, it does not delete it', () => {
    // Removing the box outright left no trace that the products existed.
    // The title bar is two lines' worth of the answer by itself - that
    // there are seven, and somewhere to press for which - so what the
    // container rule takes is the list.
    const tight = css.slice(css.indexOf('@container search-sidebar-space (max-height: 260px)'));
    const block = tight.slice(0, tight.indexOf('\n    }\n'));
    expect(block).toContain('.sidebar-products-list');
    expect(
        /\.sidebar-products-card\s*\{[^{}]*display:\s*none/.test(block),
        'expected the short-column rule to hide the list, not the whole card',
    ).toBe(false);

    // Pressing it open takes the room from Export for as long as it is open.
    const hidesFooter = rules('.search-sidebar .sidebar-products-card[data-expanded="true"] ~ .sidebar-footer');
    expect(hidesFooter.join(' ')).toContain('none');
});

test('the editions panel is placed against the viewport, not a box that can clip it', () => {
    // It hangs below the symbol row, over the boxes underneath. Absolutely
    // positioned, it belonged to the first scrollable ancestor: the pinned
    // block counted it as overflow, so focusing the panel's filter scrolled
    // that block to "reveal" it and carried the card off the top of the
    // column, with no scrollbar to undo it. Fixed, it has no such ancestor -
    // the script gives it its geometry.
    const pos = declaration('.sidebar-printings-dropdown', 'position');
    expect(pos, 'expected .sidebar-printings-dropdown to be positioned').toBe('fixed');
    // Its width comes from the row it hangs off, so its own padding and
    // border have to come out of that rather than be added to it.
    expect(declaration('.sidebar-printings-dropdown', 'box-sizing')).toBe('border-box');
});

test('the pinned block is not a scroll container', () => {
    // Nothing in it needs clipping - the card holds its natural size rather
    // than being squeezed - and `hidden` here silently makes it a scroll box
    // that anything positioned against it can be scrolled inside.
    const overflow = declarations('.sidebar-pinned', 'overflow');
    expect(
        overflow.every(v => v === 'visible'),
        `expected .sidebar-pinned not to clip, saw overflow: ${overflow.join(' | ')}`,
    ).toBe(true);
});

test('every icon placeholder is sized with the icon that replaces it', () => {
    // The server renders <i data-lucide="…"> and the bundle later swaps it
    // for an <svg>. An unsized placeholder is a 0x0 box, so the row lays out
    // at the wrong size until the bundle lands and then jumps: the SORT row
    // was 16px shorter and its label 8px higher, and the result star, whose
    // row is right-aligned, slid the whole strip 24px sideways.
    //
    // Each rule that sizes one of these icons has to size its placeholder in
    // the same breath - that is the only way the two cannot disagree - so
    // this asserts the pairing rather than any particular number.
    for (const base of ['.search-sort-pill', '.search-sort-settings', '.fav-sort-pill',
                        '.result-quick-icons .fav-btn', '.qi-actions']) {
        const esc = base.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        // the selector list of whichever rule sizes this icon
        const re = new RegExp(`([^{}]*${esc}\\s+svg[^{}]*)\\{([^{}]*)\\}`, 'g');
        let found = false, m;
        while ((m = re.exec(css)) !== null) {
            if (!/width/.test(m[2])) continue;   // skip rules that only paint
            found = true;
            expect(
                m[1],
                `"${base} svg" is sized without its placeholder; the row will jump when lucide paints`,
            ).toContain('i[data-lucide]');
        }
        expect(found, `expected a rule sizing "${base} svg"`).toBe(true);
    }
});

test('the collapsed icon row sizes both through one inherited token', () => {
    // The star's own rule out-specifies anything the narrow layout could
    // reasonably write, so a competing width there simply loses to it - which
    // is how the placeholder ended up reserving 24px against a 20px icon, a
    // 4px jump in the other direction. An inherited custom property reaches
    // it regardless of specificity.
    expect(rules('.qi-actions').join(' ')).toContain('--qi-icon-size');
    const star = css.slice(css.indexOf('.result-quick-icons .fav-btn svg'));
    expect(star.slice(0, star.indexOf('}'))).toContain('--qi-icon-size');
});
