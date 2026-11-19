const { test, expect } = require('bun:test');
const fs = require('fs');
const path = require('path');

// Each optimizer store's header and its column labels stick as one block, the
// table's thead, so the labels stay under the header however tall it wraps. A
// second sticky element with its own offset under the header only holds while
// the header keeps the height that offset assumed, and fails quietly: a row
// showing through a gap, or labels hidden behind a header wrapped on a phone.
const css = fs.readFileSync(path.join(__dirname, '../../css/upload.css'), 'utf8');
const html = fs.readFileSync(path.join(__dirname, '../../templates/upload.html'), 'utf8');

// Every body a selector is given in text (the whole sheet by default), base
// rule and @media ones alike.
function rules(selector, text = css) {
    const esc = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(?:^|[};{]|\\*/)\\s*${esc}\\s*\\{([^{}]*)\\}`, 'g');
    const out = [];
    let m;
    while ((m = re.exec(text)) !== null) out.push(m[1]);
    return out;
}

function declarations(selector, prop, text = css) {
    return rules(selector, text)
        .map(body => body.match(new RegExp(`(?:^|[;{\\s])${prop}\\s*:\\s*([^;]+);`)))
        .filter(Boolean)
        .map(m => m[1].trim());
}

test('the optimizer thead sticks under the navbar', () => {
    expect(declarations('.opt-table thead', 'position')).toContain('sticky');
    const top = declarations('.opt-table thead', 'top');
    expect(top.length).toBeGreaterThan(0);
    expect(top[top.length - 1]).toContain('--nav-height');
});

test('neither the store header nor the column labels stick down the page', () => {
    for (const selector of ['.opt-store-header', '.opt-table th']) {
        expect(rules(selector).length, `expected a ${selector} rule in css/upload.css`).toBeGreaterThan(0);
        for (const prop of ['top', 'inset', 'inset-block', 'inset-block-start']) {
            expect(declarations(selector, prop), `${selector} ${prop}`).toEqual([]);
        }
    }
    expect(declarations('.opt-table th', 'position')).not.toContain('sticky');
});

// The body of the @media block whose header is given, by its braces.
function mediaBlock(header) {
    const start = css.indexOf(header);
    expect(start, header).toBeGreaterThan(-1);
    let depth = 0;
    for (let i = css.indexOf('{', start); i < css.length; i++) {
        if (css[i] === '{') depth++;
        if (css[i] === '}' && --depth === 0) return css.slice(start, i + 1);
    }
    return '';
}

test('on a phone the store header holds to the left of a section scrolled sideways', () => {
    const phone = mediaBlock('@media (max-width: 768px)');
    expect(declarations('.opt-store', 'overflow-x', phone)).toContain('auto');
    expect(declarations('.opt-store', 'container-type', phone)).toContain('inline-size');
    expect(declarations('.opt-store-header', 'position', phone)).toContain('sticky');
    expect(declarations('.opt-store-header', 'left', phone)).toContain('0');
    expect(declarations('.opt-store-header', 'max-width', phone)).toContain('100cqw');
});

test('the store header is the first row of the optimizer thead', () => {
    const table = html.indexOf('<table class="opt-table"');
    expect(table).toBeGreaterThan(-1);
    const thead = html.indexOf('<thead>', table);
    const header = html.indexOf('<div class="opt-store-header">', table);
    const labels = html.indexOf('<th role="columnheader" data-sort-chain>Card', table);
    const tbody = html.indexOf('<tbody>', table);
    expect(thead).toBeGreaterThan(table);
    expect(header).toBeGreaterThan(thead);
    expect(labels).toBeGreaterThan(header);
    expect(tbody).toBeGreaterThan(labels);
});
