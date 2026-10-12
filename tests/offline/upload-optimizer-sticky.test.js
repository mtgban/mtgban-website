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

// Every body a selector is given, base rule and @media ones alike.
function rules(selector) {
    const esc = selector.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(?:^|[};{]|\\*/)\\s*${esc}\\s*\\{([^{}]*)\\}`, 'g');
    const out = [];
    let m;
    while ((m = re.exec(css)) !== null) out.push(m[1]);
    return out;
}

function declarations(selector, prop) {
    return rules(selector)
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

test('neither the store header nor the column labels stick on their own', () => {
    for (const selector of ['.opt-store-header', '.opt-table th']) {
        expect(rules(selector).length, `expected a ${selector} rule in css/upload.css`).toBeGreaterThan(0);
        expect(declarations(selector, 'position'), selector).not.toContain('sticky');
    }
});

test('the store header is the first row of the optimizer thead', () => {
    const table = html.indexOf('<table class="opt-table"');
    expect(table).toBeGreaterThan(-1);
    const thead = html.indexOf('<thead>', table);
    const header = html.indexOf('<div class="opt-store-header">', table);
    const labels = html.indexOf('<th>Card</th>', table);
    const tbody = html.indexOf('<tbody>', table);
    expect(thead).toBeGreaterThan(table);
    expect(header).toBeGreaterThan(thead);
    expect(labels).toBeGreaterThan(header);
    expect(tbody).toBeGreaterThan(labels);
});
