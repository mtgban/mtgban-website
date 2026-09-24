import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/scope.js', import.meta.url), 'utf8');
const mobileCss = readFileSync(new URL('../css/mobile.css', import.meta.url), 'utf8');

// A stand-in for one element of the bar: enough of the DOM for scope.js to
// bind to, and a record of what it was told.
function element(extra = {}) {
    const handlers = {};
    return {
        handlers,
        value: '',
        title: '',
        addEventListener: (type, fn) => { handlers[type] = fn; },
        removeAttribute: () => {},
        setAttribute: () => {},
        focus: () => {},
        setSelectionRange: () => {},
        querySelectorAll: () => [],
        classList: { contains: () => false, toggle: () => {}, add: () => {}, remove: () => {} },
        ...extra,
    };
}

// Runs scope.js over a bar holding `pinned`, and hands back the pieces plus
// wherever the page was sent.
function loadBar(pinned) {
    const nodes = {
        'nav-pin-btn': element(),
        'nav-scope': element(),
        'nav-scopebox': element({ value: pinned }),
        'nav-scope-clear': element(),
        'nav-scope-go': element(),
        'nav-scopefield': element(),
    };
    const navigated = [];
    const document = {
        getElementById: id => nodes[id] || null,
        body: { classList: { contains: () => false, toggle: () => {}, add: () => {}, remove: () => {} } },
        addEventListener: () => {},
    };
    const window = {
        location: {
            href: 'https://example.test/search?q=bolt&sort=alpha',
            assign: url => navigated.push(url),
        },
    };
    // setCookie comes from cookies.js on a real page; nothing on the paths
    // under test reaches it, but the reference has to resolve.
    new Function('window', 'document', 'setCookie', 'URL', source)(
        window, document, () => {}, URL,
    );
    return { nodes, navigated };
}

test('GO runs the bar the way Enter does', () => {
    const { nodes, navigated } = loadBar('s:LEA');

    nodes['nav-scope-go'].handlers.click();

    expect(navigated).toHaveLength(1);
    const url = new URL(navigated[0]);
    expect(url.searchParams.get('scope')).toBe('s:LEA');
    // The rest of the url is why this rewrites rather than submitting a form.
    expect(url.searchParams.get('q')).toBe('bolt');
    expect(url.searchParams.get('sort')).toBe('alpha');
});

test('GO and Enter send the same request', () => {
    const viaGo = loadBar('r:mythic');
    viaGo.nodes['nav-scope-go'].handlers.click();

    const viaEnter = loadBar('r:mythic');
    viaEnter.nodes['nav-scopebox'].handlers.keydown({ key: 'Enter', preventDefault: () => {} });

    expect(viaGo.navigated).toEqual(viaEnter.navigated);
});

test('GO takes what is in the box now, not what was pinned before', () => {
    const { nodes, navigated } = loadBar('s:LEA');

    nodes['nav-scopebox'].value = '  s:M19  ';
    nodes['nav-scope-go'].handlers.click();

    expect(new URL(navigated[0]).searchParams.get('scope')).toBe('s:M19');
});

test('a bar with no GO button still loads', () => {
    // The button is markup; scope.js also serves pages rendered before it.
    const nodes = {
        'nav-pin-btn': element(),
        'nav-scope': element(),
        'nav-scopebox': element({ value: '' }),
        'nav-scope-clear': element(),
        'nav-scopefield': element(),
    };
    const run = () => new Function('window', 'document', 'setCookie', 'URL', source)(
        { location: { href: 'https://example.test/search', assign: () => {} } },
        {
            getElementById: id => nodes[id] || null,
            body: { classList: { contains: () => false, toggle: () => {} } },
            addEventListener: () => {},
        },
        () => {}, URL,
    );
    expect(run).not.toThrow();
});

// The box is width:100% with padding and a border on top of it. Without
// box-sizing it renders wider than the slot it was given and covers whatever
// sits to its right - it was over CLEAR by 16px before anything was added
// beside it.
test('the mobile scope box stays inside its slot', () => {
    const rule = mobileCss.match(/\.m-scope-box\s*\{[^}]*\}/);
    expect(rule).not.toBeNull();
    expect(rule[0]).toContain('box-sizing: border-box');
});
