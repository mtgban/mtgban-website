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
function loadBar(pinned, extra = {}) {
    const nodes = {
        'nav-pin-btn': element(),
        'nav-scope': element(),
        'nav-scopebox': element({ value: pinned, id: 'nav-scopebox' }),
        'nav-scope-clear': element(),
        'nav-scope-go': element(),
        'nav-scopefield': element(),
        ...extra,
    };
    const navigated = [];
    const document = {
        getElementById: id => nodes[id] || null,
        body: { classList: { contains: () => false, toggle: () => {}, add: () => {}, remove: () => {} } },
        addEventListener: () => {},
        set cookie(value) { throw new Error('the bar stored a cookie: ' + value); },
    };
    const window = {
        location: {
            href: 'https://example.test/search?q=bolt&sort=alpha',
            assign: url => navigated.push(url),
        },
    };
    new Function('window', 'document', 'URL', source)(window, document, URL);
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

// The bar lives in the url alone. Putting the row away or clearing it leaves
// nothing behind for the next page, or the next visit, to read back.
test('closing and clearing the bar store nothing', () => {
    const { nodes, navigated } = loadBar('f:nonfoil');

    // With no setCookie in scope and document.cookie throwing, either way of
    // storing something fails the test.
    nodes['nav-pin-btn'].handlers.click();
    nodes['nav-scope-clear'].handlers.click();

    expect(new URL(navigated[0]).searchParams.get('scope')).toBe('');
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
    const run = () => new Function('window', 'document', 'URL', source)(
        { location: { href: 'https://example.test/search', assign: () => {} } },
        {
            getElementById: id => nodes[id] || null,
            body: { classList: { contains: () => false, toggle: () => {} } },
            addEventListener: () => {},
        },
        URL,
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

// A highlighted suggestion is the autocomplete's to take: Enter picks it
// instead of running the search on the half-typed filter under it.
test('Enter leaves a highlighted suggestion to the autocomplete', () => {
    const { nodes, navigated } = loadBar('r:myt', {
        'nav-scopeboxautocomplete-list': element({
            querySelector: selector => (selector === '.autocomplete-active' ? {} : null),
        }),
    });

    nodes['nav-scopebox'].handlers.keydown({ key: 'Enter', preventDefault: () => {} });

    expect(navigated).toHaveLength(0);
});

// A suggestion picked with the mouse writes the box without an input event,
// and the search form still has to send what the box shows.
test('the search form sends what the box shows', () => {
    const { nodes } = loadBar('r:myt', { 'nav-searchform': element() });

    nodes['nav-scopebox'].value = 'r:mythic';
    nodes['nav-searchform'].handlers.submit();

    expect(nodes['nav-scopefield'].value).toBe('r:mythic');
});
