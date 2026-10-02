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
// wherever the page was sent. autocomplete stands in for the shared one.
function loadBar(pinned, extra = {}, autocomplete = undefined) {
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
            href: 'https://example.test/search?q=bolt&sort=alpha' +
                (pinned ? '&scope=' + encodeURIComponent(pinned) : ''),
            pathname: '/search',
            assign: url => navigated.push(url),
        },
    };
    new Function('window', 'document', 'URL', 'autocomplete', 'location', source)(
        window, document, URL, autocomplete, window.location);
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
    const { nodes } = loadBar('f:nonfoil');

    // With no setCookie in scope and document.cookie throwing, either way of
    // storing something fails the test.
    nodes['nav-pin-btn'].handlers.click();
    nodes['nav-scope-clear'].handlers.click();

    expect(nodes['nav-scopebox'].value).toBe('');
});

// CLEAR empties the bar and stops there: running the search is GO's job.
test('CLEAR empties the bar without running the search', () => {
    const { nodes, navigated } = loadBar('f:nonfoil');

    nodes['nav-scope-clear'].handlers.click();

    expect(navigated).toEqual([]);
    expect(nodes['nav-scopebox'].value).toBe('');
    expect(nodes['nav-scopefield'].disabled).toBe(true);
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
    expect(nodes['nav-scopefield'].disabled).toBe(false);
});

// An empty bar sends no scope at all, rather than a bare scope=.
test('an empty bar stays out of the search form', () => {
    const { nodes } = loadBar('f:foil', { 'nav-searchform': element() });

    nodes['nav-scopebox'].value = '  ';
    nodes['nav-searchform'].handlers.submit();
    expect(nodes['nav-scopefield'].disabled).toBe(true);

    nodes['nav-scopebox'].value = 'f:foil';
    nodes['nav-scopebox'].handlers.input();
    expect(nodes['nav-scopefield'].disabled).toBe(false);
});

// The pinned bar takes the same f:, s: and is: suggestions as the main one.
// The call sits behind a typeof guard, so losing it fails nothing else.
test('the bar is handed the shared autocomplete', () => {
    const bound = [];
    const { nodes } = loadBar('s:sos', { 'nav-searchform': element() },
        (form, box, sealed) => bound.push({ form, box, sealed }));

    expect(bound).toHaveLength(1);
    expect(bound[0].form).toBe(nodes['nav-searchform']);
    expect(bound[0].box).toBe(nodes['nav-scopebox']);
    expect(bound[0].sealed).toBe('false');
});

// While the pointer is over the box, js/tooltips.js holds its title in
// data-ban-title and puts it back on the way out, unless that copy is gone.
test('typing an ignored scope away drops its warning and the tooltip copy', () => {
    const removed = [];
    const box = element({
        value: 's:XYZ',
        id: 'nav-scopebox',
        title: 'This scope is ignored',
        classList: { contains: name => name === 'is-ignored', toggle: () => {}, add: () => {}, remove: () => {} },
        removeAttribute: name => removed.push(name),
    });
    loadBar('s:XYZ', { 'nav-scopebox': box });
    expect(removed).toEqual([]);

    box.value = 's:LEA';
    box.handlers.input();
    expect(removed).toEqual(['title', 'data-ban-title']);
});
