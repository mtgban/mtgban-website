import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/recent-searches.js', import.meta.url), 'utf8');
const listStorageSource = readFileSync(new URL('../js/list-storage.js', import.meta.url), 'utf8');

test('multi-result sealed recents retain the sealed route', () => {
    const events = {};
    const values = new Map([
        ['mtgban_pending_search', 'sealed product'],
    ]);
    const localStorage = {
        getItem: key => values.get(key) || null,
        setItem: (key, value) => values.set(key, value),
    };
    const sessionStorage = {
        getItem: key => values.get(key) || null,
        removeItem: key => values.delete(key),
    };
    const document = {
        readyState: 'loading',
        addEventListener: (type, handler) => { events[type] = handler; },
        getElementById: () => null,
        querySelector: () => null,
    };
    const window = {
        location: {pathname: '/sealed', search: '?q=sealed%20product'},
        BAN_SEARCH_RESULT: {found: true, label: '', url: ''},
        addEventListener: () => {},
    };

    const ListStorage = new Function('localStorage', listStorageSource + '\nreturn ListStorage;')(localStorage);
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'DOMParser', 'ListStorage', source)(
        window, document, localStorage, sessionStorage, undefined, undefined, ListStorage
    );
    events.DOMContentLoaded();

    const searches = JSON.parse(values.get('mtgban_recent_searches'));
    expect(searches[0].u).toBe('/sealed?q=sealed%20product');
});

// Drives recent-searches.js through one results-page load and reports what
// it sent to the vote beacon. pending is what the search form submitted.
function runResultsPage({pathname = '/search', pending = 'black lotus', found = true, signedIn = true} = {}) {
    const events = {};
    const values = new Map();
    if (pending !== null) values.set('mtgban_pending_search', pending);
    const localStorage = {
        getItem: key => values.get(key) || null,
        setItem: (key, value) => values.set(key, value),
    };
    const sessionStorage = {
        getItem: key => values.get(key) || null,
        removeItem: key => values.delete(key),
    };
    const document = {
        readyState: 'loading',
        documentElement: {dataset: {signedIn: String(signedIn)}},
        addEventListener: (type, handler) => { events[type] = handler; },
        getElementById: () => null,
        querySelector: () => null,
    };
    const beacons = [];
    const window = {
        location: {pathname, search: '?q=black%20lotus'},
        BAN_SEARCH_RESULT: {found, label: 'Black Lotus', url: ''},
        addEventListener: () => {},
        navigator: {sendBeacon: (url, body) => { beacons.push({url, q: body.get('q')}); return true; }},
    };
    const ListStorage = new Function('localStorage', listStorageSource + '\nreturn ListStorage;')(localStorage);
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'DOMParser', 'ListStorage', source)(
        window, document, localStorage, sessionStorage, undefined, undefined, ListStorage
    );
    events.DOMContentLoaded();
    return beacons;
}

test('a typed search that found results sends one vote with the raw query', () => {
    const beacons = runResultsPage();
    expect(beacons).toEqual([{url: '/api/popular/vote', q: 'black lotus'}]);
});

test('a click-through with no pending search sends no vote', () => {
    expect(runResultsPage({pending: null})).toEqual([]);
});

test('a search that found nothing sends no vote', () => {
    expect(runResultsPage({found: false})).toEqual([]);
});

test('a sealed search sends no vote', () => {
    expect(runResultsPage({pathname: '/sealed'})).toEqual([]);
});

test('a visitor the page renders as signed out sends no vote', () => {
    expect(runResultsPage({signedIn: false})).toEqual([]);
});

// Drives recent-searches.js through one page load with a desktop list to
// render into, and reports what it stored and what the list links to.
function runListPage({pathname = '/search', search = '', pending = null, url = '', stored = null, values = new Map()} = {}) {
    const events = {};
    if (pending !== null) values.set('mtgban_pending_search', pending);
    if (stored !== null) values.set('mtgban_recent_searches', JSON.stringify(stored));
    const localStorage = {
        getItem: key => values.get(key) || null,
        setItem: (key, value) => values.set(key, value),
    };
    const sessionStorage = {
        getItem: key => values.get(key) || null,
        setItem: (key, value) => values.set(key, value),
        removeItem: key => values.delete(key),
    };
    const container = {innerHTML: '', querySelector: () => null};
    const document = {
        readyState: 'loading',
        documentElement: {dataset: {signedIn: 'false'}},
        addEventListener: (type, handler) => { events[type] = handler; },
        getElementById: id => id === 'desktop-recent-searches' ? container : null,
        querySelector: () => null,
    };
    const window = {
        location: {pathname, search, href: 'https://mtgban.test' + pathname + search, origin: 'https://mtgban.test'},
        BAN_SEARCH_RESULT: {found: true, label: '', url},
        addEventListener: () => {},
    };
    const utils = readFileSync(new URL('../js/utils.js', import.meta.url), 'utf8');
    const ListStorage = new Function('localStorage', listStorageSource + '\nreturn ListStorage;')(localStorage);
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'DOMParser', 'ListStorage', utils + '\n' + source)(
        window, document, localStorage, sessionStorage, undefined, undefined, ListStorage
    );
    events.DOMContentLoaded();
    const hrefs = [...container.innerHTML.matchAll(/class="landing-item[^"]*"[^>]*href="([^"]*)"/g)].map(m => m[1].replace(/&amp;/g, '&'));
    return {searches: JSON.parse(values.get('mtgban_recent_searches') || '[]'), hrefs, html: container.innerHTML, window};
}

test('a search run under a pinned bar keeps it and links back under it', () => {
    const {searches, hrefs, html} = runListPage({search: '?q=bolt&scope=s%3Asos%20is%3Afoil', pending: 'bolt'});
    expect(searches[0].sc).toBe('s:sos is:foil');
    expect(hrefs).toEqual(['?q=bolt&scope=s%3Asos%20is%3Afoil']);
    expect(html).toContain('<span class="landing-item-scope">s:sos is:foil</span>');
});

test('a search with no pinned bar links by its query alone', () => {
    const {searches, hrefs, html} = runListPage({search: '?q=bolt', pending: 'bolt'});
    expect(searches[0].sc).toBeUndefined();
    expect(hrefs).toEqual(['?q=bolt']);
    expect(html).not.toContain('landing-item-scope');
});

test('a multi-result sealed search keeps the pinned bar in its route', () => {
    const {searches} = runListPage({pathname: '/sealed', search: '?q=box&scope=s%3Asos', pending: 'box'});
    expect(searches[0].u).toBe('/sealed?q=box&scope=s%3Asos');
});

test('a search that named one printing still links by its own path', () => {
    const {hrefs} = runListPage({search: '?q=bolt&scope=s%3Asos', pending: 'bolt', url: '/search?q=Lightning%20Bolt%20s%3Asos'});
    expect(hrefs).toEqual(['/search?q=Lightning%20Bolt%20s%3Asos']);
});

test('a stored link that leaves the site links by its query instead', () => {
    for (const u of ['//evil.test/x', 'javascript:alert(1)', '/\\evil.test', '/\t/evil.test', '/\n/evil.test', '/\r/evil.test', 'https://evil.test/']) {
        const {hrefs} = runListPage({stored: [{q: 'bolt', u, t: 1, m: 1}]});
        expect(hrefs).toEqual(['?q=bolt']);
    }
});

test('the same query under another pinned bar replaces the entry', () => {
    const stored = [{q: 'bolt', sc: 's:sos', t: 1, m: 1}];
    const {searches} = runListPage({search: '?q=bolt', pending: 'bolt', stored});
    expect(searches.length).toBe(1);
    expect(searches[0].sc).toBeUndefined();
});

test('a search run again under a new bar is kept under that bar', () => {
    const stored = [{q: 'bolt', t: 1, m: 1}];
    const {searches, hrefs} = runListPage({search: '?q=bolt&sort=alpha&scope=s%3Asos', pending: 'bolt', stored});
    expect(searches.length).toBe(1);
    expect(searches[0].sc).toBe('s:sos');
    expect(hrefs).toEqual(['?q=bolt&scope=s%3Asos']);
});

test('a search noted from another page is recorded by the page that answers it', () => {
    const values = new Map();
    // The page the bar's GO left, then the one it opened.
    runListPage({search: '?q=bolt', values}).window.notePendingSearch('bolt');
    const {searches} = runListPage({search: '?q=bolt&scope=s%3Asos', values});
    expect(searches[0]).toMatchObject({q: 'bolt', sc: 's:sos'});
});
