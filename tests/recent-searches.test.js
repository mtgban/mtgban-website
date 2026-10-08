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
function runResultsPage({pathname = '/search', pending = 'black lotus', found = true, cookie = 'MTGBAN=abc'} = {}) {
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
        cookie,
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

test('a visitor without the cookie sends no vote', () => {
    expect(runResultsPage({cookie: ''})).toEqual([]);
});
