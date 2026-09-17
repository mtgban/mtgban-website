import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/recent-searches.js', import.meta.url), 'utf8');

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

    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'DOMParser', source)(
        window, document, localStorage, sessionStorage, undefined, undefined
    );
    events.DOMContentLoaded();

    const searches = JSON.parse(values.get('mtgban_recent_searches'));
    expect(searches[0].u).toBe('/sealed?q=sealed%20product');
});
