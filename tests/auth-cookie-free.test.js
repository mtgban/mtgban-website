import { test, expect } from 'bun:test';
import { readdirSync, readFileSync } from 'fs';
import { join } from 'path';

const jsDir = join(import.meta.dir, '..', 'js');
const templatesDir = join(import.meta.dir, '..', 'templates');

function sources(dir, extension) {
    return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
        const path = join(dir, entry.name);
        if (entry.isDirectory()) return sources(path, extension);
        return entry.name.endsWith(extension) ? [path] : [];
    });
}

// The signature cookie is not readable from a page; what its scripts gate on
// is rendered on <html> by the server. Inline scripts count too.
test('no script reads the signature cookie under either name', () => {
    const scripts = [...sources(jsDir, '.js'), ...sources(templatesDir, '.html')];
    const readers = scripts.filter((path) => /(?:MTGBAN|BAN_SIG)=|getCookie\(\s*['"](?:MTGBAN|BAN_SIG)['"]/.test(readFileSync(path, 'utf8')));
    expect(readers).toEqual([]);
});

test('every base template renders both flags on the html element', () => {
    for (const base of ['base.html', 'base-landing.html', 'mobile/base-mobile.html']) {
        const html = readFileSync(join(import.meta.dir, '..', 'templates', base), 'utf8');
        const root = html.slice(html.indexOf('<html'), html.indexOf('>', html.indexOf('<html')) + 1);
        expect(root).toContain('data-signed-in="{{.ScriptSignedIn}}"');
        expect(root).toContain('data-offline-mode="{{.ScriptOfflineMode}}"');
    }
});

// Runs user-state.js on a page whose html element carries signedIn and
// reports the requests it made. The body is null: the script is loaded from
// <head>, and reads nothing that hangs off <body>.
function userStateRequests(signedIn) {
    const source = readFileSync(join(jsDir, 'user-state.js'), 'utf8');
    const urls = [];
    const storage = { getItem: () => null, setItem() {}, removeItem() {} };
    const fetch = (url) => { urls.push(url); return Promise.reject(new Error('no network')); };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        { addEventListener() {}, Storage: function () {}, localStorage: storage },
        { body: null, documentElement: { dataset: signedIn === undefined ? {} : { signedIn } }, readyState: 'complete', addEventListener() {} },
        storage, storage, fetch, { mtime: () => 0, tombstones: () => [] });
    return urls;
}

test('user-state syncs only on a page rendered as signed in', () => {
    expect(userStateRequests('true').length).toBeGreaterThan(0);
    expect(userStateRequests('false')).toEqual([]);
    expect(userStateRequests(undefined)).toEqual([]);
});

// Runs recent-searches.js on a page with no body yet, as when it is loaded
// from <head>, and returns the votes it sent for one typed search.
function popularVotes(signedIn) {
    const source = readFileSync(join(jsDir, 'recent-searches.js'), 'utf8');
    const events = {};
    const values = new Map([['mtgban_pending_search', 'black lotus']]);
    const localStorage = { getItem: (k) => values.get(k) || null, setItem: (k, v) => values.set(k, v) };
    const sessionStorage = { getItem: (k) => values.get(k) || null, removeItem: (k) => values.delete(k) };
    const document = {
        body: null,
        documentElement: { dataset: { signedIn } },
        readyState: 'loading',
        addEventListener: (type, handler) => { events[type] = handler; },
        getElementById: () => null,
        querySelector: () => null,
    };
    const votes = [];
    const window = {
        location: { pathname: '/search', search: '?q=black%20lotus' },
        BAN_SEARCH_RESULT: { found: true, label: 'Black Lotus', url: '' },
        addEventListener: () => {},
        navigator: { sendBeacon: (url, body) => { votes.push(body.get('q')); return true; } },
    };
    const ListStorage = new Function('localStorage', readFileSync(join(jsDir, 'list-storage.js'), 'utf8') + '\nreturn ListStorage;')(localStorage);
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'DOMParser', 'ListStorage', source)(
        window, document, localStorage, sessionStorage, undefined, undefined, ListStorage);
    events.DOMContentLoaded();
    return votes;
}

test('recent-searches votes only on a page rendered as signed in', () => {
    expect(popularVotes('true')).toEqual(['black lotus']);
    expect(popularVotes('false')).toEqual([]);
});
