import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'cookies.js'), 'utf8');

function loadCookies({ cookie = '', pathname = '/', paths = {}, storage = new Map() } = {}) {
    const writes = [];
    const document = {
        get cookie() { return cookie; },
        set cookie(value) { writes.push(value); },
    };
    const window = {
        __BAN_COOKIE_PATHS: paths,
        location: { pathname },
        localStorage: {
            getItem(key) { return storage.get(key) || null; },
            setItem(key, value) { storage.set(key, value); },
        },
    };
    const api = new Function('window', 'document', source +
        '; return { getCookie, setCookie };')(window, document);
    return { api, writes, storage };
}

test('setCookie uses the path emitted by NavElem and expires the root copy', () => {
    const { api, writes } = loadCookies({
        paths: { NewspaperList: '/custom-news' },
        pathname: '/custom-news',
    });

    api.setCookie('NewspaperList', 'value', 1000);

    expect(writes).toHaveLength(2);
    expect(writes[0]).toContain('path=/custom-news');
    expect(writes[1]).toContain('path=/');
    expect(writes[1]).toContain('expires=');
});

test('legacy migration only runs on the owning route and only once', () => {
    const storage = new Map();
    const first = loadCookies({
        cookie: 'NewspaperList=legacy',
        pathname: '/other',
        paths: { NewspaperList: '/newspaper' },
        storage,
    });
    expect(first.writes).toEqual([]);

    const second = loadCookies({
        cookie: 'NewspaperList=legacy',
        pathname: '/newspaper',
        paths: { NewspaperList: '/newspaper' },
        storage,
    });
    expect(second.writes).toHaveLength(2);
    expect(second.writes[0]).toContain('path=/newspaper');
    expect(second.writes[1]).toContain('path=/');

    const third = loadCookies({
        cookie: 'NewspaperList=legacy',
        pathname: '/newspaper',
        paths: { NewspaperList: '/newspaper' },
        storage,
    });
    expect(third.writes).toEqual([]);
});
