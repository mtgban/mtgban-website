import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'cookies.js'), 'utf8');

function loadCookies({ cookie = '', pathname = '/' } = {}) {
    const writes = [];
    const document = {
        get cookie() { return cookie; },
        set cookie(value) { writes.push(value); },
    };
    const window = { location: { pathname } };
    const api = new Function('window', 'document', source +
        '; return { getCookie, setCookie };')(window, document);
    return { api, writes };
}

test('shared search cookies remain root-scoped on sealed pages', () => {
    const { api, writes } = loadCookies({ pathname: '/sealed' });

    api.setCookie('SearchSellersList', 'value', 1000);

    expect(writes[0]).toContain('path=/;');
    expect(writes.slice(1).every(w => w.startsWith('SearchSellersList=;'))).toBe(true);
});

// /search prices the custom buylist from these, so a copy scoped to /upload
// is one it never receives.
test('custom buylist cookies are root-scoped and expire the upload copy', () => {
    const { api, writes } = loadCookies({ pathname: '/upload' });

    api.setCookie('UploadCustomRate', '0.8', 1000);

    expect(writes).toHaveLength(2);
    expect(writes[0]).toContain('UploadCustomRate=0.8;');
    expect(writes[0]).toContain('path=/;');
    expect(writes[1]).toStartWith('UploadCustomRate=;');
    expect(writes[1]).toContain('path=/upload;');
});

test('route-local cookies use the current route and expire the root copy', () => {
    const { api, writes } = loadCookies({ pathname: '/newspaper' });

    api.setCookie('NewspaperList', 'value', 1000);

    expect(writes).toHaveLength(2);
    expect(writes[0]).toContain('path=/newspaper');
    expect(writes[1]).toContain('path=/');
    expect(writes[1]).toContain('expires=');
});

test('route-local cookies use only the first path segment', () => {
    const { api, writes } = loadCookies({ pathname: '/sleepers/bulk' });

    api.setCookie('SleepersEditionList', 'value', 1000);

    expect(writes[0]).toContain('path=/sleepers');
});
