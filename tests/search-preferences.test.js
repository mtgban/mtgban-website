import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/cookies.js', import.meta.url), 'utf8');

test('an empty search list remains an explicit empty preference', () => {
    let value = '';
    const document = {};
    Object.defineProperty(document, 'cookie', {
        get: () => value,
        set: next => { value = next.split(';', 1)[0]; },
    });
    const api = new Function('document', 'window', source + '\nreturn {getSearchListCookie, setSearchListCookie};')(
        document, {__BAN_COOKIE_PATHS: {}}
    );

    api.setSearchListCookie('SearchSealedSellersList', '', 1000);
    expect(value).toBe('SearchSealedSellersList=__BAN_EMPTY_LIST__');
    expect(api.getSearchListCookie('SearchSealedSellersList')).toBe('');
});
