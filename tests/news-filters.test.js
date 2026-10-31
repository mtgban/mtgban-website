import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/news-filters.js', import.meta.url), 'utf8');
const userState = readFileSync(new URL('../js/user-state.js', import.meta.url), 'utf8');

function fakeStorage(initial = {}) {
    const m = Object.assign({}, initial);
    return {
        getItem: (k) => (k in m ? m[k] : null),
        setItem: (k, v) => { m[k] = String(v); },
        removeItem: (k) => { delete m[k]; },
    };
}

// A form submitting pairs, one of them the report as the newspaper's
// hidden page field; FormData below reads them back.
function fakeForm(pairs, dataset = {}) {
    const listeners = {};
    const page = pairs.find(([k]) => k === 'page');
    return {
        pairs,
        dataset,
        elements: page ? { page: { value: page[1] } } : {},
        addEventListener: (ev, fn) => { listeners[ev] = fn; },
        listeners,
    };
}

function fakeLink(search) {
    const listeners = {};
    return { search, addEventListener: (ev, fn) => { listeners[ev] = fn; }, listeners };
}

function load({ form = null, links = [], search = '', local = fakeStorage(), userStateClock } = {}) {
    const replaced = [];
    const window = {
        location: { search, pathname: '/newspaper', replace: (u) => replaced.push(u) },
        UserState: userStateClock,
    };
    const document = {
        getElementById: (id) => (id === 'newsFilters' ? form : null),
        querySelectorAll: (sel) => (sel === '#newsTable .sort-links a' ? links : []),
    };
    class FormData {
        constructor(f) { this.pairs = (f && f.pairs) || []; }
        [Symbol.iterator]() { return this.pairs[Symbol.iterator](); }
    }
    new Function('window', 'document', 'FormData', 'localStorage', source)(window, document, FormData, local);
    return { window, replaced, local };
}

function saved(local) {
    return JSON.parse(local.getItem('mtgban_news_filters'));
}

test('submitting saves the choices for the report, less the report and empty fields', () => {
    const form = fakeForm([['page', 'top'], ['sort', 'ranking'], ['dir', 'asc'], ['rarity', 'M'], ['min_price', ''], ['max_price', '20']]);
    const { local } = load({ form, search: '?page=top&sort=ranking', userStateClock: { now: () => 4242 } });
    form.listeners.submit();
    expect(saved(local)).toEqual({ top: { q: 'sort=ranking&dir=asc&rarity=M&max_price=20', t: 4242 } });
});

test('saving one report keeps every other report\'s choices', () => {
    const local = fakeStorage({ mtgban_news_filters: JSON.stringify({ vendors: { q: 'rarity=R', t: 1 } }) });
    const form = fakeForm([['page', 'top'], ['bucket', '$5+']]);
    load({ form, search: '?page=top&bucket=', local });
    form.listeners.submit();
    const s = saved(local);
    expect(s.vendors).toEqual({ q: 'rarity=R', t: 1 });
    expect(s.top.q).toBe('bucket=%245%2B');
});

test('a sort link saves its choices, less the report and the page of results', () => {
    const link = fakeLink('?page=top&sort=spike&dir=desc&filter=&rarity=U&index=3');
    const { local } = load({ form: fakeForm([['page', 'top']]), links: [link], search: '?page=top&rarity=U' });
    link.listeners.click();
    expect(saved(local).top.q).toBe('sort=spike&dir=desc&rarity=U');
});

test('a link naming only the report opens it with its saved choices', () => {
    const local = fakeStorage({ mtgban_news_filters: JSON.stringify({ top: { q: 'sort=spike&rarity=M', t: 1 }, vendors: { q: 'rarity=C', t: 1 } }) });
    const { replaced } = load({ form: fakeForm([['page', 'top']]), search: '?page=top', local });
    expect(replaced).toEqual(['/newspaper?page=top&sort=spike&rarity=M']);
});

test('the mobile page, with no sort control, opens a report without its saved sort', () => {
    const local = fakeStorage({ mtgban_news_filters: JSON.stringify({ top: { q: 'sort=spike&dir=asc&rarity=M', t: 1 }, vendors: { q: 'sort=spike', t: 1 } }) });
    const mobile = (page) => load({ form: fakeForm([['page', page]], { sortless: 'true' }), search: '?page=' + page, local }).replaced;
    expect(mobile('top')).toEqual(['/newspaper?page=top&rarity=M']);
    expect(mobile('vendors')).toEqual([]);
    const html = readFileSync(new URL('../templates/mobile/news.html', import.meta.url), 'utf8');
    expect(html).toContain('data-sortless="true"');
});

test('a saved state cannot move the reader to another report or page of results', () => {
    const local = fakeStorage({ mtgban_news_filters: JSON.stringify({ top: { q: 'page=vendors&index=4&rarity=M', t: 1 } }) });
    const { replaced } = load({ form: fakeForm([['page', 'top']]), search: '?page=top', local });
    expect(replaced).toEqual(['/newspaper?page=top&rarity=M']);
});

test('a link with choices of its own keeps them and saves nothing', () => {
    const before = JSON.stringify({ top: { q: 'rarity=M', t: 1 } });
    const local = fakeStorage({ mtgban_news_filters: before });
    const { replaced } = load({ form: fakeForm([['page', 'top']]), search: '?page=top&rarity=', local });
    expect(replaced).toEqual([]);
    expect(local.getItem('mtgban_news_filters')).toBe(before);
});

test('a report with nothing saved, or the defaults saved, stays as linked', () => {
    for (const stored of [{}, { top: { q: '', t: 5 } }, { top: 'junk' }]) {
        const local = fakeStorage({ mtgban_news_filters: JSON.stringify(stored) });
        expect(load({ form: fakeForm([['page', 'top']]), search: '?page=top', local }).replaced).toEqual([]);
    }
    expect(load({ form: fakeForm([['page', 'top']]), search: '?page=top' }).replaced).toEqual([]);
});

test('the saved choices ride the synced preferences', () => {
    const m = userState.match(/var PREF_KEYS = \[([\s\S]*?)\];/);
    expect(m[1]).toContain("'mtgban_news_filters'");
});

test('both newspaper templates load user-state.js and give the form its id', () => {
    for (const f of ['news.html', 'mobile/news.html']) {
        const html = readFileSync(new URL('../templates/' + f, import.meta.url), 'utf8');
        expect(html).toContain('/js/user-state.js');
        expect(html).toContain('/js/news-filters.js');
        expect(html).toContain('<form id="newsFilters"');
        // form.submit() skips the submit event that saves the choices, so
        // it is only the fallback where requestSubmit is missing
        for (const m of html.matchAll(/onchange="([^"]*)"/g)) {
            expect(m[1]).toBe('this.form.requestSubmit ? this.form.requestSubmit() : this.form.submit()');
        }
    }
});

// Runs user-state.js's sync of a device's saved choices with the server's,
// and returns what it stored and whether it refreshed the page.
async function synced(local, server, dirty) {
    const storage = fakeStorage(Object.assign({ mtgban_news_filters: JSON.stringify(local) }, dirty ? { mtgban_userstate_dirty: '1' } : {}));
    const state = { version: 3, favorites: [], recents: [], preferences: { mtgban_news_filters: JSON.stringify(server) } };
    const refreshed = [];
    const window = { addEventListener() {}, NewsFilters: { refresh: () => refreshed.push(1) } };
    const fetch = () => Promise.resolve({ status: 200, ok: true, json: () => Promise.resolve(state) });
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', 'setTimeout', 'clearTimeout', userState)(
        window, { documentElement: { dataset: { signedIn: 'true' } }, readyState: 'complete', addEventListener() {} }, storage, fakeStorage(), fetch,
        { mtime: (x) => x.m || x.t || 0, tombstones: () => [], capBackpack: (list) => list }, () => 0, () => {});
    for (let i = 0; i < 20; i++) await Promise.resolve();
    return { stored: JSON.parse(storage.getItem('mtgban_news_filters')), refreshed };
}

test('a sync merges the saved choices report by report, the later state winning', async () => {
    const now = Date.now();
    const local = { top: { q: 'rarity=M', t: now - 1000 }, vendors: { q: 'rarity=C', t: now - 5000 } };
    const server = { vendors: { q: 'rarity=U', t: now - 2000 }, spikes: { q: 'bucket=%245%2B', t: now - 3000 } };
    for (const dirty of [true, false]) {
        const { stored, refreshed } = await synced(local, server, dirty);
        expect(stored).toEqual({ top: local.top, vendors: server.vendors, spikes: server.spikes });
        expect(refreshed.length).toBeGreaterThan(0);
    }
});
