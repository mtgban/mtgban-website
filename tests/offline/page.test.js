import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const DIR = join(import.meta.dir, '..', '..', 'js', 'offline');
const read = (file) => readFileSync(join(DIR, file), 'utf8');

function makeEl(attrs = {}) {
    const listeners = {};
    const names = new Set();
    return {
        attrs,
        innerHTML: '',
        textContent: '',
        value: '',
        href: '',
        classList: {
            names,
            add: (name) => names.add(name),
            remove: (name) => names.delete(name),
            toggle: (name, on) => names[on ? 'add' : 'delete'](name),
        },
        addEventListener: (type, fn) => { listeners[type] = fn; },
        fire: (type, event) => listeners[type](event),
        getAttribute: (name) => (name in attrs ? attrs[name] : null),
        setAttribute: (name, value) => { attrs[name] = value; },
        toggleAttribute: (name, on) => { if (on) attrs[name] = ''; else delete attrs[name]; },
        querySelector: () => null,
        querySelectorAll: () => [],
    };
}

// Runs the page's real scripts against stand-ins for the document, the database
// and the query. Each query answers with the rows queries[q] names.
function loadPage(file, { search = '', ids = [], pills = [], cookies = {}, queries = {}, broken = false, gates = {}, states = [] } = {}) {
    const els = Object.fromEntries(ids.map((id) => [id, makeEl()]));
    const docListeners = {};
    const winListeners = {};
    const location = { search, pathname: '/offline' };
    const hold = { draw: null, fail: false, views: [] };
    const log = { namesRead: [], pushed: [], parsed: [], executed: [], rendered: [], sorted: [], mounted: null, errors: [], art: [] };

    const document = {
        getElementById: (id) => els[id] || null,
        querySelectorAll: (sel) => (sel === '.search-sort-pill' ? pills : []),
        addEventListener: (type, fn) => { docListeners[type] = fn; },
    };
    const window = { addEventListener: (type, fn) => { winListeners[type] = fn; } };
    const history = {
        pushState: (_state, _title, url) => {
            log.pushed.push(url);
            location.search = url.startsWith('?') ? url : '';
        },
    };
    const OfflineDB = {
        open: () => (broken ? Promise.reject(new Error('no db')) : Promise.resolve()),
        searchState: async () => states.shift() || { catalogVersion: 'c1', stored: [] },
        catalog: async (version) => {
            const card = { uuid: 'a', n: 'from ' + version };
            return { list: [card], byId: new Map([['a', card]]) };
        },
        getMeta: async () => undefined,
        lookupName: async () => [],
        allNames: async (version) => { log.namesRead.push(version); return []; },
        getCard: async () => null,
        hasSet: async () => true,
        getAllRows: async () => [],
    };
    const dicts = { sets: { NEO: {} }, stores: {}, finishes: [], rarities: [] };
    const OfflineUtil = { normName: (s) => s, loadCatalogDicts: async () => dicts, loadSetPayload: async () => null };
    const OfflineQuery = {
        parse: (q) => { log.parsed.push(q); return { q }; },
        execute: async (parsed, env, view) => {
            log.executed.push(parsed);
            log.env = env;
            await gates[parsed.q];
            const out = { results: (queries[parsed.q] || []).slice(), unsupported: [], truncated: false };
            await OfflineQuery.showPage(out, env, view);
            return out;
        },
        showPage: async (out, _env, view) => {
            hold.views.push(view.allPrices ? view.allPrices() : false);
            if (view.order) view.order(out.results);
            out.page = out.results.slice(0, view.size);
            if (hold.draw) await hold.draw;
            return !hold.fail;
        },
        sortResults: (results, mode, reverse) => log.sorted.push({ mode, reverse, n: results.length }),
    };
    const OfflineSearch = { mount: (opts) => { log.mounted = opts; } };
    const render = (el, page, ctx) => { log.rendered.push({ page, ctx }); el.innerHTML = 'drawn ' + page.results.length; };
    const self = {};
    const consoleStub = { error: (...args) => log.errors.push(args) };
    const names = ['self', 'document', 'window', 'location', 'history', 'console', 'getCookie', 'setCardArtSource',
        'OfflineDB', 'OfflineUtil', 'OfflineQuery', 'OfflineSearch', 'OfflineRender', 'OfflineRenderMobile'];
    const args = [self, document, window, location, history, consoleStub, (name) => cookies[name] || '',
        (el, url) => log.art.push(url), OfflineDB, OfflineUtil, OfflineQuery, OfflineSearch, { render }, { render }];
    for (const src of [read('offline-page.js'), read(file)]) new Function(...names, src)(...args);

    return {
        els,
        log,
        hold,
        location,
        // Lets the page's setup and first query finish: nothing here is timed.
        settle: () => new Promise((resolve) => setImmediate(resolve)),
        load: () => docListeners.DOMContentLoaded(),
        pop: () => winListeners.popstate(),
    };
}

const DESKTOP = ['nav-searchbox', 'nav-searchform', 'offline-results', 'offline-count', 'cardImage', 'cardImageWrapper'];
const MOBILE = ['navsearchbox', 'navsearchform', 'm-offline-results', 'offline-pill-singles', 'offline-pill-sealed'];

async function started(file, opts) {
    const page = loadPage(file, opts);
    page.load();
    await page.settle();
    return page;
}

for (const [file, ids, box, results] of [
    ['offline-page-desktop.js', DESKTOP, 'nav-searchbox', 'offline-results'],
    ['offline-page-mobile.js', MOBILE, 'navsearchbox', 'm-offline-results'],
]) {
    const row = (uuid) => ({ uuid });

    test(file + ' runs the query in the URL, filling the box', async () => {
        const page = await started(file, { ids, search: '?q=spm%2066', queries: { 'spm 66': [row('a')] } });
        expect(page.els[box].value).toBe('spm 66');
        expect(page.log.executed).toEqual([{ q: 'spm 66', sealed: false }]);
        expect(page.els[results].innerHTML).toBe('drawn 1');
        expect(page.log.mounted.input).toBe(page.els[box]);
    });

    test(file + ' draws no more than a page', async () => {
        const rows = Array.from({ length: 150 }, (_, i) => row(String(i)));
        const page = await started(file, { ids, search: '?q=x', queries: { x: rows } });
        expect(page.els[results].innerHTML).toBe('drawn 100');
    });

    test(file + ' reads the stores to hide from their cookies', async () => {
        const cookies = { SearchSellersList: 'CK,TCG', SearchVendorsList: 'SCG', SearchListingPriority: 'stores' };
        const page = await started(file, { ids, search: '?q=x', cookies });
        expect(page.log.rendered[0].ctx).toMatchObject({ hiddenSellers: ['CK', 'TCG'], hiddenVendors: ['SCG'], byStore: true });
    });

    test(file + ' puts a submitted query in the history and runs it', async () => {
        const page = await started(file, { ids, queries: { bolt: [row('a'), row('b')] } });
        page.log.mounted.onSubmit('bolt');
        await page.settle();
        expect(page.log.pushed).toEqual(['?q=bolt']);
        expect(page.els[results].innerHTML).toBe('drawn 2');
    });

    test(file + ' keeps the sealed mode in the URL and the search', async () => {
        const page = await started(file, { ids, search: '?sealed=1' });
        expect(page.log.mounted.deps.sealed).toBe(true);
        page.log.mounted.onSubmit('box');
        await page.settle();
        expect(page.log.pushed).toEqual(['?q=box&sealed=1']);
        expect(page.log.executed).toEqual([{ q: 'box', sealed: true }]);
    });

    test(file + ' clears the results when the box empties', async () => {
        const page = await started(file, { ids, search: '?q=x', queries: { x: [row('a')] } });
        page.log.mounted.onSubmit('');
        await page.settle();
        expect(page.log.pushed).toEqual(['/offline']);
        expect(page.els[results].innerHTML).toBe('');
    });

    test(file + ' follows Back without adding to the history', async () => {
        const page = await started(file, { ids, search: '?q=x', queries: { y: [row('a')] } });
        page.location.search = '?q=y&sealed=1';
        page.pop();
        await page.settle();
        expect(page.els[box].value).toBe('y');
        expect(page.log.mounted.deps.sealed).toBe(true);
        expect(page.log.executed.at(-1)).toEqual({ q: 'y', sealed: true });
        expect(page.log.pushed).toEqual([]);
    });

    // gate holds a search open until the test lets it finish.
    const gate = () => {
        let open, fail;
        const promise = new Promise((resolve, reject) => { open = resolve; fail = reject; });
        return { promise, open, fail };
    };

    test(file + ' draws the newest search, whichever finishes first', async () => {
        const slow = gate();
        const queries = { slow: [row('a'), row('b')], fast: [row('c')] };
        const page = await started(file, { ids, queries, gates: { slow: slow.promise } });
        page.log.mounted.onSubmit('slow');
        await page.settle();
        page.log.mounted.onSubmit('fast');
        await page.settle();
        expect(page.els[results].innerHTML).toBe('drawn 1');
        slow.open();
        await page.settle();
        expect(page.els[results].innerHTML).toBe('drawn 1');
        expect(page.log.rendered).toHaveLength(1);
    });

    test(file + ' keeps a cleared page clear when an older search finishes', async () => {
        const slow = gate();
        const page = await started(file, { ids, queries: { slow: [row('a')] }, gates: { slow: slow.promise } });
        page.log.mounted.onSubmit('slow');
        await page.settle();
        page.log.mounted.onSubmit('');
        slow.open();
        await page.settle();
        expect(page.els[results].innerHTML).toBe('');
        expect(page.log.rendered).toHaveLength(0);
    });

    test(file + ' ignores an older search that fails, but not the newest', async () => {
        const old = gate();
        const newest = gate();
        const queries = { fine: [row('a')] };
        const page = await started(file, { ids, queries, gates: { old: old.promise, newest: newest.promise } });
        page.log.mounted.onSubmit('old');
        await page.settle();
        page.log.mounted.onSubmit('fine');
        await page.settle();
        old.fail(new Error('unreadable'));
        await page.settle();
        expect(page.els[results].innerHTML).toBe('drawn 1');
        expect(page.log.errors).toHaveLength(0);

        page.log.mounted.onSubmit('newest');
        await page.settle();
        newest.fail(new Error('unreadable'));
        await page.settle();
        expect(page.els[results].innerHTML).toContain('Offline data is not ready');
    });

    test(file + ' says so when the data cannot be read', async () => {
        const page = await started(file, { ids, broken: true });
        expect(page.els[results].innerHTML).toContain('Offline data is not ready');
        expect(page.log.errors).toHaveLength(1);
    });
}

test('desktop counts results, naming how many are shown', async () => {
    const rows = Array.from({ length: 150 }, (_, i) => ({ uuid: String(i) }));
    const queries = { none: [], one: rows.slice(0, 1), many: rows };
    const page = await started('offline-page-desktop.js', { ids: DESKTOP, queries });
    const count = async (q) => {
        page.log.mounted.onSubmit(q);
        await page.settle();
        return page.els['offline-count'].textContent;
    };
    expect(await count('none')).toBe('0 results found');
    expect(await count('one')).toBe('1 result found');
    expect(await count('many')).toBe('150 results found (100 shown)');
    expect(await count('')).toBe('');
});

test('a slower, older read does not take a search back to the old catalog', async () => {
    const states = [];
    const page = await started('offline-page-desktop.js', {
        ids: DESKTOP, search: '?q=x', states, queries: { x: [{ uuid: 'a' }] },
    });
    const env = page.log.env;
    let finishOlder;
    states.push(new Promise((resolve) => { finishOlder = resolve; }), { catalogVersion: 'new', stored: [] });
    const older = env.searchState();
    await env.searchState();
    expect(env.getCard('a').n).toBe('from new');

    finishOlder({ catalogVersion: 'old', stored: [] });
    await older;
    expect(env.getCard('a').n).toBe('from new');
    expect(env.allCards()[0].n).toBe('from new');
    await env.allNames();
    expect(page.log.namesRead.at(-1)).toBe('new');
});

test('a newer read moves a search to the new catalog', async () => {
    const states = [];
    const page = await started('offline-page-desktop.js', {
        ids: DESKTOP, search: '?q=x', states, queries: { x: [{ uuid: 'a' }] },
    });
    const env = page.log.env;
    states.push({ catalogVersion: 'next', stored: [] });
    await env.searchState();
    expect(env.getCard('a').n).toBe('from next');
});

test('desktop sort pills keep the answer on screen while a newer search runs', async () => {
    const slow = new Promise(() => {});
    const pill = makeEl({ 'data-sort': 'alpha' });
    const page = loadPage('offline-page-desktop.js', {
        ids: DESKTOP, pills: [pill], queries: { x: [{ uuid: 'a' }] }, gates: { slow },
    });
    page.load();
    await page.settle();
    page.log.mounted.onSubmit('x');
    await page.settle();
    page.log.mounted.onSubmit('slow');
    await page.settle();
    pill.fire('click');
    await page.settle();
    expect(page.els['offline-results'].innerHTML).toBe('drawn 1');
    expect(page.log.sorted.at(-1)).toMatchObject({ mode: 'alpha', n: 1 });
});

test('desktop asks for every price only under a price sort', async () => {
    const pill = makeEl({ 'data-sort': 'retail' });
    const page = await started('offline-page-desktop.js', {
        ids: DESKTOP, pills: [pill], search: '?q=x', queries: { x: [{ uuid: 'a' }] },
    });
    expect(page.hold.views.at(-1)).toBe(false);
    pill.fire('click');
    await page.settle();
    expect(page.hold.views.at(-1)).toBe(true);
});

test('a price sort still pricing does not draw over a newer search', async () => {
    const pill = makeEl({ 'data-sort': 'retail' });
    const queries = { x: [{ uuid: 'a' }], y: [{ uuid: 'b' }, { uuid: 'c' }] };
    const page = await started('offline-page-desktop.js', { ids: DESKTOP, pills: [pill], search: '?q=x', queries });
    let finish;
    page.hold.draw = new Promise((resolve) => { finish = resolve; });
    pill.fire('click');
    await page.settle();
    page.hold.draw = null;
    page.log.mounted.onSubmit('y');
    await page.settle();
    expect(page.els['offline-results'].innerHTML).toBe('drawn 2');
    const drawn = page.log.rendered.length;
    finish();
    await page.settle();
    expect(page.log.rendered).toHaveLength(drawn);
    expect(page.els['offline-results'].innerHTML).toBe('drawn 2');
});

test('a sort that hits a set which will not open asks the query again', async () => {
    const pill = makeEl({ 'data-sort': 'alpha' });
    const page = await started('offline-page-desktop.js', {
        ids: DESKTOP, pills: [pill], search: '?q=x', queries: { x: [{ uuid: 'a' }] },
    });
    expect(page.log.executed).toHaveLength(1);
    page.hold.fail = true;
    pill.fire('click');
    await page.settle();
    expect(page.log.executed).toHaveLength(2);
});

test('desktop sort pills sort the last answer, reversing on a second click', async () => {
    const pill = (sort) => makeEl({ 'data-sort': sort });
    const pills = [pill('chrono'), pill('alpha')];
    const page = loadPage('offline-page-desktop.js', { ids: DESKTOP, pills, queries: { x: [{ uuid: 'a' }] } });
    page.load();
    await page.settle();
    // No answer yet, so nothing to draw
    pills[1].fire('click');
    await page.settle();
    expect(page.log.sorted).toEqual([]);
    expect(pills[1].classList.names.has('active')).toBe(false);

    page.log.mounted.onSubmit('x');
    await page.settle();
    expect(page.log.sorted.at(-1)).toMatchObject({ mode: 'alpha', reverse: false });
    pills[1].fire('click');
    await page.settle();
    expect(page.log.sorted.at(-1)).toMatchObject({ mode: 'alpha', reverse: true });
    expect(pills[1].classList.names.has('reversed')).toBe(true);
    pills[0].fire('click');
    await page.settle();
    expect(page.log.sorted.at(-1)).toMatchObject({ mode: 'chrono', reverse: false });
    expect(pills[0].classList.names.has('active')).toBe(true);
    expect(pills[1].classList.names.has('active')).toBe(false);
});

test('desktop starts from the default sort cookie, reading hybrid as alphabetical', async () => {
    const page = await started('offline-page-desktop.js', {
        ids: DESKTOP, search: '?q=x', cookies: { SearchDefaultSort: 'hybrid' }, queries: { x: [{ uuid: 'a' }] },
    });
    expect(page.log.sorted[0].mode).toBe('alpha');
});

test('the sidebar image only takes a URL the renderers could have written', async () => {
    const page = await started('offline-page-desktop.js', { ids: DESKTOP, search: '?sealed=1' });
    const hover = (attrs) => page.els['offline-results'].fire('mouseover', {
        target: { closest: () => makeEl({ 'data-foil': 'true', 'data-set-code': 'NEO', ...attrs }) },
    });
    hover({ 'data-image-url': '/api/offline/images/abc.webp' });
    expect(page.log.art.at(-1)).toBe('/api/offline/images/abc.webp');
    const wrapper = page.els.cardImageWrapper.attrs;
    expect(wrapper).toMatchObject({ 'data-foil': 'true', 'data-set': 'NEO', 'data-sealed': '' });
    hover({ 'data-image-url': 'https://elsewhere.example/x.webp' });
    expect(page.log.art.at(-1)).toStartWith('data:image/gif');
    expect(wrapper['data-foil']).toBe('false');
});

test('mobile mode pills carry the query and mark the mode', async () => {
    const page = await started('offline-page-mobile.js', { ids: MOBILE, search: '?sealed=1' });
    const singles = page.els['offline-pill-singles'];
    const sealed = page.els['offline-pill-sealed'];
    expect(sealed.classList.names.has('active')).toBe(true);
    expect(singles.classList.names.has('active')).toBe(false);
    page.log.mounted.onSubmit('sol ring');
    expect(singles.href).toBe('/offline?q=sol%20ring');
    expect(sealed.href).toBe('/offline?sealed=1&q=sol%20ring');
});

test('mobile mode pills carry the query from the moment the page loads', () => {
    const page = loadPage('offline-page-mobile.js', { ids: MOBILE, search: '?q=spm%2066' });
    page.load();
    expect(page.els['offline-pill-singles'].href).toBe('/offline?q=spm%2066');
    expect(page.els['offline-pill-sealed'].href).toBe('/offline?sealed=1&q=spm%2066');
});

test('mobile mode pills follow Back to the query it lands on', async () => {
    const page = await started('offline-page-mobile.js', { ids: MOBILE, search: '?q=sol' });
    page.log.mounted.onSubmit('bolt');
    page.location.search = '?q=sol';
    page.pop();
    expect(page.els['offline-pill-singles'].href).toBe('/offline?q=sol');
    expect(page.els['offline-pill-sealed'].href).toBe('/offline?sealed=1&q=sol');
    await page.settle();
    page.location.search = '?sealed=1&q=bolt';
    page.pop();
    expect(page.els['offline-pill-sealed'].classList.names.has('active')).toBe(true);
    expect(page.els['offline-pill-singles'].href).toBe('/offline?q=bolt');
});

test('mobile mode pills drop the query when the box empties', async () => {
    const page = await started('offline-page-mobile.js', { ids: MOBILE, search: '?q=sol' });
    page.log.mounted.onSubmit('');
    expect(page.els['offline-pill-singles'].href).toBe('/offline');
    expect(page.els['offline-pill-sealed'].href).toBe('/offline?sealed=1');
});
