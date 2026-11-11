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
        blur: () => { attrs.blurred = true; },
    };
}

// Runs the page's real scripts against stand-ins for the document, the database
// and the query. Each query answers with the rows queries[q] names.
function loadPage(file, { search = '', ids = [], pills = [], navLinks = [], cookies = {}, queries = {}, broken = false, gates = {}, states = [], stored = { offline_live_search: 'false' } } = {}) {
    const els = Object.fromEntries(ids.map((id) => [id, makeEl()]));
    const docListeners = {};
    const winListeners = {};
    const location = { search, pathname: '/offline' };
    const hold = { draw: null, fail: false, views: [], full: [] };
    const log = { namesRead: [], pushed: [], replaced: [], parsed: [], drafts: [], executed: [], rendered: [], sorted: [], mounted: null, errors: [], art: [], scrolls: [], dictReads: 0 };
    const timers = new Map();
    let nextTimer = 0;

    const document = {
        getElementById: (id) => els[id] || null,
        querySelectorAll: (sel) => (sel === '.search-sort-pill' ? pills : sel === '.offline-mode-btn' ? navLinks : []),
        addEventListener: (type, fn) => { docListeners[type] = fn; },
    };
    const window = {
        addEventListener: (type, fn) => { winListeners[type] = fn; },
        scrollTo: (x, y) => log.scrolls.push(['to', y]),
        scrollBy: (x, y) => log.scrolls.push(['by', y]),
    };
    const localStorage = {
        getItem: (key) => (key in stored ? stored[key] : null),
        setItem: (key, value) => { stored[key] = value; },
    };
    const history = {
        pushState: (_state, _title, url) => {
            log.pushed.push(url);
            location.search = url.startsWith('?') ? url : '';
        },
        replaceState: (_state, _title, url) => {
            log.replaced.push(url);
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
    const OfflineUtil = { normName: (s) => s, loadCatalogDicts: async () => { log.dictReads++; return dicts; }, loadSetPayload: async () => null };
    const OfflineQuery = {
        parse: (q, _finishes, _rarities, _sets, options) => {
            log.parsed.push(q);
            log.drafts.push(options.draft);
            return { q };
        },
        answerable: (parsed) => parsed.q.length >= 3,
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
            hold.full.push(view);
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
    const setTimeout = (fn) => { timers.set(++nextTimer, fn); return nextTimer; };
    const clearTimeout = (id) => { timers.delete(id); };
    const getComputedStyle = () => ({ top: '77px' });
    const names = ['self', 'document', 'window', 'location', 'history', 'console', 'getCookie', 'setCardArtSource', 'localStorage',
        'setTimeout', 'clearTimeout', 'getComputedStyle',
        'OfflineDB', 'OfflineUtil', 'OfflineQuery', 'OfflineSearch', 'OfflineRender', 'OfflineRenderMobile'];
    const args = [self, document, window, location, history, consoleStub, (name) => cookies[name] || '',
        (el, url) => log.art.push(url), localStorage, setTimeout, clearTimeout, getComputedStyle,
        OfflineDB, OfflineUtil, OfflineQuery, OfflineSearch, { render }, { render }];
    for (const src of [read('offline-live.js'), read('offline-page.js'), read(file)]) new Function(...names, src)(...args);

    return {
        els,
        log,
        hold,
        location,
        // Lets the page's setup and first query finish: nothing here is timed.
        settle: () => new Promise((resolve) => setImmediate(resolve)),
        load: () => docListeners.DOMContentLoaded(),
        pop: () => winListeners.popstate(),
        synced: () => docListeners['offline:synced'](),
        // Stands in for the box having sat still long enough.
        pause: async () => {
            const waiting = [...timers.values()];
            timers.clear();
            waiting.forEach((fn) => fn());
            await new Promise((resolve) => setImmediate(resolve));
        },
        pausePending: () => timers.size > 0,
        type: (value) => log.mounted.onType(value),
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

    test(file + ' reads the answer on screen again when a sync finishes', async () => {
        const page = await started(file, { ids, search: '?q=bolt', queries: { bolt: [row('a')] } });
        page.synced();
        await page.settle();
        expect(page.log.executed).toEqual([{ q: 'bolt', sealed: false }, { q: 'bolt', sealed: false }]);
        expect(page.log.drafts).toEqual([false, false]);
        expect(page.els[results].innerHTML).toBe('drawn 1');
    });

    test(file + ' leaves a sync alone while no answer is on screen yet', async () => {
        let open;
        const first = new Promise((resolve) => { open = resolve; });
        const page = await started(file, { ids, search: '?q=bolt', queries: { bolt: [row('a')] }, gates: { bolt: first } });
        page.synced();
        await page.settle();
        expect(page.log.executed).toHaveLength(1);
        open();
        await page.settle();
        expect(page.els[results].innerHTML).toBe('drawn 1');
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

// Results as you type.
const LIVE = { stored: { offline_live_search: 'true' } };
const rows = (n) => Array.from({ length: n }, (_, i) => ({ uuid: 'r' + i }));

for (const [file, ids, box, results] of [
    ['offline-page-desktop.js', DESKTOP, 'nav-searchbox', 'offline-results'],
    ['offline-page-mobile.js', MOBILE, 'navsearchbox', 'm-offline-results'],
]) {
    const liveStart = (opts) => started(file, { ids, ...LIVE, ...opts });

    test(file + ' draws a first screen per keystroke and the page on the pause', async () => {
        const page = await liveStart({ queries: { sol: rows(150) } });
        page.type('sol');
        await page.settle();
        expect(page.els[results].innerHTML).toBe('drawn 10');
        expect(page.log.drafts.at(-1)).toBe(true);
        await page.pause();
        expect(page.els[results].innerHTML).toBe('drawn 100');
        expect(page.log.drafts.at(-1)).toBe(false);
    });

    test(file + ' leaves a query being typed to its pause when a sync finishes', async () => {
        const page = await liveStart({ queries: { sol: rows(3) } });
        page.type('sol');
        await page.settle();
        page.synced();
        await page.settle();
        expect(page.log.executed).toHaveLength(1);
        await page.pause();
        expect(page.log.executed).toHaveLength(2);
        page.synced();
        await page.settle();
        expect(page.log.executed).toHaveLength(3);
        expect(page.log.drafts.at(-1)).toBe(false);
    });

    test(file + ' adds one history entry per stretch of typing', async () => {
        const page = await liveStart({ queries: { sol: rows(1), 'sol ring': rows(1) } });
        page.type('sol');
        page.type('sol r');
        expect(page.log.pushed).toEqual(['?q=sol']);
        expect(page.log.replaced).toEqual([]);
        page.type('sol ring ');
        await page.pause();
        expect(page.log.pushed).toEqual(['?q=sol']);
        expect(page.log.replaced).toEqual(['?q=sol%20ring']);
        page.type('sol ring f');
        expect(page.log.pushed).toEqual(['?q=sol', '?q=sol%20ring%20f']);
    });

    test(file + ' keeps the answer up until a new one is ready, and keeps zero for the pause', async () => {
        let open;
        const gate = new Promise((resolve) => { open = resolve; });
        const page = await liveStart({ queries: { sol: rows(3) }, gates: { 'sol x': gate } });
        page.type('sol');
        await page.settle();
        page.type('sol x');
        await page.settle();
        expect(page.els[results].innerHTML).toBe('drawn 3');
        open();
        await page.settle();
        expect(page.els[results].innerHTML).toBe('drawn 3');
        await page.pause();
        expect(page.els[results].innerHTML).toBe('drawn 0');
    });

    test(file + ' skips what is not worth asking, and drops the search it replaced', async () => {
        let open;
        const gate = new Promise((resolve) => { open = resolve; });
        const page = await liveStart({ queries: { sol: rows(3) }, gates: { sol: gate } });
        page.type('sol');
        page.type('so');
        expect(page.log.executed.map((p) => p.q)).toEqual(['sol']);
        open();
        await page.settle();
        expect(page.els[results].innerHTML).toBe('');
        expect(page.pausePending()).toBe(true);
    });

    test(file + ' a pause on too little leaves the page alone, and Enter still asks', async () => {
        const page = await liveStart({ queries: { sol: rows(3) } });
        page.type('sol');
        await page.pause();
        page.type('so');
        await page.pause();
        expect(page.els[results].innerHTML).toBe('drawn 3');
        expect(page.log.executed.map((p) => p.q)).toEqual(['sol', 'sol']);
        expect(page.log.replaced.at(-1)).toBe('?q=so');
        page.log.mounted.onSubmit('so');
        await page.settle();
        expect(page.log.executed.at(-1).q).toBe('so');
        expect(page.els[results].innerHTML).toBe('drawn 0');
    });

    test(file + ' tells a replaced search to stop opening sets', async () => {
        let open;
        const gate = new Promise((resolve) => { open = resolve; });
        const page = await liveStart({ queries: { sol: rows(3) }, gates: { sol: gate } });
        const replaced = page.hold.full.length;
        page.type('sol');
        page.type('sol r');
        await page.settle();
        open();
        await page.settle();
        const views = page.hold.full.slice(replaced);
        expect(views.map((view) => view.stale())).toEqual([false, true]);
    });

    test(file + ' puts the best match first only once settled', async () => {
        const page = await liveStart({ queries: { sol: rows(1) } });
        page.type('sol');
        await page.settle();
        expect(page.hold.full.at(-1).bestMatch).toBe(false);
        await page.pause();
        expect(page.hold.full.at(-1).bestMatch).toBe(true);
    });

    test(file + ' settles on Enter without another history entry, and once', async () => {
        const page = await liveStart({ queries: { sol: rows(150) } });
        page.type('sol');
        page.log.mounted.onSubmit('sol');
        await page.settle();
        expect(page.pausePending()).toBe(false);
        expect(page.els[results].innerHTML).toBe('drawn 100');
        expect(page.log.pushed).toEqual(['?q=sol']);
        const asked = page.log.executed.length;
        page.log.mounted.onSubmit('sol');
        await page.settle();
        expect(page.log.executed.length).toBe(asked);
        expect(page.log.pushed).toEqual(['?q=sol']);
    });

    test(file + ' Back ends the typing and reads the query as finished', async () => {
        const page = await liveStart({ search: '?q=bolt', queries: { bolt: rows(150) } });
        page.type('bolt f');
        page.location.search = '?q=bolt';
        page.pop();
        await page.settle();
        expect(page.pausePending()).toBe(false);
        expect(page.log.drafts.at(-1)).toBe(false);
        expect(page.els[box].value).toBe('bolt');
        expect(page.els[results].innerHTML).toBe('drawn 100');
        page.type('bolt g');
        expect(page.log.pushed).toEqual(['?q=bolt%20f', '?q=bolt%20g']);
    });

    test(file + ' emptying the box clears the page at once', async () => {
        const page = await liveStart({ queries: { sol: rows(3) } });
        page.type('sol');
        await page.settle();
        page.type('');
        await page.settle();
        expect(page.els[results].innerHTML).toBe('');
        expect(page.pausePending()).toBe(false);
        expect(page.log.replaced.at(-1)).toBe('/offline');
    });

    test(file + ' scrolls back up only when the answer changes', async () => {
        const page = await liveStart({ queries: { sol: rows(3), 'sol ': rows(3), 'sol r': rows(2) } });
        page.type('sol');
        await page.settle();
        expect(page.log.scrolls).toEqual([]);
        page.type('sol ');
        await page.settle();
        expect(page.log.scrolls).toEqual([]);
        page.type('sol r');
        await page.settle();
        expect(page.log.scrolls).toEqual([['to', 0]]);
    });

    test(file + ' leaves a settled page up while typing finds the same rows', async () => {
        const page = await liveStart({ queries: { sol: rows(150), 'sol ': rows(150), 'sol r': rows(150), 'sol ri': rows(2) } });
        page.type('sol');
        await page.pause();
        const drawn = page.log.rendered.length;
        page.type('sol ');
        page.type('sol r');
        await page.settle();
        expect(page.log.rendered).toHaveLength(drawn);
        expect(page.els[results].innerHTML).toBe('drawn 100');
        page.type('sol ri');
        await page.settle();
        expect(page.log.rendered).toHaveLength(drawn + 1);
        expect(page.els[results].innerHTML).toBe('drawn 2');
    });

    test(file + ' draws a typed page once, and a pause only when it changes it', async () => {
        const page = await liveStart({ queries: { sol: rows(3), 'sol ': rows(3), 'sol r': rows(3) } });
        page.type('sol');
        page.type('sol ');
        await page.settle();
        expect(page.log.rendered.map((r) => r.page.typing)).toEqual([true]);
        await page.pause();
        expect(page.log.rendered.map((r) => r.page.typing)).toEqual([true, false]);
        page.type('sol r');
        await page.pause();
        expect(page.log.rendered).toHaveLength(2);
        page.synced();
        await page.settle();
        expect(page.log.rendered).toHaveLength(3);
    });

    test(file + ' only counts again when typing keeps the first screen', async () => {
        const page = await liveStart({ queries: { sol: rows(150), 'sol r': rows(120), 'sol ri': rows(5) } });
        page.type('sol');
        await page.settle();
        page.type('sol r');
        await page.settle();
        expect(page.log.rendered).toHaveLength(1);
        if (page.els['offline-count']) expect(page.els['offline-count'].textContent).toBe('120 results found (100 shown)');
        page.type('sol ri');
        await page.settle();
        expect(page.log.rendered).toHaveLength(2);
    });

    test(file + ' with the setting off leaves the order and the scroll alone', async () => {
        const page = await started(file, { ids, queries: { sol: rows(3), bolt: rows(2) } });
        expect(page.log.mounted.live()).toBe(false);
        page.log.mounted.onSubmit('sol');
        await page.settle();
        page.log.mounted.onSubmit('bolt');
        await page.settle();
        expect(page.hold.full.at(-1).bestMatch).toBe(false);
        expect(page.log.scrolls).toEqual([]);
        expect(page.log.pushed).toEqual(['?q=sol', '?q=bolt']);
    });

    test(file + ' reads the setting on each event', async () => {
        const stored = { offline_live_search: 'false' };
        const page = await started(file, { ids, stored });
        expect(page.log.mounted.live()).toBe(false);
        stored.offline_live_search = 'true';
        expect(page.log.mounted.live()).toBe(true);
    });
}

test('each page has its own default with nothing stored', async () => {
    const desktop = await started('offline-page-desktop.js', { ids: DESKTOP, stored: {} });
    const mobile = await started('offline-page-mobile.js', { ids: MOBILE, stored: {} });
    expect(desktop.log.mounted.live()).toBe(true);
    expect(mobile.log.mounted.live()).toBe(false);
});

test('desktop holds a price sort and the image until the pause', async () => {
    const page = await started('offline-page-desktop.js', {
        ids: DESKTOP, ...LIVE, cookies: { SearchDefaultSort: 'retail' }, queries: { sol: rows(3) },
    });
    page.type('sol');
    await page.settle();
    expect(page.hold.views.at(-1)).toBe(false);
    expect(page.log.sorted.at(-1)).toMatchObject({ mode: 'chrono', reverse: false });
    await page.pause();
    expect(page.hold.views.at(-1)).toBe(true);
    expect(page.log.sorted.at(-1)).toMatchObject({ mode: 'retail' });
});

test('desktop leaves the image alone while typing, and follows at the pause', async () => {
    const page = loadPage('offline-page-desktop.js', { ids: DESKTOP, ...LIVE, queries: { sol: rows(3) } });
    const header = makeEl({ 'data-image-url': '/api/offline/images/a.webp' });
    page.els['offline-results'].querySelector = () => header;
    page.load();
    await page.settle();
    page.type('sol');
    await page.settle();
    expect(page.log.art).toEqual([]);
    await page.pause();
    expect(page.log.art).toEqual(['/api/offline/images/a.webp']);
});

test('desktop counts the page a settled answer will show while typing', async () => {
    const page = await started('offline-page-desktop.js', { ids: DESKTOP, ...LIVE, queries: { sol: rows(150), lig: rows(4) } });
    page.type('sol');
    await page.settle();
    expect(page.els['offline-count'].textContent).toBe('150 results found (100 shown)');
    page.type('lig');
    await page.settle();
    expect(page.els['offline-count'].textContent).toBe('4 results found');
});

test('a sort pill settles what is being typed', async () => {
    const pill = makeEl({ 'data-sort': 'alpha' });
    const page = await started('offline-page-desktop.js', { ids: DESKTOP, ...LIVE, pills: [pill], queries: { sol: rows(150) } });
    page.type('sol');
    await page.settle();
    pill.fire('click');
    await page.settle();
    expect(page.pausePending()).toBe(false);
    expect(page.els['offline-results'].innerHTML).toBe('drawn 100');
    expect(page.log.sorted.at(-1)).toMatchObject({ mode: 'alpha' });
    expect(page.log.replaced).toEqual(['?q=sol']);
});

function headersFor(page, n) {
    const headers = Array.from({ length: n }, (_, i) => {
        const header = makeEl({ 'data-image-url': '/api/offline/images/' + i + '.webp' });
        header.nextElementSibling = { getBoundingClientRect: () => ({ bottom: 500 + i }) };
        return header;
    });
    const el = page.els['offline-results'];
    el.querySelectorAll = () => headers;
    el.querySelector = () => headers[0];
    return headers;
}

test('arrow keys walk the results, with the image following', async () => {
    const page = loadPage('offline-page-desktop.js', { ids: DESKTOP, ...LIVE, search: '?q=sol', queries: { sol: rows(3) } });
    const headers = headersFor(page, 3);
    page.load();
    await page.settle();
    page.log.mounted.onArrow(-1);
    await page.settle();
    expect(page.log.scrolls).toEqual([]);

    page.log.mounted.onArrow(1);
    await page.settle();
    expect(headers[1].classList.names.has('offline-cursor')).toBe(true);
    expect(page.log.art.at(-1)).toBe('/api/offline/images/1.webp');
    expect(page.log.scrolls.at(-1)).toEqual(['by', 500 - 77]);

    page.log.mounted.onArrow(1);
    await page.settle();
    page.log.mounted.onArrow(1);
    await page.settle();
    expect(headers[2].classList.names.has('offline-cursor')).toBe(true);
    expect(headers[1].classList.names.has('offline-cursor')).toBe(false);

    page.log.mounted.onArrow(-1);
    await page.settle();
    page.log.mounted.onArrow(-1);
    await page.settle();
    expect(headers[0].classList.names.has('offline-cursor')).toBe(true);
    expect(page.log.scrolls.at(-1)).toEqual(['to', 0]);
});

test('an arrow key settles what is being typed, then moves', async () => {
    const page = loadPage('offline-page-desktop.js', { ids: DESKTOP, ...LIVE, queries: { sol: rows(150) } });
    const headers = headersFor(page, 2);
    page.load();
    await page.settle();
    page.type('sol');
    page.log.mounted.onArrow(1);
    await page.settle();
    expect(page.pausePending()).toBe(false);
    expect(page.els['offline-results'].innerHTML).toBe('drawn 100');
    expect(headers[1].classList.names.has('offline-cursor')).toBe(true);
});

test('Enter closes the keyboard on a phone, and only with the setting on', async () => {
    const live = await started('offline-page-mobile.js', { ids: MOBILE, ...LIVE, queries: { sol: rows(1) } });
    live.type('sol');
    live.log.mounted.onSubmit('sol');
    expect(live.els.navsearchbox.attrs.blurred).toBe(true);

    const off = await started('offline-page-mobile.js', { ids: MOBILE });
    off.log.mounted.onSubmit('sol');
    expect(off.els.navsearchbox.attrs.blurred).toBeUndefined();

    const desktop = await started('offline-page-desktop.js', { ids: DESKTOP, ...LIVE, queries: { sol: rows(1) } });
    desktop.type('sol');
    desktop.log.mounted.onSubmit('sol');
    expect(desktop.els['nav-searchbox'].attrs.blurred).toBeUndefined();
});

test('the navbar links on desktop keep the query as it is typed', async () => {
    const search = { href: 'http://x.test/offline?q=old', setAttribute(_n, value) { this.href = 'http://x.test' + value; } };
    const sealed = { href: 'http://x.test/offline?sealed=1&q=old', setAttribute(_n, value) { this.href = 'http://x.test' + value; } };
    const page = await started('offline-page-desktop.js', { ids: DESKTOP, ...LIVE, navLinks: [search, sealed], queries: { 'sol r': rows(1) } });
    page.type('sol r');
    expect(new URL(search.href).searchParams.get('q')).toBe('sol r');
    expect(new URL(sealed.href).searchParams.get('q')).toBe('sol r');
    expect(new URL(sealed.href).searchParams.get('sealed')).toBe('1');
    page.type('');
    expect(new URL(search.href).search).toBe('');
});

test('the sets and stores are read again once a sync has finished', async () => {
    const states = [{ catalogVersion: 'c1', stored: [], lastSync: 'one' }];
    const page = await started('offline-page-mobile.js', { ids: MOBILE, ...LIVE, queries: { sol: rows(1) }, states });
    expect(page.log.dictReads).toBe(1);
    page.type('sol');
    await page.settle();
    const env = page.log.env;
    states.push({ catalogVersion: 'c1', stored: [], lastSync: 'one' });
    await env.searchState();
    expect(page.log.dictReads).toBe(1);
    states.push({ catalogVersion: 'c1', stored: [], lastSync: 'two' });
    await env.searchState();
    expect(page.log.dictReads).toBe(2);
});
