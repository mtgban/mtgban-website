import { test, expect } from 'bun:test';
import { read, tagsWith, expectTrack, fakeBAN } from '../metrics-helpers.js';
import { registry, trackProblems } from '../track-registry.js';

const desktop = read('templates/offline.html');
const mobile = read('templates/mobile/offline.html');

// --- Marks ---

test('the five desktop sort pills count sort', () => {
    const found = tagsWith(desktop, 'class="search-sort-pill"');
    expect(found.length).toBe(5);
    found.forEach((t) => expectTrack(t, 'ui.offline.page', 'sort', undefined));
});

test.each([
    ['mobile', 'id="offline-pill-singles"', 'ui.offline.page', 'kind'],
    ['mobile', 'id="offline-pill-sealed"', 'ui.offline.page', 'kind'],
    ['desktop', 'id="offline-banner-back"', 'ui.offline.banner', 'back_to_live'],
    ['mobile', 'id="offline-banner-back"', 'ui.offline.banner', 'back_to_live'],
])('%s: the tag with %s tracks %s:%s', (file, marker, name, value) => {
    const found = tagsWith({ desktop, mobile }[file], marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], name, value, undefined);
});

test('every mark on the offline pages is in the registry', () => {
    expect(trackProblems(desktop)).toEqual([]);
    expect(trackProblems(mobile)).toEqual([]);
});

// A stand-in element that records its attributes.
function el() {
    const attrs = {};
    const listeners = {};
    return {
        attrs, listeners, classList: { add() {}, remove() {}, toggle() {} },
        setAttribute: (k, v) => { attrs[k] = v; },
        getAttribute: (k) => (k in attrs ? attrs[k] : null),
        addEventListener: (type, fn) => { listeners[type] = fn; },
        appendChild() {}, querySelectorAll: () => [],
    };
}

test('the offline navbar marks its Search and Sealed switch as kind', () => {
    const navbar = read('js/navbar.js');
    const start = navbar.indexOf('// ── On /offline, the navbar is a Singles/Sealed mode switch');
    const block = navbar.slice(start);
    const built = [];
    const sections = Object.assign(el(), { querySelector: () => null, insertBefore: (a) => built.push(a) });
    const nav = Object.assign(el(), { querySelector: () => sections });
    const document = { querySelector: () => nav, getElementById: () => null, createElement: () => el() };
    new Function('document', 'location', block)(document, { pathname: '/offline', search: '?q=bolt' });
    expect(built.length).toBe(2);
    for (const a of built) {
        expect(a.attrs['data-track']).toBe('ui.offline.page');
        expect(a.attrs['data-track-value']).toBe('kind');
    }
});

test('the unreachable toast marks Browse offline and its dismiss button', async () => {
    const made = [];
    const winListeners = {};
    const document = {
        getElementById: () => null, hidden: false,
        createElement: () => { const e = el(); made.push(e); return e; },
        body: { appendChild() {} },
    };
    const window = { addEventListener: (type, fn) => { winListeners[type] = fn; } };
    const localStorage = { getItem: (k) => (k === 'offline_mode' ? 'true' : null) };
    const fetch = () => Promise.reject(new Error('offline'));
    new Function('self', 'window', 'document', 'location', 'localStorage', 'fetch', 'setTimeout', 'clearTimeout', 'setInterval', read('js/offline/offline-watch.js'))(
        {}, window, document, { pathname: '/search', search: '' }, localStorage, fetch, () => 0, () => {}, () => 0);
    winListeners.offline();
    await new Promise((resolve) => setImmediate(resolve));
    const marked = made.filter((e) => e.attrs['data-track']).map((e) => [e.attrs['data-track'], e.attrs['data-track-value']]);
    expect(marked).toEqual([['ui.offline.banner', 'browse_offline'], ['ui.offline.banner', 'dismiss']]);
});

// --- offline-mode.js, loaded as tests/offline/mode.test.js loads it, with window.BAN added ---

function memoryStorage(initial = {}) {
    const values = new Map(Object.entries(initial));
    return {
        values,
        getItem: (k) => (values.has(k) ? values.get(k) : null),
        setItem: (k, v) => { values.set(k, String(v)); },
        removeItem: (k) => { values.delete(k); },
    };
}

function loadOfflineMode({ ban = true, stored = {}, register = () => Promise.resolve({}), persist = () => Promise.resolve(true), ensureKey = () => Promise.resolve() } = {}) {
    const src = read('js/offline/offline-mode.js');
    const f = fakeBAN();
    const doc = {
        documentElement: { dataset: { offlineMode: 'true' } },
        readyState: 'complete',
        addEventListener: () => {},
        dispatchEvent: () => {},
        getElementById: () => null,
    };
    let worker = null;
    const win = {
        addEventListener: () => {}, removeEventListener: () => {},
        isSecureContext: true, indexedDB: {}, crypto: { subtle: {} },
        confirm: () => true,
    };
    if (ban) win.BAN = f.BAN;
    const anyDB = new Proxy({}, { get: (t, k) => (k === 'ensureKey' ? ensureKey : () => Promise.resolve([])) });
    const navigator = {
        storage: { persist },
        serviceWorker: { register, getRegistrations: () => Promise.resolve([]) },
    };
    const globals = {
        localStorage: memoryStorage(stored),
        OfflineDB: anyDB,
        navigator,
        caches: { keys: () => Promise.resolve([]), delete: () => Promise.resolve(true) },
        indexedDB: { deleteDatabase: () => { const req = {}; setImmediate(() => req.onsuccess && req.onsuccess()); return req; } },
        Worker: class { constructor() { worker = this; } postMessage() {} },
        CustomEvent: class { constructor(type, init) { this.detail = init && init.detail; } },
    };
    const names = Object.keys(globals);
    new Function('window', 'document', ...names, src)(win, doc, ...names.map((n) => globals[n]));
    return { mode: win.OfflineMode, calls: f.calls, message: (data) => worker.onmessage({ data }), storage: globals.localStorage };
}

const flush = () => new Promise((resolve) => setImmediate(resolve));
const named = (calls, prefix) => calls.filter((c) => c[0].startsWith(prefix));

test('switching offline mode on counts the worker and the mode', async () => {
    const m = loadOfflineMode();
    await m.mode.enable();
    expect(named(m.calls, 'ui.offline.s').filter((c) => c[0] === 'ui.offline.sw')).toEqual([['ui.offline.sw', 'install_ok', undefined]]);
    const order = m.calls.map((c) => c[0] + ':' + c[1]);
    expect(order.indexOf('ui.offline.sw:install_ok')).toBeLessThan(order.indexOf('ui.offline.mode:enable'));
    expect(order).toContain('ui.offline.mode:enable');
});

test('a worker that will not register counts install_fail and no enable', async () => {
    const m = loadOfflineMode({ register: () => Promise.reject(new Error('refused')) });
    await expect(m.mode.enable()).rejects.toThrow('refused');
    expect(m.calls).toEqual([['ui.offline.sw', 'install_fail', undefined]]);
});

test('a persist() rejection before register counts neither', async () => {
    const m = loadOfflineMode({ persist: () => Promise.reject(new Error('no persist')) });
    await expect(m.mode.enable()).rejects.toThrow('no persist');
    expect(m.calls).toEqual([]);
});

test('a key that fails after the worker registered counts install_ok and no enable', async () => {
    const m = loadOfflineMode({ ensureKey: () => Promise.reject(new Error('no key')) });
    await expect(m.mode.enable()).rejects.toThrow('no key');
    expect(m.calls).toEqual([['ui.offline.sw', 'install_ok', undefined]]);
});

test('switching off counts disable', async () => {
    const m = loadOfflineMode({ stored: { offline_mode: 'true' } });
    await m.mode.disable().catch(() => {});
    expect(m.calls.filter((c) => c[0] === 'ui.offline.mode')).toEqual([['ui.offline.mode', 'disable', undefined]]);
});

async function syncing(opts) {
    const m = loadOfflineMode(Object.assign({ stored: { offline_mode: 'true' } }, opts));
    m.mode.sync();
    await flush();
    return m;
}
const syncCalls = (m) => m.calls.filter((c) => c[0] === 'ui.offline.sync');

const stages = (m) => syncCalls(m).map((c) => c[1] + ':' + c[2]);

test('a finished sync is ok for catalog and prices; with images for images too', async () => {
    const m = await syncing();
    m.message({ type: 'done', images: false });
    expect(stages(m)).toEqual(['ok:catalog', 'ok:prices']);
    const n = await syncing();
    n.message({ type: 'done', images: true });
    expect(stages(n)).toEqual(['ok:catalog', 'ok:prices', 'ok:images']);
});

test.each([
    ['manifest', ['fail:catalog']],
    ['catalog', ['fail:catalog']],
    ['prices', ['ok:catalog', 'fail:prices']],
    ['images', ['ok:catalog', 'ok:prices', 'fail:images']],
])('a sync failed at %s counts the stages before it ok', async (stage, want) => {
    const m = await syncing();
    m.message({ type: 'error', stage, message: 'boom' });
    expect(stages(m)).toEqual(want);
});

test('every registered scope of ui.offline.sync is sent with ok by some message', async () => {
    const sent = new Set();
    for (const msg of [{ type: 'done', images: true }, { type: 'error', stage: 'images', message: 'boom' }]) {
        const m = await syncing();
        m.message(msg);
        for (const c of syncCalls(m)) if (c[1] === 'ok') sent.add(c[2]);
    }
    expect([...sent].sort()).toEqual([...registry['ui.offline.sync'].scopes].sort());
});

test('a failed sync with an unknown stage counts nothing', async () => {
    const m = await syncing();
    for (const stage of ['setup', undefined, 'constructor', '__proto__']) m.message({ type: 'error', stage, message: 'boom' });
    expect(syncCalls(m)).toEqual([]);
});

test('a progress message counts nothing', async () => {
    const m = await syncing();
    m.message({ type: 'progress', stage: 'prices', done: 1, total: 2 });
    expect(syncCalls(m)).toEqual([]);
});

test('force resync counts when it starts, not while a sync is running', async () => {
    const m = await syncing();
    await m.mode.forceResync();
    expect(m.calls.filter((c) => c[0] === 'ui.offline.data')).toEqual([]);
    m.message({ type: 'done', images: false });
    await m.mode.forceResync();
    expect(m.calls.filter((c) => c[0] === 'ui.offline.data')).toEqual([['ui.offline.data', 'resync', undefined]]);
});

test('delete offline data counts wipe', async () => {
    const m = loadOfflineMode({ stored: { offline_mode: 'true' } });
    await m.mode.wipeLocal().catch(() => {});
    expect(m.calls.filter((c) => c[0] === 'ui.offline.data')).toEqual([['ui.offline.data', 'wipe', undefined]]);
});

test('with no BAN, enable still resolves and a sync still finishes', async () => {
    const m = loadOfflineMode({ ban: false });
    await m.mode.enable();
    expect(m.storage.getItem('offline_mode')).toBe('true');
    m.message({ type: 'done', images: true });
    m.message({ type: 'error', stage: 'prices', message: 'x' });
});

// --- offline-live.js ---

test('the live switch reports the state it is set to', () => {
    const f = fakeBAN();
    const self = { BAN: f.BAN };
    const localStorage = memoryStorage();
    new Function('self', 'localStorage', read('js/offline/offline-live.js'))(self, localStorage);
    self.OfflineLive.set(true);
    self.OfflineLive.set(false);
    expect(f.calls).toEqual([['ui.offline.live', 'on', undefined], ['ui.offline.live', 'off', undefined]]);
    const bare = {};
    new Function('self', 'localStorage', read('js/offline/offline-live.js'))(bare, localStorage);
    expect(() => bare.OfflineLive.set(true)).not.toThrow();
});

// --- offline-page.js, with the stand-ins of tests/offline/page.test.js ---

function loadPage({ search = '', pathname = '/offline', ban = true, queries = {} } = {}) {
    const ids = ['nav-searchbox', 'nav-searchform', 'offline-results', 'offline-count', 'cardImage', 'cardImageWrapper'];
    const els = Object.fromEntries(ids.map((id) => [id, Object.assign(el(), { innerHTML: '', value: '', blur() {}, querySelector: () => null })]));
    const docListeners = {};
    const location = { search, pathname };
    const f = fakeBAN();
    const log = { mounted: null, rendered: 0 };
    const document = {
        getElementById: (id) => els[id] || null,
        querySelectorAll: () => [],
        addEventListener: (type, fn) => { docListeners[type] = fn; },
    };
    const window = { addEventListener() {}, scrollTo() {}, scrollBy() {} };
    if (ban) window.BAN = f.BAN;
    const localStorage = memoryStorage({ offline_live_search: 'false' });
    const history = {
        pushState: (_s, _t, url) => { location.search = url.startsWith('?') ? url : ''; },
        replaceState: (_s, _t, url) => { location.search = url.startsWith('?') ? url : ''; },
    };
    const OfflineDB = {
        open: () => Promise.resolve(),
        searchState: async () => ({ catalogVersion: 'c1', stored: [] }),
        catalog: async () => ({ list: [], byId: new Map() }),
        getMeta: async () => undefined, lookupName: async () => [], allNames: async () => [],
        getCard: async () => null, hasSet: async () => true, getAllRows: async () => [],
    };
    const dicts = { sets: {}, stores: {}, finishes: [], rarities: [] };
    const OfflineUtil = { normName: (s) => s, loadCatalogDicts: async () => dicts, loadSetPayload: async () => null };
    const OfflineQuery = {
        parse: (q) => ({ q }),
        answerable: (parsed) => parsed.q.length >= 3,
        execute: async (parsed, env, view) => {
            const out = { results: (queries[parsed.q] || []).slice(), unsupported: [], truncated: false };
            await OfflineQuery.showPage(out, env, view);
            return out;
        },
        showPage: async (out, _env, view) => { out.page = out.results.slice(0, view.size); return true; },
        sortResults: () => {},
    };
    const OfflineSearch = { mount: (opts) => { log.mounted = opts; } };
    const render = (target, page) => { log.rendered++; target.innerHTML = 'drawn ' + page.results.length; };
    const timers = new Map();
    let next = 0;
    const names = ['self', 'document', 'window', 'location', 'history', 'console', 'getCookie', 'setCardArtSource', 'localStorage',
        'setTimeout', 'clearTimeout', 'getComputedStyle',
        'OfflineDB', 'OfflineUtil', 'OfflineQuery', 'OfflineSearch', 'OfflineRender', 'OfflineRenderMobile'];
    const args = [{}, document, window, location, history, { error() {} }, () => '', () => {}, localStorage,
        (fn) => { timers.set(++next, fn); return next; }, (id) => timers.delete(id), () => ({ top: '0px' }),
        OfflineDB, OfflineUtil, OfflineQuery, OfflineSearch, { render }, { render }];
    for (const file of ['offline-live.js', 'offline-page.js', 'offline-page-desktop.js']) new Function(...names, read('js/offline/' + file))(...args);
    return {
        calls: f.calls, log, els,
        load: async () => { docListeners.DOMContentLoaded(); await flush(); },
        synced: async () => { docListeners['offline:synced'](); await flush(); },
        pause: async () => { const w = [...timers.values()]; timers.clear(); w.forEach((fn) => fn()); await flush(); },
    };
}
const searches = (p) => p.calls.filter((c) => c[0] === 'ui.offline.search');

test('the same query settled at load and again after a sync is one search', async () => {
    const p = loadPage({ search: '?q=bolt', queries: { bolt: [{ uuid: 'a' }] } });
    await p.load();
    await p.synced();
    expect(p.els['offline-results'].innerHTML).toBe('drawn 1');
    expect(searches(p)).toEqual([['ui.offline.search', undefined, undefined]]);
    p.log.mounted.onSubmit('bolt');
    await flush();
    expect(searches(p).length).toBe(1);
    p.log.mounted.onSubmit('shock');
    await flush();
    expect(searches(p).length).toBe(2);
});

test('a typed query counts once it settles, not for each letter', async () => {
    const p = loadPage();
    await p.load();
    p.log.mounted.onType('bo');
    p.log.mounted.onType('bol');
    p.log.mounted.onType('bolt');
    await flush();
    expect(searches(p)).toEqual([]);
    await p.pause();
    expect(searches(p).length).toBe(1);
});

test('an empty box counts no search', async () => {
    const p = loadPage();
    await p.load();
    p.log.mounted.onType('');
    p.log.mounted.onSubmit('');
    await flush();
    expect(searches(p)).toEqual([]);
});

test('the shell at /search counts failover; at /offline it does not', async () => {
    const away = loadPage({ pathname: '/search' });
    await away.load();
    expect(away.calls.filter((c) => c[0] === 'ui.offline.failover')).toEqual([['ui.offline.failover', undefined, undefined]]);
    const home = loadPage();
    await home.load();
    expect(home.calls.filter((c) => c[0] === 'ui.offline.failover')).toEqual([]);
});

test('with no BAN a search still draws', async () => {
    const p = loadPage({ ban: false, pathname: '/search', search: '?q=bolt', queries: { bolt: [{ uuid: 'a' }] } });
    await p.load();
    expect(p.els['offline-results'].innerHTML).toBe('drawn 1');
});

// --- offline-page-mobile.js's card controls ---

test('the mobile card tabs and condition pills count tab and condition', () => {
    const src = read('js/offline/offline-page-mobile.js');
    const f = fakeBAN();
    let render = null;
    const self = { OfflinePage: { start: (hooks) => { render = hooks.render; return { sealed: () => false }; } } };
    const window = { BAN: f.BAN };
    const document = { getElementById: () => null };
    new Function('self', 'window', 'document', 'OfflineRenderMobile', src)(self, window, document, { render() {} });
    const card = { querySelectorAll: () => [] };
    const tab = Object.assign(el(), { closest: () => card });
    const pill = Object.assign(el(), { closest: (sel) => (sel === '.m-card' ? card : { querySelectorAll: () => [] }) });
    const orphan = Object.assign(el(), { closest: () => null });
    const results = { querySelectorAll: (sel) => (sel === '.m-tab' ? [tab] : sel === '.m-cond-pill' ? [pill, orphan] : []) };
    render(results, {}, {}, {});
    tab.listeners.click.call(tab);
    pill.listeners.click.call(pill);
    orphan.listeners.click.call(orphan);
    expect(f.calls).toEqual([['ui.offline.page', 'tab', undefined], ['ui.offline.page', 'condition', undefined]]);
});

// --- offline-images-ui.js ---

function loadImagesUI(ban = true, { totalBytes = 0, estimate = null } = {}) {
    const f = fakeBAN();
    const docListeners = {};
    const make = () => Object.assign(el(), { dataset: {}, hidden: false, disabled: false, textContent: '', style: {}, querySelector: () => make() });
    const byId = { 'offline-img-editions-picker': make(), 'offline-img-estimate': make(), 'offline-img-sync-btn': make(), 'offline-img-pause-btn': make(), 'offline-img-progress': make() };
    const label = make();
    byId['offline-img-progress'].querySelector = () => label;
    const document = { getElementById: (id) => byId[id] || null, addEventListener: (type, fn) => { docListeners[type] = fn; } };
    const window = {
        EditionsPicker: { init() {}, refresh() {}, serialize: () => 'NEO' },
        OfflineImages: { estimateSelection: () => ({ count: 0, bytes: 0, missing: [] }), computeWorkList: () => ({ work: [], totalBytes }), formatBytes: () => '0 B' },
        OfflineDB: { getMeta: () => Promise.resolve({ images: {} }), setMeta: () => Promise.resolve(), getAllRows: () => Promise.resolve([]) },
        OfflineMode: { available: () => true, enabled: () => true, sync() {}, cancelSync() {}, refreshUsage() {} },
    };
    if (ban) window.BAN = f.BAN;
    const localStorage = memoryStorage();
    new Function('window', 'document', 'localStorage', 'navigator', read('js/offline/offline-images-ui.js'))(window, document, localStorage,
        estimate ? { storage: { estimate: () => Promise.resolve(estimate) } } : {});
    window.OfflineImagesUI.init();
    return {
        calls: f.calls,
        label: () => label.textContent,
        change: () => byId['offline-img-editions-picker'].listeners.change(),
        syncNow: () => byId['offline-img-sync-btn'].listeners.click(),
        pause: () => byId['offline-img-pause-btn'].listeners.click(),
        done: () => docListeners['offline:sync-message']({ detail: { type: 'done', images: true } }),
    };
}
const images = (u) => u.calls.filter((c) => c[0] === 'ui.offline.images').map((c) => c[1]);

test('changing editions counts once until the next sync', async () => {
    const u = loadImagesUI();
    u.change();
    u.change();
    expect(images(u)).toEqual(['editions_changed']);
    u.syncNow();
    await flush();
    u.done();
    u.change();
    expect(images(u)).toEqual(['editions_changed', 'sync_now', 'editions_changed']);
});

test('sync now counts only once the storage check lets the sync start', async () => {
    const full = loadImagesUI(true, { totalBytes: 1000, estimate: { quota: 1000, usage: 900 } });
    full.syncNow();
    await flush();
    expect(full.label()).toContain('Not enough storage');
    expect(images(full)).toEqual([]);
    const fits = loadImagesUI(true, { totalBytes: 10, estimate: { quota: 1000, usage: 0 } });
    fits.syncNow();
    await flush();
    expect(images(fits)).toEqual(['sync_now']);
});

test('pause counts pause', () => {
    const u = loadImagesUI();
    u.pause();
    expect(images(u)).toEqual(['pause']);
});

test('with no BAN the image controls still work', async () => {
    const u = loadImagesUI(false);
    expect(() => { u.change(); u.syncNow(); u.pause(); }).not.toThrow();
});

// --- Registry ---

test('the offline names hold the values the scripts send', () => {
    expect(registry['ui.offline.sync'].enum).toEqual(['ok', 'fail']);
    expect(registry['ui.offline.sync'].scopes).toEqual(['catalog', 'prices', 'images']);
    expect(registry['ui.offline.sw'].enum).toEqual(['install_ok', 'install_fail']);
    expect(registry['ui.offline.images'].enum).toEqual(['sync_now', 'pause', 'editions_changed']);
    expect(registry['ui.offline.page'].enum).toEqual(['sort', 'tab', 'condition', 'kind']);
    expect(registry['ui.offline.search'].values).toBe('ValueNone');
    expect(registry['ui.offline.failover'].values).toBe('ValueNone');
});
