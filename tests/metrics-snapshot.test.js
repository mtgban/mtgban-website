import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { loadMetrics, settle } from './metrics-loader.js';

const TODAY = 20000; // the loader's day; the mark stores whole days

const REGISTRY = [
    { name: 'SearchDefaultSort', storage: 'cookie', path: 'root', kind: 'enum', enum: ['chrono', 'hybrid', 'alpha'], default: 'chrono' },
    { name: 'SearchMiscOpts.noSussy', storage: 'cookie', path: 'root', kind: 'flag', default: 'off' },
    { name: 'SearchMiscOpts.skipEmpty', storage: 'cookie', path: 'root', kind: 'flag', default: 'off' },
    { name: 'SearchSellersList', storage: 'cookie', path: 'root', kind: 'list', default: '' },
    { name: 'SearchStoreFactors', storage: 'both', path: 'root', kind: 'blob', default: '' },
    { name: 'ArbitFilters', storage: 'both', path: 'root', kind: 'query', default: '' },
    { name: 'chartDateRange', storage: 'both', path: 'root', kind: 'number', default: '180' },
    { name: 'theme', storage: 'local', path: 'root', kind: 'enum', enum: ['light', 'dark', 'system'], default: 'system' },
    { name: 'chartSpanGaps', storage: 'local', path: 'root', kind: 'flag', default: 'on' },
    { name: 'chartCheckpointTypes', storage: 'local', path: 'root', kind: 'list', default: 'ban,release,reprint' },
    { name: 'mtgban_upload_presets', storage: 'local', path: 'root', kind: 'blob', default: '' },
    { name: 'mtgban_backpack_sort', storage: 'local', path: 'root', kind: 'blob', default: '{"by":"added","dir":"desc"}' },
    { name: 'UploadOptimizerOpts.lowval', storage: 'cookie', path: 'upload', kind: 'flag', default: 'on' },
    { name: 'UploadOptimizerOpts.highval', storage: 'cookie', path: 'upload', kind: 'flag', default: 'off' },
    { name: 'UploadPercSpread', storage: 'cookie', path: 'upload', kind: 'number', default: '60' },
    { name: 'UploadSorting', storage: 'cookie', path: 'upload', kind: 'enum', enum: ['setchrono', 'highprice'], default: '' },
    { name: 'gdocURL', storage: 'cookie', path: 'upload', kind: 'blob', default: '' },
    { name: 'uploadMode', storage: 'both', path: 'upload', kind: 'flag', default: 'off' },
    { name: 'NewspaperList', storage: 'cookie', path: 'newspaper', kind: 'list', default: '' },
];

// loadSnapshot runs metrics.js on the loader's fakes with a page of settings.
function loadSnapshot(opts = {}) {
    const gets = [];
    // The loader's own fetch parses a POST body; this one also answers the registry GET.
    const fetch = (url, o) => {
        if (o && o.body) return Promise.resolve({ status: 204 });
        gets.push(url);
        if (opts.offline) return Promise.reject(new TypeError('no network'));
        if (opts.status) return Promise.resolve({ ok: false, status: opts.status, json: async () => ({}) });
        return Promise.resolve({ ok: true, status: 200, json: async () => opts.body || ({ settings: opts.registry || REGISTRY }) });
    };
    const globals = { fetch, location: { pathname: opts.pathname || '/' } };
    if (opts.writeThrows) {
        globals.localStorage = { getItem: () => null, setItem() { throw new Error('full'); }, removeItem() {} };
    }
    if (opts.localStorage) globals.localStorage = opts.localStorage;
    const p = loadMetrics({
        cfg: { on: opts.on !== false, page: '', build: 'b1' }, // no page label: no ui.load among the counts
        dnt: opts.dnt, gpc: opts.gpc, stored: opts.local || {}, day: opts.day || TODAY,
        storage: opts.storageThrows ? 'throws' : 'ok', globals, win: opts.win, docProps: opts.docProps,
    });
    p.document.cookie = opts.cookie || '';
    p.snapshot = p.window.BAN.snapshot;
    p.gets = gets;
    // counted flushes the buffer the way a hidden page does and returns what left.
    p.counted = () => { p.hide('pagehide'); return p.beacons.flatMap((b) => b.body); };
    // zero runs the zero-delay timers queued so far.
    p.zero = () => { for (const t of p.live().filter((t) => t.ms === 0)) { t.live = false; t.fn(); } };
    // load fires the window's load event and the zero-delay timer it queued.
    p.load = () => { p.emit('load'); p.zero(); };
    return p;
}

const shared = loadSnapshot().snapshot;

// val looks the entry up in REGISTRY and reads it over a cookie string and a local store.
function val(name, { cookie = '', local = {} } = {}) {
    const entry = REGISTRY.find((s) => s.name === name);
    if (!entry) throw new Error('no fixture entry ' + name);
    return valOf(entry, { cookie, local });
}

function valOf(entry, { cookie = '', local = {} } = {}) {
    const jar = shared.cookies(cookie);
    const read = { cookie: (n) => jar[n] || '', local: (k) => (k in local ? local[k] : null) };
    return shared.value(entry, read);
}

test('scopes: root everywhere, plus the page whose path the cookies sit at', () => {
    const { snapshot } = loadSnapshot();
    expect(snapshot.scopes('/')).toEqual(['root']);
    expect(snapshot.scopes('/search')).toEqual(['root']);
    expect(snapshot.scopes('/sealed')).toEqual(['root']);
    expect(snapshot.scopes('/upload')).toEqual(['root', 'upload']);
    expect(snapshot.scopes('/upload/handoff')).toEqual(['root', 'upload']);
    expect(snapshot.scopes('/newspaper')).toEqual(['root', 'newspaper']);
    expect(snapshot.scopes('/uploads')).toEqual(['root']);
    expect(snapshot.scopes('/root')).toEqual(['root']);
});

test('the page scopes are the registry\'s setting paths', () => {
    const src = readFileSync(new URL('../observability/settings.go', import.meta.url), 'utf8');
    const m = src.match(/var SettingPaths = \[\]string\{([^}]*)\}/);
    const paths = [...(m ? m[1] : '').matchAll(/"([^"]*)"/g)].map((x) => x[1]);
    expect(paths[0]).toBe('root');
    expect(paths.length).toBe(7);
    for (const p of paths.slice(1)) expect(shared.scopes('/' + p)).toEqual(['root', p]);
});

test('cookies: first copy wins, quotes come off, values are decoded', () => {
    const { snapshot } = loadSnapshot();
    const jar = snapshot.cookies('UploadSorting=highprice; a=1; UploadSorting=setchrono; q="CK|TCG Low"; f=f%3D1%26minsell%3D2; bad=%E0%A4%A');
    expect(jar.UploadSorting).toBe('highprice');
    expect(jar.q).toBe('CK|TCG Low');
    expect(jar.f).toBe('f=1&minsell=2');
    expect(jar.bad).toBe('%E0%A4%A');
});

test('an enum is sent as its registry value, and only off its default', () => {
    expect(val('SearchDefaultSort', { cookie: '' })).toBe('');
    expect(val('SearchDefaultSort', { cookie: 'SearchDefaultSort=chrono' })).toBe('');   // saved, but the default
    expect(val('SearchDefaultSort', { cookie: 'SearchDefaultSort=alpha' })).toBe('alpha');
    expect(val('SearchDefaultSort', { cookie: 'SearchDefaultSort=velocity' })).toBe(''); // not a value it has
    expect(val('theme', { local: { theme: 'dark' } })).toBe('dark');
    expect(val('theme', { local: { theme: 'system' } })).toBe('');
    expect(val('UploadSorting', { cookie: 'UploadSorting=highprice' })).toBe('highprice');
});

test('a packed flag cookie is split into its flags', () => {
    const cookie = 'SearchMiscOpts=noSussy,hidePromos,';
    expect(val('SearchMiscOpts.noSussy', { cookie })).toBe('on');
    expect(val('SearchMiscOpts.skipEmpty', { cookie })).toBe('');
    expect(val('SearchMiscOpts.noSussy', { cookie: '' })).toBe('');
});

test('a packed flag that defaults on reports off, and an unset cookie reports nothing', () => {
    expect(val('UploadOptimizerOpts.lowval', { cookie: '' })).toBe('');                     // never saved: defaults apply
    expect(val('UploadOptimizerOpts.lowval', { cookie: 'UploadOptimizerOpts=lowval,lowvalabs,' })).toBe('');
    expect(val('UploadOptimizerOpts.lowval', { cookie: 'UploadOptimizerOpts=highval,' })).toBe('off');
    expect(val('UploadOptimizerOpts.highval', { cookie: 'UploadOptimizerOpts=highval,' })).toBe('on');
    expect(val('UploadOptimizerOpts.lowval', { cookie: 'UploadOptimizerOpts=,' })).toBe('off'); // saved with nothing ticked
});

test('a flag of its own reads true-like values, and a default-on flag reports off', () => {
    expect(val('uploadMode', { cookie: 'uploadMode=true' })).toBe('on');
    expect(val('uploadMode', { cookie: 'uploadMode=false' })).toBe('');
    expect(val('uploadMode', { cookie: '', local: { uploadMode: 'buylist' } })).toBe('');   // the local copy speaks other words
    expect(val('uploadMode', { cookie: '', local: { uploadMode: 'true' } })).toBe('');      // and is never read
    expect(val('chartSpanGaps', { local: {} })).toBe('');
    expect(val('chartSpanGaps', { local: { chartSpanGaps: 'true' } })).toBe('');
    expect(val('chartSpanGaps', { local: { chartSpanGaps: 'false' } })).toBe('off');
});

test('an empty cookie or stored value is the default', () => {
    // The upload presets save these three as '' every time; the mobile drawer saves SearchMiscOpts as ''.
    const presets = [
        { name: 'UploadAltPrice', storage: 'cookie', path: 'upload', kind: 'blob', default: 'TCGLow' },
        { name: 'UploadPriceSource', storage: 'cookie', path: 'upload', kind: 'enum', enum: ['credit', 'marketCredit'], default: '' },
        { name: 'UploadSorting', storage: 'cookie', path: 'upload', kind: 'enum', enum: ['setchrono', 'highprice'], default: '' },
    ];
    const cookie = 'UploadAltPrice=; UploadPriceSource=; UploadSorting=; SearchMiscOpts=';
    for (const e of presets) expect(valOf(e, { cookie })).toBe('');
    expect(valOf(presets[0], { cookie: 'UploadAltPrice=TCGLow' })).toBe('');
    expect(valOf(presets[0], { cookie: 'UploadAltPrice=TCGMarket' })).toBe('set');
    for (const n of ['SearchMiscOpts.noSussy', 'SearchMiscOpts.skipEmpty']) expect(val(n, { cookie })).toBe('');
    for (const e of REGISTRY) {
        const empty = { cookie: e.name.split('.')[0] + '=', local: { [e.name]: '' } };
        expect([e.name, valOf(e, empty)]).toEqual([e.name, '']);
    }
});

test('a number is set only when it differs from its default as a number', () => {
    expect(val('UploadPercSpread', { cookie: 'UploadPercSpread=60' })).toBe('');
    expect(val('UploadPercSpread', { cookie: 'UploadPercSpread=60.0' })).toBe('');
    expect(val('UploadPercSpread', { cookie: 'UploadPercSpread=75' })).toBe('set');
    expect(val('UploadPercSpread', { cookie: 'UploadPercSpread=abc' })).toBe('');
    expect(val('chartDateRange', { cookie: '', local: { chartDateRange: '365' } })).toBe('set'); // no cookie of that name: the local copy
    expect(val('chartDateRange', { cookie: 'SearchChartRange=365', local: {} })).toBe('');       // the mirror is never read
});

test('a list is set when it holds something that is not its default', () => {
    expect(val('SearchSellersList', { cookie: 'SearchSellersList=CK,TCG,' })).toBe('set');
    expect(val('SearchSellersList', { cookie: 'SearchSellersList=,' })).toBe('');
    expect(val('chartCheckpointTypes', { local: { chartCheckpointTypes: '["reprint","ban","release"]' } })).toBe('');
    expect(val('chartCheckpointTypes', { local: { chartCheckpointTypes: '["ban"]' } })).toBe('set');
    expect(val('chartCheckpointTypes', { local: { chartCheckpointTypes: '[]' } })).toBe('set'); // every marker hidden
    expect(val('chartCheckpointTypes', { local: {} })).toBe('');
});

test('free text is reported as set and nothing more', () => {
    const cookie = 'gdocURL=https%3A%2F%2Fdocs.google.com%2Fspreadsheets%2Fd%2Fsecret';
    expect(val('gdocURL', { cookie })).toBe('set');
    expect(val('gdocURL', { cookie: '' })).toBe('');
});

test('a blob is set when it holds something live', () => {
    expect(val('mtgban_upload_presets', { local: { mtgban_upload_presets: '[]' } })).toBe('');
    expect(val('mtgban_upload_presets', { local: { mtgban_upload_presets: '[{"id":"a","del":true,"savedAt":1}]' } })).toBe('');
    expect(val('mtgban_upload_presets', { local: { mtgban_upload_presets: '[{"id":"a","name":"Mine"}]' } })).toBe('set');
    expect(val('mtgban_upload_presets', { local: { mtgban_upload_presets: 'null' } })).toBe('');
    expect(val('mtgban_upload_presets', { local: { mtgban_upload_presets: '{}' } })).toBe('');
    expect(val('mtgban_backpack_sort', { local: { mtgban_backpack_sort: '{"by":"added","dir":"desc"}' } })).toBe('');
    expect(val('mtgban_backpack_sort', { local: { mtgban_backpack_sort: '{ "by": "added", "dir": "desc" }' } })).toBe(''); // the default, spaced
    expect(val('mtgban_backpack_sort', { local: { mtgban_backpack_sort: '{"by":"name","dir":"asc"}' } })).toBe('set');
    expect(val('SearchStoreFactors', { cookie: 'SearchStoreFactors=CK:5:', local: { mtgban_store_factors: '{}' } })).toBe('set');
    expect(val('SearchStoreFactors', { cookie: '', local: { mtgban_store_factors: '{}' } })).toBe('');
});

test('saved filters are set only when they hold a filter', () => {
    expect(val('ArbitFilters', { cookie: 'ArbitFilters=' + encodeURIComponent('f=1&t=1731300000000') })).toBe('');  // a reset
    expect(val('ArbitFilters', { cookie: 'ArbitFilters=' + encodeURIComponent('f=1&minsell=2&t=1731300000000') })).toBe('set');
});

test('entries: a reader row per scope, then that scope\'s settings off default', () => {
    const { snapshot } = loadSnapshot();
    const jar = snapshot.cookies('SearchDefaultSort=alpha; UploadSorting=highprice; gdocURL=https%3A%2F%2Fx.test%2Fs; NewspaperList=LEA,');
    const read = { cookie: (n) => jar[n] || '', local: () => null };
    expect(snapshot.entries(REGISTRY, read, ['root', 'upload'])).toEqual([
        { n: 'state.reader', s: 'root', v: '' },
        { n: 'state.set', s: 'SearchDefaultSort', v: 'alpha' },
        { n: 'state.reader', s: 'upload', v: '' },
        { n: 'state.set', s: 'UploadSorting', v: 'highprice' },
        { n: 'state.set', s: 'gdocURL', v: 'set' },
    ]);
    // NewspaperList is another page's: unreadable in fact, and skipped by rule
    expect(snapshot.entries(REGISTRY, read, ['root']).some((e) => e.s === 'UploadSorting')).toBe(false);
});

test('nothing a reader typed or picked from data is ever in an entry', () => {
    const { snapshot } = loadSnapshot();
    const cookie = 'SearchSellersList=SecretStore,; gdocURL=https%3A%2F%2Fprivate.test%2Fsheet; UploadPercSpread=73; SearchDefaultSort=<script>';
    const jar = snapshot.cookies(cookie);
    const read = { cookie: (n) => jar[n] || '', local: (k) => ({ mtgban_upload_presets: '[{"id":"a","name":"My private preset"}]' }[k] || null) };
    const sent = JSON.stringify(snapshot.entries(REGISTRY, read, ['root', 'upload']));
    for (const secret of ['SecretStore', 'private.test', '73', 'My private preset', 'script']) {
        expect(sent).not.toContain(secret);
    }
    const allowed = new Set(['', 'on', 'off', 'set', ...REGISTRY.flatMap((s) => s.enum || [])]);
    for (const e of JSON.parse(sent)) expect(allowed.has(e.v)).toBe(true);
});

test('run counts each scope once a day, through the buffer', async () => {
    const p = loadSnapshot({ pathname: '/upload', cookie: 'UploadSorting=highprice' });
    await p.snapshot.run();
    expect(p.gets).toEqual(['/api/metrics/settings.json?hash=b1']);
    expect(p.counted()).toEqual([
        { n: 'state.reader', s: 'root', c: 1 },
        { n: 'state.reader', s: 'upload', c: 1 },
        { n: 'state.set', s: 'UploadSorting', v: 'highprice', c: 1 },
    ]);
    expect(JSON.parse(p.m.mtgban_metrics_snap)).toEqual({ root: TODAY, upload: TODAY });
});

test('run on a day already sent fetches nothing and counts nothing', async () => {
    const p = loadSnapshot({ pathname: '/upload', local: { mtgban_metrics_snap: JSON.stringify({ root: TODAY, upload: TODAY }) } });
    await p.snapshot.run();
    expect(p.gets.length).toBe(0);
    expect(p.counted()).toEqual([]);
});

test('a page load on a day already sent costs one localStorage read', async () => {
    const calls = [];
    const store = { mtgban_metrics_snap: JSON.stringify({ root: TODAY }) };
    const localStorage = {
        getItem: (k) => { calls.push('get ' + k); return k in store ? store[k] : null; },
        setItem: (k) => { calls.push('set ' + k); },
        removeItem: (k) => { calls.push('remove ' + k); },
    };
    const p = loadSnapshot({ pathname: '/', localStorage });
    calls.length = 0; // what the script read at start-up is not the snapshot's
    p.load();
    await settle();
    expect(calls).toEqual(['get mtgban_metrics_snap']);
    expect(p.gets.length).toBe(0);
    expect(p.live().length).toBe(0);
});

test('a scope first seen today is sent without repeating the one already sent', async () => {
    const p = loadSnapshot({ pathname: '/upload', local: { mtgban_metrics_snap: JSON.stringify({ root: TODAY }) } });
    await p.snapshot.run();
    expect(p.counted()).toEqual([{ n: 'state.reader', s: 'upload', c: 1 }]);
    expect(JSON.parse(p.m.mtgban_metrics_snap)).toEqual({ root: TODAY, upload: TODAY });
});

test('yesterday\'s mark is due again, by the UTC day', async () => {
    const p = loadSnapshot({ pathname: '/', local: { mtgban_metrics_snap: JSON.stringify({ root: TODAY - 1 }) } });
    await p.snapshot.run();
    expect(p.counted()).toEqual([{ n: 'state.reader', s: 'root', c: 1 }]);
    expect(p.snapshot.due({ root: TODAY }, ['root'], TODAY)).toEqual([]);
    expect(p.snapshot.due({ root: TODAY - 1 }, ['root', 'upload'], TODAY)).toEqual(['root', 'upload']);
});

test('the mark keeps only the path scopes', async () => {
    const p = loadSnapshot({ pathname: '/', local: { mtgban_metrics_snap: JSON.stringify({ upload: TODAY - 2, junk: 'x', arbit: 'y' }) } });
    await p.snapshot.run();
    expect(JSON.parse(p.m.mtgban_metrics_snap)).toEqual({ root: TODAY, upload: TODAY - 2 });
});

test('a garbled mark reads as never sent', async () => {
    for (const mark of ['not json', '[1,2]', '7', 'null']) {
        const p = loadSnapshot({ pathname: '/', local: { mtgban_metrics_snap: mark } });
        await p.snapshot.run();
        expect(p.counted().length).toBe(1);
    }
});

test('a failed registry fetch counts nothing and leaves the mark for the next load', async () => {
    for (const opts of [{ offline: true }, { status: 503 }, { body: { nope: [] } }]) {
        const p = loadSnapshot({ pathname: '/', ...opts });
        await p.snapshot.run();
        expect(p.counted()).toEqual([]);
        expect(p.m.mtgban_metrics_snap).toBeUndefined();
    }
});

test('a browser that cannot keep the mark counts nothing', async () => {
    const blocked = loadSnapshot({ pathname: '/', storageThrows: true });
    await blocked.snapshot.run();
    expect(blocked.gets.length).toBe(0);
    expect(blocked.counted()).toEqual([]);

    const full = loadSnapshot({ pathname: '/', writeThrows: true });
    await full.snapshot.run();
    expect(full.counted()).toEqual([]);
});

test('two calls make one fetch and one snapshot', async () => {
    const p = loadSnapshot({ pathname: '/' });
    await Promise.all([p.snapshot.run(), p.snapshot.run()]);
    expect(p.gets.length).toBe(1);
    expect(p.counted().length).toBe(1);
});

test('a snapshot over fifty entries leaves whole, in two posts', async () => {
    const registry = [];
    for (let i = 0; i < 60; i++) registry.push({ name: 'Flag' + i, storage: 'local', path: 'root', kind: 'flag', default: 'off' });
    const local = {};
    for (const s of registry) local[s.name] = 'true';
    const p = loadSnapshot({ pathname: '/', registry, local });
    await p.snapshot.run();
    const sent = p.counted();
    expect(p.beacons.length).toBe(2);
    expect(sent.length).toBe(61);
    expect(sent.filter((e) => e.n === 'state.set').length).toBe(60);
});

test('the page load starts one snapshot', () => {
    const p = loadSnapshot({ pathname: '/' });
    expect(p.gets.length).toBe(0);
    p.load();
    p.emit('load');
    p.zero();
    expect(p.gets.length).toBe(1);
});

test('a prerendered page waits until it is shown', () => {
    const p = loadSnapshot({ pathname: '/', docProps: { prerendering: true } });
    p.load();
    expect(p.gets.length).toBe(0);
    p.emit('prerenderingchange');
    p.zero();
    expect(p.gets.length).toBe(1);
});

test('a page inside a frame sends no snapshot', () => {
    const p = loadSnapshot({ pathname: '/', win: { top: {} } });
    expect(p.win.load).toBeUndefined();
    p.load();
    expect(p.gets.length).toBe(0);
});

test('with metrics off or an opt-out the script never asks for the registry and keeps no mark', () => {
    for (const opts of [{ on: false }, { dnt: '1' }, { gpc: true }]) {
        const p = loadSnapshot({ pathname: '/', local: { mtgban_metrics_snap: JSON.stringify({ root: TODAY - 1 }) }, ...opts });
        expect(p.window.BAN.snapshot).toBeUndefined();
        expect(p.win.load).toBeUndefined();
        expect(p.gets.length).toBe(0);
        expect(p.writes).not.toContain('mtgban_metrics_snap');
        expect(p.m.mtgban_metrics_snap).toBeUndefined(); // an opt-out clears the mark left before it
        expect(p.beacons).toEqual([]);
    }
});

test('an opt-out that arrives while the registry loads keeps no mark and sends nothing', async () => {
    const p = loadSnapshot({ pathname: '/' });
    const done = p.snapshot.run();
    p.navigator.globalPrivacyControl = true;
    await done;
    expect(p.gets.length).toBe(1);
    expect(p.writes).not.toContain('mtgban_metrics_snap');
    expect(p.counted()).toEqual([]);
});
