import { test, expect } from 'bun:test';
import { read, fakeBAN } from './metrics-helpers.js';
import { registry } from './track-registry.js';

const source = read('js/settings-changes.js');
const window = {};
new Function('window', source)(window);
const { SettingsChanges } = window;

const cases = [
    ['an enum reports its new value',
        { SearchDefaultSort: 'chrono' }, { SearchDefaultSort: 'retail' },
        [{ name: 'SearchDefaultSort', value: 'retail' }]],
    ['an enum emptied reports cleared',
        { UploadSorting: 'highprice' }, { UploadSorting: '' },
        [{ name: 'UploadSorting', value: 'cleared' }]],
    ['a packed cookie reports each flag that flipped and nothing else',
        { SearchMiscOpts: 'noSussy,hidePromos,' }, { SearchMiscOpts: 'noSussy,skipEmpty,' },
        [{ name: 'SearchMiscOpts.hidePromos', value: 'off' }, { name: 'SearchMiscOpts.skipEmpty', value: 'on' }]],
    ['a never-set optimizer cookie is its defaults',
        { UploadOptimizerOpts: '' }, { UploadOptimizerOpts: 'lowval,lowvalabs,minmargin,customperc,' },
        []],
    ['a never-set optimizer cookie saved with every box off turns the four defaults off',
        { UploadOptimizerOpts: null }, { UploadOptimizerOpts: ',' },
        [{ name: 'UploadOptimizerOpts.customperc', value: 'off' }, { name: 'UploadOptimizerOpts.lowval', value: 'off' },
            { name: 'UploadOptimizerOpts.lowvalabs', value: 'off' }, { name: 'UploadOptimizerOpts.minmargin', value: 'off' }]],
    ['a store list is a set: order and a trailing comma are not a change',
        { SearchSellersList: 'CK,TCG' }, { SearchSellersList: 'TCG,CK,' },
        []],
    ['a list reports set, never its stores',
        { SearchSellersList: '' }, { SearchSellersList: 'CK,' },
        [{ name: 'SearchSellersList', value: 'set' }]],
    ['a list emptied reports cleared',
        { NewspaperList: 'LEA,LEB' }, { NewspaperList: '' },
        [{ name: 'NewspaperList', value: 'cleared' }]],
    ['a number reports set',
        { UploadPercSpread: '60' }, { UploadPercSpread: '75' },
        [{ name: 'UploadPercSpread', value: 'set' }]],
    ['the store factors binding is reported under its cookie',
        { StoreFactors: '{}' }, { StoreFactors: '{"CK":{"d":5}}' },
        [{ name: 'SearchStoreFactors', value: 'set' }]],
    ['the drawer writing a default into an unset cookie is not a change; stores over the price default is',
        { SearchDefaultTab: null, SearchDefaultView: null, MobileSearchLayout: null, SearchListingPriority: null, SearchSealedContents: null },
        { SearchDefaultTab: 'sellers', SearchDefaultView: 'NM', MobileSearchLayout: 'expanded', SearchListingPriority: 'stores', SearchSealedContents: 'contents' },
        [{ name: 'SearchListingPriority', value: 'stores' }]],
    ['an enum set to its default from unset, or emptied back to it, is not a change',
        { SearchDefaultSort: '', SearchListingPriority: 'prices' }, { SearchDefaultSort: 'chrono', SearchListingPriority: '' },
        []],
    ['a name on one side only is read as empty',
        {}, { UploadMargin: '12', SearchMiscOpts: 'noUpsell,' },
        [{ name: 'SearchMiscOpts.noUpsell', value: 'on' }, { name: 'UploadMargin', value: 'set' }]],
    ['inherited names are no setting and send nothing',
        { constructor: 'a', toString: 'b' }, { constructor: 'a', toString: 'c' },
        []],
    ['a packed token outside the closed flags is never sent',
        { SearchMiscOpts: 'noSussy,bogus words' }, { SearchMiscOpts: 'noSussy,' },
        []],
    ['an enum value outside its words is sent as set',
        { SearchDefaultView: 'NM' }, { SearchDefaultView: 'anything else' },
        [{ name: 'SearchDefaultView', value: 'set' }]],
    ['emptying every store factor is cleared',
        { StoreFactors: '{"CK":{"d":5}}' }, { StoreFactors: '{}' },
        [{ name: 'SearchStoreFactors', value: 'cleared' }]],
];
test.each(cases)('%s', (_, before, after, want) => {
    expect(SettingsChanges.diff(before, after)).toEqual(want);
});

test('every value diff can send is a registered ui.settings.change value', () => {
    const sent = new Set();
    for (const [, before, after] of cases) for (const c of SettingsChanges.diff(before, after)) sent.add(c.value);
    for (const v of sent) expect(registry['ui.settings.change'].enum).toContain(v);
    expect(registry['ui.settings.save'].enum).toEqual(['modal', 'mobile_drawer']);
});

// The settings registry's preferences and the words each may send, read from observability/settings.go.
const closed = {};
for (const m of read('observability/settings.go').matchAll(/^\s*\{Name: "([^"]+)"(.*)$/gm)) {
    if (!/Class: "preference"/.test(m[2])) continue;
    const kind = (m[2].match(/Kind: "([^"]+)"/) || [])[1];
    const words = (m[2].match(/Enum: \[\]string\{([^}]*)\}/) || [])[1];
    closed[m[1]] = kind === 'flag' ? ['on', 'off']
        : ['set', 'cleared'].concat(kind === 'enum' ? [...words.matchAll(/"([^"]*)"/g)].map((w) => w[1]) : []);
}

// Review focus: nothing read from a cookie leaves unless it is a closed registry word.
test('hostile cookie names and values send only closed registry words', () => {
    const hostileNames = ['constructor', 'toString', '__proto__', 'hasOwnProperty', 'valueOf', 'x'.repeat(5000),
        'https://example.com/?q=Black+Lotus', 'Search%44efaultView', 'SearchMiscOpts.noSussy', 'theme'];
    const hostileValues = ['', null, 'x'.repeat(5000), 'https://example.com/a?b=c', 'retail', 'compact', 'buylist',
        'N%4D', 'noSussy%2ChidePromos', 'constructor,toString,__proto__,hasOwnProperty', 'Black Lotus alpha,noSussy',
        '{}', '{"CK":{"d":5}}', 'NM', 'on', 'off'];
    const names = Object.keys(closed).map((n) => n.split('.')[0]).concat(['StoreFactors'], hostileNames)
        .filter((n, i, all) => all.indexOf(n) === i);
    const { BAN, calls } = fakeBAN();
    window.BAN = BAN;
    try {
        for (const name of names) {
            for (const before of hostileValues) {
                for (const after of hostileValues) {
                    const b = JSON.parse('{}');
                    const a = JSON.parse('{}');
                    Object.defineProperty(b, name, { value: before, enumerable: true });
                    Object.defineProperty(a, name, { value: after, enumerable: true });
                    SettingsChanges.report(b, a, 'modal');
                }
            }
        }
    } finally {
        delete window.BAN;
    }
    const changes = calls.filter((c) => c[0] === 'ui.settings.change');
    expect(changes.length).toBeGreaterThan(100);
    for (const [, value, scope] of changes) {
        expect(Object.prototype.hasOwnProperty.call(closed, scope)).toBe(true);
        expect(closed[scope]).toContain(value);
    }
    expect(changes.some((c) => c[2] === 'SearchDefaultView' && c[1] === 'retail')).toBe(false);
    for (const c of calls) expect(['ui.settings.change', 'ui.settings.save']).toContain(c[0]);
});

test('parse splits at the first equals sign', () => {
    expect(SettingsChanges.parse(['StoreFactors={"a":"b=c"}', 'UploadSorting='])).toEqual({ StoreFactors: '{"a":"b=c"}', UploadSorting: '' });
});

test('report sends each change with the setting in scope, then one save', () => {
    const { BAN, calls } = fakeBAN();
    window.BAN = BAN;
    SettingsChanges.report({ SearchDefaultSort: 'chrono' }, { SearchDefaultSort: 'alpha' }, 'modal');
    delete window.BAN;
    expect(calls).toEqual([['ui.settings.change', 'alpha', 'SearchDefaultSort'], ['ui.settings.save', 'modal', undefined]]);
});

test('a save that changed nothing still counts the save', () => {
    const { BAN, calls } = fakeBAN();
    window.BAN = BAN;
    SettingsChanges.report({ SearchDefaultSort: 'chrono' }, { SearchDefaultSort: 'chrono' }, 'mobile_drawer');
    delete window.BAN;
    expect(calls).toEqual([['ui.settings.save', 'mobile_drawer', undefined]]);
});

test('report does nothing without window.BAN', () => {
    expect(() => SettingsChanges.report({ SearchDefaultSort: 'chrono' }, { SearchDefaultSort: 'alpha' }, 'modal')).not.toThrow();
});

test('snapshot reads exactly the drawer cookies', () => {
    const asked = [];
    const snap = SettingsChanges.snapshot((name) => { asked.push(name); return name === 'SearchDefaultTab' ? 'buyers' : null; });
    expect(Object.keys(snap)).toEqual(SettingsChanges.DRAWER);
    expect(asked).toEqual(SettingsChanges.DRAWER);
    expect(snap.SearchDefaultTab).toBe('buyers');
});

// runDrawer runs the mobile drawer's inline saveSettings over a cookie jar.
function runDrawer({ jar = {}, listing = true, factors = null, BAN, loaded = true } = {}) {
    const page = read('templates/mobile/search.html');
    const start = page.indexOf('function saveSettings()');
    const fn = page.slice(start, page.indexOf('\n}\n', start) + 2);
    const cookies = new Map(Object.entries(jar));
    const win = {};
    if (loaded) win.SettingsChanges = SettingsChanges;
    if (BAN) win.BAN = BAN;
    if (factors) win.StoreFactors = { saveEditor: () => cookies.set('SearchStoreFactors', factors) };
    const document = {
        querySelector: () => null,
        querySelectorAll: () => [],
        getElementById: (id) => (id === 'm-set-sellers-priority' || id === 'm-set-vendors-priority' ? { value: '' }
            : id === 'm-set-listing-priority' ? (listing ? {} : null)
                : id === 'm-set-store-factors' ? (factors ? {} : null) : null),
    };
    // The shared file reads window.BAN from the window it was loaded into.
    window.BAN = win.BAN;
    try {
        new Function('window', 'document', 'setCookie', 'getCookie', 'localStorage', 'closeSettings', 'SettingsChanges', fn + '\nsaveSettings();')(
            win, document, (k, v) => cookies.set(k, v), (k) => (cookies.has(k) ? cookies.get(k) : null),
            { setItem() {} }, () => {}, win.SettingsChanges);
    } finally {
        delete window.BAN;
    }
    return cookies;
}

// Review focus: a reader's first save writes a default into every unset cookie.
test("the drawer's first save reports only the listing priority it writes off its default", () => {
    const { BAN, calls } = fakeBAN();
    runDrawer({ BAN });
    expect(calls).toEqual([['ui.settings.change', 'stores', 'SearchListingPriority'], ['ui.settings.save', 'mobile_drawer', undefined]]);
});

test('the drawer reads the store factors after their save wrote them', () => {
    const { BAN, calls } = fakeBAN();
    runDrawer({ BAN, listing: false, factors: '{"CK":{"d":5}}' });
    expect(calls).toEqual([['ui.settings.change', 'set', 'SearchStoreFactors'], ['ui.settings.save', 'mobile_drawer', undefined]]);
});

test('a drawer save over unknown cookie text sends no scope or value outside the registry', () => {
    const { BAN, calls } = fakeBAN();
    runDrawer({ BAN, jar: { SearchMiscOpts: 'noSussy,Black Lotus alpha', SearchDefaultView: 'my secret text', SearchDefaultTab: 'https://example.com/' } });
    expect(calls.length).toBeGreaterThan(1);
    for (const [name, value, scope] of calls) {
        if (name !== 'ui.settings.change') continue;
        expect(Object.prototype.hasOwnProperty.call(closed, scope)).toBe(true);
        expect(closed[scope]).toContain(value);
    }
    expect(calls).toContainEqual(['ui.settings.change', 'off', 'SearchMiscOpts.noSussy']);
    expect(calls).toContainEqual(['ui.settings.change', 'NM', 'SearchDefaultView']);
});

test('the drawer saves with no SettingsChanges loaded, and with no window.BAN', () => {
    const { BAN, calls } = fakeBAN();
    expect(runDrawer({ BAN, loaded: false }).get('SearchDefaultTab')).toBe('sellers');
    expect(calls).toEqual([]);
    expect(runDrawer().get('SearchListingPriority')).toBe('stores');
});

// modal runs settings.js with one store factors binding, the body loaded and the save button wired.
// Quiet marks chained promises handled; the modal leaves a failed save unhandled.
class Quiet extends Promise {
    then(a, b) {
        const p = super.then(a, b);
        Promise.prototype.then.call(p, null, () => {});
        return p;
    }
}

async function modal(BAN, { saveResult = () => undefined, changes = SettingsChanges, reloads = [], quiet = false } = {}) {
    let factors = '{}';
    const el = (found = {}) => {
        const e = {
            dataset: {}, hidden: true, innerHTML: '', handlers: {},
            classList: { add() {}, remove() {}, contains: () => false, toggle() {} },
            querySelector: (sel) => found[sel] || null,
            querySelectorAll: () => [],
            addEventListener(type, fn) { e.handlers[type] = fn; },
            focus() {},
        };
        return e;
    };
    const saveBtn = el();
    const body = el();
    const modalEl = el({ '[data-role="save"]': saveBtn, '.settings-modal-body': body });
    const document = {
        readyState: 'complete', activeElement: { tagName: 'BODY' }, body: el(),
        getElementById: (id) => ({ 'settings-modal': modalEl, 'settings-backdrop': el(), 'settings-store-factors': {} }[id] || null),
        querySelector: () => null,
        querySelectorAll: () => [],
        addEventListener() {},
    };
    const win = {
        location: { search: '', pathname: '/search', hash: '', reload() { reloads.push(1); } },
        history: { replaceState() {} },
        SettingsChanges: changes,
        StoreFactors: { binding: () => ({ load() {}, save: saveResult, serialize: () => 'StoreFactors=' + factors }) },
    };
    if (BAN) win.BAN = BAN;
    window.BAN = win.BAN;
    const noop = () => {};
    const fetch = () => Promise.resolve({ ok: true, text: () => Promise.resolve('') });
    new Function('window', 'document', 'sessionStorage', 'getCookie', 'setCookie', 'writeCookie', 'cookiePath', 'routePath', 'fetch', 'setTimeout', 'Promise',
        read('js/settings.js'))(win, document, { getItem: () => null, setItem() {} }, () => null, noop, noop, () => '/', () => '/search', fetch, noop,
        quiet ? Quiet : Promise);
    win.openSettings();
    // The body fetch and its follow-ups settle by microtasks alone.
    for (let i = 0; i < 8; i++) await Promise.resolve();
    // The save's promise settles by microtasks alone.
    const save = async () => {
        saveBtn.handlers.click();
        for (let i = 0; i < 8; i++) await Promise.resolve();
    };
    return { save, set: (v) => { factors = v; } };
}

test('a modal save reports what changed since the body loaded, then the save', async () => {
    const { BAN, calls } = fakeBAN();
    try {
        const m = await modal(BAN);
        m.set('{"CK":{"d":5}}');
        await m.save();
    } finally {
        delete window.BAN;
    }
    expect(calls).toEqual([['ui.settings.change', 'set', 'SearchStoreFactors'], ['ui.settings.save', 'modal', undefined]]);
});

test('a modal save that fails counts nothing', async () => {
    const { BAN, calls } = fakeBAN();
    const reloads = [];
    try {
        const m = await modal(BAN, { saveResult: () => Promise.reject(new Error('refused')), reloads, quiet: true });
        m.set('{"CK":{"d":5}}');
        await m.save();
    } finally {
        delete window.BAN;
    }
    expect(calls).toEqual([]);
    expect(reloads).toEqual([]);
});

test('a report that throws still lets the modal save reload', async () => {
    const { BAN } = fakeBAN();
    const reloads = [];
    const changes = { parse: SettingsChanges.parse, report() { throw new Error('boom'); } };
    try {
        const m = await modal(BAN, { changes, reloads });
        m.set('{"CK":{"d":5}}');
        await m.save();
    } finally {
        delete window.BAN;
    }
    expect(reloads).toEqual([1]);
});
