import { test, expect } from 'bun:test';
import { read, tagsWith, expectTrack, fakeBAN } from './metrics-helpers.js';
import { palette } from './palette-harness.js';

const desktop = read('templates/partials/navbar.html');
const mobile = read('templates/mobile/partials/navbar.html');
const files = { desktop, mobile };

test.each([
    ['desktop', 'class="nav2-brand"', 'ui.nav.link', 'brand'],
    ['mobile', 'class="m-nav-home"', 'ui.nav.link', 'brand'],
    ['desktop', 'data-util="account"', 'ui.nav.link', 'account'],
    ['desktop', 'data-util="guide"', 'ui.nav.link', 'guide'],
    ['desktop', 'title="Patreon"', 'ui.nav.link', 'patreon'],
    ['desktop', 'title="Discord"', 'ui.nav.link', 'discord'],
    ['desktop', 'id="nav-hint"', 'ui.nav.hint', 'dismiss'],
    ['desktop', 'class="ban-nav-hamburger"', 'ui.nav.menu', 'open'],
    ['mobile', 'class="m-nav-hamburger"', 'ui.nav.menu', 'open'],
])('%# the %s tag with %s tracks %s:%s', (file, marker, name, value) => {
    const found = tagsWith(files[file], marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], name, value, undefined);
});

test('every menu link and both external links are tracked, in both templates', () => {
    for (const src of [desktop, mobile]) {
        const links = tagsWith(src, 'class="{{.Class}}"');
        expect(links.length).toBe(1);
        expectTrack(links[0], 'ui.nav.link', 'menu_link', undefined);
        const ext = tagsWith(src, 'href="https://www.patreon.com/mtgban"').filter((t) => !t.includes('tools-quick-btn'));
        expect(ext.length).toBe(1);
        expectTrack(ext[0], 'ui.nav.link', 'patreon', undefined);
        const discord = tagsWith(src, 'href="/discord"').filter((t) => !t.includes('tools-quick-btn'));
        expect(discord.length).toBe(1);
        expectTrack(discord[0], 'ui.nav.link', 'discord', undefined);
    }
});

// The section buttons and tiles are rebuilt by script, so no template carries the attribute.
test('no section button or tile is tracked by attribute', () => {
    const tags = tagsWith(desktop, 'class="nav2-section-btn"').concat(tagsWith(desktop, 'class="tools-tile{{'));
    expect(tags.length).toBeGreaterThan(0);
    for (const tag of tags) {
        expect(tag).not.toContain('data-track');
    }
});

const navbar = read('js/navbar.js');
const toggle = navbar.slice(navbar.indexOf('// ── Tools dropdown open/close'), navbar.indexOf('// ── Drag-and-drop'));
const drag = navbar.slice(navbar.indexOf('(function() {', navbar.indexOf('Drag-and-drop: reorder')), navbar.indexOf('Drag hint tile'));

// element is a stub with classes, attributes, children and one listener a type.
function element(classes = [], attrs = {}) {
    const cls = new Set(classes);
    const el = {
        attrs, listeners: {}, children: [], parentNode: null, inert: false,
        classList: {
            add: (...c) => c.forEach((x) => cls.add(x)), remove: (...c) => c.forEach((x) => cls.delete(x)),
            contains: (c) => cls.has(c), toggle: (c, on) => (on ? cls.add(c) : cls.delete(c)),
        },
        getAttribute: (k) => (k in attrs ? attrs[k] : null),
        setAttribute: (k, v) => { attrs[k] = String(v); },
        addEventListener: (type, fn) => { el.listeners[type] = fn; },
        contains(other) { return other === el || el.children.includes(other); },
        querySelector: () => null,
        querySelectorAll: () => [],
        focus() {},
    };
    return el;
}

const ev = () => ({ preventDefault() {}, stopPropagation() {}, dataTransfer: { setData() {} } });

// loadTools runs the Tools dropdown section; window is the page's window.
function loadTools(window) {
    const btn = element();
    const dd = element();
    const doc = { activeElement: null, getElementById: (id) => ({ 'tools-btn': btn, 'tools-dropdown': dd }[id]), addEventListener() {} };
    new Function('document', 'window', toggle)(doc, window);
    return { btn, dd };
}

// loadSlots runs the drag section over one section button and one tile.
function loadSlots(window) {
    const nav = element(['nav2-sections']);
    const grid = element([], { id: 'tools-grid' });
    const btn = element(['nav2-section-btn'], { 'data-tool': 'search' });
    const tile = element(['tools-tile'], { 'data-tool': 'sets' });
    nav.children.push(btn);
    grid.children.push(tile);
    const document = {
        getElementById: (id) => ({ 'tools-grid': grid }[id] || null),
        querySelector: (sel) => (sel === '.nav2-sections' ? nav : null),
        querySelectorAll: (sel) => (sel.indexOf('.tools-tile, .nav2-section-btn') === 0 ? [tile, btn] : []),
        createElement: () => element(),
    };
    window.__BAN_NAV = [];
    new Function('document', 'localStorage', 'window', 'location', 'setTimeout', drag)(
        document, { getItem: () => null, setItem() {} }, window, { pathname: '/search' }, () => {});
    return { btn, tile };
}

test('opening the Tools menu counts once; closing it does not', () => {
    const { BAN, calls } = fakeBAN();
    const { btn } = loadTools({ BAN });
    btn.listeners.click(ev());
    btn.listeners.click(ev());
    expect(calls).toEqual([['ui.nav.tools', 'open', undefined]]);
});

test('a slot click counts by where it sits; a click that ends a drag does not', () => {
    const { BAN, calls } = fakeBAN();
    const { btn, tile } = loadSlots({ BAN });
    tile.listeners.click(ev());
    btn.listeners.click(ev());
    expect(calls).toEqual([['ui.nav.link', 'tools_tile', undefined], ['ui.nav.link', 'section', undefined]]);
    btn.listeners.dragstart(ev());
    btn.listeners.click(ev());
    expect(calls.filter((c) => c[0] === 'ui.nav.link').length).toBe(2);
});

const nightmode = read('js/nightmode.js');

// loadTheme runs nightmode.js with an OS in light mode and no stored theme.
function loadTheme(window) {
    const store = new Map();
    const button = element(['ban-theme-toggle']);
    window.matchMedia = () => ({ matches: false, addEventListener() {} });
    const document = {
        body: { classList: { toggle() {} }, setAttribute() {} },
        querySelectorAll: (sel) => (sel === '.ban-theme-toggle' ? [button] : []),
    };
    const localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v) };
    new Function('window', 'document', 'localStorage', nightmode)(window, document, localStorage);
    return { button, store };
}

test('the theme toggle reports the pref it lands on', () => {
    const { BAN, calls } = fakeBAN();
    const { button } = loadTheme({ BAN });
    button.listeners.click(ev());
    button.listeners.click(ev());
    button.listeners.click(ev());
    expect(calls).toEqual([['ui.theme', 'dark', 'toggle'], ['ui.theme', 'light', 'toggle'], ['ui.theme', 'system', 'toggle']]);
});

test('BANTheme.cycle makes no call of its own', () => {
    const { BAN, calls } = fakeBAN();
    const window = { BAN };
    loadTheme(window);
    expect(window.BANTheme.cycle()).toBe('dark');
    expect(calls).toEqual([]);
});

const offlineMode = read('js/offline/offline-mode.js');

// loadOffline runs offline-mode.js on a page whose navbar shows the offline switch.
function loadOffline(window) {
    let pref = false;
    const btn = element();
    btn.dataset = {};
    btn.hidden = true;
    const OfflinePrefer = { KEY: 'offline_prefer', get: () => pref, set: (on) => { pref = on; } };
    window.OfflinePrefer = OfflinePrefer;
    window.addEventListener = () => {};
    const document = {
        documentElement: { dataset: { offlineMode: 'true' } },
        readyState: 'complete',
        addEventListener: () => {},
        dispatchEvent: () => {},
        getElementById: (id) => (id === 'nav-offline-toggle' ? btn : null),
    };
    const store = new Map([['offline_mode', 'true']]);
    const localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, v), removeItem: (k) => store.delete(k) };
    const location = { search: '', pathname: '/search', href: '/search' };
    new Function('window', 'document', 'localStorage', 'OfflinePrefer', 'location', offlineMode)(window, document, localStorage, OfflinePrefer, location);
    return { btn, location, pref: () => pref };
}

test('the offline switch reports the state it switches to', () => {
    const { BAN, calls } = fakeBAN();
    const { btn, location } = loadOffline({ BAN });
    expect(btn.hidden).toBe(false);
    btn.listeners.click(ev());
    expect(calls).toEqual([['ui.nav.offline', 'on', undefined]]);
    expect(location.href).toBe('/offline');
});

test('with no window.BAN every one of these still runs', () => {
    const { btn, dd } = loadTools({});
    btn.listeners.click(ev());
    expect(dd.classList.contains('open')).toBe(true);

    const slots = loadSlots({});
    expect(() => slots.tile.listeners.click(ev())).not.toThrow();

    const window = {};
    const theme = loadTheme(window);
    theme.button.listeners.click(ev());
    expect(theme.store.get('theme')).toBe('dark');

    const offline = loadOffline({});
    offline.btn.listeners.click(ev());
    expect(offline.pref()).toBe(true);
    expect(offline.location.href).toBe('/offline');
});

// The palette's Toggle Theme row counts the theme it switched to, scoped to the palette.
test('the palette Toggle Theme row reports the pref it lands on', () => {
    for (const [BANTheme, want] of [[undefined, 'dark'], [{ cycle: () => 'system' }, 'system']]) {
        const p = palette();
        if (BANTheme) p.window.BANTheme = BANTheme;
        p.doc({ key: '/' });
        p.type('toggle theme');
        p.key({ key: 'ArrowDown' }); // past the Search row
        p.key({ key: 'Enter' });
        expect(p.named('ui.theme')).toEqual([[want, 'palette']]);
    }
    const p = palette({ noBAN: true });
    p.doc({ key: '/' });
    p.type('toggle theme');
    p.key({ key: 'ArrowDown' });
    expect(() => p.key({ key: 'Enter' })).not.toThrow();
});
