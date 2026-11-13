import { test, expect } from 'bun:test';
import { read, tagsWith, expectTrack, fakeBAN } from './metrics-helpers.js';

const files = {
    navbar: read('templates/partials/navbar.html'),
    mobileSearch: read('templates/mobile/search.html'),
    offline: read('templates/offline.html'),
    body: read('templates/settings/body.html'),
};

test.each([
    ['navbar', 'id="nav-settings-btn"', 'ui.settings.open', 'gear'],
    ['mobileSearch', 'class="m-search-btn m-settings-btn"', 'ui.settings.open', 'gear'],
    ['offline', 'id="offline-settings-link"', 'ui.settings.open', 'link'],
    ['body', 'class="settings-rail-tab"', 'ui.settings.tab', '{{.}}'],
])('%# the %s tag with %s tracks %s:%s', (file, marker, name, value) => {
    const found = tagsWith(files[file], marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], name, value, undefined);
});

const opens = (calls) => calls.filter((c) => c[0] === 'ui.settings.open');

// loader runs settings-loader.js on a parsed page; activeTag is what holds focus.
function loader({ activeTag = 'BODY', BAN } = {}) {
    const listeners = {};
    const document = {
        currentScript: { src: 'http://localhost/js/settings-loader.js?hash=abc123' },
        activeElement: { tagName: activeTag },
        readyState: 'complete',
        head: { appendChild() {} },
        createElement(tag) { return { tagName: tag, remove() {} }; },
        querySelector: () => null,
        addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
        removeEventListener() {},
    };
    const window = { location: { search: '' }, console: { error() {} } };
    if (BAN) window.BAN = BAN;
    new Function('window', 'document', 'sessionStorage', read('js/settings-loader.js'))(window, document, { getItem: () => null });
    const press = (init) => {
        const e = Object.assign({ preventDefault() {} }, init);
        (listeners.keydown || []).forEach((fn) => fn(e));
    };
    return { window, press };
}

test('Ctrl+Comma through the loader counts hotkey once', () => {
    const { BAN, calls } = fakeBAN();
    loader({ BAN }).press({ ctrlKey: true, key: ',' });
    expect(opens(calls)).toEqual([['ui.settings.open', 'hotkey', undefined]]);
});

test('Ctrl+Comma typed into an input counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    loader({ BAN, activeTag: 'INPUT' }).press({ ctrlKey: true, key: ',' });
    expect(opens(calls)).toEqual([]);
});

test('the loader opening the modal by script counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    loader({ BAN }).window.openSettings('upload');
    expect(opens(calls)).toEqual([]);
});

// stub is an element that answers the queries settings-shell.js and settings.js make of it.
function stub(found = {}) {
    const cls = new Set();
    return {
        dataset: {}, innerHTML: '', hidden: true,
        classList: {
            add: (...c) => c.forEach((x) => cls.add(x)), remove: (...c) => c.forEach((x) => cls.delete(x)),
            contains: (c) => cls.has(c), toggle: (c, on) => (on ? cls.add(c) : cls.delete(c)),
        },
        querySelector: (sel) => found[sel] || null,
        querySelectorAll: (sel) => found['all:' + sel] || [],
        addEventListener() {},
        setAttribute() {},
        focus() {},
    };
}

const shellSrc = read('js/settings-shell.js');

// shell binds settings-shell.js to a modal with one empty pane.
function shell(window) {
    const pane = stub();
    pane.dataset.tab = 'search';
    const rail = stub();
    const body = stub({ '.settings-rail': rail, 'all:.settings-pane': [pane] });
    const modal = stub({ '.settings-modal-body': body });
    new Function('window', 'document', shellSrc)(window, { addEventListener() {}, getElementById: () => null });
    return window.SettingsShell.bind(modal, {});
}

test('a search is counted when it starts, not per keystroke', () => {
    const { BAN, calls } = fakeBAN();
    const s = shell({ BAN });
    s.applySearch('s');
    s.applySearch('so');
    s.applySearch('');
    s.applySearch('x');
    expect(calls.filter((c) => c[0] === 'ui.settings.search')).toEqual([
        ['ui.settings.search', 'used', undefined], ['ui.settings.search', 'used', undefined],
    ]);
});

// settings runs settings.js on a page at search; the modal fetch never answers.
function settings({ search = '?settings=upload', BAN } = {}) {
    const listeners = {};
    const modal = stub({ '.settings-modal-body': stub() });
    const backdrop = stub();
    const document = {
        readyState: 'complete',
        activeElement: { tagName: 'BODY' },
        body: stub(),
        getElementById: (id) => ({ 'settings-modal': modal, 'settings-backdrop': backdrop }[id] || null),
        querySelectorAll: () => [],
        addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
    };
    const window = {
        location: { search, pathname: '/search', hash: '' },
        history: { replaceState() {} },
    };
    if (BAN) window.BAN = BAN;
    const noop = () => {};
    new Function('window', 'document', 'sessionStorage', 'getCookie', 'setCookie', 'writeCookie', 'cookiePath', 'routePath', 'fetch', 'setTimeout',
        read('js/settings.js'))(window, document, { getItem: () => null }, () => null, noop, noop, () => '/', () => '/search',
        () => new Promise(() => {}), (fn) => fn());
    const press = (init) => {
        const e = Object.assign({ preventDefault() {} }, init);
        (listeners.keydown || []).forEach((fn) => fn(e));
    };
    return { window, modal, press };
}

test('a ?settings= link counts param', () => {
    const { BAN, calls } = fakeBAN();
    const { modal } = settings({ BAN });
    expect(modal.classList.contains('open')).toBe(true);
    expect(opens(calls)).toEqual([['ui.settings.open', 'param', undefined]]);
});

test('Ctrl+Comma with the modal closed counts hotkey; with it already open counts no open', () => {
    const { BAN, calls } = fakeBAN();
    const p = settings({ search: '', BAN });
    p.press({ ctrlKey: true, key: ',' });
    expect(opens(calls)).toEqual([['ui.settings.open', 'hotkey', undefined]]);
    p.press({ ctrlKey: true, key: ',' });
    expect(opens(calls)).toEqual([['ui.settings.open', 'hotkey', undefined]]);
});

test('settings.js opening the modal by script counts nothing', () => {
    const { BAN, calls } = fakeBAN();
    settings({ search: '', BAN }).window.openSettings('upload');
    expect(opens(calls)).toEqual([]);
});

test('with no window.BAN the loader, the shell and the modal still run', () => {
    expect(() => loader().press({ ctrlKey: true, key: ',' })).not.toThrow();
    const s = shell({});
    expect(() => s.applySearch('x')).not.toThrow();
    const p = settings();
    expect(p.modal.classList.contains('open')).toBe(true);
    p.press({ ctrlKey: true, key: ',' });
});
