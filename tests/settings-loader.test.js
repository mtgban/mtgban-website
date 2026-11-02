import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/settings-loader.js', import.meta.url), 'utf8');
const t = (f) => readFileSync(new URL('../templates/' + f, import.meta.url), 'utf8');

// Runs the loader on a page already parsed, whose head records what is
// appended to it; linked names the sheets the page carries itself.
function page({ search = '', toast = false, activeTag = 'BODY', linked = [] } = {}) {
    const head = [];
    const listeners = {};
    const errors = [];
    const document = {
        currentScript: { src: 'http://localhost/js/settings-loader.js?hash=abc123' },
        activeElement: { tagName: activeTag },
        readyState: 'complete',
        head: { appendChild(el) { head.push(el); } },
        createElement(tag) { return { tagName: tag, remove() { head.splice(head.indexOf(this), 1); } }; },
        querySelector(sel) {
            const path = /href\^="([^"]+)"/.exec(sel)[1];
            return linked.includes(path) || head.some(el => el.rel === 'stylesheet' && el.href.startsWith(path)) ? {} : null;
        },
        addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
        removeEventListener(type, fn) { listeners[type] = (listeners[type] || []).filter(f => f !== fn); },
    };
    const sessionStorage = { getItem: (k) => (toast && k === 'settingsSavedToast' ? '1' : null) };
    const window = { location: { search }, console: { error(m) { errors.push(m); } } };
    new Function('window', 'document', 'sessionStorage', source)(window, document, sessionStorage);
    const press = (init) => {
        const e = Object.assign({ defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } }, init);
        (listeners.keydown || []).slice().forEach(fn => fn(e));
        return e;
    };
    const settle = () => new Promise(r => setTimeout(r, 0));
    const of = (tag, rel) => head.filter(el => el.tagName === tag && (!rel || el.rel === rel));
    return { window, head, listeners, errors, press, settle, of };
}

test('the gear links both sheets, then runs the scripts in order, then opens the tab asked for', async () => {
    const p = page();
    const stub = p.window.openSettings;
    stub('upload');

    expect(p.of('link', 'stylesheet').map(l => l.href)).toEqual([
        '/css/settings-modal.css?hash=abc123', '/css/editions-picker.css?hash=abc123',
    ]);
    expect(p.of('link', 'preload').map(l => l.href)).toEqual([
        '/js/editions-picker.js?hash=abc123', '/js/settings-shell.js?hash=abc123', '/js/settings.js?hash=abc123',
    ]);
    // settings.js unhides the modal's shell as it runs, so no script before the sheets
    expect(p.of('script')).toHaveLength(0);

    p.of('link', 'stylesheet').forEach(l => l.onload());
    await p.settle();
    const scripts = p.of('script');
    expect(scripts.map(s => s.src)).toEqual([
        '/js/editions-picker.js?hash=abc123', '/js/settings-shell.js?hash=abc123', '/js/settings.js?hash=abc123',
    ]);
    expect(scripts.every(s => s.async === false)).toBe(true);

    // settings.js takes window.openSettings over as it runs
    const opened = [];
    p.window.openSettings = (tab) => opened.push(tab);
    scripts.forEach(s => s.onload());
    await p.settle();
    expect(opened).toEqual(['upload']);
    // and the shortcut with it
    expect(p.listeners.keydown).toHaveLength(0);
    expect(p.errors).toEqual([]);
});

test('Ctrl+Comma opens outside a field and is left alone inside one', () => {
    const reading = page();
    expect(reading.press({ ctrlKey: true, key: ',' }).defaultPrevented).toBe(true);
    expect(reading.of('link', 'stylesheet')).toHaveLength(2);

    const typing = page({ activeTag: 'INPUT' });
    expect(typing.press({ metaKey: true, key: ',' }).defaultPrevented).toBe(false);
    expect(typing.head).toHaveLength(0);

    const other = page();
    expect(other.press({ ctrlKey: true, key: 'k' }).defaultPrevented).toBe(false);
    expect(other.head).toHaveLength(0);
});

test('a ?settings= link and the toast after a save load the modal at once, and nothing else does', () => {
    expect(page({ search: '?settings=1' }).of('link', 'stylesheet')).toHaveLength(2);
    expect(page({ search: '?q=bolt&settings=upload' }).of('link', 'stylesheet')).toHaveLength(2);
    expect(page({ toast: true }).of('link', 'stylesheet')).toHaveLength(2);
    expect(page({ search: '?q=bolt' }).head).toHaveLength(0);
});

test('a sheet the page already links is not linked again', () => {
    const p = page({ linked: ['/css/settings-modal.css'] });
    p.window.openSettings();
    expect(p.of('link', 'stylesheet').map(l => l.href)).toEqual(['/css/editions-picker.css?hash=abc123']);
});

test('a script that fails to load is reported and tried again on the next open', async () => {
    const p = page();
    p.window.openSettings();
    p.of('link', 'stylesheet').forEach(l => l.onload());
    await p.settle();
    p.of('script')[0].onerror();
    await p.settle();
    expect(p.errors).toEqual(['settings: /js/editions-picker.js did not load']);
    expect(p.listeners.keydown).toHaveLength(1);
    // The sheets are in and stay; only the scripts are fetched again
    p.window.openSettings();
    expect(p.of('link', 'stylesheet')).toHaveLength(2);
    await p.settle();
    expect(p.of('script')).toHaveLength(6);
});

test('a sheet that fails to load is dropped and linked again on the next open', async () => {
    const p = page();
    p.window.openSettings();
    p.of('link', 'stylesheet')[0].onerror();
    p.of('link', 'stylesheet')[0].onload();
    await p.settle();
    expect(p.of('script')).toHaveLength(0);
    expect(p.errors).toEqual(['settings: /css/settings-modal.css did not load']);
    expect(p.of('link', 'stylesheet').map(l => l.href)).toEqual(['/css/editions-picker.css?hash=abc123']);
    p.window.openSettings();
    expect(p.of('link', 'stylesheet').map(l => l.href)).toEqual([
        '/css/editions-picker.css?hash=abc123', '/css/settings-modal.css?hash=abc123',
    ]);
});

test('the base hands the modal to the loader; the pages with the alert dialog keep its sheet', () => {
    const base = t('base.html');
    expect(base).toContain('/js/settings-loader.js');
    for (const gone of ['/js/settings.js', '/js/settings-shell.js', '/js/editions-picker.js',
        '/css/settings-modal.css', '/css/editions-picker.css']) {
        expect(base).not.toContain(gone);
    }
    for (const path of ['/css/settings-modal.css', '/css/editions-picker.css',
        '/js/editions-picker.js', '/js/settings-shell.js', '/js/settings.js']) {
        expect(source).toContain("'" + path + "'");
    }
    // The alert dialog borrows the modal's sheet (css/alerts.css)
    for (const f of ['search.html', 'alerts.html', 'alerts_confirm.html']) {
        expect(t(f)).toContain('/css/settings-modal.css');
    }
    // The shell is hidden until settings.js, with its sheet in, shows it
    const shell = t('partials/settings-modal.html');
    expect(shell).toContain('id="settings-backdrop" hidden>');
    expect(shell).toContain('aria-labelledby="settings-modal-title" hidden>');
    expect(readFileSync(new URL('../js/settings.js', import.meta.url), 'utf8')).toContain('modalEl.hidden = false;');
});
