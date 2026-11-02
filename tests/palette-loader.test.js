import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/palette-loader.js', import.meta.url), 'utf8');

class KeyboardEvent {
    constructor(type, init) { this.type = type; Object.assign(this, init); this.defaultPrevented = false; }
    preventDefault() { this.defaultPrevented = true; }
}

// Runs the loader on a page whose head records what is appended to it, with
// the caret on activeTag. press() fires a keydown at the document's listeners.
function page({ guide = false, activeTag = 'BODY', width = 1024 } = {}) {
    const head = [];
    const listeners = {};
    const dispatched = [];
    const document = {
        currentScript: { src: 'http://localhost/js/palette-loader.js?hash=abc123' },
        activeElement: { tagName: activeTag, isContentEditable: false },
        head: { appendChild(el) { head.push(el); } },
        createElement(tag) { return { tagName: tag, remove() { head.splice(head.indexOf(this), 1); } }; },
        addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
        removeEventListener(type, fn) { listeners[type] = (listeners[type] || []).filter(f => f !== fn); },
        dispatchEvent(e) { dispatched.push(e); },
    };
    const window = { __BAN_PALETTE: { nav: [] }, innerWidth: width, console: { error() {} } };
    if (guide) window.__BAN_GUIDE = { sections: [] };
    new Function('window', 'document', 'KeyboardEvent', source)(window, document, KeyboardEvent);
    const press = (init) => {
        const e = new KeyboardEvent('keydown', init);
        (listeners.keydown || []).slice().forEach(fn => fn(e));
        return e;
    };
    const settle = () => new Promise(r => setTimeout(r, 0));
    const of = (tag, rel) => head.filter(el => el.tagName === tag && (!rel || el.rel === rel));
    return { head, press, dispatched, settle, listeners, of };
}

test('Ctrl+K loads the stylesheet, then the scripts in order, then replays the key', async () => {
    const p = page();
    const e = p.press({ key: 'k', ctrlKey: true });
    expect(e.defaultPrevented).toBe(true);

    const [sheet] = p.of('link', 'stylesheet');
    expect(sheet.href).toBe('/css/command-palette.css?hash=abc123');
    expect(p.of('link', 'preload').map(l => l.href)).toEqual([
        '/js/palette-chips.js?hash=abc123', '/js/guide-data.js?hash=abc123', '/js/command-palette.js?hash=abc123',
    ]);
    // No script runs before the sheet is in: the palette paints its overlay as it loads
    expect(p.of('script')).toHaveLength(0);

    sheet.onload();
    await p.settle();
    const scripts = p.of('script');
    expect(scripts.map(s => s.src)).toEqual([
        '/js/palette-chips.js?hash=abc123', '/js/guide-data.js?hash=abc123', '/js/command-palette.js?hash=abc123',
    ]);
    expect(scripts.every(s => s.async === false)).toBe(true);
    expect(p.dispatched).toHaveLength(0);

    scripts.forEach(s => s.onload());
    await p.settle();
    expect(p.dispatched).toHaveLength(1);
    expect(p.dispatched[0]).toMatchObject({ type: 'keydown', key: 'k', ctrlKey: true, bubbles: true });
});

test('a Ctrl+K matched by keyCode alone replays as the k the palette looks for', async () => {
    const p = page();
    expect(p.press({ key: '\u043b', keyCode: 75, ctrlKey: true }).defaultPrevented).toBe(true);
    p.of('link', 'stylesheet')[0].onload();
    await p.settle();
    p.of('script').forEach(s => s.onload());
    await p.settle();
    expect(p.dispatched[0]).toMatchObject({ key: 'k', keyCode: 75, ctrlKey: true });
});

test('"/" loads the palette outside a field and is left alone inside one', () => {
    const typing = page({ activeTag: 'INPUT' });
    expect(typing.press({ key: '/' }).defaultPrevented).toBe(false);
    expect(typing.head).toHaveLength(0);

    const reading = page();
    expect(reading.press({ key: '/' }).defaultPrevented).toBe(true);
    expect(reading.of('link', 'stylesheet')).toHaveLength(1);
});

test('the guide page keeps its own copy of the guide data', async () => {
    const p = page({ guide: true });
    p.press({ key: 'k', metaKey: true });
    p.of('link', 'stylesheet')[0].onload();
    await p.settle();
    expect(p.of('script').map(s => s.src)).toEqual([
        '/js/palette-chips.js?hash=abc123', '/js/command-palette.js?hash=abc123',
    ]);
});

test('a second press while loading neither loads twice nor replays twice', async () => {
    const p = page();
    p.press({ key: 'k', ctrlKey: true });
    p.press({ key: 'k', ctrlKey: true });
    expect(p.of('link', 'stylesheet')).toHaveLength(1);
    expect(p.listeners.keydown).toHaveLength(0);
});

test('a script that fails to load hands the shortcut back', async () => {
    const p = page();
    p.press({ key: 'k', ctrlKey: true });
    p.of('link', 'stylesheet')[0].onload();
    await p.settle();
    p.of('script')[0].onerror();
    await p.settle();
    expect(p.dispatched).toHaveLength(0);
    expect(p.listeners.keydown).toHaveLength(1);
    // The next press starts over
    p.press({ key: 'k', ctrlKey: true });
    expect(p.of('link', 'stylesheet')).toHaveLength(2);
});

test('a stylesheet that fails to load is dropped and linked again on the next press', async () => {
    const p = page();
    p.press({ key: 'k', ctrlKey: true });
    p.of('link', 'stylesheet')[0].onerror();
    await p.settle();
    expect(p.of('script')).toHaveLength(0);
    expect(p.of('link', 'stylesheet')).toHaveLength(0);
    expect(p.listeners.keydown).toHaveLength(1);
    p.press({ key: 'k', ctrlKey: true });
    expect(p.of('link', 'stylesheet').map(l => l.href)).toEqual(['/css/command-palette.css?hash=abc123']);
});

test('a window narrower than the palette allows leaves the keys alone', () => {
    const p = page({ width: 600 });
    expect(p.press({ key: 'k', ctrlKey: true }).defaultPrevented).toBe(false);
    expect(p.head).toHaveLength(0);
});

test('every base loads the providers for the search box and the loader, and nothing more of the palette', () => {
    for (const f of ['base.html', 'base-landing.html']) {
        const html = readFileSync(new URL('../templates/' + f, import.meta.url), 'utf8');
        expect(html).toContain('/js/palette-providers.js');
        expect(html).toContain('/js/palette-loader.js');
        for (const gone of ['/js/command-palette.js', '/js/palette-chips.js', '/js/guide-data.js', '/css/command-palette.css']) {
            expect(html).not.toContain(gone);
        }
    }
    // The paths the loader fetches are the files the bases used to carry
    for (const path of ['/css/command-palette.css', '/js/palette-chips.js', '/js/guide-data.js', '/js/command-palette.js']) {
        expect(source).toContain("'" + path + "'");
    }
});
