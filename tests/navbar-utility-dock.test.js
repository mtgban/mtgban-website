import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

// The bar's four icons (backpack, account, guide, settings) drag down to the
// Links strip of the Tools menu and back. The elements move, the layout
// remembers which are docked, and the inline restore script in the navbar
// partial docks them again before paint.

const navbar = readFileSync(new URL('../js/navbar.js', import.meta.url), 'utf8');
const drag = navbar.slice(navbar.indexOf('// ── Drag-and-drop'), navbar.indexOf('// ── Drag hint tile'));
const template = readFileSync(new URL('../templates/partials/navbar.html', import.meta.url), 'utf8');
const restore = template.slice(template.indexOf('(function() {', template.indexOf('Synchronous, inline layout restoration')), template.indexOf('})();', template.indexOf('Append any server-rendered tool')) + 5);

function element(attrs = {}, classes = []) {
    const listeners = {};
    const cls = new Set(classes);
    const el = {
        attrs, listeners, children: [], parentNode: null,
        classList: {
            add: (...c) => c.forEach((x) => cls.add(x)),
            remove: (...c) => c.forEach((x) => cls.delete(x)),
            contains: (c) => cls.has(c),
            toggle: (c, on) => (on ? cls.add(c) : cls.delete(c)),
        },
        getAttribute: (k) => (k in attrs ? attrs[k] : null),
        setAttribute: (k, v) => { attrs[k] = String(v); },
        addEventListener: (type, fn) => { listeners[type] = fn; },
        appendChild(c) { if (c.parentNode) c.parentNode.children.splice(c.parentNode.children.indexOf(c), 1); c.parentNode = this; this.children.push(c); },
        insertBefore(c, ref) {
            if (c.parentNode) c.parentNode.children.splice(c.parentNode.children.indexOf(c), 1);
            c.parentNode = this;
            const at = ref ? this.children.indexOf(ref) : this.children.length;
            this.children.splice(at, 0, c);
        },
        remove() { if (this.parentNode) { this.parentNode.children.splice(this.parentNode.children.indexOf(this), 1); this.parentNode = null; } },
        querySelectorAll(sel) {
            if (sel === '[data-util]') return this.children.filter((c) => 'data-util' in c.attrs);
            return [];
        },
        querySelector(sel) {
            if (sel === '.ban-nav-hamburger') return this.children.find((c) => c.classList.contains('ban-nav-hamburger')) || null;
            const m = sel.match(/^\.nav2-utility \[data-util="(\w+)"\]$/);
            if (m) return this.children.find((c) => c.attrs['data-util'] === m[1]) || null;
            return null;
        },
        closest(sel) { return sel === '.tools-quick' ? this.parentNode : null; },
        click() { listeners.click && listeners.click({ stopPropagation() {} }); },
    };
    return el;
}

function page() {
    const utility = element({}, ['nav2-utility']);
    const utils = {};
    ['backpack', 'account', 'guide', 'settings'].forEach((name) => {
        utils[name] = element({ 'data-util': name });
        utility.appendChild(utils[name]);
    });
    const hamburger = element({}, ['ban-nav-hamburger']);
    utility.appendChild(hamburger);
    const quick = element({}, ['tools-quick']);
    const dock = element({ id: 'tools-quick-dock' });
    quick.appendChild(dock);
    const toolsBtn = element({ 'aria-expanded': 'false' });
    toolsBtn.listeners.click = () => toolsBtn.setAttribute('aria-expanded', 'true');
    const grid = element({ id: 'tools-grid' });
    const sections = element({}, ['nav2-sections']);
    const byId = { 'tools-grid': grid, 'tools-quick-dock': dock, 'tools-btn': toolsBtn };
    const stored = {};
    const document = {
        getElementById: (id) => byId[id] || null,
        querySelector: (sel) => (sel === '.nav2-sections' ? sections : sel === '.nav2-utility' ? utility : utility.querySelector(sel)),
        querySelectorAll: (sel) => (sel === '[data-util]' ? Object.values(utils) : []),
    };
    const localStorage = {
        getItem: (k) => (k in stored ? stored[k] : null),
        setItem: (k, v) => { stored[k] = v; },
    };
    return { utility, utils, hamburger, quick, dock, toolsBtn, document, localStorage, stored };
}

function layout(p) { return JSON.parse(p.stored.mtgban_nav_layout_v1); }
function names(el) { return el.children.map((c) => c.attrs['data-util'] || 'hamburger'); }

// loadDrag runs the drag code; with `narrow` it gets a matchMedia whose
// change events the test fires itself.
function loadDrag(p, narrow) {
    const window = { __BAN_NAV: [] };
    if (narrow) {
        narrow.addEventListener = (type, fn) => { narrow.fire = (matches) => { narrow.matches = matches; fn({ matches }); }; };
        window.matchMedia = () => narrow;
    }
    new Function('document', 'localStorage', 'window', 'location', 'setTimeout', drag)(
        p.document, p.localStorage, window, { pathname: '/search' }, () => {});
}
function loadRestore(p, narrow) {
    new Function('document', 'localStorage', 'location', 'matchMedia', restore)(
        p.document, p.localStorage, { pathname: '/search' }, narrow === undefined ? undefined : () => ({ matches: narrow }));
}

const ev = () => ({ preventDefault() {}, stopPropagation() {}, dataTransfer: {} });

test('an icon dragged onto the Links strip docks there and the layout records it', () => {
    const p = page();
    loadDrag(p);
    p.utils.guide.listeners.dragstart(ev());
    expect(p.toolsBtn.getAttribute('aria-expanded')).toBe('true');
    p.quick.listeners.drop(ev());
    p.utils.guide.listeners.dragend();
    expect(names(p.dock)).toEqual(['guide']);
    expect(names(p.utility)).toEqual(['backpack', 'account', 'settings', 'hamburger']);
    expect(layout(p).dock).toEqual(['guide']);
});

test('a docked icon dragged back takes its place in the bar, before the hamburger', () => {
    const p = page();
    loadDrag(p);
    ['settings', 'account'].forEach((n) => {
        p.utils[n].listeners.dragstart(ev());
        p.quick.listeners.drop(ev());
        p.utils[n].listeners.dragend();
    });
    expect(names(p.dock)).toEqual(['settings', 'account']);
    expect(layout(p).dock).toEqual(['settings', 'account']);

    // Dragging a docked icon marks the bar's slot and leaves the menu as it is.
    p.toolsBtn.setAttribute('aria-expanded', 'false');
    p.utils.account.listeners.dragstart(ev());
    expect(p.utility.classList.contains('undock-ready')).toBe(true);
    expect(p.toolsBtn.getAttribute('aria-expanded')).toBe('false');
    p.utility.listeners.drop(ev());
    p.utils.account.listeners.dragend();
    expect(p.utility.classList.contains('undock-ready')).toBe(false);
    expect(names(p.utility)).toEqual(['backpack', 'account', 'guide', 'hamburger']);

    // The Tools button takes the drop too.
    p.utils.settings.listeners.dragstart(ev());
    p.toolsBtn.listeners.drop(ev());
    p.utils.settings.listeners.dragend();
    expect(names(p.utility)).toEqual(['backpack', 'account', 'guide', 'settings', 'hamburger']);
    expect(layout(p).dock).toEqual([]);
});

test('the inline restore script docks the saved icons before paint', () => {
    const p = page();
    p.stored.mtgban_nav_layout_v1 = JSON.stringify({ dock: ['account', 'backpack'] });
    loadRestore(p);
    expect(names(p.dock)).toEqual(['account', 'backpack']);
    expect(names(p.utility)).toEqual(['guide', 'settings', 'hamburger']);
});

test('a saved layout without a dock leaves the bar alone', () => {
    const p = page();
    p.stored.mtgban_nav_layout_v1 = JSON.stringify({ sections: [], grid: [] });
    loadRestore(p);
    expect(names(p.dock)).toEqual([]);
    expect(names(p.utility)).toEqual(['backpack', 'account', 'guide', 'settings', 'hamburger']);
});

// Under 900px the sections are hidden, the Tools button and the strip with
// them, so a docked icon would be out of reach: the bar keeps every icon
// while it is narrow, and the saved list waits for it to widen.
test('a narrow bar keeps the icons out of the dock before paint', () => {
    const p = page();
    p.stored.mtgban_nav_layout_v1 = JSON.stringify({ dock: ['guide'] });
    loadRestore(p, true);
    expect(names(p.dock)).toEqual([]);
    expect(names(p.utility)).toEqual(['backpack', 'account', 'guide', 'settings', 'hamburger']);
});

test('narrowing the bar brings the docked icons back, widening docks them again, the saved list untouched', () => {
    const p = page();
    const narrow = { matches: false };
    loadDrag(p, narrow);
    ['settings', 'account'].forEach((n) => {
        p.utils[n].listeners.dragstart(ev());
        p.quick.listeners.drop(ev());
        p.utils[n].listeners.dragend();
    });
    expect(layout(p).dock).toEqual(['settings', 'account']);

    narrow.fire(true);
    expect(names(p.dock)).toEqual([]);
    expect(names(p.utility)).toEqual(['backpack', 'account', 'guide', 'settings', 'hamburger']);
    expect(layout(p).dock).toEqual(['settings', 'account']);

    // A drag on the narrow bar opens nothing and keeps the saved list.
    p.toolsBtn.setAttribute('aria-expanded', 'false');
    p.utils.guide.listeners.dragstart(ev());
    expect(p.toolsBtn.getAttribute('aria-expanded')).toBe('false');
    p.utility.listeners.drop(ev());
    p.utils.guide.listeners.dragend();
    expect(layout(p).dock).toEqual(['settings', 'account']);

    narrow.fire(false);
    expect(names(p.dock)).toEqual(['settings', 'account']);
    expect(names(p.utility)).toEqual(['backpack', 'guide', 'hamburger']);
});

test('a malformed saved name is skipped and the rest of the restore still runs', () => {
    const p = page();
    p.stored.mtgban_nav_layout_v1 = JSON.stringify({ dock: ['gui"de', 7, 'settings'], sections: [], grid: [] });
    expect(() => loadRestore(p)).not.toThrow();
    expect(names(p.dock)).toEqual(['settings']);
});

test('widening skips a malformed saved name and the re-save drops it', () => {
    const p = page();
    const narrow = { matches: true };
    p.stored.mtgban_nav_layout_v1 = JSON.stringify({ dock: ['gui"de', 'settings'], sections: [], grid: [] });
    loadDrag(p, narrow);
    narrow.fire(false);
    expect(names(p.dock)).toEqual(['settings']);
    p.utils.settings.listeners.dragstart(ev());
    p.utility.listeners.drop(ev());
    p.utils.settings.listeners.dragend();
    expect(layout(p).dock).toEqual([]);
});

// UTIL_ORDER is the bar's order as the server renders it.
test('the undock order matches the template', () => {
    const utility = template.slice(template.indexOf('<div class="nav2-utility">'), template.indexOf('ban-nav-hamburger'));
    const rendered = [...utility.matchAll(/data-util="(\w+)"/g)].map((m) => m[1]);
    const order = JSON.parse(navbar.match(/var UTIL_ORDER = (\[[^\]]*\]);/)[1].replace(/'/g, '"'));
    expect(order).toEqual(rendered);
});
