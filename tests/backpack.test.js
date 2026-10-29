import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/backpack.js', import.meta.url), 'utf8');
const listStorage = readFileSync(new URL('../js/list-storage.js', import.meta.url), 'utf8');

// A stand-in DOM: elements with attributes, classes, children, text, and the
// handful of lookups the script uses.
function el(tag) {
    const node = {
        tag, attrs: {}, classes: new Set(), children: [], listeners: {}, parentNode: null, textContent: '', hidden: false,
        value: '', checked: false, disabled: false, type: '', name: '',
        style: {},
        get classList() {
            const s = this.classes;
            return { add: (c) => s.add(c), remove: (c) => s.delete(c), toggle: (c, on) => { on ? s.add(c) : s.delete(c); }, contains: (c) => s.has(c) };
        },
        setAttribute(n, v) { this.attrs[n] = String(v); if (n === 'id') ids[v] = this; if (n === 'class') String(v).split(/\s+/).filter(Boolean).forEach((c) => this.classes.add(c)); },
        getAttribute(n) { return n in this.attrs ? this.attrs[n] : null; },
        removeAttribute(n) { delete this.attrs[n]; },
        appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
        append(...cs) { cs.forEach((c) => this.appendChild(c)); },
        remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((c) => c !== this); },
        replaceWith(n) { const p = this.parentNode; if (!p) return; n.parentNode = p; p.children[p.children.indexOf(this)] = n; this.parentNode = null; },
        addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); },
        click() { (this.listeners.click || []).forEach((fn) => fn({ preventDefault() {}, stopPropagation() {} })); },
        focus() { if (currentDoc) currentDoc.activeElement = this; },
        closest(sel) { let n = this; while (n) { if (n.matches(sel)) return n; n = n.parentNode; } return null; },
        matches(sel) { return sel.split(',').some((s) => { s = s.trim(); return s.startsWith('.') ? this.classes.has(s.slice(1)) : s.startsWith('#') ? this.attrs.id === s.slice(1) : s.includes('[') ? this.tag === s.split('[')[0] && s.slice(s.indexOf('[') + 1, -1) in this.attrs : this.tag === s; }); },
        querySelector(sel) { return this.querySelectorAll(sel)[0] || null; },
        querySelectorAll(sel) { const out = []; const walk = (n) => { n.children.forEach((c) => { if (c.matches(sel)) out.push(c); walk(c); }); }; walk(this); return out; },
        submit() { submitted.push(this); if (submitHook) submitHook(); },
    };
    return node;
}
let ids = {};
let submitted = [];
let submitHook = null;
let confirms = [];
let currentDoc = null;

function page({ store = [], emptyAfter = '0', mobile = false, ban, pending, max, tabs, active, tabList, session, sections = [], navMenu = false, sort, fetch } = {}) {
    ids = {}; submitted = []; submitHook = null; confirms = [];
    const m = { mtgban_backpack: JSON.stringify(store), mtgban_backpack_empty_after: emptyAfter };
    if (active) m.mtgban_backpack_active = String(active);
    if (tabList) m.mtgban_backpack_tabs = JSON.stringify(tabList);
    if (sort) m.mtgban_backpack_sort = JSON.stringify(sort);
    const localStorage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const sm = session || (pending ? { mtgban_backpack_pending_clear: JSON.stringify(pending) } : {});
    const sessionStorage = { getItem: (k) => (k in sm ? sm[k] : null), setItem: (k, v) => { sm[k] = String(v); }, removeItem: (k) => { delete sm[k]; } };
    const body = el('body'); if (mobile) body.classes.add('mobile');
    const nav = el('button'); nav.setAttribute('id', 'nav-backpack'); nav.hidden = true;
    const navCount = el('span'); navCount.setAttribute('id', 'nav-backpack-count'); navCount.hidden = true; nav.appendChild(navCount);
    body.appendChild(nav);
    if (navMenu) { const menu = el('div'); menu.setAttribute('id', 'nav-backpack-menu'); menu.hidden = true; body.appendChild(menu); }
    // Two result rows, each with an add and a minus button carrying the card id.
    const minus = [];
    const rows = ['uuid-1', 'uuid-2'].map((id) => {
        const row = el('div'); row.classes.add('result-header');
        Object.entries({ 'data-card-id': id, 'data-card-name': 'Card ' + id, 'data-set-code': 'S', 'data-edition': 'Set', 'data-number': '7', 'data-image-url': '', 'data-finish-tag': '', 'data-finish-class': '', 'data-treatments': '', 'data-has-warning': 'false' }).forEach(([k, v]) => row.setAttribute(k, v));
        const btn = el('button'); btn.classes.add('pack-btn'); btn.setAttribute('data-card-id', id);
        const count = el('span'); count.classes.add('pack-btn-count'); count.hidden = true; btn.appendChild(count);
        const less = el('button'); less.classes.add('pack-minus-btn'); less.setAttribute('data-card-id', id); less.hidden = true;
        row.append(btn, less); body.appendChild(row);
        minus.push(less);
        return btn;
    });
    // Upload optimizer sections, each a take button and rows of [id, qty, unticked, cond].
    const optSections = sections.map((rows) => {
        const section = el('div'); section.classes.add('opt-store');
        const take = el('button'); take.classes.add('pack-take-btn'); take.hidden = true;
        const fold = el('button'); fold.classes.add('section-fold');
        section.append(take, fold);
        rows.forEach(([id, qty, unticked, cond = '']) => {
            const tr = el('tr'); tr.setAttribute('data-opt-id', id); tr.setAttribute('data-opt-cond', cond); tr.setAttribute('data-load-qty', String(qty));
            if (unticked) tr.classes.add('opt-removed');
            section.appendChild(tr);
        });
        body.appendChild(section);
        return { section, take, fold, rows: section.children.filter((c) => c.tag === 'tr') };
    });
    const storageListeners = [];
    const pageshowListeners = [];
    const window = {
        localStorage, sessionStorage, confirm: (msg) => { confirms.push(msg); return true; },
        addEventListener: (ev, fn) => { if (ev === 'storage') storageListeners.push(fn); if (ev === 'pageshow') pageshowListeners.push(fn); },
        location: { pathname: '/search' },
    };
    if (ban) window.BAN_BACKPACK = ban;
    if (max) window.BAN_BACKPACK_MAX = max;
    if (tabs) window.BAN_BACKPACK_TABS = tabs;
    if (fetch) window.fetch = fetch;
    const docListeners = {};
    const document = {
        body, readyState: 'complete', addEventListener: (ev, fn) => { (docListeners[ev] = docListeners[ev] || []).push(fn); },
        getElementById: (id) => ids[id] || null,
        createElement: (tag) => el(tag),
        querySelectorAll: (sel) => body.querySelectorAll(sel),
        activeElement: null,
    };
    currentDoc = document;
    // key fires a keydown on the document and says whether it was prevented.
    const key = (k, shiftKey = false) => {
        let prevented = false;
        (docListeners.keydown || []).forEach((fn) => fn({ key: k, shiftKey, preventDefault() { prevented = true; } }));
        return prevented;
    };
    window.CardRow = { read: (btn) => {
        const row = btn.closest('.result-header'); if (!row) return null;
        return { id: row.getAttribute('data-card-id'), name: row.getAttribute('data-card-name'), set: 'S', edition: 'Set', number: '7', finishTag: '', finishClass: '', img: '', cw: false, t: Date.now() };
    } };
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'ListStorage',
        listStorage + '; window.ListStorage = ListStorage; ' + source)(
        window, document, localStorage, sessionStorage, undefined);
    const stored = () => JSON.parse(m.mtgban_backpack);
    const pendingIds = () => (sm.mtgban_backpack_pending_clear === undefined ? undefined : JSON.parse(sm.mtgban_backpack_pending_clear));
    return {
        window, document, m, sm, rows, minus, nav, navCount, stored, key, pendingIds, optSections,
        fireChange: (target) => (docListeners.change || []).forEach((fn) => fn({ target })),
        fireStorage: (key = 'mtgban_backpack') => storageListeners.forEach((fn) => fn({ key })),
        firePageshow: (persisted) => pageshowListeners.forEach((fn) => fn({ persisted })),
    };
}

describe('adding', () => {
    test('the first click creates an entry with qty 1 and marks the row and navbar', () => {
        const p = page();
        p.window.addToBackpack(p.rows[0]);
        const live = p.stored().filter((e) => !e.del);
        expect(live.length).toBe(1);
        expect(live[0].qty).toBe(1);
        expect(live[0].m).toBe(live[0].t);
        expect(p.rows[0].classes.has('active')).toBe(true);
        expect(p.rows[0].children[0].textContent).toBe('1');
        expect(p.rows[0].children[0].hidden).toBe(false);
        expect(p.rows[0].getAttribute('title')).toBe('Add another copy');
        expect(p.nav.hidden).toBe(false);
        expect(p.navCount.textContent).toBe('1');
        expect(p.navCount.hidden).toBe(false);
        expect(p.nav.getAttribute('aria-label')).toBe('Backpack, 1 copy');
    });

    test('an empty backpack names the navbar button without a count', () => {
        const p = page();
        expect(p.nav.getAttribute('aria-label')).toBe('Backpack');
    });

    test('a second click adds a copy and bumps m', async () => {
        const p = page();
        p.window.addToBackpack(p.rows[0]);
        const before = p.stored()[0].m;
        await new Promise((r) => setTimeout(r, 2));
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored()[0].qty).toBe(2);
        expect(p.stored()[0].m).toBeGreaterThan(before);
        expect(p.rows[0].children[0].textContent).toBe('2');
        expect(p.navCount.textContent).toBe('2');
    });

    test('a click at 999 toasts without writing', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'x', qty: 999, t: 1, m: 1 }] });
        const toast = el('div'); toast.setAttribute('id', 'desktop-fav-toast'); p.document.body.appendChild(toast);
        const before = p.m.mtgban_backpack;
        p.window.addToBackpack(p.rows[0]);
        expect(p.m.mtgban_backpack).toBe(before);
        expect(toast.textContent).toBe('999 copies is the most for one product');
    });

    test('the phone menu item says it adds another copy once the card is in', () => {
        const p = page();
        const item = el('button'); item.classes.add('pack-btn'); item.setAttribute('data-card-id', 'uuid-1');
        const label = el('span'); label.classes.add('pack-btn-label'); label.textContent = 'Add to backpack'; item.appendChild(label);
        p.rows[0].parentNode.appendChild(item);
        p.window.addToBackpack(item);
        expect(label.textContent).toBe('Add another copy');
        expect(p.rows[0].classes.has('active')).toBe(true);
    });

    test('the collapsed desktop menu label follows the title', () => {
        const p = page();
        const label = el('span'); label.classes.add('qi-label'); label.textContent = 'Remove from backpack'; p.minus[0].appendChild(label);
        p.window.addToBackpack(p.rows[0]);
        p.window.addToBackpack(p.rows[0]);
        expect(p.minus[0].getAttribute('title')).toBe('Remove one copy');
        expect(label.textContent).toBe('Remove one copy');
    });

    test('the add and minus buttons are named by their action, not the count they show', () => {
        const p = page();
        expect(p.rows[0].getAttribute('aria-label')).toBe('Add to backpack');
        p.window.addToBackpack(p.rows[0]);
        p.window.addToBackpack(p.rows[0]);
        expect(p.rows[0].children[0].textContent).toBe('2');
        expect(p.rows[0].getAttribute('aria-label')).toBe('Add another copy');
        expect(p.minus[0].getAttribute('aria-label')).toBe('Remove one copy');
    });

    test('the phone menu items carry the same names as their labels', () => {
        const p = page();
        const item = el('button'); item.classes.add('pack-btn'); item.setAttribute('data-card-id', 'uuid-1');
        const less = el('button'); less.classes.add('pack-minus-btn'); less.setAttribute('data-card-id', 'uuid-1');
        p.rows[0].parentNode.append(item, less);
        p.window.addToBackpack(item);
        expect(item.getAttribute('aria-label')).toBe('Add another copy');
        expect(less.getAttribute('aria-label')).toBe('Remove from backpack');
    });

    test('re-adding a removed card gives a live entry with qty 1', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'x', qty: 4, t: 1, m: 2, del: 2 }] });
        p.window.addToBackpack(p.rows[0]);
        const e = p.stored().find((x) => x.id === 'uuid-1');
        expect(e.del).toBeUndefined();
        expect(e.qty).toBe(1);
    });

    test('the cap refuses the 101st product with a toast', () => {
        const store = [];
        for (let i = 0; i < 100; i++) store.push({ id: 'c' + i, name: 'c', qty: 1, t: i, m: i });
        const p = page({ store });
        const toast = el('div'); toast.setAttribute('id', 'desktop-fav-toast'); p.document.body.appendChild(toast);
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored().filter((e) => !e.del).length).toBe(100);
        expect(toast.textContent).toBe('Backpack is full (100 products)');
    });

    test('a tier backpack size moves the cap', () => {
        const store = [];
        for (let i = 0; i < 200; i++) store.push({ id: 'c' + i, name: 'c', qty: 1, t: i, m: i });
        const p = page({ store, max: 201 });
        const toast = el('div'); toast.setAttribute('id', 'desktop-fav-toast'); p.document.body.appendChild(toast);
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored().filter((e) => !e.del).length).toBe(201);
        p.window.addToBackpack(p.rows[1]);
        expect(p.stored().filter((e) => !e.del).length).toBe(201);
        expect(toast.textContent).toBe('Backpack is full (201 products)');
    });

    test('a card already in a full backpack still takes another copy', () => {
        const store = [];
        for (let i = 0; i < 100; i++) store.push({ id: i === 0 ? 'uuid-1' : 'c' + i, name: 'c', qty: 1, t: i, m: i });
        const p = page({ store });
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored().find((e) => e.id === 'uuid-1').qty).toBe(2);
    });

    test('a removed entry is stored with only what names and orders it', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', edition: 'E', img: 'x', qty: 2, t: 1, m: 1 }] });
        p.window.Backpack.remove('uuid-1');
        expect(Object.keys(p.stored()[0]).sort()).toEqual(['cond', 'del', 'id', 'm', 'pack', 't']);
        p.window.Backpack.undo();
        expect(p.stored()[0].name).toBe('A');
    });

    test('the 999 ceiling toasts without writing', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'x', qty: 999, t: 1, m: 1 }] });
        const toast = el('div'); toast.setAttribute('id', 'desktop-fav-toast'); p.document.body.appendChild(toast);
        const before = p.m.mtgban_backpack;
        p.window.Backpack.setQty('uuid-1', 1000);
        expect(p.m.mtgban_backpack).toBe(before);
        expect(toast.textContent).toBe('999 copies is the most for one product');
    });

    test('a stored string qty counts as a number and steps up', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'x', qty: '5', t: 1, m: 1 }, { id: 7, name: 'bad id', qty: 1, t: 1, m: 1 }] });
        expect(p.window.Backpack.count()).toEqual({ copies: 5, cards: 1 });
        p.window.Backpack.setQty('uuid-1', p.window.Backpack.read()[0].qty + 1);
        expect(p.stored().find((e) => e.id === 'uuid-1').qty).toBe(6);
    });

    test('a quantity out of range is held to 1..999', () => {
        const p = page({ store: [{ id: 'uuid-1', qty: 5000, t: 1, m: 1 }, { id: 'uuid-2', qty: -3, t: 1, m: 1 }] });
        expect(p.window.Backpack.read().map((e) => e.qty)).toEqual([999, 1]);
    });

    test('the fallback entry for a button outside a row has an empty name', () => {
        const p = page();
        const btn = el('button'); btn.setAttribute('data-card-id', 'loose'); btn.setAttribute('title', 'Add to backpack');
        p.window.addToBackpack(btn);
        expect(p.stored()[0].name).toBe('');
    });

    test('stamps come from the UserState clock when there is one', () => {
        const p = page();
        p.window.UserState = { now: () => 12345 };
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored()[0].t).toBe(12345);
        expect(p.stored()[0].m).toBe(12345);
    });

    test('a stored entry without an id is skipped, not fatal', () => {
        const p = page({ store: [{ name: 'broken', qty: 1, t: 1, m: 1 }, { id: 'uuid-2', name: 'ok', qty: 2, t: 1, m: 1 }] });
        expect(p.window.Backpack.count()).toEqual({ copies: 2, cards: 1 });
        expect(p.rows[1].children[0].hidden).toBe(false);
    });
});

describe('the minus button', () => {
    test('shows only for a card in the backpack', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 1, t: 1, m: 1 }] });
        expect(p.minus[0].hidden).toBe(false);
        expect(p.minus[0].getAttribute('title')).toBe('Remove from backpack');
        expect(p.minus[1].hidden).toBe(true);
    });

    test('takes one copy out, then the card at 1', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        expect(p.minus[0].getAttribute('title')).toBe('Remove one copy');
        p.window.takeFromBackpack(p.minus[0]);
        expect(p.stored()[0].qty).toBe(1);
        expect(p.rows[0].children[0].textContent).toBe('1');
        expect(p.minus[0].getAttribute('title')).toBe('Remove from backpack');
        p.window.takeFromBackpack(p.minus[0]);
        expect(p.stored()[0].del).toBeDefined();
        expect(p.minus[0].hidden).toBe(true);
        expect(p.rows[0].classes.has('active')).toBe(false);
        expect(p.rows[0].children[0].hidden).toBe(true);
        expect(p.rows[0].getAttribute('title')).toBe('Add to backpack');
        expect(p.navCount.hidden).toBe(true);
    });

    test('taking the last copy with the minus focused moves focus to the add button', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        p.minus[0].focus();
        p.window.takeFromBackpack(p.minus[0]);
        expect(p.document.activeElement).toBe(p.minus[0]);
        p.window.takeFromBackpack(p.minus[0]);
        expect(p.minus[0].hidden).toBe(true);
        expect(p.document.activeElement).toBe(p.rows[0]);
    });

    test('taking the last copy leaves focus alone when the minus did not have it', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 1, t: 1, m: 1 }] });
        p.rows[1].focus();
        p.window.takeFromBackpack(p.minus[0]);
        expect(p.document.activeElement).toBe(p.rows[1]);
    });

    test('a card not in the backpack writes nothing', () => {
        const p = page();
        p.window.takeFromBackpack(p.minus[0]);
        expect(p.stored()).toEqual([]);
    });
});

describe('grades', () => {
    const live = (p) => p.stored().filter((e) => !e.del).map((e) => [e.id, e.cond, e.qty]);

    test('an entry stored without a grade reads as NM, keyed by the bare id', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }, { id: 'uuid-1', cond: 'bogus', qty: 1, t: 1, m: 1 }] });
        expect(p.window.Backpack.read().map((e) => e.cond)).toEqual(['NM', 'NM']);
        p.window.Backpack.setQty('uuid-1', 3);
        expect(p.stored()[0].qty).toBe(3);
    });

    test('the same card in two grades is two entries', () => {
        const p = page({ store: [{ id: 'uuid-1', cond: 'SP', qty: 2, t: 1, m: 1 }, { id: 'uuid-1', qty: 1, t: 1, m: 1 }] });
        p.window.Backpack.setQty('uuid-1|SP', 5);
        expect(live(p)).toEqual([['uuid-1', 'SP', 5], ['uuid-1', 'NM', 1]]);
        p.window.Backpack.remove('uuid-1');
        expect(live(p)).toEqual([['uuid-1', 'SP', 5]]);
        expect(p.window.Backpack.count()).toEqual({ copies: 5, cards: 1 });
    });

    test('the panel lists a card\'s grades best first', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A HP', cond: 'HP', qty: 1, t: 5, m: 5 }, { id: 'uuid-2', name: 'B', qty: 1, t: 9, m: 9 }, { id: 'uuid-1', name: 'A SP', cond: 'SP', qty: 1, t: 5, m: 5 }] });
        p.nav.click();
        const rows = ids['backpack-panel'].querySelectorAll('.backpack-row-name').map((n) => n.textContent);
        expect(rows).toEqual(['B', 'A SP', 'A HP']);
        const form = p.window.Backpack.sendForm('retail');
        expect(form.children.filter((i) => i.name === 'hashes').map((i) => i.value)).toEqual(['uuid-2', 'uuid-1', 'uuid-1']);
    });

    test('the search add puts an NM copy in beside another grade', () => {
        const p = page({ store: [{ id: 'uuid-1', cond: 'SP', qty: 2, t: 1, m: 1 }] });
        p.window.addToBackpack(p.rows[0]);
        p.window.addToBackpack(p.rows[0]);
        expect(live(p).sort()).toEqual([['uuid-1', 'NM', 2], ['uuid-1', 'SP', 2]]);
    });

    test('a card held only in another grade shows an active add with no count and no minus', () => {
        const p = page({ store: [{ id: 'uuid-1', cond: 'SP', qty: 2, t: 1, m: 1 }] });
        expect(p.rows[0].classes.has('active')).toBe(true);
        expect(p.rows[0].children[0].hidden).toBe(true);
        expect(p.rows[0].getAttribute('title')).toBe('Add an NM copy');
        expect(p.minus[0].hidden).toBe(true);
    });

    test('beside another grade the buttons count and name NM copies', () => {
        const p = page({ store: [{ id: 'uuid-1', cond: 'SP', qty: 2, t: 1, m: 1 }, { id: 'uuid-1', qty: 3, t: 1, m: 1 }] });
        expect(p.rows[0].children[0].textContent).toBe('3');
        expect(p.rows[0].getAttribute('title')).toBe('Add another NM copy');
        expect(p.minus[0].getAttribute('title')).toBe('Remove one NM copy');
        p.window.Backpack.setQty('uuid-1', 1);
        p.window.renderBackpack();
        expect(p.minus[0].getAttribute('title')).toBe('Remove the NM copy');
    });

    test('the search minus takes NM copies only', () => {
        const p = page({ store: [{ id: 'uuid-1', cond: 'SP', qty: 2, t: 1, m: 1 }, { id: 'uuid-1', qty: 1, t: 1, m: 1 }] });
        p.window.takeFromBackpack(p.minus[0]);
        expect(live(p)).toEqual([['uuid-1', 'SP', 2]]);
        p.window.takeFromBackpack(p.minus[0]);
        expect(live(p)).toEqual([['uuid-1', 'SP', 2]]);
        expect(p.minus[0].hidden).toBe(true);
    });

    test('undo puts back a removed grade and takes out an added one', () => {
        const p = page({ store: [{ id: 'uuid-1', cond: 'SP', qty: 2, t: 1, m: 1 }] });
        p.window.addToBackpack(p.rows[0]);
        p.window.Backpack.remove('uuid-1|SP');
        p.window.Backpack.undo();
        expect(live(p).sort()).toEqual([['uuid-1', 'NM', 1], ['uuid-1', 'SP', 2]]);
        p.window.Backpack.undo();
        expect(live(p)).toEqual([['uuid-1', 'SP', 2]]);
    });

    test('a send to empty after records keys, and Upload clears just those', () => {
        const store = [{ id: 'uuid-1', cond: 'SP', qty: 2, t: 1, m: 1 }, { id: 'uuid-1', qty: 1, t: 1, m: 1 }, { id: 'uuid-2', qty: 1, t: 2, m: 2 }];
        const p = page({ store, emptyAfter: '1' });
        p.nav.click();
        ids['backpack-send-retail'].click();
        expect(p.pendingIds()).toEqual(['uuid-2', 'uuid-1', 'uuid-1|SP']);
        const later = [...store, { id: 'uuid-1', cond: 'HP', qty: 1, t: 3, m: 3 }];
        const u = page({ store: later, pending: p.pendingIds(), ban: { canUpload: true, priced: ['uuid-2', 'uuid-1', 'uuid-1'] } });
        expect(live(u)).toEqual([['uuid-1', 'HP', 1]]);
    });
});

describe('numbered backpacks', () => {
    const live = (p) => p.stored().filter((e) => !e.del).map((e) => [e.pack, e.id, e.cond, e.qty]).sort();
    const two = [{ id: 'uuid-1', name: 'One', qty: 2, t: 1, m: 1 }, { id: 'uuid-1', name: 'Two', pack: 2, qty: 5, t: 2, m: 2 }, { id: 'uuid-2', name: 'Two B', pack: 2, qty: 1, t: 3, m: 3 }];

    test('an entry without a backpack is in backpack 1, keyed as before', () => {
        const p = page({ store: [{ id: 'uuid-1', qty: 1, t: 1, m: 1 }] });
        expect(p.window.Backpack.read()[0].pack).toBe(1);
        p.window.Backpack.setQty('uuid-1', 4);
        expect(live(p)).toEqual([[1, 'uuid-1', 'NM', 4]]);
    });

    test('the search buttons and the navbar act on the active backpack', () => {
        const p = page({ store: two, tabs: 3, active: 2 });
        expect(p.rows[0].children[0].textContent).toBe('5');
        expect(p.navCount.textContent).toBe('6');
        p.window.addToBackpack(p.rows[0]);
        p.window.takeFromBackpack(p.minus[1]);
        expect(live(p)).toEqual([[1, 'uuid-1', 'NM', 2], [2, 'uuid-1', 'NM', 6]]);
        expect(p.stored().find((e) => e.id === 'uuid-2').del).toBeDefined();
    });

    test('the add starts a card in the active backpack beside another backpack\'s copy', () => {
        const p = page({ store: [{ id: 'uuid-1', qty: 2, t: 1, m: 1 }], tabs: 2, active: 2, tabList: [{ pack: 1 }, { pack: 2 }] });
        expect(p.rows[0].classes.has('active')).toBe(false);
        p.window.addToBackpack(p.rows[0]);
        expect(live(p)).toEqual([[1, 'uuid-1', 'NM', 2], [2, 'uuid-1', 'NM', 1]]);
    });

    test('each backpack fills on its own', () => {
        const store = [];
        for (let i = 0; i < 3; i++) store.push({ id: 'c' + i, qty: 1, t: i, m: i }, { id: 'd' + i, pack: 2, qty: 1, t: i, m: i });
        const p = page({ store, max: 3, tabs: 3, active: 3, tabList: [{ pack: 1 }, { pack: 2 }, { pack: 3 }] });
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored().filter((e) => !e.del)).toHaveLength(7);
        const full = page({ store, max: 3, tabs: 3, active: 2 });
        full.window.addToBackpack(full.rows[0]);
        expect(full.stored().filter((e) => !e.del)).toHaveLength(6);
        expect(ids['backpack-toast'].textContent).toBe('Backpack is full (3 products)');
    });

    test('the panel, Clear and a send take only the active backpack', () => {
        const p = page({ store: two, tabs: 2, active: 2, emptyAfter: '1' });
        p.nav.click();
        expect(ids['backpack-panel'].querySelectorAll('.backpack-row-name').map((n) => n.textContent)).toEqual(['Two B', 'Two']);
        expect(ids['backpack-count'].textContent).toBe('6 copies of 2 products');
        ids['backpack-send-retail'].click();
        expect(submitted[0].children.filter((i) => i.name === 'hashesQtys').map((i) => i.value)).toEqual(['1', '5']);
        expect(p.pendingIds()).toEqual(['2/uuid-2', '2/uuid-1']);
        ids['backpack-clear'].click();
        expect(live(p)).toEqual([[1, 'uuid-1', 'NM', 2]]);
    });

    test('Upload empties the backpack a send came from', () => {
        const p = page({ store: two, pending: ['2/uuid-2', '2/uuid-1'], ban: { canUpload: true, priced: ['uuid-2', 'uuid-1'] } });
        expect(live(p)).toEqual([[1, 'uuid-1', 'NM', 2]]);
    });

    test('undo takes back an add to another backpack, and a grade change stays in its backpack', () => {
        const p = page({ store: two, tabs: 2, active: 2 });
        p.window.Backpack.setCond('2/uuid-2', 'SP');
        expect(live(p)).toContainEqual([2, 'uuid-2', 'SP', 1]);
        p.window.addToBackpack(p.rows[1]);
        p.window.Backpack.undo();
        p.window.Backpack.undo();
        expect(live(p)).toEqual([[1, 'uuid-1', 'NM', 2], [2, 'uuid-1', 'NM', 5], [2, 'uuid-2', 'NM', 1]]);
    });

    test('a save keeps every backpack\'s cards up to the size each', () => {
        const store = [];
        for (let i = 0; i < 4; i++) store.push({ id: 'c' + i, qty: 1, t: i, m: i }, { id: 'd' + i, pack: 2, qty: 1, t: i, m: i });
        const p = page({ store, max: 4, tabs: 2 });
        p.window.Backpack.setQty('c0', 2);
        expect(p.stored().filter((e) => !e.del)).toHaveLength(8);
    });

    test('a tier lowered to fewer backpacks keeps its newest cards up to the total', () => {
        const store = [{ id: 'a', qty: 1, t: 1, m: 1 }, { id: 'b', pack: 2, qty: 1, t: 2, m: 2 }, { id: 'c', pack: 2, qty: 1, t: 3, m: 3 }];
        const p = page({ store, max: 2, tabs: 1 });
        p.window.Backpack.setQty('2/c', 2);
        expect(p.stored().filter((e) => !e.del).map((e) => e.id).sort()).toEqual(['b', 'c']);
    });

    test('an add past the total across backpacks is refused', () => {
        const store = [{ id: 'a', qty: 1, t: 1, m: 1 }, { id: 'b', pack: 2, qty: 1, t: 2, m: 2 }, { id: 'c', pack: 2, qty: 1, t: 3, m: 3 }];
        const p = page({ store, max: 3, tabs: 1 });
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored().filter((e) => !e.del)).toHaveLength(3);
        expect(ids['backpack-toast'].textContent).toBe('Backpacks are full (3 products in all)');
    });

    test('the optimizer takes from the active backpack', () => {
        const p = page({ store: two, tabs: 2, active: 2, sections: [[['uuid-1', 2, false, 'NM']]] });
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(live(p)).toEqual([[1, 'uuid-1', 'NM', 2], [2, 'uuid-1', 'NM', 3], [2, 'uuid-2', 'NM', 1]]);
    });
});

describe('the backpack tabs', () => {
    function open(p) { p.nav.click(); return ids['backpack-panel']; }
    const strip = () => ids['backpack-tabs'];
    const tabsOf = () => strip().children.filter((b) => b.classes.has('backpack-tab'));
    const labels = () => tabsOf().map((b) => b.children[0].textContent + ':' + b.children[1].textContent + (b.getAttribute('aria-selected') === 'true' ? '*' : ''));
    const names = () => ids['backpack-list'].querySelectorAll('.backpack-row-name').map((n) => n.textContent);
    const keydown = (n, key) => { const ev = { key, prevented: false, stopped: false, preventDefault() { this.prevented = true; }, stopPropagation() { this.stopped = true; } }; (n.listeners.keydown || []).forEach((fn) => fn(ev)); return ev; };
    const two = [{ id: 'uuid-1', name: 'One', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'Two', pack: 2, qty: 3, t: 2, m: 2 }];

    test('one backpack and no room for another shows no strip', () => {
        open(page({ store: two.slice(0, 1) }));
        expect(strip().hidden).toBe(true);
    });

    test('a tier with room shows the one backpack and a +', () => {
        open(page({ store: two.slice(0, 1), tabs: 3 }));
        expect(strip().hidden).toBe(false);
        expect(strip().getAttribute('role')).toBe('tablist');
        expect(labels()).toEqual(['Backpack 1:2*']);
        expect(ids['backpack-tab-add'].getAttribute('aria-label')).toBe('Add a backpack');
    });

    test('+ opens an empty backpack the search add then fills', () => {
        const p = page({ store: two.slice(0, 1), tabs: 2 });
        open(p);
        ids['backpack-tab-add'].click();
        expect(labels()).toEqual(['Backpack 1:2', 'Backpack 2:0*']);
        expect(names()).toEqual([]);
        expect(strip().children.some((b) => b.classes.has('backpack-tab-add'))).toBe(false);
        expect(p.document.activeElement).toBe(tabsOf()[1]);
        p.window.addToBackpack(p.rows[1]);
        expect(labels()).toEqual(['Backpack 1:2', 'Backpack 2:1*']);
        expect(p.navCount.textContent).toBe('1');
        expect(p.stored().find((e) => e.id === 'uuid-2').pack).toBe(2);
    });

    test('picking a tab shows its backpack and moves the search buttons to it', () => {
        const p = page({ store: two, tabs: 2 });
        open(p);
        expect(names()).toEqual(['One']);
        tabsOf()[1].click();
        expect(names()).toEqual(['Two']);
        expect(labels()).toEqual(['Backpack 1:2', 'Backpack 2:3*']);
        expect(p.m.mtgban_backpack_active).toBe('2');
        expect(p.rows[0].classes.has('active')).toBe(false);
        expect(p.rows[1].children[0].textContent).toBe('3');
        expect(p.navCount.textContent).toBe('3');
    });

    test('the arrow keys move along the tabs', () => {
        const p = page({ store: two, tabs: 3 });
        open(p);
        expect(keydown(tabsOf()[0], 'ArrowRight').prevented).toBe(true);
        expect(p.m.mtgban_backpack_active).toBe('2');
        expect(p.document.activeElement).toBe(tabsOf()[1]);
        keydown(tabsOf()[1], 'ArrowRight');
        expect(p.m.mtgban_backpack_active).toBe('1');
        keydown(tabsOf()[0], 'ArrowLeft');
        expect(p.m.mtgban_backpack_active).toBe('2');
    });

    test('a backpack with cards the synced list lacks still has a tab', () => {
        open(page({ store: two, tabs: 1, tabList: [{ pack: 1, name: 'Trades' }] }));
        expect(strip().hidden).toBe(false);
        expect(labels()).toEqual(['Trades:2*', 'Backpack 2:3']);
        expect(strip().children.some((b) => b.classes.has('backpack-tab-add'))).toBe(false);
    });

    test('clicking the open tab renames it; Enter saves and Escape keeps the name', () => {
        const p = page({ store: two, tabs: 2 });
        open(p);
        tabsOf()[0].click();
        let field = strip().children[0];
        expect(field.getAttribute('aria-label')).toBe('Backpack name');
        expect(p.document.activeElement).toBe(field);
        field.value = '  Trade binder  ';
        keydown(field, 'Enter');
        expect(labels()[0]).toBe('Trade binder:2*');
        expect(JSON.parse(p.m.mtgban_backpack_tabs)).toEqual([{ pack: 1, name: 'Trade binder' }, { pack: 2, name: 'Backpack 2' }]);
        expect(p.document.activeElement).toBe(tabsOf()[0]);
        tabsOf()[0].click();
        field = strip().children[0];
        field.value = 'Nope';
        const ev = keydown(field, 'Escape');
        expect(ev.stopped).toBe(true);
        expect(labels()[0]).toBe('Trade binder:2*');
        expect(ids['backpack-panel'].classes.has('open')).toBe(true);
    });

    test('leaving the field saves, and a blank or long name is held', () => {
        const p = page({ store: two, tabs: 2 });
        open(p);
        tabsOf()[0].click();
        let field = strip().children[0];
        field.value = 'x'.repeat(50);
        (field.listeners.blur || []).forEach((fn) => fn());
        expect(labels()[0]).toBe('x'.repeat(40) + ':2*');
        tabsOf()[0].click();
        field = strip().children[0];
        field.value = '   ';
        keydown(field, 'Enter');
        expect(labels()[0]).toBe('x'.repeat(40) + ':2*');
    });

    test('deleting a backpack with cards asks, drops it and its cards, and undo brings both back', () => {
        const p = page({ store: two, tabs: 2, active: 2, tabList: [{ pack: 1 }, { pack: 2, name: 'Trades' }] });
        open(p);
        const del = strip().children.find((b) => b.classes.has('backpack-tab-del'));
        expect(del.getAttribute('aria-label')).toBe('Delete Trades');
        del.click();
        expect(confirms).toEqual(['Delete Trades and its 1 product?']);
        expect(labels()).toEqual(['Backpack 1:2*']);
        expect(p.stored().find((e) => e.id === 'uuid-2').del).toBeDefined();
        ids['backpack-undo'].click();
        expect(labels()).toEqual(['Backpack 1:2', 'Trades:3*']);
        expect(names()).toEqual(['Two']);
    });

    test('an empty backpack goes without asking, and the last one has no ×', () => {
        const p = page({ store: two.slice(0, 1), tabs: 2, active: 2, tabList: [{ pack: 1 }, { pack: 2 }] });
        open(p);
        strip().children.find((b) => b.classes.has('backpack-tab-del')).click();
        expect(confirms).toEqual([]);
        expect(labels()).toEqual(['Backpack 1:2*']);
        expect(strip().children.some((b) => b.classes.has('backpack-tab-del'))).toBe(false);
    });

    test('undo opens the backpack its step changed', () => {
        const p = page({ store: two, tabs: 2 });
        open(p);
        p.window.Backpack.setQty('2/uuid-2', 9);
        expect(names()).toEqual(['One']);
        ids['backpack-undo'].click();
        expect(labels()).toEqual(['Backpack 1:2', 'Backpack 2:3*']);
    });

    test('another window changing the tabs re-renders', () => {
        const p = page({ store: two, tabs: 2 });
        open(p);
        p.m.mtgban_backpack_active = '2';
        p.fireStorage('mtgban_backpack_active');
        expect(names()).toEqual(['Two']);
        p.m.mtgban_backpack_tabs = JSON.stringify([{ pack: 1, name: 'A' }, { pack: 2, name: 'B' }]);
        p.fireStorage('mtgban_backpack_tabs');
        expect(labels()).toEqual(['A:2', 'B:3*']);
    });
});

describe('taking from the backpack a send came from', () => {
    const live = (p) => p.stored().filter((e) => !e.del).map((e) => [e.pack, e.id, e.qty]).sort();
    const store = [{ id: 'uuid-1', qty: 2, t: 1, m: 1 }, { id: 'uuid-1', pack: 2, qty: 3, t: 2, m: 2 }];
    const tabList = [{ pack: 1 }, { pack: 2, name: 'Trades' }];

    // sent sends backpack 2 and returns the session the Upload page opens with.
    function sent() {
        const p = page({ store, tabs: 2, active: 2, tabList });
        p.nav.click();
        ids['backpack-send-retail'].click();
        return p.sm;
    }

    test('the Upload page showing the send takes from its backpack, whatever tab is open', () => {
        const session = sent();
        const p = page({ store, tabs: 2, active: 1, tabList, session, ban: { canUpload: true, priced: ['uuid-1'] }, sections: [[['uuid-1', 1, false, 'NM']]] });
        expect(p.optSections[0].take.hidden).toBe(false);
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(confirms).toEqual(["Remove this store's ticked cards from Trades?"]);
        expect(live(p)).toEqual([[1, 'uuid-1', 2], [2, 'uuid-1', 2]]);
        expect(ids['backpack-toast'].textContent).toBe('Removed 1 copy from Trades');
    });

    test('a page posting itself back still takes from the backpack sent', () => {
        const session = sent();
        page({ store, tabs: 2, active: 1, tabList, session, ban: { canUpload: true, priced: ['uuid-1'] } });
        const p = page({ store, tabs: 2, active: 1, tabList, session, ban: { canUpload: true, priced: ['uuid-1'] }, sections: [[['uuid-1', 1, false, 'NM']]] });
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(live(p)).toEqual([[1, 'uuid-1', 2], [2, 'uuid-1', 2]]);
    });

    test('an Upload page of other cards takes from the open backpack', () => {
        const session = sent();
        const p = page({ store, tabs: 2, active: 1, tabList, session, ban: { canUpload: true, priced: ['uuid-1', 'uuid-9'] }, sections: [[['uuid-1', 1, false, 'NM']]] });
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(live(p)).toEqual([[1, 'uuid-1', 1], [2, 'uuid-1', 3]]);
    });
});

describe('moving cards between backpacks', () => {
    function open(p) { p.nav.click(); return ids['backpack-panel']; }
    const live = (p) => p.stored().filter((e) => !e.del).map((e) => [e.pack, e.id, e.cond, e.qty]).sort();
    const rowsOf = () => ids['backpack-list'].children;
    const tabsOf = () => ids['backpack-tabs'].children.filter((b) => b.classes.has('backpack-tab'));
    const fire = (n, type, ev) => (n.listeners[type] || []).forEach((fn) => fn(ev));
    const pick = (sel, v) => { sel.value = v; fire(sel, 'change'); };
    const moves = (sel) => sel.children.filter((g) => g.tag === 'optgroup' && g.getAttribute('label') === 'Move to').flatMap((g) => g.children.map((o) => o.value + ':' + o.textContent));
    const transfer = (types = []) => ({ types, data: {}, setData(t, v) { this.data[t] = v; this.types = [t]; }, getData(t) { return this.data[t]; } });
    const dragEvent = (dt) => ({ dataTransfer: dt, prevented: false, preventDefault() { this.prevented = true; } });
    const tabList = [{ pack: 1 }, { pack: 2, name: 'Trades' }, { pack: 3 }];
    const store = [{ id: 'uuid-1', name: 'One', qty: 2, t: 2, m: 2 }, { id: 'uuid-2', name: 'Two', cond: 'SP', qty: 1, t: 1, m: 1 }, { id: 'uuid-1', name: 'One', pack: 2, qty: 3, t: 1, m: 1 }];

    test('one backpack has nothing to move to', () => {
        const p = page({ store: store.slice(0, 2) });
        open(p);
        expect(rowsOf()[0].querySelector('.backpack-row-art').getAttribute('draggable')).toBeNull();
        expect(moves(rowsOf()[0].querySelector('.backpack-cond'))).toEqual([]);
    });

    test('the dropdown moves every copy to another backpack, joining what is there', () => {
        const p = page({ store, tabs: 3, tabList });
        open(p);
        const sel = rowsOf()[0].querySelector('.backpack-cond');
        expect(moves(sel)).toEqual(['@2:Trades', '@3:Backpack 3']);
        pick(sel, '@2');
        expect(live(p)).toEqual([[1, 'uuid-2', 'SP', 1], [2, 'uuid-1', 'NM', 5]]);
        expect(ids['backpack-toast'].textContent).toBe('Moved to Trades');
        expect(tabsOf().map((b) => b.children[1].textContent)).toEqual(['1', '5', '0']);
        expect(p.m.mtgban_backpack_active).toBeUndefined();
        expect(p.document.activeElement).toBe(tabsOf()[0]);
    });

    test('a row dragged by its art onto another tab moves there', () => {
        const p = page({ store, tabs: 3, tabList });
        open(p);
        const row = rowsOf()[1];
        const art = row.querySelector('.backpack-row-art');
        expect(row.getAttribute('draggable')).toBeNull();
        expect(art.getAttribute('draggable')).toBe('true');
        const dt = transfer();
        fire(art, 'dragstart', dragEvent(dt));
        expect(row.classes.has('dragging')).toBe(true);
        const target = tabsOf()[2];
        const over = dragEvent(dt);
        fire(target, 'dragover', over);
        expect(over.prevented).toBe(true);
        expect(target.classes.has('drop-target')).toBe(true);
        fire(target, 'drop', dragEvent(dt));
        expect(live(p)).toEqual([[1, 'uuid-1', 'NM', 2], [2, 'uuid-1', 'NM', 3], [3, 'uuid-2', 'SP', 1]]);
        expect(ids['backpack-toast'].textContent).toBe('Moved to Backpack 3');
    });

    test('a tab takes no other drag, and the open tab takes none', () => {
        const p = page({ store, tabs: 3, tabList });
        open(p);
        const over = dragEvent(transfer(['text/plain']));
        fire(tabsOf()[1], 'dragover', over);
        expect(over.prevented).toBe(false);
        expect(tabsOf()[0].listeners.dragover).toBeUndefined();
    });

    test('a full backpack refuses a new card but takes more copies of one it holds', () => {
        const full = [{ id: 'a', pack: 2, qty: 1, t: 1, m: 1 }, { id: 'uuid-1', pack: 2, qty: 997, t: 1, m: 1 }];
        const p = page({ store: [{ id: 'uuid-1', qty: 2, t: 2, m: 2 }, { id: 'uuid-2', qty: 1, t: 1, m: 1 }, ...full], max: 2, tabs: 2, tabList });
        expect(p.window.Backpack.moveTo('uuid-2', 2)).toBe(false);
        expect(ids['backpack-toast'].textContent).toBe('Trades is full (2 products)');
        expect(p.window.Backpack.moveTo('uuid-1', 2)).toBe(true);
        expect(live(p)).toEqual([[1, 'uuid-2', 'NM', 1], [2, 'a', 'NM', 1], [2, 'uuid-1', 'NM', 999]]);
    });

    test('a move that would pass 999 copies is refused with the ceiling', () => {
        const p = page({ store: [{ id: 'uuid-1', qty: 2, t: 2, m: 2 }, { id: 'uuid-1', pack: 2, qty: 998, t: 1, m: 1 }], tabs: 2, tabList });
        const before = p.m.mtgban_backpack;
        expect(p.window.Backpack.moveTo('uuid-1', 2)).toBe(false);
        expect(p.m.mtgban_backpack).toBe(before);
        expect(ids['backpack-toast'].textContent).toBe('999 copies is the most for one product');
    });

    test('a refused drop clears the tab\'s outline', () => {
        const p = page({ store: [{ id: 'uuid-1', qty: 2, t: 2, m: 2 }, { id: 'uuid-1', pack: 2, qty: 998, t: 1, m: 1 }], tabs: 2, tabList });
        open(p);
        const dt = transfer();
        fire(rowsOf()[0].querySelector('.backpack-row-art'), 'dragstart', dragEvent(dt));
        const target = tabsOf()[1];
        fire(target, 'dragover', dragEvent(dt));
        fire(target, 'drop', dragEvent(dt));
        expect(target.classes.has('drop-target')).toBe(false);
    });

    test('undo puts a moved card back where it was', () => {
        const p = page({ store, tabs: 3, tabList });
        p.window.Backpack.moveTo('uuid-2|SP', 3);
        p.window.Backpack.undo();
        expect(live(p)).toEqual([[1, 'uuid-1', 'NM', 2], [1, 'uuid-2', 'SP', 1], [2, 'uuid-1', 'NM', 3]]);
    });
});

describe('the condition dropdown', () => {
    function open(p) { p.nav.click(); return ids['backpack-panel']; }
    const live = (p) => p.stored().filter((e) => !e.del).map((e) => [e.id, e.cond, e.qty]).sort();
    const selects = (panel) => panel.querySelectorAll('.backpack-cond');
    const pick = (sel, v) => { sel.value = v; (sel.listeners.change || []).forEach((fn) => fn()); };
    const choices = (sel) => sel.children.filter((o) => o.tag === 'option').map((o) => o.value);
    const adds = (sel) => sel.children.filter((o) => o.tag === 'optgroup').flatMap((g) => g.children.map((o) => [o.value, o.textContent]));

    test('offers every grade, NM picked, and to add the card in the others', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        const sel = selects(open(p))[0];
        expect(sel.getAttribute('aria-label')).toBe('Condition');
        expect(sel.value).toBe('NM');
        expect(choices(sel)).toEqual(['NM', 'SP', 'MP', 'HP', 'PO']);
        expect(sel.children[0].getAttribute('title')).toBe('Near Mint');
        expect(sel.children.find((o) => o.tag === 'optgroup').getAttribute('label')).toBe('Add another condition');
        expect(adds(sel)).toEqual([['+SP', 'Also as SP'], ['+MP', 'Also as MP'], ['+HP', 'Also as HP'], ['+PO', 'Also as PO']]);
    });

    test('a grade another entry of the card holds is not offered', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }, { id: 'uuid-1', name: 'A', cond: 'MP', qty: 1, t: 1, m: 1 }, { id: 'uuid-2', name: 'B', cond: 'SP', qty: 1, t: 0, m: 0 }] });
        const [nm, mp] = selects(open(p));
        expect(mp.value).toBe('MP');
        expect(choices(nm)).toEqual(['NM', 'SP', 'HP', 'PO']);
        expect(choices(mp)).toEqual(['SP', 'MP', 'HP', 'PO']);
        expect(adds(nm).map((a) => a[0])).toEqual(['+SP', '+HP', '+PO']);
    });

    test('with every grade held there is nothing to add', () => {
        const store = ['NM', 'SP', 'MP', 'HP', 'PO'].map((cond) => ({ id: 'uuid-1', name: 'A', cond, qty: 1, t: 1, m: 1 }));
        const sel = selects(open(page({ store })))[0];
        expect(choices(sel)).toEqual(['NM']);
        expect(adds(sel)).toEqual([]);
    });

    test('picking a grade moves the entry with its copies and place, and keeps focus on it', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 3, t: 5, m: 5 }, { id: 'uuid-2', name: 'B', qty: 1, t: 1, m: 1 }] });
        const panel = open(p);
        pick(selects(panel)[0], 'HP');
        expect(live(p)).toEqual([['uuid-1', 'HP', 3], ['uuid-2', 'NM', 1]]);
        expect(p.stored().find((e) => e.id === 'uuid-1' && !e.del).t).toBe(5);
        expect(p.stored().find((e) => e.id === 'uuid-1' && e.del).cond).toBe('NM');
        expect(panel.querySelectorAll('.backpack-row-name').map((n) => n.textContent)).toEqual(['A', 'B']);
        expect(selects(panel)[0].value).toBe('HP');
        expect(p.document.activeElement).toBe(selects(panel)[0]);
        expect(p.rows[0].classes.has('active')).toBe(true);
        expect(p.minus[0].hidden).toBe(true);
    });

    test('picking an add puts one copy in that grade beside the entry', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 3, t: 5, m: 5 }, { id: 'uuid-2', name: 'B', qty: 1, t: 9, m: 9 }] });
        const panel = open(p);
        pick(selects(panel)[1], '+MP');
        expect(live(p)).toEqual([['uuid-1', 'MP', 1], ['uuid-1', 'NM', 3], ['uuid-2', 'NM', 1]]);
        const sels = selects(panel);
        expect(sels.map((x) => x.value)).toEqual(['NM', 'NM', 'MP']);
        expect(p.document.activeElement).toBe(sels[1]);
        expect(choices(sels[1])).toEqual(['NM', 'SP', 'HP', 'PO']);
        expect(ids['backpack-count'].textContent).toBe('5 copies of 3 products');
    });

    test('an add into a full backpack toasts and writes nothing', () => {
        const store = [];
        for (let i = 0; i < 100; i++) store.push({ id: i === 0 ? 'uuid-1' : 'c' + i, name: 'c', qty: 1, t: i, m: i });
        const p = page({ store });
        const before = p.m.mtgban_backpack;
        expect(p.window.Backpack.addCond('uuid-1', 'SP')).toBe(false);
        expect(p.m.mtgban_backpack).toBe(before);
        expect(ids['backpack-toast'].textContent).toBe('Backpack is full (100 products)');
    });

    test('NM to SP and back leaves one live NM entry, and undo walks it back', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        p.window.Backpack.setCond('uuid-1', 'SP');
        p.window.Backpack.setCond('uuid-1|SP', 'NM');
        expect(live(p)).toEqual([['uuid-1', 'NM', 2]]);
        expect(p.stored().filter((e) => e.cond === 'NM')).toHaveLength(1);
        p.window.Backpack.undo();
        expect(live(p)).toEqual([['uuid-1', 'SP', 2]]);
        p.window.Backpack.undo();
        expect(live(p)).toEqual([['uuid-1', 'NM', 2]]);
        expect(p.window.Backpack.undo()).toBe(false);
    });

    test('moving into a grade the card already holds adds the copies to it', () => {
        const p = page({ store: [{ id: 'uuid-1', qty: 2, t: 1, m: 1 }, { id: 'uuid-1', cond: 'SP', qty: 997, t: 1, m: 1 }] });
        p.window.Backpack.setCond('uuid-1', 'SP');
        expect(live(p)).toEqual([['uuid-1', 'SP', 999]]);
        p.window.Backpack.undo();
        expect(live(p)).toEqual([['uuid-1', 'NM', 2], ['uuid-1', 'SP', 997]]);
    });

    test('Tab moves through the dropdown inside the panel', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        const sel = selects(open(p))[0];
        sel.focus();
        expect(p.key('Tab')).toBe(false);
        expect(p.key('Tab', true)).toBe(false);
    });
});

describe('the panel', () => {
    function open(p) { p.nav.click(); return ids['backpack-panel']; }

    test('opens with one row per live entry, newest first, and the count line', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'Old', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'New', qty: 1, t: 5, m: 5 }] });
        const panel = open(p);
        expect(panel.classes.has('open')).toBe(true);
        expect(p.nav.getAttribute('aria-expanded')).toBe('true');
        const names = panel.querySelectorAll('.backpack-row-name').map((n) => n.textContent);
        expect(names).toEqual(['New', 'Old']);
        expect(ids['backpack-count'].textContent).toBe('3 copies of 2 products');
        expect(ids['backpack-send-retail'].disabled).toBe(false);
    });

    test('plus and minus change the store; minus at 1 removes', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'B', qty: 1, t: 2, m: 2 }] });
        const panel = open(p);
        expect(panel.querySelectorAll('.backpack-remove')).toEqual([]);
        panel.querySelectorAll('.backpack-plus')[1].click();   // A (second row, older)
        expect(p.stored().find((e) => e.id === 'uuid-1').qty).toBe(3);
        panel.querySelectorAll('.backpack-minus')[0].click();  // B at 1
        expect(p.stored().find((e) => e.id === 'uuid-2').del).toBeDefined();
        for (let i = 0; i < 3; i++) panel.querySelectorAll('.backpack-minus')[0].click(); // A is the only row now
        expect(p.stored().filter((e) => !e.del).length).toBe(0);
        expect(ids['backpack-list'].querySelectorAll('.backpack-row').length).toBe(0);
        expect(ids['backpack-send-retail'].disabled).toBe(true);
        expect(ids['backpack-empty'].textContent).toBe('Add products from any search with the backpack button.');
    });

    test('the minus is named Remove when it would take the last copy', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        const panel = open(p);
        expect(panel.querySelectorAll('.backpack-minus')[0].getAttribute('aria-label')).toBe('One fewer');
        panel.querySelectorAll('.backpack-minus')[0].click();
        expect(panel.querySelectorAll('.backpack-minus')[0].getAttribute('aria-label')).toBe('Remove');
    });

    test('plus at the 999 ceiling toasts without writing', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 999, t: 1, m: 1 }] });
        const toast = el('div'); toast.setAttribute('id', 'desktop-fav-toast'); p.document.body.appendChild(toast);
        const panel = open(p);
        const before = p.m.mtgban_backpack;
        panel.querySelectorAll('.backpack-plus')[0].click();
        expect(p.m.mtgban_backpack).toBe(before);
        expect(toast.textContent).toBe('999 copies is the most for one product');
        expect(panel.querySelectorAll('.backpack-qty')[0].textContent).toBe('999');
    });

    test('Clear tombstones everything after a confirm', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        open(p);
        ids['backpack-clear'].click();
        expect(confirms).toEqual(['Empty the backpack?']);
        expect(p.stored().every((e) => e.del)).toBe(true);
        expect(p.nav.hidden).toBe(false);
        expect(p.navCount.hidden).toBe(true);
    });

    test('a declined confirm leaves the store untouched', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        p.window.confirm = (msg) => { confirms.push(msg); return false; };
        open(p);
        const before = p.m.mtgban_backpack;
        ids['backpack-clear'].click();
        expect(confirms).toEqual(['Empty the backpack?']);
        expect(p.m.mtgban_backpack).toBe(before);
    });

    test('Clear asks through confirmDialog when the page has it', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        const asked = [];
        p.window.confirmDialog = (msg, onOk, opts) => { asked.push([msg, opts.anchor]); onOk(); };
        const panel = open(p);
        ids['backpack-clear'].click();
        expect(asked).toEqual([['Empty the backpack?', panel]]);
        expect(confirms).toEqual([]);
        expect(p.stored().every((e) => e.del)).toBe(true);
    });

    test('Escape closes only an open panel, gives focus back to the navbar button, and waits on the dialog', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        p.key('Escape');
        expect(p.document.activeElement).toBe(null);
        const panel = open(p);
        const dialog = el('div'); dialog.setAttribute('id', 'ban-confirm-dialog'); p.document.body.appendChild(dialog);
        p.key('Escape');
        expect(panel.classes.has('open')).toBe(true);
        dialog.hidden = true;
        p.key('Escape');
        expect(panel.classes.has('open')).toBe(false);
        expect(p.nav.getAttribute('aria-expanded')).toBe('false');
        expect(p.document.activeElement).toBe(p.nav);
    });

    test('a Clear of a full backpack keeps a tombstone for each card', () => {
        const store = [];
        for (let i = 0; i < 100; i++) store.push({ id: 'c' + i, name: 'c', qty: 1, t: i, m: i });
        const p = page({ store });
        open(p);
        ids['backpack-clear'].click();
        expect(p.stored()).toHaveLength(100);
        expect(p.stored().every((e) => e.del)).toBe(true);
    });

    test('a storage event from another tab re-renders', () => {
        const p = page({ store: [] });
        open(p);
        p.m.mtgban_backpack = JSON.stringify([{ id: 'uuid-1', name: 'A', qty: 5, t: 1, m: 1 }]);
        p.fireStorage();
        expect(p.navCount.textContent).toBe('5');
        expect(ids['backpack-list'].querySelectorAll('.backpack-row').length).toBe(1);
    });

    test('a storage event for another key does not re-render', () => {
        const p = page({ store: [] });
        p.m.mtgban_backpack = JSON.stringify([{ id: 'uuid-1', name: 'A', qty: 5, t: 1, m: 1 }]);
        p.fireStorage('something_else');
        expect(p.navCount.textContent).toBe('0');
    });

    test('the open panel is modal and Tab wraps inside it', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        const panel = open(p);
        expect(panel.getAttribute('aria-modal')).toBe('true');
        expect(p.document.activeElement).toBe(ids['backpack-close']);
        ids['backpack-send-buylist'].focus();
        expect(p.key('Tab')).toBe(true);
        expect(p.document.activeElement).toBe(ids['backpack-close']);
        expect(p.key('Tab', true)).toBe(true);
        expect(p.document.activeElement).toBe(ids['backpack-send-buylist']);
        ids['backpack-clear'].focus();
        expect(p.key('Tab')).toBe(false);
    });

    test('a hidden confirm dialog inside the panel stays out of the Tab trap', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        const panel = open(p);
        const dlg = p.document.createElement('div'); dlg.setAttribute('id', 'ban-confirm-dialog'); dlg.hidden = true;
        dlg.appendChild(p.document.createElement('button'));
        panel.appendChild(dlg);
        ids['backpack-send-buylist'].focus();
        expect(p.key('Tab')).toBe(true);
        expect(p.document.activeElement).toBe(ids['backpack-close']);
    });

    test('a closed panel leaves Tab alone', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        open(p);
        p.key('Escape');
        expect(p.key('Tab')).toBe(false);
    });

    test('the mobile body gets the sheet class', () => {
        const p = page({ mobile: true });
        const panel = open(p);
        expect(panel.classes.has('backpack-sheet')).toBe(true);
        expect(panel.classes.has('m-drawer')).toBe(false);
    });
});

describe('undo', () => {
    function open(p) { p.nav.click(); return ids['backpack-panel']; }
    const live = (p) => p.stored().filter((e) => !e.del);

    test('undoing a tap that added a card takes it out again', () => {
        const p = page();
        p.window.addToBackpack(p.rows[0]);
        expect(p.window.Backpack.undo()).toBe(true);
        expect(live(p)).toEqual([]);
        p.window.renderBackpack();
        expect(p.rows[0].classes.has('active')).toBe(false);
    });

    test('undoing a tap that added a copy takes just that copy out', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 4, t: 1, m: 1 }] });
        p.window.addToBackpack(p.rows[0]);
        p.window.Backpack.undo();
        expect(live(p).map((e) => [e.id, e.qty, e.t])).toEqual([['uuid-1', 4, 1]]);
    });

    test('undoing the minus that took the last copy brings the card back', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 1, t: 1, m: 1 }] });
        p.window.takeFromBackpack(p.minus[0]);
        p.window.Backpack.undo();
        expect(live(p).map((e) => [e.id, e.qty, e.t])).toEqual([['uuid-1', 1, 1]]);
    });

    test('quantity changes and removals step back one at a time', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        p.window.Backpack.setQty('uuid-1', 3);
        p.window.Backpack.remove('uuid-1');
        p.window.Backpack.undo();
        expect(live(p).map((e) => e.qty)).toEqual([3]);
        p.window.Backpack.undo();
        expect(live(p).map((e) => e.qty)).toEqual([2]);
        expect(p.window.Backpack.undo()).toBe(false);
    });

    test('a change that changes nothing leaves no step', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        p.window.Backpack.setQty('uuid-1', 2);
        p.window.Backpack.clear(['nope']);
        expect(p.window.Backpack.undo()).toBe(false);
    });

    test('undoing a Clear brings back every card', () => {
        const p = page({ store: [{ id: 'a', name: 'A', qty: 2, t: 3, m: 3 }, { id: 'b', name: 'B', qty: 1, t: 2, m: 2 }, { id: 'c', name: 'C', qty: 5, t: 1, m: 1 }] });
        p.window.Backpack.clear();
        p.window.Backpack.undo();
        expect(live(p).map((e) => [e.id, e.qty]).sort()).toEqual([['a', 2], ['b', 1], ['c', 5]]);
        expect(p.window.Backpack.read().filter((e) => !e.del).sort((x, y) => y.t - x.t).map((e) => e.id)).toEqual(['a', 'b', 'c']);
    });

    test('a restored card is stamped after the removal, so the sync merge keeps it', async () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 1, t: 1, m: 1 }] });
        p.window.takeFromBackpack(p.minus[0]);
        const removed = p.stored()[0].m;
        await new Promise((r) => setTimeout(r, 2));
        p.window.Backpack.undo();
        const e = p.stored()[0];
        expect(e.del).toBeUndefined();
        expect(e.m).toBeGreaterThan(removed);
    });

    test('the steps outlive a page load in the same tab', () => {
        const first = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }] });
        first.window.addToBackpack(first.rows[0]);
        const next = page({ store: first.stored(), session: first.sm });
        next.window.Backpack.undo();
        expect(live(next).map((e) => e.qty)).toEqual([2]);
    });

    test('only the last 20 steps are kept', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 1, t: 1, m: 1 }] });
        for (let q = 2; q <= 30; q++) p.window.Backpack.setQty('uuid-1', q);
        let n = 0;
        while (p.window.Backpack.undo()) n++;
        expect(n).toBe(20);
        expect(live(p)[0].qty).toBe(10);
    });

    test('the panel Undo button is off until there is a step, and takes it back', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 1, t: 1, m: 1 }] });
        const panel = open(p);
        expect(ids['backpack-undo'].disabled).toBe(true);
        panel.querySelectorAll('.backpack-minus')[0].click();
        expect(panel.querySelectorAll('.backpack-row')).toEqual([]);
        expect(ids['backpack-undo'].disabled).toBe(false);
        ids['backpack-undo'].click();
        expect(panel.querySelectorAll('.backpack-qty')[0].textContent).toBe('1');
        expect(p.navCount.textContent).toBe('1');
        expect(ids['backpack-undo'].disabled).toBe(true);
    });
});

describe('sending', () => {
    test('Retail posts hashes and quantities in order, keeping the backpack', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'B', qty: 1, t: 2, m: 2 }] });
        p.nav.click();
        ids['backpack-send-retail'].click();
        expect(submitted.length).toBe(1);
        const form = submitted[0];
        expect(form.getAttribute('action')).toBe('/upload');
        const inputs = form.children.map((i) => [i.name, i.value]);
        expect(inputs).toEqual([['mode', 'false'], ['hashes', 'uuid-2'], ['hashesQtys', '1'], ['hashesCond', 'NM'], ['hashes', 'uuid-1'], ['hashesQtys', '2'], ['hashesCond', 'NM']]);
        expect(p.stored().filter((e) => !e.del).length).toBe(2);
    });

    test('Buylist with the switch on keeps the backpack and records the cards sent', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'B', qty: 1, t: 2, m: 2 }], emptyAfter: '1' });
        p.nav.click();
        expect(ids['backpack-empty-after'].checked).toBe(true);
        let liveAtSubmit = null;
        submitHook = () => { liveAtSubmit = p.stored().filter((e) => !e.del).length; };
        ids['backpack-send-buylist'].click();
        expect(liveAtSubmit).toBe(2);
        expect(submitted[0].children[0].value).toBe('true');
        expect(submitted[0].children.length).toBe(7);
        expect(p.stored().filter((e) => !e.del).length).toBe(2);
        expect(p.pendingIds()).toEqual(['uuid-2', 'uuid-1']);
    });

    test('a send with the switch off drops an earlier request to empty', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }], pending: ['uuid-1'] });
        p.nav.click();
        ids['backpack-send-retail'].click();
        expect(submitted.length).toBe(1);
        expect(p.pendingIds()).toBeUndefined();
    });

    test('a reader without Upload gets disabled buttons and sends nothing', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }], emptyAfter: '1', ban: { canUpload: false } });
        p.nav.click();
        for (const id of ['backpack-send-retail', 'backpack-send-buylist']) {
            expect(ids[id].disabled).toBe(true);
            expect(ids[id].getAttribute('title')).toBe('Upload needs a higher tier');
            ids[id].click();
        }
        expect(ids['backpack-empty-after'].disabled).toBe(true);
        expect(submitted).toEqual([]);
        expect(p.stored().filter((e) => !e.del).length).toBe(1);
    });

    test('a reader with Upload sends as without BAN_BACKPACK', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }], ban: { canUpload: true } });
        p.nav.click();
        expect(ids['backpack-send-retail'].disabled).toBe(false);
        expect(ids['backpack-send-retail'].getAttribute('title')).toBeNull();
        expect(ids['backpack-empty-after'].disabled).toBe(false);
        ids['backpack-send-retail'].click();
        expect(submitted.length).toBe(1);
    });

    test('the switch is remembered locally', () => {
        const p = page();
        p.nav.click();
        const sw = ids['backpack-empty-after'];
        sw.checked = true;
        (sw.listeners.change || []).forEach((fn) => fn());
        expect(p.m.mtgban_backpack_empty_after).toBe('1');
    });
});

describe('on the Upload page', () => {
    const store = [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'B', qty: 1, t: 2, m: 2 }];

    test('results for the cards sent empty the backpack', () => {
        const p = page({ store, pending: ['uuid-2', 'uuid-1'], ban: { canUpload: true, priced: ['uuid-2', 'uuid-1'] } });
        expect(p.stored().every((e) => e.del)).toBe(true);
        expect(p.navCount.hidden).toBe(true);
        expect(p.pendingIds()).toBeUndefined();
    });

    test('a card added after the send stays', () => {
        const p = page({ store: [...store, { id: 'uuid-3', name: 'C', qty: 1, t: 3, m: 3 }], pending: ['uuid-2', 'uuid-1'], ban: { canUpload: true, priced: ['uuid-2', 'uuid-1'] } });
        expect(p.stored().filter((e) => !e.del).map((e) => e.id)).toEqual(['uuid-3']);
        expect(p.navCount.textContent).toBe('1');
    });

    test('a page without results keeps the backpack and drops the request', () => {
        const p = page({ store, pending: ['uuid-2', 'uuid-1'], ban: { canUpload: true, priced: null } });
        expect(p.stored().filter((e) => !e.del).length).toBe(2);
        expect(p.navCount.textContent).toBe('3');
        expect(p.pendingIds()).toBeUndefined();
    });

    test('results for other cards keep the backpack', () => {
        const p = page({ store, pending: ['uuid-2', 'uuid-1'], ban: { canUpload: true, priced: ['uuid-9'] } });
        expect(p.stored().filter((e) => !e.del).length).toBe(2);
        expect(p.pendingIds()).toBeUndefined();
    });

    test('results with no request to empty keep the backpack', () => {
        const p = page({ store, ban: { canUpload: true, priced: ['uuid-2', 'uuid-1'] } });
        expect(p.stored().filter((e) => !e.del).length).toBe(2);
    });

    test('the search page leaves the request for Upload', () => {
        const p = page({ store, pending: ['uuid-2', 'uuid-1'], ban: { canUpload: true } });
        expect(p.stored().filter((e) => !e.del).length).toBe(2);
        expect(p.pendingIds()).toEqual(['uuid-2', 'uuid-1']);
    });

    test('Back to a cached search page shows the backpack Upload emptied', () => {
        const p = page({ store, emptyAfter: '1' });
        p.nav.click();
        ids['backpack-send-retail'].click();
        // The Upload page empties the shared store while this one sits in the cache.
        p.m.mtgban_backpack = JSON.stringify(store.map((e) => ({ ...e, del: 9, m: 9 })));
        p.firePageshow(true);
        expect(p.navCount.hidden).toBe(true);
        expect(ids['backpack-list'].querySelectorAll('.backpack-row').length).toBe(0);
        expect(ids['backpack-send-retail'].disabled).toBe(true);
    });
});

describe('taking an Upload store section out', () => {
    const live = (p) => p.stored().filter((e) => !e.del).map((e) => [e.id, e.qty]);

    test('shows only while a ticked row is a card in the backpack', () => {
        const p = page({
            store: [{ id: 'a', name: 'A', qty: 2, t: 1, m: 1 }],
            sections: [[['a', 1], ['b', 1]], [['b', 1]], [['a', 1, true]]],
        });
        expect(p.optSections.map((s) => s.take.hidden)).toEqual([false, true, true]);
    });

    test('ticking and unticking a row shows and hides it', () => {
        const p = page({ store: [{ id: 'a', name: 'A', qty: 1, t: 1, m: 1 }], sections: [[['a', 1]]] });
        const s = p.optSections[0];
        s.rows[0].classes.add('opt-removed');
        p.fireChange(s.rows[0]);
        expect(s.take.hidden).toBe(true);
        s.rows[0].classes.delete('opt-removed');
        p.fireChange(s.rows[0]);
        expect(s.take.hidden).toBe(false);
    });

    test('takes the ticked rows\' copies out and leaves the rest', () => {
        const p = page({
            store: [{ id: 'a', name: 'A', qty: 4, t: 3, m: 3 }, { id: 'b', name: 'B', qty: 1, t: 2, m: 2 }, { id: 'c', name: 'C', qty: 2, t: 1, m: 1 }],
            sections: [[['a', 1], ['a', 2], ['b', 3], ['c', 2, true], ['x', 1]]],
        });
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(live(p)).toEqual([['a', 1], ['c', 2]]);
        expect(ids['backpack-toast'].textContent).toBe('Removed 4 copies from the backpack');
    });

    test('hides every section once none of its cards is left', () => {
        const p = page({ store: [{ id: 'a', name: 'A', qty: 1, t: 1, m: 1 }], sections: [[['a', 1]], [['a', 1]]] });
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(p.optSections.map((s) => s.take.hidden)).toEqual([true, true]);
        expect(p.navCount.hidden).toBe(true);
    });

    test('taking the last with the button focused moves focus to the fold button', () => {
        const p = page({ store: [{ id: 'a', name: 'A', qty: 1, t: 1, m: 1 }], sections: [[['a', 1]]] });
        const s = p.optSections[0];
        s.take.focus();
        p.window.takeRowsFromBackpack(s.take);
        expect(p.document.activeElement).toBe(s.fold);
    });

    test('a take that leaves the button up keeps focus on it', () => {
        const p = page({ store: [{ id: 'a', name: 'A', qty: 3, t: 1, m: 1 }], sections: [[['a', 1]]] });
        const s = p.optSections[0];
        s.take.focus();
        p.window.takeRowsFromBackpack(s.take);
        expect(s.take.hidden).toBe(false);
        expect(p.document.activeElement).toBe(s.take);
    });

    test('one undo puts the whole section back', () => {
        const p = page({ store: [{ id: 'a', name: 'A', qty: 3, t: 2, m: 2 }, { id: 'b', name: 'B', qty: 1, t: 1, m: 1 }], sections: [[['a', 1], ['b', 1]]] });
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(p.window.Backpack.undo()).toBe(true);
        expect(live(p).sort()).toEqual([['a', 3], ['b', 1]]);
        expect(p.window.Backpack.undo()).toBe(false);
    });

    test('asks before taking, and a no takes nothing', () => {
        const p = page({ store: [{ id: 'a', name: 'A', qty: 1, t: 1, m: 1 }], sections: [[['a', 1]]] });
        const before = p.m.mtgban_backpack;
        p.window.confirm = (msg) => { confirms.push(msg); return false; };
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(confirms).toEqual(["Remove this store's ticked cards from the backpack?"]);
        expect(p.m.mtgban_backpack).toBe(before);
        expect(p.optSections[0].take.hidden).toBe(false);
    });

    test('asks through confirmDialog when the page has it', () => {
        const p = page({ store: [{ id: 'a', name: 'A', qty: 1, t: 1, m: 1 }], sections: [[['a', 1]]] });
        const asked = [];
        let ok = null;
        p.window.confirmDialog = (msg, onOk, opts) => { asked.push([msg, opts.confirmLabel]); ok = onOk; };
        const before = p.m.mtgban_backpack;
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(asked).toEqual([["Remove this store's ticked cards from the backpack?", 'Remove']]);
        expect(confirms).toEqual([]);
        expect(p.m.mtgban_backpack).toBe(before);
        ok();
        expect(live(p)).toEqual([]);
    });

    test('takes each row\'s copies from the grade it was sent in', () => {
        const p = page({
            store: [{ id: 'a', qty: 3, t: 2, m: 2 }, { id: 'a', cond: 'SP', qty: 2, t: 2, m: 2 }, { id: 'a', cond: 'HP', qty: 1, t: 2, m: 2 }],
            sections: [[['a', 1, false, 'NM'], ['a', 2, false, 'SP'], ['a', 1, true, 'HP']]],
        });
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(p.stored().filter((e) => !e.del).map((e) => [e.cond, e.qty]).sort()).toEqual([['HP', 1], ['NM', 2]]);
    });

    test('rows without a grade take the card\'s copies in any grade, best first', () => {
        const p = page({
            store: [{ id: 'a', qty: 2, t: 2, m: 2 }, { id: 'a', cond: 'MP', qty: 1, t: 2, m: 2 }, { id: 'a', cond: 'SP', qty: 1, t: 2, m: 2 }, { id: 'b', cond: 'HP', qty: 1, t: 1, m: 1 }],
            sections: [[['a', 2], ['a', 1], ['b', 1], ['b', 1]]],
        });
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(p.stored().filter((e) => !e.del).map((e) => [e.id, e.cond, e.qty])).toEqual([['a', 'MP', 1]]);
        expect(ids['backpack-toast'].textContent).toBe('Removed 4 copies from the backpack');
    });

    test('rows without a grade leave what a graded row already took', () => {
        const p = page({
            store: [{ id: 'a', qty: 2, t: 2, m: 2 }, { id: 'a', cond: 'SP', qty: 2, t: 2, m: 2 }],
            sections: [[['a', 2, false, 'NM'], ['a', 1]]],
        });
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(p.stored().filter((e) => !e.del).map((e) => [e.cond, e.qty])).toEqual([['SP', 1]]);
    });

    test('a row without a grade shows the button for a card held in any grade', () => {
        const p = page({ store: [{ id: 'a', cond: 'SP', qty: 1, t: 1, m: 1 }], sections: [[['a', 1]]] });
        expect(p.optSections[0].take.hidden).toBe(false);
    });

    test('shows only while a ticked row is in a grade the backpack holds', () => {
        const p = page({ store: [{ id: 'a', cond: 'SP', qty: 1, t: 1, m: 1 }], sections: [[['a', 1, false, 'NM']], [['a', 1, false, 'SP']]] });
        expect(p.optSections.map((s) => s.take.hidden)).toEqual([true, false]);
    });

    test('a section with nothing in the backpack writes nothing', () => {
        const p = page({ store: [{ id: 'a', name: 'A', qty: 1, t: 1, m: 1 }], sections: [[['b', 1]]] });
        const before = p.m.mtgban_backpack;
        p.window.takeRowsFromBackpack(p.optSections[0].take);
        expect(p.m.mtgban_backpack).toBe(before);
        expect(p.window.Backpack.undo()).toBe(false);
    });
});

describe('the navbar switcher', () => {
    const menu = () => ids['nav-backpack-menu'];
    const picks = () => menu().children.map((b) => b.children[0].textContent + ':' + b.children[1].textContent + (b.getAttribute('aria-pressed') === 'true' ? '*' : ''));
    const two = [{ id: 'uuid-1', name: 'One', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'Two', pack: 2, qty: 3, t: 2, m: 2 }];

    test('one backpack shows no switcher and keeps the title', () => {
        const p = page({ store: two.slice(0, 1), tabs: 3, navMenu: true });
        expect(menu().hidden).toBe(true);
        expect(menu().children).toEqual([]);
        expect(p.nav.getAttribute('title')).toBe('Backpack');
    });

    test('two backpacks list each with its copies, the active one pressed', () => {
        const p = page({ store: two, tabs: 2, navMenu: true, tabList: [{ pack: 1, name: 'Trades' }, { pack: 2 }] });
        expect(menu().hidden).toBe(false);
        expect(picks()).toEqual(['Trades:2*', 'Backpack 2:3']);
        expect(p.nav.getAttribute('title')).toBe(null);
        expect(p.nav.getAttribute('aria-label')).toBe('Backpack, 2 copies');
    });

    test('picking one sends the search buttons there without opening the panel', () => {
        const p = page({ store: two, tabs: 2, navMenu: true });
        expect(p.rows[0].classes.has('active')).toBe(true);
        menu().children[1].focus();
        menu().children[1].click();
        expect(p.m.mtgban_backpack_active).toBe('2');
        expect(picks()).toEqual(['Backpack 1:2', 'Backpack 2:3*']);
        expect(p.rows[0].classes.has('active')).toBe(false);
        expect(p.rows[1].classes.has('active')).toBe(true);
        expect(p.navCount.textContent).toBe('3');
        expect(ids['backpack-panel']).toBe(undefined);
        expect(p.document.activeElement).toBe(menu().children[1]);
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored().find((e) => e.id === 'uuid-1' && e.pack === 2).qty).toBe(1);
    });

    test('a re-render from another tab keeps the focused pick focused', () => {
        const p = page({ store: two, tabs: 2, navMenu: true });
        menu().children[1].focus();
        const before = menu().children[1];
        p.m.mtgban_backpack_active = '2';
        p.fireStorage('mtgban_backpack_active');
        expect(menu().children[1]).not.toBe(before);
        expect(p.document.activeElement).toBe(menu().children[1]);
        expect(picks()).toEqual(['Backpack 1:2', 'Backpack 2:3*']);
    });

    test('a backpack added in the panel joins the switcher', () => {
        const p = page({ store: two.slice(0, 1), tabs: 3, navMenu: true });
        p.window.Backpack.addTab();
        p.window.renderBackpack();
        expect(picks()).toEqual(['Backpack 1:2', 'Backpack 2:0*']);
    });
});

describe('sorting the panel', () => {
    const store = [
        { id: 'uuid-1', name: 'Bolt', edition: 'Magic 2010', number: '146', qty: 1, t: 3, m: 3 },
        { id: 'uuid-2', name: 'Arc', edition: 'Alpha', number: '10', qty: 1, t: 1, m: 1 },
        { id: 'uuid-3', name: 'Cut', edition: 'Alpha', number: '9', qty: 1, t: 2, m: 2 },
        { id: 'uuid-1', name: 'Bolt', edition: 'Magic 2010', number: '146', cond: 'SP', qty: 1, t: 3, m: 3 },
    ];
    const names = () => ids['backpack-list'].querySelectorAll('.backpack-row').map((r) => r.querySelector('.backpack-row-name').textContent + (r.getAttribute('data-key').includes('|') ? ' ' + r.getAttribute('data-key').split('|')[1] : ''));
    const pick = (by) => { const sel = ids['backpack-sort-by']; sel.value = by; sel.listeners.change.forEach((fn) => fn()); };
    const reverse = () => ids['backpack-sort-dir'].click();
    const tick = () => new Promise((r) => setTimeout(r, 0));
    const json = (data, status = 200) => Promise.resolve({ ok: status === 200, status, json: () => Promise.resolve(data) });

    test('the panel opens newest first, as before', () => {
        const p = page({ store });
        p.nav.click();
        expect(names()).toEqual(['Bolt', 'Bolt SP', 'Cut', 'Arc']);
        expect(ids['backpack-sort-by'].value).toBe('added');
        expect(ids['backpack-sort-dir'].getAttribute('title')).toBe('Newest first');
    });

    test('name runs A to Z, a card\'s grades together best first, and reverses', () => {
        const p = page({ store });
        p.nav.click();
        pick('name');
        expect(names()).toEqual(['Arc', 'Bolt', 'Bolt SP', 'Cut']);
        expect(JSON.parse(p.m.mtgban_backpack_sort)).toEqual({ by: 'name', dir: 'asc' });
        reverse();
        expect(names()).toEqual(['Cut', 'Bolt', 'Bolt SP', 'Arc']);
        expect(ids['backpack-sort-dir'].getAttribute('title')).toBe('Z–A');
    });

    test('edition orders by edition, then collector number as a number', () => {
        const p = page({ store });
        p.nav.click();
        pick('edition');
        expect(names()).toEqual(['Cut', 'Arc', 'Bolt', 'Bolt SP']);
    });

    test('the sort orders the panel only; a send keeps the backpack\'s order', () => {
        const p = page({ store, sort: { by: 'name', dir: 'asc' } });
        p.nav.click();
        expect(names()[0]).toBe('Arc');
        const form = p.window.Backpack.sendForm('retail');
        expect(form.children.filter((i) => i.name === 'hashes').map((i) => i.value)).toEqual(['uuid-1', 'uuid-1', 'uuid-3', 'uuid-2']);
    });

    test('a price sort fetches the open backpack\'s cards once each and orders by price, priceless last', async () => {
        const calls = [];
        const fetch = (url) => { calls.push(url); return json({ 'uuid-1': { sellPrice: 2, sellVendor: 'TCG Low', buyPrice: 1 }, 'uuid-2': { sellPrice: 5, sellVendor: 'Card Kingdom' }, 'uuid-3': { sellPrice: null } }); };
        const p = page({ store, fetch });
        p.nav.click();
        expect(calls).toEqual([]);
        pick('retail');
        expect(ids['backpack-sort-note'].textContent).toBe('Loading prices…');
        await tick(); await tick(); await tick();
        expect(calls).toEqual(['/data/prices/' + encodeURIComponent('uuid-1,uuid-2,uuid-3')]);
        expect(names()).toEqual(['Arc', 'Bolt', 'Bolt SP', 'Cut']);
        const lines = ids['backpack-list'].querySelectorAll('.backpack-row-price').map((n) => n.textContent);
        expect(lines).toEqual(['NM $ 5.00 · Card Kingdom', 'NM $ 2.00 · TCG Low', 'NM $ 2.00 · TCG Low', 'No NM price']);
        expect(ids['backpack-sort-note'].hidden).toBe(true);
        reverse();
        expect(names()).toEqual(['Bolt', 'Bolt SP', 'Arc', 'Cut']);
        pick('buylist');
        expect(names()).toEqual(['Bolt', 'Bolt SP', 'Arc', 'Cut']);
        expect(calls.length).toBe(1);
    });

    test('prices fetched once serve the tab until they age out', async () => {
        const calls = [];
        const fetch = (url) => { calls.push(url); return json({}); };
        const p = page({ store, fetch, sort: { by: 'retail', dir: 'desc' } });
        p.nav.click();
        await tick(); await tick(); await tick();
        expect(calls.length).toBe(1);
        p.window.Backpack.close();
        p.nav.click();
        await tick();
        expect(calls.length).toBe(1);
        expect(Object.keys(JSON.parse(p.sm.mtgban_backpack_prices)).sort()).toEqual(['uuid-1', 'uuid-2', 'uuid-3']);
    });

    test('prices a tab cannot store are kept for the page, not fetched again', async () => {
        const calls = [];
        const fetch = (url) => { calls.push(url); return json({ 'uuid-1': { sellPrice: 2, sellVendor: 'TCG Low' } }); };
        page({ store, fetch, sort: { by: 'retail', dir: 'desc' }, session: Object.freeze({}) }).nav.click();
        await tick(); await tick(); await tick(); await tick();
        expect(calls.length).toBe(1);
        expect(ids['backpack-list'].querySelectorAll('.backpack-row-price')[0].textContent).toBe('NM $ 2.00 · TCG Low');
    });

    test('a refusal says why and stops until the sort is picked again', async () => {
        const calls = [];
        const fetch = (url) => { calls.push(url); return json({}, 401); };
        const p = page({ store, fetch, sort: { by: 'retail', dir: 'desc' } });
        p.nav.click();
        await tick(); await tick();
        expect(ids['backpack-sort-note'].textContent).toBe('Log in to sort by price');
        p.window.renderBackpack();
        await tick();
        expect(calls.length).toBe(1);
        pick('retail');
        await tick(); await tick();
        expect(calls.length).toBe(2);
    });

    test('more than 50 cards go in paced calls of 50, a 429 retried once', async () => {
        const many = Array.from({ length: 60 }, (_, i) => ({ id: 'id-' + i, name: 'C' + i, qty: 1, t: i, m: i }));
        const calls = [];
        let limited = false;
        const fetch = (url) => {
            calls.push(decodeURIComponent(url.slice('/data/prices/'.length)).split(',').length);
            if (calls.length === 2 && !limited) { limited = true; return json({}, 429); }
            return json({});
        };
        const p = page({ store: many, fetch, sort: { by: 'buylist', dir: 'desc' } });
        p.nav.click();
        await tick(); await tick();
        expect(ids['backpack-sort-note'].textContent).toBe('Loading prices 1/2…');
        await new Promise((r) => setTimeout(r, 2000));
        expect(calls).toEqual([50, 10, 10]);
        expect(ids['backpack-sort-note'].hidden).toBe(true);
    });

    test('closing the panel stops the load after the call in flight, and reopening picks it up', async () => {
        const many = Array.from({ length: 60 }, (_, i) => ({ id: 'id-' + i, name: 'C' + i, qty: 1, t: i, m: i }));
        const calls = [];
        const fetch = (url) => { calls.push(decodeURIComponent(url.slice('/data/prices/'.length)).split(',').length); return json({}); };
        const p = page({ store: many, fetch, sort: { by: 'retail', dir: 'desc' } });
        p.nav.click();
        p.window.Backpack.close();
        await new Promise((r) => setTimeout(r, 600));
        expect(calls).toEqual([50]);
        p.nav.click();
        await tick(); await tick(); await tick();
        expect(calls).toEqual([50, 10]);
    });

    test('a closed panel fetches nothing', () => {
        const calls = [];
        const p = page({ store, fetch: (url) => { calls.push(url); return json({}); }, sort: { by: 'retail', dir: 'desc' } });
        p.window.renderBackpack();
        expect(calls).toEqual([]);
    });

    test('one entry under a price sort fetches nothing and shows no note', async () => {
        const calls = [];
        const p = page({ store: store.slice(0, 1), fetch: (url) => { calls.push(url); return json({}); }, sort: { by: 'retail', dir: 'desc' } });
        p.nav.click();
        await tick();
        expect(calls).toEqual([]);
        expect(ids['backpack-sort-note'].hidden).toBe(true);
    });

    test('one entry shows no sort bar', () => {
        const p = page({ store: store.slice(0, 1) });
        p.nav.click();
        expect(ids['backpack-sort'].hidden).toBe(true);
    });
});
