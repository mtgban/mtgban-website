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
        appendChild(c) { c.parentNode = this; this.children.push(c); return c; },
        append(...cs) { cs.forEach((c) => this.appendChild(c)); },
        remove() { if (this.parentNode) this.parentNode.children = this.parentNode.children.filter((c) => c !== this); },
        addEventListener(ev, fn) { (this.listeners[ev] = this.listeners[ev] || []).push(fn); },
        click() { (this.listeners.click || []).forEach((fn) => fn({ preventDefault() {}, stopPropagation() {} })); },
        focus() { if (currentDoc) currentDoc.activeElement = this; },
        closest(sel) { let n = this; while (n) { if (n.matches(sel)) return n; n = n.parentNode; } return null; },
        matches(sel) { return sel.split(',').some((s) => { s = s.trim(); return s.startsWith('.') ? this.classes.has(s.slice(1)) : s.startsWith('#') ? this.attrs.id === s.slice(1) : this.tag === s; }); },
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

function page({ store = [], emptyAfter = '0', mobile = false, ban } = {}) {
    ids = {}; submitted = []; submitHook = null; confirms = [];
    const m = { mtgban_backpack: JSON.stringify(store), mtgban_backpack_empty_after: emptyAfter };
    const localStorage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const body = el('body'); if (mobile) body.classes.add('mobile');
    const nav = el('button'); nav.setAttribute('id', 'nav-backpack'); nav.hidden = true;
    const navCount = el('span'); navCount.setAttribute('id', 'nav-backpack-count'); navCount.hidden = true; nav.appendChild(navCount);
    body.appendChild(nav);
    // Two result rows, each with a button carrying the card id.
    const rows = ['uuid-1', 'uuid-2'].map((id) => {
        const row = el('div'); row.classes.add('result-header');
        Object.entries({ 'data-card-id': id, 'data-card-name': 'Card ' + id, 'data-set-code': 'S', 'data-edition': 'Set', 'data-number': '7', 'data-image-url': '', 'data-finish-tag': '', 'data-finish-class': '', 'data-treatments': '', 'data-has-warning': 'false' }).forEach(([k, v]) => row.setAttribute(k, v));
        const btn = el('button'); btn.classes.add('pack-btn'); btn.setAttribute('data-card-id', id);
        const count = el('span'); count.classes.add('pack-btn-count'); count.hidden = true; btn.appendChild(count);
        row.appendChild(btn); body.appendChild(row);
        return btn;
    });
    const storageListeners = [];
    const window = {
        localStorage, addEventListener: (ev, fn) => { if (ev === 'storage') storageListeners.push(fn); }, confirm: (msg) => { confirms.push(msg); return true; },
        location: { pathname: '/search' },
    };
    if (ban) window.BAN_BACKPACK = ban;
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
    new Function('window', 'document', 'localStorage', 'ListStorage',
        listStorage + '; window.ListStorage = ListStorage; ' + source)(
        window, document, localStorage, undefined);
    const stored = () => JSON.parse(m.mtgban_backpack);
    return { window, document, m, rows, nav, navCount, stored, key, fireStorage: (key = 'mtgban_backpack') => storageListeners.forEach((fn) => fn({ key })) };
}

describe('adding', () => {
    test('the first add creates an entry with qty 1 and marks the row and navbar', () => {
        const p = page();
        p.window.addToBackpack(p.rows[0]);
        const live = p.stored().filter((e) => !e.del);
        expect(live.length).toBe(1);
        expect(live[0].qty).toBe(1);
        expect(live[0].m).toBe(live[0].t);
        expect(p.rows[0].classes.has('active')).toBe(true);
        expect(p.rows[0].children[0].textContent).toBe('1');
        expect(p.rows[0].children[0].hidden).toBe(false);
        expect(p.nav.hidden).toBe(false);
        expect(p.navCount.textContent).toBe('1');
        expect(p.navCount.hidden).toBe(false);
    });

    test('a second add raises the count and bumps m', async () => {
        const p = page();
        p.window.addToBackpack(p.rows[0]);
        const before = p.stored()[0].m;
        await new Promise((r) => setTimeout(r, 2));
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored()[0].qty).toBe(2);
        expect(p.stored()[0].m).toBeGreaterThan(before);
        expect(p.navCount.textContent).toBe('2');
    });

    test('re-adding a removed card gives a live entry with qty 1', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'x', qty: 4, t: 1, m: 2, del: 2 }] });
        p.window.addToBackpack(p.rows[0]);
        const e = p.stored().find((x) => x.id === 'uuid-1');
        expect(e.del).toBeUndefined();
        expect(e.qty).toBe(1);
    });

    test('the cap refuses the 201st card with a toast', () => {
        const store = [];
        for (let i = 0; i < 200; i++) store.push({ id: 'c' + i, name: 'c', qty: 1, t: i, m: i });
        const p = page({ store });
        const toast = el('div'); toast.setAttribute('id', 'desktop-fav-toast'); p.document.body.appendChild(toast);
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored().filter((e) => !e.del).length).toBe(200);
        expect(toast.textContent).toBe('Backpack is full (200 cards)');
    });

    test('a live card past the cap still increments', () => {
        const store = [];
        for (let i = 0; i < 200; i++) store.push({ id: i === 0 ? 'uuid-1' : 'c' + i, name: 'c', qty: 1, t: i, m: i });
        const p = page({ store });
        p.window.addToBackpack(p.rows[0]);
        expect(p.stored().find((e) => e.id === 'uuid-1').qty).toBe(2);
    });

    test('the 999 ceiling toasts without writing', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'x', qty: 999, t: 1, m: 1 }] });
        const toast = el('div'); toast.setAttribute('id', 'desktop-fav-toast'); p.document.body.appendChild(toast);
        const before = p.m.mtgban_backpack;
        p.window.addToBackpack(p.rows[0]);
        expect(p.m.mtgban_backpack).toBe(before);
        expect(toast.textContent).toBe('999 copies is the most for one card');
    });

    test('a stored string qty counts as a number and increments', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'x', qty: '5', t: 1, m: 1 }, { id: 7, name: 'bad id', qty: 1, t: 1, m: 1 }] });
        expect(p.window.Backpack.count()).toEqual({ copies: 5, cards: 1 });
        p.window.addToBackpack(p.rows[0]);
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
        expect(p.rows[1].children[0].textContent).toBe('2');
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
        expect(ids['backpack-count'].textContent).toBe('3 copies of 2 cards');
        expect(ids['backpack-send-retail'].disabled).toBe(false);
    });

    test('plus, minus and remove change the store; minus at 1 removes', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'B', qty: 1, t: 2, m: 2 }] });
        const panel = open(p);
        panel.querySelectorAll('.backpack-plus')[1].click();   // A (second row, older)
        expect(p.stored().find((e) => e.id === 'uuid-1').qty).toBe(3);
        panel.querySelectorAll('.backpack-minus')[0].click();  // B at 1
        expect(p.stored().find((e) => e.id === 'uuid-2').del).toBeDefined();
        panel.querySelectorAll('.backpack-remove')[0].click(); // A is the only row now
        expect(p.stored().filter((e) => !e.del).length).toBe(0);
        expect(ids['backpack-list'].querySelectorAll('.backpack-row').length).toBe(0);
        expect(ids['backpack-send-retail'].disabled).toBe(true);
        expect(ids['backpack-empty'].textContent).toBe('Add cards from any search with the backpack button.');
    });

    test('plus at the 999 ceiling toasts without writing', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 999, t: 1, m: 1 }] });
        const toast = el('div'); toast.setAttribute('id', 'desktop-fav-toast'); p.document.body.appendChild(toast);
        const panel = open(p);
        const before = p.m.mtgban_backpack;
        panel.querySelectorAll('.backpack-plus')[0].click();
        expect(p.m.mtgban_backpack).toBe(before);
        expect(toast.textContent).toBe('999 copies is the most for one card');
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

    test('a Clear of 120 cards keeps a tombstone for each', () => {
        const store = [];
        for (let i = 0; i < 120; i++) store.push({ id: 'c' + i, name: 'c', qty: 1, t: i, m: i });
        const p = page({ store });
        open(p);
        ids['backpack-clear'].click();
        expect(p.stored()).toHaveLength(120);
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

describe('sending', () => {
    test('Retail posts hashes and quantities in order, keeping the backpack', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }, { id: 'uuid-2', name: 'B', qty: 1, t: 2, m: 2 }] });
        p.nav.click();
        ids['backpack-send-retail'].click();
        expect(submitted.length).toBe(1);
        const form = submitted[0];
        expect(form.getAttribute('action')).toBe('/upload');
        const inputs = form.children.map((i) => [i.name, i.value]);
        expect(inputs).toEqual([['mode', 'false'], ['hashes', 'uuid-2'], ['hashesQtys', '1'], ['hashes', 'uuid-1'], ['hashesQtys', '2']]);
        expect(p.stored().filter((e) => !e.del).length).toBe(2);
    });

    test('Buylist with the switch on empties the backpack before submitting', () => {
        const p = page({ store: [{ id: 'uuid-1', name: 'A', qty: 2, t: 1, m: 1 }], emptyAfter: '1' });
        p.nav.click();
        expect(ids['backpack-empty-after'].checked).toBe(true);
        let clearedAtSubmit = null;
        submitHook = () => { clearedAtSubmit = p.stored().every((e) => e.del); };
        ids['backpack-send-buylist'].click();
        expect(clearedAtSubmit).toBe(true);
        expect(submitted[0].children[0].value).toBe('true');
        expect(submitted[0].children.length).toBe(3);
        expect(p.stored().every((e) => e.del)).toBe(true);
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
