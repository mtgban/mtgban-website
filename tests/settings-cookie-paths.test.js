import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const cookiesSrc = readFileSync(join(import.meta.dir, '..', 'js', 'cookies.js'), 'utf8');
const settingsSrc = readFileSync(join(import.meta.dir, '..', 'js', 'settings.js'), 'utf8');

// A DOM just big enough for settings.js: elements with attributes and
// children, and the compound selectors it queries, with descendant combinators.
function el(tag, attrs = {}, children = []) {
    const node = {
        tagName: tag.toUpperCase(), attrs, children, parent: null, listeners: {},
        id: attrs.id || '', name: attrs.name || '', value: attrs.value || '',
        defaultValue: attrs.value || '', checked: false, disabled: false, dataset: {},
        classList: {
            set: new Set((attrs.class || '').split(' ').filter(Boolean)),
            add(...c) { c.forEach(x => this.set.add(x)); },
            remove(...c) { c.forEach(x => this.set.delete(x)); },
            contains(c) { return this.set.has(c); },
            toggle(c, on) { if (on === undefined ? !this.set.has(c) : on) this.set.add(c); else this.set.delete(c); },
        },
        addEventListener(type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); },
        dispatchEvent() {},
        focus() {},
        contains(other) { for (let n = other; n; n = n.parent) if (n === this) return true; return false; },
        querySelectorAll(sel) { return descendants(this).filter(n => matches(n, sel)); },
        querySelector(sel) { return this.querySelectorAll(sel)[0] || null; },
        closest(sel) { for (let n = this; n; n = n.parent) if (matches(n, sel)) return n; return null; },
    };
    for (const [k, v] of Object.entries(attrs)) {
        if (k.startsWith('data-')) node.dataset[k.slice(5).replace(/-(\w)/g, (_, c) => c.toUpperCase())] = v;
    }
    adopt(node, children);
    return node;
}

function adopt(node, children) {
    node.children = children;
    children.forEach(c => { c.parent = node; });
}

function descendants(node) {
    return node.children.flatMap(c => [c, ...descendants(c)]);
}

function matchesOne(n, sel) {
    const parts = sel.match(/^[a-z]+|#[\w-]+|\.[\w-]+|\[[^\]]+\]|:checked/g) || [];
    return parts.every(p => {
        if (p === ':checked') return n.checked;
        if (p[0] === '#') return n.id === p.slice(1);
        if (p[0] === '.') return n.classList.contains(p.slice(1));
        if (p[0] === '[') {
            const m = p.match(/^\[([\w-]+)(\^?=)?"?([^"]*)"?\]$/);
            const v = m[1] === 'id' ? n.id : n.attrs[m[1]];
            if (!m[2]) return v !== undefined;
            return m[2] === '^=' ? (v || '').startsWith(m[3]) : v === m[3];
        }
        return n.tagName === p.toUpperCase();
    });
}

function matches(n, sel) {
    const chain = sel.trim().split(/\s+/);
    if (!matchesOne(n, chain.pop())) return false;
    let up = n.parent;
    while (chain.length && up) {
        if (matchesOne(up, chain[chain.length - 1])) chain.pop();
        up = up.parent;
    }
    return chain.length === 0;
}

const checkbox = name => el('input', { type: 'checkbox', name });

// The body /api/settings/modal returns: the Arbitrage tab's grid, the
// Upload tab with two /upload cookies and a root one, and a Search tab whose
// cookies are all root ones.
function bodyFixture() {
    return [
        el('section', { class: 'settings-pane', 'data-tab': 'search', 'data-path': '/search' }, [
            el('div', { id: 'settings-search-sort' }),
        ]),
        el('section', { class: 'settings-pane', 'data-tab': 'upload', 'data-path': '/upload' }, [
            el('input', { id: 'opt-margin', type: 'text', value: '10' }),
            el('div', { id: 'settings-upload-checks' }, ['lowval', 'highval'].map(k => el('input', { type: 'checkbox', 'data-misc': k }))),
            el('select', { 'data-cookie': 'UploadCustomBuyer', value: 'TCGLow' }),
        ]),
        el('section', { class: 'settings-pane', 'data-tab': 'arbit', 'data-path': '/arbit' }, [
            el('div', { id: 'settings-arbit-vendors', 'data-cookie': 'ArbitVendorsList' }, [checkbox('CK'), checkbox('SCG')]),
        ]),
    ];
}

// Loads settings.js on pathname with the browser's cookies, opens the
// modal, and resolves once the body has loaded.
async function openModal({ pathname, cookie, values }) {
    const writes = [];
    const fetches = [];
    const modalBody = el('div', { class: 'settings-modal-body' });
    let bodyHTML = '';
    Object.defineProperty(modalBody, 'innerHTML', {
        get() { return bodyHTML; },
        set(html) {
            bodyHTML = html;
            adopt(modalBody, html === 'BODY' ? bodyFixture()
                : html.includes('data-role="retry"') ? [el('button', { 'data-role': 'retry' })] : []);
        },
    });
    const saveBtn = el('button', { class: 'settings-btn primary', 'data-role': 'save' });
    saveBtn.disabled = true;
    const modal = el('div', { id: 'settings-modal' }, [modalBody, saveBtn]);
    const root = el('html', {}, [modal, el('div', { id: 'settings-backdrop' })]);

    const docListeners = {};
    const document = {
        get cookie() { return cookie; },
        set cookie(v) { writes.push(v); },
        body: el('body'),
        activeElement: null,
        getElementById: id => root.querySelector('#' + id),
        querySelector: sel => root.querySelector(sel),
        querySelectorAll: sel => root.querySelectorAll(sel),
        addEventListener(type, fn) { docListeners[type] = fn; },
    };
    const fetch = (url) => {
        fetches.push(url);
        if (url === '/api/settings/modal') return Promise.resolve({ ok: true, text: () => Promise.resolve('BODY') });
        const path = url.split('/settings-values')[0];
        if (!(path in values)) return Promise.resolve({ ok: false, status: 500 });
        return Promise.resolve({ ok: true, json: () => Promise.resolve(values[path]) });
    };
    const window = {
        location: { pathname, search: '', hash: '', reload() { window.reloaded = true; } },
        history: { replaceState() {} },
    };
    const sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
    new Function('window', 'document', 'fetch', 'sessionStorage',
        'with (window) {' + cookiesSrc + '\n' + settingsSrc + '}')(window, document, fetch, sessionStorage);

    // The document is in when the loader runs settings.js, which sets up at once
    window.openSettings('arbit');
    await new Promise(r => setTimeout(r, 10));

    const find = sel => root.querySelector(sel);
    const save = async () => {
        saveBtn.listeners.click.forEach(fn => fn());
        await new Promise(r => setTimeout(r, 10));
    };
    return { find, save, writes, fetches, modalBody, window };
}

test('a tab opened on another page loads the values its own page reads', async () => {
    // The ArbitVendorsList copy /search sees is a stray an older build left there
    const m = await openModal({
        pathname: '/search',
        cookie: 'ArbitVendorsList=SCG,; UploadCustomBuyer=CKBuylist',
        values: { '/arbit': { ArbitVendorsList: 'CK,' }, '/upload': { UploadMargin: '15' } },
    });

    expect(m.fetches.sort()).toEqual([
        '/api/settings/modal',
        '/arbit/settings-values?name=ArbitVendorsList',
        '/upload/settings-values?name=UploadMargin&name=UploadOptimizerOpts',
    ]);
    expect(m.find('input[name="CK"]').checked).toBe(true);
    expect(m.find('input[name="SCG"]').checked).toBe(false);
    expect(m.find('#opt-margin').value).toBe('15');
    expect(m.find('select').value).toBe('CKBuylist');
});

test('saving on another page writes each cookie where its page reads it', async () => {
    const m = await openModal({
        pathname: '/search',
        cookie: '',
        values: { '/arbit': { ArbitVendorsList: 'CK,' }, '/upload': {} },
    });
    m.find('input[name="SCG"]').checked = true;
    await m.save();

    const set = name => m.writes.filter(w => w.startsWith(name + '=') && !w.startsWith(name + '=;'));
    expect(set('ArbitVendorsList')).toHaveLength(1);
    expect(set('ArbitVendorsList')[0]).toStartWith('ArbitVendorsList=CK,SCG,;');
    expect(set('ArbitVendorsList')[0]).toContain('path=/arbit;');
    // The input's default, as the Upload page reads when nothing is set
    expect(set('UploadMargin')[0]).toContain('path=/upload;');
    expect(set('UploadCustomBuyer')[0]).toContain('path=/;');
    // Strays an older build left wherever the tab was saved, and nowhere twice
    const expired = name => m.writes.filter(w => w.startsWith(name + '=;')).map(w => w.match(/path=([^;]*)/)[1]).sort();
    expect(expired('ArbitVendorsList')).toEqual(['/', '/search', '/upload']);
    expect(expired('UploadMargin')).toEqual(['/', '/arbit', '/search']);
    expect(expired('UploadCustomBuyer')).toEqual(['/arbit', '/search', '/upload']);
    expect(m.window.reloaded).toBe(true);
});

test('on its own page a tab reads its cookies there and fetches nothing', async () => {
    const m = await openModal({
        pathname: '/arbit',
        cookie: 'ArbitVendorsList=SCG,',
        values: { '/upload': {} },
    });

    expect(m.fetches.sort()).toEqual(['/api/settings/modal', '/upload/settings-values?name=UploadMargin&name=UploadOptimizerOpts']);
    expect(m.find('input[name="SCG"]').checked).toBe(true);
});

// Saving a tab shown blank would erase what its page reads
test('a page whose values cannot be fetched fails the load', async () => {
    const m = await openModal({ pathname: '/search', cookie: '', values: { '/upload': {} } });

    expect(m.modalBody.innerHTML).toContain('Could not load settings.');
    expect(m.find('[data-role="save"]').disabled).toBe(true);
    await m.save();
    expect(m.writes).toHaveLength(0);
});

test('unticking every option saves a value that does not bring the defaults back', async () => {
    const m = await openModal({
        pathname: '/upload',
        cookie: '',
        values: { '/arbit': { ArbitVendorsList: '' } },
    });
    expect(m.find('[data-misc="lowval"]').checked).toBe(true);
    m.find('[data-misc="lowval"]').checked = false;
    await m.save();

    const saved = m.writes.find(w => w.startsWith('UploadOptimizerOpts=') && !w.startsWith('UploadOptimizerOpts=;'));
    expect(saved).toStartWith('UploadOptimizerOpts=,;');
});
