import { readFileSync } from 'fs';

const read = f => readFileSync(new URL('../js/' + f, import.meta.url), 'utf8');
const utils = read('utils.js');
const providersSrc = read('palette-providers.js');
const chipsSrc = read('palette-chips.js');
const source = read('command-palette.js');

// Takes any call or property the palette reaches for and keeps what it was given.
function fakeElement() {
    const state = { value: '', innerHTML: '', textContent: '', style: {}, handlers: {}, children: {}, rows: [], rowsFor: null };
    state.classList = { add() {}, remove() {}, toggle() {}, contains: () => false };
    state.addEventListener = (type, fn) => { state.handlers[type] = fn; };
    state.querySelector = sel => state.children[sel] || (state.children[sel] = fakeElement());
    // One row per option the palette drew, the same objects until it draws again.
    state.querySelectorAll = sel => {
        if (sel !== '.cp-result') return [];
        if (state.rowsFor !== state.innerHTML) {
            state.rowsFor = state.innerHTML;
            state.rows = (state.innerHTML.match(/role="option"/g) || []).map(() => fakeElement());
        }
        return state.rows;
    };
    return new Proxy(function () {}, {
        get(target, prop) {
            if (typeof prop === 'symbol') return undefined;
            if (!(prop in state)) state[prop] = fakeElement();
            return state[prop];
        },
        set(target, prop, value) { state[prop] = value; return true; },
        apply: () => fakeElement(),
    });
}

// opts: nav, guide (sections), stored ({ localStorage key: value }), cards and
// sealed (name lists), path, hashes (count of result hashes on the page),
// exports (the export fields the upload page shows), confirm, noBAN.
export function palette(opts = {}) {
    const tracked = [];
    const values = new Map(Object.entries(opts.stored || {}).map(([k, v]) => [k, JSON.stringify(v)]));
    const localStorage = { getItem: k => (values.has(k) ? values.get(k) : null), setItem: (k, v) => values.set(k, v) };
    const made = [];
    const docHandlers = {};
    let overlay;
    const document = {
        body: fakeElement(), head: fakeElement(),
        activeElement: { tagName: 'BODY', focus() {} },
        createElement: () => { const el = fakeElement(); if (!overlay) overlay = el; made.push(el); return el; },
        getElementById: () => null,
        // The upload page's export buttons, and the hashes a results page carries.
        querySelector: sel => ((opts.exports || []).some(f => sel.indexOf("'" + f + "'") >= 0) ? {} : null),
        querySelectorAll: sel => (sel.indexOf('input[name="hashes"]') >= 0
            ? Array.from({ length: opts.hashes || 0 }, () => ({ tagName: 'INPUT', value: 'h' })) : []),
        addEventListener: (type, fn) => { docHandlers[type] = fn; },
    };
    const location = { href: 'https://mtgban.test/search', origin: 'https://mtgban.test', pathname: opts.path || '/search', search: '' };
    const window = {
        __BAN_PALETTE: { nav: opts.nav || [{ name: 'Search', link: '/search' }, { name: 'Newspaper', link: '/newspaper' }, { name: 'Upload', link: '/upload' }] },
        __BAN_PALETTE_TARGETS: { newspaper: [{ value: 'syp', label: 'TCG Syp List' }] },
        __BAN_GUIDE: { sections: opts.guide || [] },
        // A call is kept as [name, value, scope] with the arguments it was not given left off.
        BAN: { track: (...a) => { while (a.length && a[a.length - 1] === undefined) a.pop(); tracked.push(a); } },
        innerWidth: 1280, location, addEventListener() {}, confirm: () => opts.confirm !== false,
    };
    if (opts.noBAN) delete window.BAN;
    if (opts.exports) window.submitExport = () => {};
    const fetch = () => new Promise(() => {});
    const fetchNames = sealed => Promise.resolve(sealed === 'true' ? (opts.sealed || []) : (opts.cards || []));
    new Function('window', 'fetch', providersSrc)(window, fetch);
    new Function('window', 'document', chipsSrc)(window, document);
    new Function('window', 'document', 'localStorage', 'location', 'setTimeout', 'clearTimeout', 'fetch', 'fetchNames', 'requestAnimationFrame', 'navigator',
        utils + '\n' + source)(window, document, localStorage, location, fn => { fn(); return 0; }, () => {}, fetch, fetchNames, fn => fn(), {});

    const input = overlay.querySelector('#cp-input');
    const results = overlay.querySelector('#cp-results');
    const chipBox = overlay.querySelector('#cp-chips');
    const ev = init => ({ preventDefault() {}, stopPropagation() {}, ...init });
    return {
        tracked, location, window, made, input,
        // The [value, scope] pairs sent under one name, in order.
        named: name => tracked.filter(t => t[0] === name).map(t => t.slice(1)),
        doc: init => docHandlers.keydown(ev(init)),
        type: text => { input.value = text; input.handlers.input(); },
        key: init => input.handlers.keydown(ev(init)),
        chipKey: init => chipBox.handlers.keydown(ev(init)),
        click: i => results.querySelectorAll('.cp-result')[i].handlers.click(ev({ target: { closest: () => null } })),
        // The trash button on saved row i.
        clickDelete: (i, id) => results.querySelectorAll('.cp-result')[i].handlers.click(
            ev({ target: { closest: () => ({ getAttribute: () => id }) } })),
        html: () => results.innerHTML,
        stored: k => JSON.parse(values.get(k) || '[]'),
        // Lets an already resolved promise (the name lists) land, by microtasks alone.
        settle: async () => { for (let i = 0; i < 4; i++) await Promise.resolve(); },
    };
}
