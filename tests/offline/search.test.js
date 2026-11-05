const { test, expect } = require('bun:test');

// Shared modules attach to self; give bun one.
globalThis.self = globalThis.self || globalThis;
require('../../js/offline/offline-search.js');

const OfflineSearch = globalThis.OfflineSearch;

// Minimal normName mirror for the fakes (matches offline-util contract enough for tests).
function normName(s) {
    return (s || '').toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim();
}

const NAMES = [
    { key: 'boseiju who endures', uuids: ['u-bwe-neo', 'u-bwe-promo'] },
    { key: 'boseiju reaches skyward', uuids: ['u-brs'] },
    { key: 'sol ring', uuids: ['u-sol'] },
];
const CARDS = {
    'u-bwe-neo': { uuid: 'u-bwe-neo', n: 'Boseiju, Who Endures', num: '266', set: 'NEO' },
    'u-brs': { uuid: 'u-brs', n: 'Boseiju Reaches Skyward', num: '177', set: 'NEO' },
    'u-sol': { uuid: 'u-sol', n: 'Sol Ring', num: '263', set: 'C21' },
};
const SETS = { NEO: { n: 'Kamigawa: Neon Dynasty', k: 'neo' }, C21: { n: 'Commander 2021', k: '' } };

function deps() {
    return {
        normName: normName,
        allNames: async function () { return NAMES; },
        getCard: async function (u) { return CARDS[u]; },
        sets: SETS,
    };
}

test('under 3 chars returns nothing', async () => {
    expect(await OfflineSearch.suggest('bo', deps())).toEqual([]);
    expect(await OfflineSearch.suggest('', deps())).toEqual([]);
});

test('prefix match resolves display rows with keyrune', async () => {
    const out = await OfflineSearch.suggest('boseiju', deps());
    expect(out.map(r => r.name)).toEqual(['Boseiju, Who Endures', 'Boseiju Reaches Skyward']);
    const bwe = out[0];
    expect(bwe.uuid).toBe('u-bwe-neo');
    expect(bwe.setCode).toBe('NEO');
    expect(bwe.setName).toBe('Kamigawa: Neon Dynasty');
    expect(bwe.number).toBe('266');
    expect(bwe.keyrune).toBe('neo');
});

// The online matcher's rules (internal/suggest, js/autocomplete.js): the
// typed text starts the name, with its spaces closed on both sides, or after
// a leading word the reader may leave out; a word inside the name is no match.
test('matches the start of a name, not any word in it', async () => {
    const names = [
        { key: 'sol ring', uuids: ['u-sol'] },
        { key: 'blue eyed silver zombie', uuids: ['u-bes'] },
        { key: 'the wanderer', uuids: ['u-wan'] },
        { key: 'wandering emperor', uuids: ['u-wem'] },
        { key: 'the ur dragon', uuids: ['u-urd'] },
        { key: 'secret lair drop jace s ire', uuids: ['u-sld'] },
    ];
    const cards = {
        'u-sol': { uuid: 'u-sol', n: 'Sol Ring', set: 'C21' },
        'u-bes': { uuid: 'u-bes', n: 'Blue-Eyed Silver Zombie', set: 'FIN' },
        'u-wan': { uuid: 'u-wan', n: 'The Wanderer', set: 'WAR' },
        'u-wem': { uuid: 'u-wem', n: 'Wandering Emperor', set: 'NEO' },
        'u-urd': { uuid: 'u-urd', n: 'The Ur-Dragon', set: 'C17' },
        'u-sld': { uuid: 'u-sld', n: "Secret Lair Drop: Jace's Ire", set: 'SLD' },
    };
    const d = deps();
    d.allNames = async function () { return names; };
    d.getCard = async function (u) { return cards[u]; };
    const found = async (typed) => (await OfflineSearch.suggest(typed, d)).map(r => r.name);
    expect(await found('ring')).toEqual([]);
    expect(await found('sol r')).toEqual(['Sol Ring']);
    expect(await found('solring')).toEqual(['Sol Ring']);
    expect(await found('blueeyed')).toEqual(['Blue-Eyed Silver Zombie']);
    expect(await found('blue eyed')).toEqual(['Blue-Eyed Silver Zombie']);
    expect(await found('wander')).toEqual(['The Wanderer', 'Wandering Emperor']);
    expect(await found('the w')).toEqual(['The Wanderer']);
    expect(await found('zombie')).toEqual([]);
    expect(await found('urdragon')).toEqual(['The Ur-Dragon']);
    expect(await found('jaces')).toEqual(["Secret Lair Drop: Jace's Ire"]);
    expect(await found('lair drop')).toEqual([]);
});

// Online, a typed comma narrows the list (__acCommasMatch in js/autocomplete.js).
test('a typed comma narrows to the names that have it there', async () => {
    const names = [
        { key: 'saheeli sublime artificer', uuids: ['u-ssa'] },
        { key: 'saheeli rai', uuids: ['u-sr'] },
        { key: 'the wanderer', uuids: ['u-wan'] },
        { key: 'the wandering emperor', uuids: ['u-wem'] },
        { key: 'secret lair drop jace vryn s prodigy', uuids: ['u-sld'] },
    ];
    const cards = {
        'u-ssa': { uuid: 'u-ssa', n: 'Saheeli, Sublime Artificer', set: 'WAR' },
        'u-sr': { uuid: 'u-sr', n: 'Saheeli Rai', set: 'KLD' },
        'u-wan': { uuid: 'u-wan', n: 'The Wanderer', set: 'WAR' },
        'u-wem': { uuid: 'u-wem', n: 'The Wandering, Emperor', set: 'NEO' },
        'u-sld': { uuid: 'u-sld', n: "Secret Lair Drop: Jace, Vryn's Prodigy", set: 'SLD' },
    };
    const d = deps();
    d.allNames = async function () { return names; };
    d.getCard = async function (u) { return cards[u]; };
    const found = async (typed) => (await OfflineSearch.suggest(typed, d)).map(r => r.name);
    expect(await found('saheeli')).toEqual(['Saheeli, Sublime Artificer', 'Saheeli Rai']);
    expect(await found('Saheeli,')).toEqual(['Saheeli, Sublime Artificer']);
    expect(await found('saheeli, sub')).toEqual(['Saheeli, Sublime Artificer']);
    expect(await found('saheeli r,')).toEqual([]);
    expect(await found('wandering,')).toEqual(['The Wandering, Emperor']);
    expect(await found('wanderer,')).toEqual([]);
    expect(await found('jace,')).toEqual(["Secret Lair Drop: Jace, Vryn's Prodigy"]);
});

// The index is walked in key order, where the commas are already gone, so
// the names a comma keeps can sort past the first batch of hits.
test('a comma name past the first batch of hits is still found', async () => {
    const names = [];
    const cards = {};
    for (let i = 0; i < 45; i++) {
        const u = 'u-thing-' + i;
        names.push({ key: 'chandra s thing ' + String(i).padStart(2, '0'), uuids: [u] });
        cards[u] = { uuid: u, n: "Chandra's Thing " + String(i).padStart(2, '0'), set: 'NEO' };
    }
    names.push({ key: 'chandra torch of defiance', uuids: ['u-ctd'] });
    cards['u-ctd'] = { uuid: 'u-ctd', n: 'Chandra, Torch of Defiance', set: 'KLD' };
    const d = deps();
    d.allNames = async function () { return names; };
    let lookups = 0;
    d.getCard = async function (u) { lookups++; return cards[u]; };
    expect((await OfflineSearch.suggest('chandra,', d)).map(r => r.name)).toEqual(['Chandra, Torch of Defiance']);
    expect(lookups).toBe(46);
    lookups = 0;
    expect(await OfflineSearch.suggest('chandra', d)).toHaveLength(10);
    expect(lookups).toBe(40);
});

// A comma few names carry must not walk every prefix match, and a keystroke
// the box has moved past ends its walk at the next round.
test('a comma walk is capped, and stops once the answer is stale', async () => {
    const names = [];
    const cards = {};
    for (let i = 0; i < 300; i++) {
        const u = 'u-' + i;
        names.push({ key: 'sol thing ' + String(i).padStart(3, '0'), uuids: [u] });
        cards[u] = { uuid: u, n: 'Sol Thing ' + String(i).padStart(3, '0'), set: 'NEO' };
    }
    const d = deps();
    d.allNames = async function () { return names; };
    let lookups = 0;
    d.getCard = async function (u) { lookups++; return cards[u]; };
    expect(await OfflineSearch.suggest('sol,', d)).toEqual([]);
    expect(lookups).toBe(200);
    lookups = 0;
    let rounds = 0;
    expect(await OfflineSearch.suggest('sol,', d, () => rounds++ > 0)).toEqual([]);
    expect(lookups).toBe(40);
});

test('missing keyrune yields empty string, not undefined', async () => {
    const out = await OfflineSearch.suggest('sol ring', deps());
    expect(out[0].keyrune).toBe('');
    expect(out[0].setName).toBe('Commander 2021');
});

test('each name appears once even with multiple uuids', async () => {
    const out = await OfflineSearch.suggest('boseiju who', deps());
    expect(out).toHaveLength(1);
    expect(out[0].uuid).toBe('u-bwe-neo');
});

test('capped at 10 rows', async () => {
    const many = [];
    const cards = {};
    for (var i = 0; i < 20; i++) {
        const u = 'u' + i;
        many.push({ key: 'card ' + i, uuids: [u] });
        cards[u] = { uuid: u, n: 'Card ' + i, num: String(i), set: 'NEO' };
    }
    const d = deps();
    d.allNames = async function () { return many; };
    d.getCard = async function (u) { return cards[u]; };
    const out = await OfflineSearch.suggest('card', d);
    expect(out).toHaveLength(10);
});

test('missing card record is skipped, not thrown', async () => {
    const d = deps();
    d.getCard = async function (u) { return u === 'u-sol' ? undefined : CARDS[u]; };
    const out = await OfflineSearch.suggest('sol ring', d);
    expect(out).toEqual([]);
});

test('sealed flag scopes suggestions to the active mode', async () => {
    const names = [
        { key: 'final fantasy booster box', uuids: ['u-box'] },
        { key: 'final fantasy cloud', uuids: ['u-cloud'] },
    ];
    const cards = {
        'u-box': { uuid: 'u-box', n: 'Final Fantasy Booster Box', num: '', set: 'FIN', s: true },
        'u-cloud': { uuid: 'u-cloud', n: 'Final Fantasy Cloud', num: '1', set: 'FIN' },
    };
    const d = deps();
    d.allNames = async function () { return names; };
    d.getCard = async function (u) { return cards[u]; };
    d.sets = { FIN: { n: 'Final Fantasy', k: 'fin' } };

    d.sealed = false;
    expect((await OfflineSearch.suggest('final fantasy', d)).map(r => r.uuid)).toEqual(['u-cloud']);
    d.sealed = true;
    expect((await OfflineSearch.suggest('final fantasy', d)).map(r => r.uuid)).toEqual(['u-box']);
    delete d.sealed;
    expect((await OfflineSearch.suggest('final fantasy', d)).map(r => r.uuid).sort()).toEqual(['u-box', 'u-cloud']);
});

// A stand-in for the elements mount touches, counting the writes that repaint.
function fakeElement(tag) {
    const listeners = {};
    const el = {
        tag, children: [], parentNode: null, className: '', scrollTop: 0, writes: 0, _html: '', attrs: {}, value: '',
        classList: {
            names: new Set(),
            add(name) { this.names.add(name); },
            remove(name) { this.names.delete(name); },
        },
        get innerHTML() { return this._html; },
        set innerHTML(html) { this._html = html; this.writes++; },
        appendChild(child) { child.parentNode = el; el.children.push(child); return child; },
        removeChild(child) { el.children.splice(el.children.indexOf(child), 1); child.parentNode = null; return child; },
        addEventListener(type, fn) { (listeners[type] = listeners[type] || []).push(fn); },
        fire(type, event) { (listeners[type] || []).forEach(fn => fn(event || {preventDefault() {}})); },
        getAttribute(name) { return el.attrs[name] ?? null; },
        setAttribute(name, value) { el.attrs[name] = value; },
    };
    return el;
}

function mountFake() {
    globalThis.document = {createElement: fakeElement};
    globalThis.escapeHtml = (s) => String(s);
    const parent = fakeElement('form');
    const input = parent.appendChild(fakeElement('input'));
    const submitted = [];
    const lists = [];
    const realAppend = parent.appendChild;
    parent.appendChild = (child) => { lists.push(child); return realAppend(child); };
    const names = ['sol ring', 'sol talisman', 'soldier'].map((key) => ({key, uuids: [key]}));
    OfflineSearch.mount({
        input,
        deps: {
            normName: (s) => s.toLowerCase().trim(),
            allNames: async () => names,
            getCard: async (uuid) => ({uuid, n: uuid, set: 'NEO', num: '1'}),
            sets: {NEO: {n: 'Neon', k: 'neo'}},
            sealed: null,
        },
        onSubmit: (q) => submitted.push(q),
    });
    async function type(value) {
        input.value = value;
        input.fire('input');
        await new Promise(setImmediate);
    }
    const open = () => parent.children.find((c) => c.className.includes('ac-dropdown'));
    return {input, type, open, lists, submitted};
}

test('typing keeps the open list and rewrites only the rows that changed', async () => {
    const {type, open, lists} = mountFake();
    await type('sol');
    const list = open();
    expect(list.children).toHaveLength(3);
    const writes = () => list.children.map((row) => row.writes);
    expect(writes()).toEqual([1, 1, 1]);
    await type('soli');
    expect(open()).toBeUndefined();
    await type('sol');
    await type('sol ');
    expect(lists).toHaveLength(2);
    const again = open();
    const before = again.children.map((row) => row.writes);
    await type('sol ');
    expect(open()).toBe(again);
    expect(again.children.map((row) => row.writes)).toEqual(before);
    // A shorter answer drops rows from the end of the same list
    await type('sold');
    expect(open()).toBe(again);
    expect(again.children).toHaveLength(1);
    expect(again.children[0].innerHTML).toContain('soldier');
    expect(lists).toHaveLength(2);
});

test('a new answer drops the highlight and a click takes the row it shows', async () => {
    const {input, type, open, submitted} = mountFake();
    await type('sol');
    input.fire('keydown', {key: 'ArrowDown', preventDefault() {}});
    expect(open().children[0].classList.names.has('autocomplete-active')).toBe(true);
    await type('sol ');
    expect(open().children[0].classList.names.has('autocomplete-active')).toBe(false);
    input.fire('keydown', {key: 'Enter', preventDefault() {}});
    expect(submitted).toEqual(['sol']);
    await type('sol t');
    open().children[0].fire('mousedown');
    expect(submitted).toEqual(['sol', 'sol talisman']);
});

test('an answer that arrives after Enter does not reopen the list', async () => {
    const {input, type, open, submitted} = mountFake();
    input.value = 'sol';
    input.fire('input');
    input.fire('keydown', {key: 'Enter', preventDefault() {}});
    await new Promise(setImmediate);
    expect(submitted).toEqual(['sol']);
    expect(open()).toBeUndefined();
    await type('sol ');
    expect(open()).toBeDefined();
});

function mountLive(isLive) {
    const parent = fakeElement('div');
    const input = fakeElement('input');
    input.parentNode = parent;
    const log = { typed: [], arrows: [], submitted: [] };
    OfflineSearch.mount({
        input,
        deps: deps(),
        live: () => isLive(),
        onType: (value) => log.typed.push(value),
        onArrow: (step) => log.arrows.push(step),
        onSubmit: (q) => log.submitted.push(q),
    });
    return { input, parent, log };
}

test('live, typing runs the page instead of suggesting', async () => {
    const m = mountLive(() => true);
    m.input.value = 'bos';
    m.input.fire('input');
    await new Promise((resolve) => setImmediate(resolve));
    expect(m.log.typed).toEqual(['bos']);
    expect(m.parent.children).toEqual([]);
});

test('live, the arrows go to the page', () => {
    const m = mountLive(() => true);
    let prevented = 0;
    const key = (k) => ({ key: k, preventDefault: () => { prevented++; } });
    m.input.fire('keydown', key('ArrowDown'));
    m.input.fire('keydown', key('ArrowUp'));
    expect(m.log.arrows).toEqual([1, -1]);
    expect(prevented).toBe(2);
});

test('live, Enter submits once with the box trimmed', () => {
    const m = mountLive(() => true);
    m.input.value = ' bolt ';
    m.input.fire('keydown', { key: 'Enter', preventDefault: () => {} });
    expect(m.log.submitted).toEqual(['bolt']);
});

test('switching the setting takes effect on the next keystroke, both ways', async () => {
    let on = false;
    const m = mountLive(() => on);
    m.input.value = 'bos';
    m.input.fire('input');
    await new Promise((resolve) => setImmediate(resolve));
    expect(m.log.typed).toEqual([]);
    expect(m.parent.children.length).toBe(1);

    on = true;
    m.input.value = 'bose';
    m.input.fire('input');
    expect(m.log.typed).toEqual(['bose']);
    expect(m.parent.children).toEqual([]);

    on = false;
    m.input.value = 'bos';
    m.input.fire('input');
    await new Promise((resolve) => setImmediate(resolve));
    expect(m.log.typed).toEqual(['bose']);
    expect(m.parent.children.length).toBe(1);
});

// The index the sync worker builds, keyed by the real normName, finds a name
// in any script by the prefix typed.
test('finds a Japanese or Cyrillic name by prefix', async () => {
    require('../../js/offline/offline-util.js');
    const realNorm = globalThis.OfflineUtil.normName;
    const cards = {
        'u-jp': { uuid: 'u-jp', n: '精霊龍、ウギン', set: 'FRF' },
        'u-ru': { uuid: 'u-ru', n: 'Шивский дракон', set: 'M10' },
        'u-en': { uuid: 'u-en', n: 'Shivan Dragon', set: 'M10' },
    };
    const names = Object.values(cards)
        .map((c) => ({ key: realNorm(c.n), uuids: [c.uuid] }))
        .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0));
    const d = deps();
    d.normName = realNorm;
    d.allNames = async function () { return names; };
    d.getCard = async function (u) { return cards[u]; };
    const found = async (typed) => (await OfflineSearch.suggest(typed, d)).map(r => r.name);
    expect(await found('精霊龍')).toEqual(['精霊龍、ウギン']);
    expect(await found('精霊龍ウギン')).toEqual(['精霊龍、ウギン']);
    expect(await found('Шивск')).toEqual(['Шивский дракон']);
    expect(await found('шивский др')).toEqual(['Шивский дракон']);
    expect(await found('shivan')).toEqual(['Shivan Dragon']);
});
