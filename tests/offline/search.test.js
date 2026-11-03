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
