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

test('substring match resolves display rows with keyrune', async () => {
    const out = await OfflineSearch.suggest('boseiju', deps());
    expect(out.map(r => r.name)).toEqual(['Boseiju, Who Endures', 'Boseiju Reaches Skyward']);
    const bwe = out[0];
    expect(bwe.uuid).toBe('u-bwe-neo');
    expect(bwe.setCode).toBe('NEO');
    expect(bwe.setName).toBe('Kamigawa: Neon Dynasty');
    expect(bwe.number).toBe('266');
    expect(bwe.keyrune).toBe('neo');
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
