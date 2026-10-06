import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/palette-providers.js', import.meta.url), 'utf8');

// Loads the providers against a server that answers each url in `served`, or
// cannot be reached when it is null, and a browser whose offline catalog, if
// offline mode is on, holds `catalog`, on a page serving `game`.
function load(served, catalog, offlineOn, game) {
    const opened = [];
    const window = {
        OfflineMode: { enabled: () => offlineOn },
        OfflineDB: { getMeta: key => { opened.push(key); return Promise.resolve(catalog[key]); } },
        document: { body: { getAttribute: name => (name === 'data-game' ? game || '' : null) } },
    };
    const fetch = url => served === null
        ? Promise.reject(new TypeError('Failed to fetch'))
        : Promise.resolve({ ok: true, json: () => Promise.resolve(served[url]) });
    new Function('window', 'fetch', source)(window, fetch);
    return { providers: window.__palette_providers, opened };
}

// A menu fetches on first use and fills in once the answer lands.
async function values(providers, prefix) {
    const provider = providers.getProvider(prefix);
    provider.getCandidates('');
    await new Promise(resolve => providers.setOnDataReady(resolve));
    return provider.getCandidates('').map(entry => entry.value);
}

const rainbow = [{ value: 'nonfoil', label: 'Non-foil', count: 9 }, { value: 'rainbowfoil', label: 'Rainbow Foil', count: 3 }];

test('the game names its finishes after the three every game has', async () => {
    const { providers } = load({ '/api/palette/finishes.json': rainbow }, {}, false);
    expect(await values(providers, 'f:')).toEqual(['foil', 'nonfoil', 'etched', 'rainbowfoil']);
});

test('a finish shows its short forms beside it', async () => {
    const served = { '/api/palette/finishes.json': [{ value: 'galaxyfoil', label: 'Galaxy Foil', count: 3, aliases: ['galaxy'] }] };
    const { providers } = load(served, {}, false);
    await values(providers, 'f:');
    expect(providers.getProvider('f:').getCandidates('galaxy')[0]).toMatchObject({ value: 'galaxyfoil', sublabel: 'galaxy' });
});

test('offline, the finishes come from the catalog', async () => {
    const { providers, opened } = load(null, { catalogFinishes: rainbow }, true);
    expect(await values(providers, 'f:')).toEqual(['foil', 'nonfoil', 'etched', 'rainbowfoil']);
    expect(opened).toEqual(['catalogFinishes']);
});

test('a browser that never turned offline mode on is left alone', async () => {
    const { providers, opened } = load(null, { catalogFinishes: rainbow }, false);
    expect(await values(providers, 'f:')).toEqual(['foil', 'nonfoil', 'etched']);
    expect(opened).toEqual([]);
});

// The catalog files its sets by code; offline they are listed the way the
// server lists them, newest first, under s: and e: alike.
const catalogSets = {
    WTR: { n: 'Welcome to Rathe', k: 'wtr', d: '2019-10-11' },
    MST: { n: 'Part the Mistveil', k: 'mst', d: '2024-05-31' },
};

test('offline, the sets come from the catalog', async () => {
    for (const prefix of ['s:', 'e:']) {
        const { providers, opened } = load(null, { catalogSets }, true);
        expect(await values(providers, prefix)).toEqual(['MST', 'WTR']);
        expect(opened).toEqual(['catalogSets']);
        expect(providers.getProvider(prefix).getCandidates('mst')[0]).toMatchObject({
            value: 'MST', label: 'Part the Mistveil', sublabel: 'MST · 2024', keyrune: 'mst',
        });
    }
});

test('without offline mode the set menu stays empty and the catalog shut', async () => {
    const { providers, opened } = load(null, { catalogSets }, false);
    expect(await values(providers, 's:')).toEqual([]);
    expect(opened).toEqual([]);
});

test('the server answers for the sets whenever it can', async () => {
    const served = { '/api/palette/sets.json': [{ code: 'WTR', name: 'Welcome to Rathe', released: '2019-10-11', keyrune: 'wtr' }] };
    const { providers, opened } = load(served, { catalogSets }, true);
    expect(await values(providers, 's:')).toEqual(['WTR']);
    expect(opened).toEqual([]);
});

test('a set carries the mark the server gives its symbol', async () => {
    const served = { '/api/palette/sets.json': [
        { code: 'THB', name: 'Theros Beyond Death', keyrune: 'thb' },
        { code: 'PTHB', name: 'Theros Beyond Death Promos', keyrune: 'thb', mark: '★' },
    ] };
    const { providers } = load(served, {}, false);
    await values(providers, 's:');
    const marks = {};
    for (const c of providers.getProvider('s:').getCandidates('')) marks[c.value] = c.mark;
    expect(marks).toEqual({ THB: '', PTHB: '★' });
});

test("offline, a set carries the catalog's mark", async () => {
    const sets = { FBB: { n: 'Foreign Black Border', k: '3ed', d: '1994-04-01', m: 'BB' } };
    const { providers } = load(null, { catalogSets: sets }, true);
    await values(providers, 's:');
    expect(providers.getProvider('s:').getCandidates('')[0].mark).toBe('BB');
});

// The rarity menu is the loaded game's, rarest first, with the letter that
// names a rarity alone beside it.
const lorcanaRarities = [
    { value: 'enchanted', label: 'Enchanted', count: 18 },
    { value: 'superrare', label: 'Superrare', count: 19 },
    { value: 'common', label: 'Common', letter: 'c', count: 72 },
];

test('the game names its rarities', async () => {
    const { providers } = load({ '/api/palette/rarities.json': lorcanaRarities }, {}, false);
    expect(await values(providers, 'r:')).toEqual(['enchanted', 'superrare', 'common']);
    expect(providers.getProvider('r:').getCandidates('c')[0]).toMatchObject({ value: 'common', sublabel: 'c' });
});

test('offline, the rarities come from the catalog', async () => {
    const { providers, opened } = load(null, { catalogRarities: lorcanaRarities }, true);
    expect(await values(providers, 'r:')).toEqual(['enchanted', 'superrare', 'common']);
    expect(opened).toEqual(['catalogRarities']);
});

test('a card chip narrows the rarities to the card\'s', async () => {
    const { providers } = load({ '/api/palette/rarities.json': lorcanaRarities }, {}, false);
    await values(providers, 'r:');
    const narrowed = providers.getProvider('r:').getCandidates('', { cardMeta: { rarities: ['superrare'] } });
    expect(narrowed.map(entry => entry.value)).toEqual(['superrare']);
});

// Every game but Magic names its colours, and the menu is the loaded game's;
// Magic keeps its letters and named groups.
const pokemonColors = [
    { value: 'grass', label: 'Grass' },
    { value: 'fire', label: 'Fire' },
    { value: 'colorless', label: 'Colorless' },
    { value: 'multicolor', label: 'Multicolor' },
];

test('the game names its colours', async () => {
    const { providers } = load({ '/api/palette/colors.json': pokemonColors }, {}, false, 'pokemon');
    expect(await values(providers, 'c:')).toEqual(['grass', 'fire', 'colorless', 'multicolor']);
});

test('a card chip keeps the card\'s colours and the two terms', async () => {
    const { providers } = load({ '/api/palette/colors.json': pokemonColors }, {}, false, 'pokemon');
    await values(providers, 'c:');
    const narrowed = providers.getProvider('c:').getCandidates('', { cardMeta: { colors: ['fire'] } });
    expect(narrowed.map(entry => entry.value)).toEqual(['fire', 'colorless', 'multicolor']);
});

test('a Magic card chip reads the colour names the card carries', () => {
    const { providers } = load({}, {}, false, 'magic');
    const narrowed = providers.getProvider('c:').getCandidates('', { cardMeta: { colors: ['blue', 'white'] } });
    expect(narrowed.map(entry => entry.value)).toEqual(['W', 'U', 'C', 'M', 'azorius']);
});

test('Magic keeps its letters and named groups', () => {
    for (const game of ['magic', '']) {
        const { providers } = load({}, {}, false, game);
        const offered = providers.getProvider('c:').getCandidates('').map(entry => entry.value);
        expect(offered.slice(0, 5)).toEqual(['W', 'U', 'B', 'R', 'G']);
        expect(offered).toContain('azorius');
    }
});
