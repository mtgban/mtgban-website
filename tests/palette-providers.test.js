import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/palette-providers.js', import.meta.url), 'utf8');

// Loads the providers against a server that answers each url in `served`, or
// cannot be reached when it is null, and a browser whose offline catalog, if
// offline mode is on, holds `catalog`.
function load(served, catalog, offlineOn) {
    const opened = [];
    const window = {
        OfflineMode: { enabled: () => offlineOn },
        OfflineDB: { getMeta: key => { opened.push(key); return Promise.resolve(catalog[key]); } },
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
