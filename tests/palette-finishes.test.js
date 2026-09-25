import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/palette-providers.js', import.meta.url), 'utf8');

// Loads the providers against a server that answers with `served`, or cannot
// be reached when it is null, and a browser whose offline catalog, if offline
// mode is on, lists `catalog`.
function load(served, catalog, offlineOn) {
    const opened = [];
    const window = {
        OfflineMode: { enabled: () => offlineOn },
        OfflineDB: { getMeta: key => { opened.push(key); return Promise.resolve(catalog); } },
    };
    const fetch = () => served === null
        ? Promise.reject(new TypeError('Failed to fetch'))
        : Promise.resolve({ ok: true, json: () => Promise.resolve(served) });
    new Function('window', 'fetch', source)(window, fetch);
    return { providers: window.__palette_providers, opened };
}

// The menu fetches on first use and fills in once the answer lands.
async function values(providers) {
    const finish = providers.getProvider('f:');
    finish.getCandidates('');
    await new Promise(resolve => providers.setOnDataReady(resolve));
    return finish.getCandidates('').map(entry => entry.value);
}

const rainbow = [{ value: 'nonfoil', label: 'Non-foil', count: 9 }, { value: 'rainbowfoil', label: 'Rainbow Foil', count: 3 }];

test('the game names its finishes after the three every game has', async () => {
    const { providers } = load(rainbow, null, false);
    expect(await values(providers)).toEqual(['foil', 'nonfoil', 'etched', 'rainbowfoil']);
});

test('offline, the finishes come from the catalog', async () => {
    const { providers, opened } = load(null, rainbow, true);
    expect(await values(providers)).toEqual(['foil', 'nonfoil', 'etched', 'rainbowfoil']);
    expect(opened).toEqual(['catalogFinishes']);
});

test('a browser that never turned offline mode on is left alone', async () => {
    const { providers, opened } = load(null, rainbow, false);
    expect(await values(providers)).toEqual(['foil', 'nonfoil', 'etched']);
    expect(opened).toEqual([]);
});
