import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/palette-providers.js', import.meta.url), 'utf8');

// Loads the providers against a server that answers with `served`.
function load(served) {
    const window = {};
    const fetch = () => Promise.resolve({ ok: true, json: () => Promise.resolve(served) });
    new Function('window', 'fetch', source)(window, fetch);
    return window.__palette_providers;
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
    expect(await values(load(rainbow))).toEqual(['foil', 'nonfoil', 'etched', 'rainbowfoil']);
});
