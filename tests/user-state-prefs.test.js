import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/user-state.js', import.meta.url), 'utf8');

test('upload presets ride the synced preferences', () => {
    const m = source.match(/var PREF_KEYS = \[([\s\S]*?)\];/);
    expect(m).not.toBeNull();
    expect(m[1]).toContain("'mtgban_upload_presets'");
});

test('upload.html loads list-storage.js before user-state.js', () => {
    const html = readFileSync(new URL('../templates/upload.html', import.meta.url), 'utf8');
    const listStorageIdx = html.indexOf('/js/list-storage.js');
    const userStateIdx = html.indexOf('/js/user-state.js');
    expect(listStorageIdx).toBeGreaterThan(-1);
    expect(userStateIdx).toBeGreaterThan(-1);
    expect(listStorageIdx).toBeLessThan(userStateIdx);
});

// Runs user-state.js signed in, with a server holding prefs, and returns what
// UploadPresets.refresh saw in storage when hydrate called it.
async function hydrateWith(preferences) {
    const m = {};
    const storage = { getItem: (k) => (k in m ? m[k] : null), setItem: (k, v) => { m[k] = String(v); }, removeItem: (k) => { delete m[k]; } };
    const session = { getItem: () => null, setItem() {}, removeItem() {} };
    const seen = [];
    const window = { addEventListener() {}, UploadPresets: { refresh: () => seen.push(m.mtgban_upload_presets) } };
    const document = { cookie: 'MTGBAN=x', readyState: 'complete', addEventListener() {} };
    const res = { status: 200, ok: true, json: () => Promise.resolve({ version: 3, favorites: [], recents: [], preferences }) };
    const fetch = () => Promise.resolve(res);
    new Function('window', 'document', 'localStorage', 'sessionStorage', 'fetch', 'ListStorage', source)(
        window, document, storage, session, fetch, { mtime: (x) => x.m || x.t || 0 });
    for (let i = 0; i < 10; i++) await Promise.resolve();
    return seen;
}

test('hydrate refreshes the upload presets after writing the synced list', async () => {
    const list = JSON.stringify([{ id: 'p_a', name: 'A', opts: { mode: 'false' } }]);
    const seen = await hydrateWith({ mtgban_upload_presets: list });
    expect(seen).toEqual([list]);
});
