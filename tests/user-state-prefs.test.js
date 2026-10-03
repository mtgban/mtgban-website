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
