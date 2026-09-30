import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// Load the shipped module with stubbed window/document; DOM/network wiring stays inert.
function loadOfflineMode(cookie = '') {
    const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-mode.js'), 'utf8');
    const cookies = readFileSync(join(import.meta.dir, '..', '..', 'js', 'cookies.js'), 'utf8');
    const win = {};
    const doc = {
        cookie,
        readyState: 'complete',
        addEventListener: () => {},
        getElementById: () => null,
    };
    new Function('window', 'document', cookies + '\n' + src)(win, doc);
    return win.OfflineMode;
}

const OfflineMode = loadOfflineMode();

// The flag rides in the signed MTGBAN cookie: base64 over url.Values.
test('available reads SearchOfflineMode out of the MTGBAN cookie', () => {
    const signed = (values) => 'theme=dark; MTGBAN=' + encodeURIComponent(btoa(values));
    expect(loadOfflineMode(signed('UserTier=Pioneer&SearchOfflineMode=true')).available()).toBe(true);
    expect(loadOfflineMode(signed('UserTier=Pioneer')).available()).toBe(false);
    expect(loadOfflineMode('theme=dark').available()).toBe(false);
});

// --- Storage line sync-status text ---

test('syncStatusText reports last sync date when present', () => {
    const iso = '2026-07-11T12:00:00Z';
    expect(OfflineMode.syncStatusText({ lastSync: iso, syncing: false }))
        .toBe('last sync ' + new Date(iso).toLocaleString());
});

test('syncStatusText reports enabling offline mode during the first sync', () => {
    expect(OfflineMode.syncStatusText({ lastSync: null, syncing: true })).toBe('enabling offline mode');
});

test('syncStatusText reports not synced yet when idle with no prior sync', () => {
    expect(OfflineMode.syncStatusText({ lastSync: null, syncing: false })).toBe('not synced yet');
});

test('syncStatusText prefers last sync date even while a later sync is running', () => {
    const iso = '2026-07-11T12:00:00Z';
    expect(OfflineMode.syncStatusText({ lastSync: iso, syncing: true }))
        .toBe('last sync ' + new Date(iso).toLocaleString());
});
