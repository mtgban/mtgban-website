import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// Load the shipped module with stubbed window/document; DOM/network wiring stays inert.
function loadOfflineMode(cookie = '', win = {}, globals = {}) {
    const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-mode.js'), 'utf8');
    const cookies = readFileSync(join(import.meta.dir, '..', '..', 'js', 'cookies.js'), 'utf8');
    const doc = {
        cookie,
        readyState: 'complete',
        addEventListener: () => {},
        getElementById: () => null,
    };
    const names = Object.keys(globals);
    new Function('window', 'document', ...names, cookies + '\n' + src)(win, doc, ...names.map((n) => globals[n]));
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

// --- Leave-site guard ---

// Runs one sync and reports whether it left a beforeunload listener behind.
async function guardedDuring(opts) {
    const listeners = new Set();
    const win = {
        addEventListener: (type, fn) => { if (type === 'beforeunload') listeners.add(fn); },
        removeEventListener: (type, fn) => { if (type === 'beforeunload') listeners.delete(fn); },
    };
    const posted = [];
    const OfflineMode = loadOfflineMode('', win, {
        localStorage: { getItem: (k) => (k === 'offline_mode' ? 'true' : null) },
        OfflineDB: { getMeta: () => Promise.resolve([]) },
        Worker: class { postMessage(m) { posted.push(m); } },
    });
    OfflineMode.sync(opts);
    await Promise.resolve();
    await Promise.resolve();
    expect(posted.length).toBe(1);
    return listeners.size > 0;
}

test('the page-load sync does not ask before leaving the page', async () => {
    expect(await guardedDuring()).toBe(false);
});

test('an image sync asks before leaving the page', async () => {
    expect(await guardedDuring({ images: true })).toBe(true);
});
