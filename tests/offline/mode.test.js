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
        dispatchEvent: () => {},
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

// --- Finished-sync status line ---

test('doneStatusText reads the first sync as setup, later ones as updates', () => {
    const first = { lastSync: null };
    const later = { lastSync: '2026-07-11T12:00:00Z' };
    expect(OfflineMode.doneStatusText({ changedSets: 42 }, first, true)).toBe('Ready offline - sync images to display pictures while offline');
    expect(OfflineMode.doneStatusText({ changedSets: 42 }, first, false)).toBe('Ready offline');
    expect(OfflineMode.doneStatusText({ changedSets: 0 }, later, true)).toBe('Up to date');
    expect(OfflineMode.doneStatusText({ changedSets: 1 }, later, true)).toBe('Updated 1 set');
    expect(OfflineMode.doneStatusText({ changedSets: 912, failedSets: 4 }, later, true))
        .toBe('Updated 912 sets (4 sets failed, retried on the next sync)');
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

// --- Image sync asked for mid-refresh ---

// Sync Images Now pressed while the page-load refresh runs used to be dropped,
// and the refresh's done then read as the image sync finishing.
test('an image sync asked for during a price refresh runs after it', async () => {
    const posted = [];
    const listeners = new Set();
    let worker;
    const anyDB = new Proxy({}, { get: () => () => Promise.resolve([]) });
    const win = {
        addEventListener: (type, fn) => { if (type === 'beforeunload') listeners.add(fn); },
        removeEventListener: (type, fn) => { if (type === 'beforeunload') listeners.delete(fn); },
    };
    const OfflineMode = loadOfflineMode('', win, {
        localStorage: { getItem: (k) => (k === 'offline_mode' ? 'true' : null) },
        OfflineDB: anyDB,
        Worker: class { constructor() { worker = this; } postMessage(m) { posted.push(m); } },
        CustomEvent: class { constructor(type, init) { this.detail = init && init.detail; } },
    });
    const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
    OfflineMode.sync();
    await settle();
    OfflineMode.sync({ images: true });
    await settle();
    expect(posted.map((m) => m.images)).toEqual([false]);

    worker.onmessage({ data: { type: 'done', images: false } });
    expect(listeners.size).toBe(1); // still asks before leaving until it starts
    await settle();
    expect(posted.map((m) => m.images)).toEqual([false, true]);
});

// Pause before the queued image sync starts drops it, tells the images panel,
// and leaves the price refresh it waited on alone.
test('a pause drops an image sync still queued behind a price refresh', async () => {
    const posted = [];
    const events = [];
    let worker;
    const anyDB = new Proxy({}, { get: () => () => Promise.resolve([]) });
    const OfflineMode = loadOfflineMode('', { addEventListener: () => {}, removeEventListener: () => {} }, {
        localStorage: { getItem: (k) => (k === 'offline_mode' ? 'true' : null) },
        OfflineDB: anyDB,
        Worker: class { constructor() { worker = this; } postMessage(m) { posted.push(m); } },
        CustomEvent: class { constructor(type, init) { this.detail = init && init.detail; events.push(this.detail); } },
    });
    const settle = () => new Promise((resolve) => setTimeout(resolve, 0));
    OfflineMode.sync();
    await settle();
    OfflineMode.sync({ images: true });
    OfflineMode.cancelSync();
    expect(events).toContainEqual({ type: 'done', images: true });

    worker.onmessage({ data: { type: 'done', images: false } });
    await settle();
    expect(posted.map((m) => m.type + ':' + m.images)).toEqual(['sync:false']);
});
