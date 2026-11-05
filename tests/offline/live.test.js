import { test, expect, afterEach } from 'bun:test';

globalThis.self = globalThis.self || globalThis;
require('../../js/offline/offline-live.js');

const OfflineLive = globalThis.OfflineLive;
afterEach(() => { delete globalThis.localStorage; });

function withStorage(stored) {
    globalThis.localStorage = {
        getItem: (key) => (key in stored ? stored[key] : null),
        setItem: (key, value) => { stored[key] = value; },
    };
}

test('with nothing stored, desktop is on and mobile is off', () => {
    withStorage({});
    expect(OfflineLive.on('desktop')).toBe(true);
    expect(OfflineLive.on('mobile')).toBe(false);
});

test('a stored choice beats either default', () => {
    withStorage({});
    OfflineLive.set(false);
    expect(OfflineLive.on('desktop')).toBe(false);
    OfflineLive.set(true);
    expect(OfflineLive.on('mobile')).toBe(true);
});

test('blocked storage falls back to the default and does not throw', () => {
    globalThis.localStorage = {
        getItem: () => { throw new Error('blocked'); },
        setItem: () => { throw new Error('blocked'); },
    };
    expect(OfflineLive.on('desktop')).toBe(true);
    expect(OfflineLive.on('mobile')).toBe(false);
    OfflineLive.set(false);
});

// Synced, one device's choice would overwrite the other's default.
test('the setting stays out of the synced preferences', () => {
    const { readFileSync } = require('fs');
    const { join } = require('path');
    const synced = readFileSync(join(import.meta.dir, '..', '..', 'js', 'user-state.js'), 'utf8');
    expect(synced).not.toContain('offline_live_search');
});
