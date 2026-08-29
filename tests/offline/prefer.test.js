const { test, expect, beforeEach } = require('bun:test');

globalThis.self = globalThis.self || globalThis;

// Minimal localStorage stand-in.
var store = {};
globalThis.localStorage = {
    getItem: function (k) { return Object.prototype.hasOwnProperty.call(store, k) ? store[k] : null; },
    setItem: function (k, v) { store[k] = String(v); },
    removeItem: function (k) { delete store[k]; }
};

require('../../js/offline/offline-prefer.js');

beforeEach(() => { store = {}; });

test('defaults to false when unset', () => {
    expect(OfflinePrefer.get()).toBe(false);
});

test('set(true) then get() is true, and writes the literal flag', () => {
    OfflinePrefer.set(true);
    expect(localStorage.getItem('offline_prefer')).toBe('true');
    expect(OfflinePrefer.get()).toBe(true);
});

test('set(false) removes the key', () => {
    OfflinePrefer.set(true);
    OfflinePrefer.set(false);
    expect(localStorage.getItem('offline_prefer')).toBe(null);
    expect(OfflinePrefer.get()).toBe(false);
});

test('KEY is the device-local flag name', () => {
    expect(OfflinePrefer.KEY).toBe('offline_prefer');
});
