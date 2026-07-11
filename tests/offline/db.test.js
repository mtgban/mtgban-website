const { test, expect } = require('bun:test');

// Only isGhostDb is testable in bun (no IDB runtime); open() recovery is
// covered by the E2E evidence in task-8-report.md.
globalThis.self = globalThis.self || globalThis;
require('../../js/offline/offline-db.js');

const { isGhostDb } = globalThis.OfflineDB;

test('ghost DB missing meta store is detected', () => {
    var ghost = { objectStoreNames: { contains: () => false } };
    expect(isGhostDb(ghost)).toBe(true);
});

test('healthy DB with meta store present is not ghost', () => {
    var healthy = { objectStoreNames: { contains: () => true } };
    expect(isGhostDb(healthy)).toBe(false);
});

test('ghost check targets the meta store specifically', () => {
    var metaMissing = { objectStoreNames: { contains: (n) => n !== 'meta' } };
    expect(isGhostDb(metaMissing)).toBe(true);
    var metaPresent = { objectStoreNames: { contains: (n) => n === 'meta' } };
    expect(isGhostDb(metaPresent)).toBe(false);
});
