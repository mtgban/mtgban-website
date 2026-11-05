const { test, expect } = require('bun:test');

// Shared modules attach to self; give bun one.
globalThis.self = globalThis.self || globalThis;
require('../../js/offline/offline-age.js');

const OfflineAge = globalThis.OfflineAge;
const NOW = Date.parse('2026-07-11T12:00:00Z');
const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

function ago(ms) { return new Date(NOW - ms).toISOString(); }

test('refreshText says when prices were last refreshed', () => {
    const at = (ms) => new Date(NOW - ms).toLocaleString();
    expect(OfflineAge.refreshText(ago(5 * MIN), NOW)).toBe('Offline prices last refreshed at ' + at(5 * MIN) + '.');
    expect(OfflineAge.refreshText(ago(3 * DAY), NOW)).toBe('Offline prices last refreshed at ' + at(3 * DAY) + '.');
});

test('refreshText marks prices older than three days stale', () => {
    const at = new Date(NOW - 4 * DAY).toLocaleString();
    expect(OfflineAge.refreshText(ago(4 * DAY), NOW)).toBe('Offline prices last refreshed at ' + at + ' (stale).');
});

test('refreshText reads missing or invalid lastSync as never refreshed', () => {
    for (const v of [null, undefined, '', 'not a date']) {
        expect(OfflineAge.refreshText(v, NOW)).toBe('Offline prices have not been refreshed on this device yet.');
    }
});

test('staleness is strictly over three days, unknown counts as stale', () => {
    expect(OfflineAge.STALE_MS).toBe(3 * DAY);
    expect(OfflineAge.isStale(ago(3 * DAY), NOW)).toBe(false);
    expect(OfflineAge.isStale(ago(3 * DAY + 1), NOW)).toBe(true);
    expect(OfflineAge.isStale(null, NOW)).toBe(true);
    expect(OfflineAge.isStale('junk', NOW)).toBe(true);
});

test('bannerText warns about sets still downloading on a first sync', () => {
    expect(OfflineAge.bannerText(null, NOW, 829, 0)).toBe('Prices are still downloading (829 sets left). Some cards might be missing.');
    expect(OfflineAge.bannerText(null, NOW, 1, 0)).toBe('Prices are still downloading (1 set left). Some cards might be missing.');
    expect(OfflineAge.bannerText(null, NOW, 0, 0)).toBe(OfflineAge.refreshText(null, NOW));
});

test('bannerText warns about sets a sync left out', () => {
    const refreshed = OfflineAge.refreshText(ago(5 * MIN), NOW);
    expect(OfflineAge.bannerText(ago(5 * MIN), NOW, 0, 0)).toBe(refreshed);
    expect(OfflineAge.bannerText(ago(5 * MIN), NOW, 0, 3)).toBe(refreshed + '\nThere are 3 sets that need to resync, a few results will be unavailable.');
    expect(OfflineAge.bannerText(ago(5 * MIN), NOW, 0, 1)).toBe(refreshed + '\nThere is 1 set that needs to resync, a few results will be unavailable.');
    // A refresh of sets already here is not a first sync
    expect(OfflineAge.bannerText(ago(5 * MIN), NOW, 40, 0)).toBe(refreshed);
});
