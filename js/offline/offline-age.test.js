const { test, expect } = require('bun:test');
require('./offline-age.js');

const OfflineAge = globalThis.OfflineAge;
const NOW = Date.parse('2026-07-11T12:00:00Z');
const MIN = 60 * 1000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

function ago(ms) { return new Date(NOW - ms).toISOString(); }

test('missing or invalid lastSync reads as never synced', () => {
    expect(OfflineAge.formatAge(null, NOW)).toBe('never synced');
    expect(OfflineAge.formatAge(undefined, NOW)).toBe('never synced');
    expect(OfflineAge.formatAge('', NOW)).toBe('never synced');
    expect(OfflineAge.formatAge('not a date', NOW)).toBe('never synced');
});

test('fresh and future timestamps read as just now', () => {
    expect(OfflineAge.formatAge(ago(0), NOW)).toBe('just now');
    expect(OfflineAge.formatAge(ago(45 * 1000), NOW)).toBe('just now');
    expect(OfflineAge.formatAge(ago(-5 * MIN), NOW)).toBe('just now');
});

test('minute granularity under an hour', () => {
    expect(OfflineAge.formatAge(ago(90 * 1000), NOW)).toBe('1 minute ago');
    expect(OfflineAge.formatAge(ago(5 * MIN), NOW)).toBe('5 minutes ago');
    expect(OfflineAge.formatAge(ago(59 * MIN), NOW)).toBe('59 minutes ago');
});

test('hour granularity under a day', () => {
    expect(OfflineAge.formatAge(ago(HOUR), NOW)).toBe('1 hour ago');
    expect(OfflineAge.formatAge(ago(3 * HOUR + 20 * MIN), NOW)).toBe('3 hours ago');
    expect(OfflineAge.formatAge(ago(23 * HOUR), NOW)).toBe('23 hours ago');
});

test('day granularity beyond that', () => {
    expect(OfflineAge.formatAge(ago(DAY), NOW)).toBe('1 day ago');
    expect(OfflineAge.formatAge(ago(4 * DAY + HOUR), NOW)).toBe('4 days ago');
});

test('staleness is strictly over three days, unknown counts as stale', () => {
    expect(OfflineAge.STALE_MS).toBe(3 * DAY);
    expect(OfflineAge.isStale(ago(3 * DAY), NOW)).toBe(false);
    expect(OfflineAge.isStale(ago(3 * DAY + 1), NOW)).toBe(true);
    expect(OfflineAge.isStale(null, NOW)).toBe(true);
    expect(OfflineAge.isStale('junk', NOW)).toBe(true);
});
