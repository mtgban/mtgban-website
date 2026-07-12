const { test, expect } = require('bun:test');

// OfflineAge is a dependency; load it as the banner would.
globalThis.self = globalThis.self || globalThis;
require('../../js/offline/offline-age.js');
const OfflineAge = globalThis.OfflineAge;

const NOW = Date.parse('2026-07-11T12:00:00Z');
const DAY = 24 * 60 * 60 * 1000;

function ago(ms) { return new Date(NOW - ms).toISOString(); }

// Mirrors the text assembly in renderAge().
function bannerAgeText(lastSync, nowMs) {
    var stale = OfflineAge.isStale(lastSync, nowMs);
    return 'Offline data: ' + OfflineAge.formatAge(lastSync, nowMs) + (stale ? ' (stale)' : '');
}

// Mirrors the back-URL logic in poll().
function buildBackUrl(search) {
    var q = new URLSearchParams(search).get('q');
    return q ? '/search?q=' + encodeURIComponent(q) : '/search';
}

// --- banner age text ---

test('fresh data shows age without stale suffix', () => {
    expect(bannerAgeText(ago(0), NOW)).toBe('Offline data: just now');
    expect(bannerAgeText(ago(30 * 60 * 1000), NOW)).toBe('Offline data: 30 minutes ago');
});

test('data older than three days shows stale suffix', () => {
    expect(bannerAgeText(ago(3 * DAY + 1), NOW)).toBe('Offline data: 3 days ago (stale)');
    expect(bannerAgeText(ago(7 * DAY), NOW)).toBe('Offline data: 7 days ago (stale)');
});

test('null lastSync shows never-synced with stale suffix', () => {
    expect(bannerAgeText(null, NOW)).toBe('Offline data: never synced (stale)');
});

// --- back-URL construction ---

test('no query param produces bare search URL', () => {
    expect(buildBackUrl('')).toBe('/search');
    expect(buildBackUrl('?foo=bar')).toBe('/search');
});

test('q param is carried through and encoded', () => {
    // URLSearchParams decodes + as space; encodeURIComponent re-encodes to %20.
    expect(buildBackUrl('?q=black+lotus')).toBe('/search?q=black%20lotus');
    expect(buildBackUrl('?q=simple')).toBe('/search?q=simple');
});

test('special characters in q are percent-encoded', () => {
    var result = buildBackUrl('?q=a%26b');
    expect(result).toBe('/search?q=a%26b');
});
