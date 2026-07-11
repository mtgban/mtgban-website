import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// The shipped file is a plain script attaching to self; load it into a sandbox.
function loadOfflineImages() {
    const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-images.js'), 'utf8');
    const sandbox = {};
    new Function('self', src)(sandbox);
    return sandbox.OfflineImages;
}

const OfflineImages = loadOfflineImages();

const images = {
    NEO: { h: 'aaaa', n: 302, b: 24800000 },
    MID: { h: 'bbbb', n: 400, b: 30000000 },
    VOW: { h: 'cccc', n: 350, b: 28000000 },
};

test('formatBytes renders human sizes', () => {
    expect(OfflineImages.formatBytes(0)).toBe('0 B');
    expect(OfflineImages.formatBytes(302)).toBe('302 B');
    expect(OfflineImages.formatBytes(1000)).toBe('1 KB');
    expect(OfflineImages.formatBytes(123456)).toBe('123 KB');
    expect(OfflineImages.formatBytes(24800000)).toBe('24.8 MB');
    expect(OfflineImages.formatBytes(1400000000)).toBe('1.4 GB');
    expect(OfflineImages.formatBytes(9500000000)).toBe('9.5 GB');
});

test('entryMeta maps bundle entries to cache keys', () => {
    expect(OfflineImages.entryMeta('abc-123.webp')).toEqual({
        uuid: 'abc-123',
        url: '/api/offline/images/abc-123.webp',
        contentType: 'image/webp',
    });
    // cwebp-missing fallback entries: jpg bytes behind the canonical .webp key
    expect(OfflineImages.entryMeta('abc-123.jpg').contentType).toBe('image/jpeg');
    expect(OfflineImages.entryMeta('abc-123.jpg').url).toBe('/api/offline/images/abc-123.webp');
    expect(OfflineImages.entryMeta('nested/abc.webp')).toBeNull();
    expect(OfflineImages.entryMeta('README.txt')).toBeNull();
});

test('computeWorkList selects missing, changed, and unfinished bundles', () => {
    const states = {
        NEO: { code: 'NEO', hash: 'aaaa', done: true },  // up to date: skip
        MID: { code: 'MID', hash: 'old', done: true },   // hash changed: resync
        VOW: { code: 'VOW', hash: 'cccc', done: false }, // interrupted: resume
    };
    const plan = OfflineImages.computeWorkList(images, ['NEO', 'MID', 'VOW'], states);
    expect(plan.work.map(w => w.code)).toEqual(['MID', 'VOW']);
    expect(plan.totalBytes).toBe(58000000);
    expect(plan.totalCount).toBe(750);
});

test('computeWorkList ignores bundle-less codes and handles empty input', () => {
    const plan = OfflineImages.computeWorkList(images, ['NEO', 'NOPE'], {});
    expect(plan.work).toEqual([{ code: 'NEO', hash: 'aaaa', count: 302, bytes: 24800000 }]);
    expect(OfflineImages.computeWorkList(null, null, null).work).toEqual([]);
});

test('computeWorkList sorts work by set code', () => {
    const plan = OfflineImages.computeWorkList(images, ['VOW', 'MID', 'NEO'], null);
    expect(plan.work.map(w => w.code)).toEqual(['MID', 'NEO', 'VOW']);
});

test('estimateSelection sums manifest counts and bytes', () => {
    const est = OfflineImages.estimateSelection(images, ['NEO', 'MID', 'NOPE']);
    expect(est.bytes).toBe(54800000);
    expect(est.count).toBe(702);
    expect(est.missing).toEqual(['NOPE']);
    expect(OfflineImages.estimateSelection(images, []).bytes).toBe(0);
});
