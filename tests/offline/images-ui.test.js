import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// Load OfflineImages for use in the pure-logic tests below.
function loadOfflineImages() {
    const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-images.js'), 'utf8');
    const sandbox = {};
    new Function('self', src)(sandbox);
    return sandbox.OfflineImages;
}

const OfflineImages = loadOfflineImages();

// --- CSV cleanup ---

// The EditionsPicker.serialize() returns a trailing-comma csv.
// The UI module cleans it via: raw.split(',').filter(Boolean)
function parsePickerCsv(raw) {
    return raw.split(',').filter(Boolean);
}

// The UI saves codes via: codes.join(',') (no trailing comma).
function cleanJoin(codes) {
    return codes.join(',');
}

test('parsePickerCsv strips trailing comma', () => {
    expect(parsePickerCsv('NEO,MID,VOW,')).toEqual(['NEO', 'MID', 'VOW']);
});

test('parsePickerCsv handles empty string', () => {
    expect(parsePickerCsv('')).toEqual([]);
});

test('parsePickerCsv handles single edition with trailing comma', () => {
    expect(parsePickerCsv('NEO,')).toEqual(['NEO']);
});

test('parsePickerCsv handles no trailing comma', () => {
    expect(parsePickerCsv('NEO,MID')).toEqual(['NEO', 'MID']);
});

test('cleanJoin produces no trailing comma', () => {
    expect(cleanJoin(['NEO', 'MID', 'VOW'])).toBe('NEO,MID,VOW');
    expect(cleanJoin(['NEO'])).toBe('NEO');
    expect(cleanJoin([])).toBe('');
});

// --- Estimate text assembly ---

const images = {
    NEO: { h: 'aaaa', n: 302, b: 24800000 },
    MID: { h: 'bbbb', n: 400, b: 30000000 },
    VOW: { h: 'cccc', n: 350, b: 28000000 },
};

function buildEstimateText(imagesMap, codes) {
    var est = OfflineImages.estimateSelection(imagesMap, codes);
    var text = codes.length
        ? 'Selected: ' + codes.length + ' editions, ' + est.count + ' images, ' + OfflineImages.formatBytes(est.bytes)
        : 'No editions selected: no images will be downloaded.';
    if (est.missing.length) text += ' (' + est.missing.length + ' without bundles yet)';
    return text;
}

test('buildEstimateText when nothing selected', () => {
    expect(buildEstimateText(images, [])).toBe('No editions selected: no images will be downloaded.');
});

test('buildEstimateText with known editions', () => {
    expect(buildEstimateText(images, ['NEO', 'MID'])).toBe('Selected: 2 editions, 702 images, 54.8 MB');
});

test('buildEstimateText appends missing count when some codes have no bundle', () => {
    expect(buildEstimateText(images, ['NEO', 'NOPE'])).toBe(
        'Selected: 2 editions, 302 images, 24.8 MB (1 without bundles yet)'
    );
});

test('buildEstimateText with all codes missing from manifest', () => {
    expect(buildEstimateText(images, ['X', 'Y'])).toBe(
        'Selected: 2 editions, 0 images, 0 B (2 without bundles yet)'
    );
});

// --- Progress percent math ---

function progressPct(done, total) {
    return total ? Math.round(done / total * 100) : 100;
}

test('progressPct computes percentage', () => {
    expect(progressPct(0, 10)).toBe(0);
    expect(progressPct(5, 10)).toBe(50);
    expect(progressPct(10, 10)).toBe(100);
    expect(progressPct(1, 3)).toBe(33);
});

test('progressPct returns 100 when total is zero', () => {
    expect(progressPct(0, 0)).toBe(100);
});

// --- Storage label assembly ---

function buildStorageText(usage, quota) {
    return 'Storage: ' + OfflineImages.formatBytes(usage || 0) + ' used of ' + OfflineImages.formatBytes(quota || 0);
}

test('buildStorageText formats storage estimate', () => {
    expect(buildStorageText(50000000, 1000000000)).toBe('Storage: 50 MB used of 1 GB');
    expect(buildStorageText(0, 0)).toBe('Storage: 0 B used of 0 B');
});

// --- Quota preflight math (mirrors startSync logic) ---

function quotaExceeded(totalBytes, quota, usage) {
    return totalBytes > ((quota || 0) - (usage || 0)) * 0.9;
}

test('quotaExceeded returns true when not enough free space', () => {
    expect(quotaExceeded(600, 1000, 500)).toBe(true);  // free*0.9 = 450 < 600
});

test('quotaExceeded returns false when enough free space', () => {
    expect(quotaExceeded(400, 1000, 500)).toBe(false); // free*0.9 = 450 > 400
});

test('quotaExceeded handles zero quota gracefully', () => {
    expect(quotaExceeded(1, 0, 0)).toBe(true);
    expect(quotaExceeded(0, 0, 0)).toBe(false);
});
