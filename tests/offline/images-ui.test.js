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

// Load the shipped UI module with stubbed window/document; DOM wiring stays inert.
function loadImagesUI() {
    const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-images-ui.js'), 'utf8');
    const win = { OfflineImages };
    const doc = { addEventListener: () => {}, getElementById: () => null };
    new Function('window', 'document', src)(win, doc);
    return win.OfflineImagesUI;
}

const UI = loadImagesUI();

// --- CSV cleanup ---

test('parsePickerCsv strips trailing comma', () => {
    expect(UI.parsePickerCsv('NEO,MID,VOW,')).toEqual(['NEO', 'MID', 'VOW']);
});

test('parsePickerCsv handles empty string', () => {
    expect(UI.parsePickerCsv('')).toEqual([]);
});

test('parsePickerCsv handles single edition with trailing comma', () => {
    expect(UI.parsePickerCsv('NEO,')).toEqual(['NEO']);
});

test('parsePickerCsv handles no trailing comma', () => {
    expect(UI.parsePickerCsv('NEO,MID')).toEqual(['NEO', 'MID']);
});

test('join produces no trailing comma', () => {
    expect(['NEO', 'MID', 'VOW'].join(',')).toBe('NEO,MID,VOW');
    expect(['NEO'].join(',')).toBe('NEO');
    expect([].join(',')).toBe('');
});

// --- Estimate text assembly ---

const images = {
    NEO: { h: 'aaaa', n: 302, b: 24800000 },
    MID: { h: 'bbbb', n: 400, b: 30000000 },
    VOW: { h: 'cccc', n: 350, b: 28000000 },
};

test('buildEstimateText when nothing selected', () => {
    expect(UI.buildEstimateText(images, [])).toBe('No editions selected: no images will be downloaded.');
});

test('buildEstimateText with known editions', () => {
    expect(UI.buildEstimateText(images, ['NEO', 'MID'])).toBe('Selected: 2 editions, 702 images, 54.8 MB');
});

test('buildEstimateText appends missing count when some codes have no bundle', () => {
    expect(UI.buildEstimateText(images, ['NEO', 'NOPE'])).toBe(
        'Selected: 2 editions, 302 images, 24.8 MB (1 without bundles yet)'
    );
});

test('buildEstimateText with all codes missing from manifest', () => {
    expect(UI.buildEstimateText(images, ['X', 'Y'])).toBe(
        'Selected: 2 editions, 0 images, 0 B (2 without bundles yet)'
    );
});

// --- Progress percent math ---

test('progressPct computes percentage', () => {
    expect(UI.progressPct(0, 10)).toBe(0);
    expect(UI.progressPct(5, 10)).toBe(50);
    expect(UI.progressPct(10, 10)).toBe(100);
    expect(UI.progressPct(1, 3)).toBe(33);
});

test('progressPct returns 100 when total is zero', () => {
    expect(UI.progressPct(0, 0)).toBe(100);
});

// --- Storage label assembly ---

test('buildStorageText formats storage estimate', () => {
    expect(UI.buildStorageText(50000000, 1000000000)).toBe('Storage: 50 MB used of 1 GB');
    expect(UI.buildStorageText(0, 0)).toBe('Storage: 0 B used of 0 B');
});

// --- Quota preflight math (mirrors startSync logic) ---

test('quotaExceeded returns true when not enough free space', () => {
    expect(UI.quotaExceeded(600, 1000, 500)).toBe(true);  // free*0.9 = 450 < 600
});

test('quotaExceeded returns false when enough free space', () => {
    expect(UI.quotaExceeded(400, 1000, 500)).toBe(false); // free*0.9 = 450 > 400
});

test('quotaExceeded handles zero quota gracefully', () => {
    expect(UI.quotaExceeded(1, 0, 0)).toBe(true);
    expect(UI.quotaExceeded(0, 0, 0)).toBe(false);
});

// --- Done-message assembly ---

test('buildDoneMessage reports paused regardless of missing count', () => {
    expect(UI.buildDoneMessage(true, 0, 3)).toBe('Paused. Sync Images Now resumes where it left off.');
    expect(UI.buildDoneMessage(true, 2, 3)).toBe('Paused. Sync Images Now resumes where it left off.');
});

test('buildDoneMessage reports plain finish when nothing is missing', () => {
    expect(UI.buildDoneMessage(false, 0, 3)).toBe('Image sync finished.');
});

test('buildDoneMessage reports all-missing outcome when every selected edition lacks a bundle', () => {
    expect(UI.buildDoneMessage(false, 3, 3)).toBe('0 of 3 selected editions have bundles yet.');
});

test('buildDoneMessage appends missing count when some but not all editions lack bundles', () => {
    expect(UI.buildDoneMessage(false, 2, 5)).toBe('Image sync finished. (2 editions have no bundles yet)');
});
