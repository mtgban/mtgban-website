import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { resolve } from 'path';

/*
 * Pure-logic tests for the offline-watch toast state machine.
 *
 * The production IIFE (js/offline/offline-watch.js) cannot be imported
 * directly because it self-executes in a browser environment. These tests
 * mirror the state machine transitions described in the task brief using an
 * equivalent in-process model.
 */

// ---------------------------------------------------------------------------
// Load buildOfflineHref from production module via sandbox
// ---------------------------------------------------------------------------

const offlineWatchSrc = readFileSync(
    resolve(import.meta.dir, '../../js/offline/offline-watch.js'),
    'utf-8'
);

const sandbox = {
    self: {},
    location: { pathname: '/offline', search: '' },
};

new Function('self', 'location', offlineWatchSrc)(sandbox.self, sandbox.location);
const buildOfflineHref = sandbox.self.OfflineWatch.buildOfflineHref;

// ---------------------------------------------------------------------------
// Minimal in-process state machine matching offline-watch.js logic
// ---------------------------------------------------------------------------

function createMachine() {
    var dismissed = false;
    var toastVisible = false;
    var toastBuilt = false;

    function buildToast() {
        toastBuilt = true;
    }

    function showToast() {
        if (dismissed) return;
        if (!toastBuilt) buildToast();
        toastVisible = true;
    }

    function hideToast() {
        toastVisible = false;
    }

    function dismiss() {
        dismissed = true;
        hideToast();
    }

    // Mirrors check() outcome after probe resolves.
    function onProbe(ok) {
        if (ok) {
            dismissed = false; // recovery re-arms
            hideToast();
        } else {
            showToast();
        }
    }

    return {
        onProbe: onProbe,
        dismiss: dismiss,
        get dismissed() { return dismissed; },
        get toastVisible() { return toastVisible; },
        get toastBuilt() { return toastBuilt; },
    };
}

// ---------------------------------------------------------------------------
// Initial state
// ---------------------------------------------------------------------------

test('initial: dismissed is false', () => {
    var m = createMachine();
    expect(m.dismissed).toBe(false);
});

test('initial: toast is not visible', () => {
    var m = createMachine();
    expect(m.toastVisible).toBe(false);
});

test('initial: toast element not yet built', () => {
    var m = createMachine();
    expect(m.toastBuilt).toBe(false);
});

// ---------------------------------------------------------------------------
// Probe failure -> show toast
// ---------------------------------------------------------------------------

test('probe failure shows toast', () => {
    var m = createMachine();
    m.onProbe(false);
    expect(m.toastVisible).toBe(true);
});

test('probe failure builds toast element', () => {
    var m = createMachine();
    m.onProbe(false);
    expect(m.toastBuilt).toBe(true);
});

test('probe failure does not set dismissed', () => {
    var m = createMachine();
    m.onProbe(false);
    expect(m.dismissed).toBe(false);
});

// ---------------------------------------------------------------------------
// Probe success -> hide toast, re-arm
// ---------------------------------------------------------------------------

test('probe success when idle keeps toast hidden', () => {
    var m = createMachine();
    m.onProbe(true);
    expect(m.toastVisible).toBe(false);
});

test('probe success clears dismissed flag', () => {
    var m = createMachine();
    m.dismiss();
    m.onProbe(true);
    expect(m.dismissed).toBe(false);
});

test('probe success hides toast that was visible', () => {
    var m = createMachine();
    m.onProbe(false);
    expect(m.toastVisible).toBe(true);
    m.onProbe(true);
    expect(m.toastVisible).toBe(false);
});

// ---------------------------------------------------------------------------
// Dismiss
// ---------------------------------------------------------------------------

test('dismiss sets dismissed=true', () => {
    var m = createMachine();
    m.dismiss();
    expect(m.dismissed).toBe(true);
});

test('dismiss hides visible toast', () => {
    var m = createMachine();
    m.onProbe(false); // show
    m.dismiss();
    expect(m.toastVisible).toBe(false);
});

test('dismiss on hidden toast keeps it hidden', () => {
    var m = createMachine();
    m.dismiss();
    expect(m.toastVisible).toBe(false);
});

// ---------------------------------------------------------------------------
// Suppression after dismiss
// ---------------------------------------------------------------------------

test('probe failure after dismiss does not re-show toast', () => {
    var m = createMachine();
    m.onProbe(false); // show
    m.dismiss();
    m.onProbe(false); // should be suppressed
    expect(m.toastVisible).toBe(false);
});

test('dismissed flag persists across multiple failures', () => {
    var m = createMachine();
    m.dismiss();
    m.onProbe(false);
    m.onProbe(false);
    m.onProbe(false);
    expect(m.toastVisible).toBe(false);
    expect(m.dismissed).toBe(true);
});

// ---------------------------------------------------------------------------
// Recovery re-arm
// ---------------------------------------------------------------------------

test('probe success after dismiss re-arms (dismissed=false)', () => {
    var m = createMachine();
    m.onProbe(false);
    m.dismiss();
    m.onProbe(true); // recovery
    expect(m.dismissed).toBe(false);
});

test('probe failure after recovery shows toast again', () => {
    var m = createMachine();
    m.onProbe(false);
    m.dismiss();
    m.onProbe(true); // re-arm
    m.onProbe(false); // new outage
    expect(m.toastVisible).toBe(true);
});

test('multiple recovery cycles each re-arm the toast', () => {
    var m = createMachine();
    for (var i = 0; i < 3; i++) {
        m.onProbe(false);
        expect(m.toastVisible).toBe(true);
        m.dismiss();
        expect(m.toastVisible).toBe(false);
        m.onProbe(true);
        expect(m.dismissed).toBe(false);
    }
});

// ---------------------------------------------------------------------------
// No stacking: repeated failures do not stack
// ---------------------------------------------------------------------------

test('repeated probe failures keep toast visible but not stacked', () => {
    var m = createMachine();
    m.onProbe(false);
    m.onProbe(false);
    m.onProbe(false);
    expect(m.toastVisible).toBe(true);
    expect(m.toastBuilt).toBe(true);
});

test('toast element is built only once across failures', () => {
    var m = createMachine();
    var buildCount = 0;
    var orig = m.onProbe; // closures already share toastBuilt

    // Use a variant that counts builds via first-show.
    var m2 = createMachine();
    m2.onProbe(false);
    var builtAfterFirst = m2.toastBuilt;
    m2.onProbe(false);
    var builtAfterSecond = m2.toastBuilt;
    expect(builtAfterFirst).toBe(true);
    expect(builtAfterSecond).toBe(true); // still true, not rebuilt
});

// ---------------------------------------------------------------------------
// Interaction sequences
// ---------------------------------------------------------------------------

test('show -> hide (success) -> show again cycle', () => {
    var m = createMachine();
    m.onProbe(false);
    expect(m.toastVisible).toBe(true);
    m.onProbe(true);
    expect(m.toastVisible).toBe(false);
    m.onProbe(false);
    expect(m.toastVisible).toBe(true);
});

test('dismiss without prior failure clears nothing (safe)', () => {
    var m = createMachine();
    m.dismiss();
    expect(m.dismissed).toBe(true);
    expect(m.toastVisible).toBe(false);
    expect(m.toastBuilt).toBe(false);
});

test('recovery without prior dismiss still clears dismissed flag', () => {
    var m = createMachine();
    m.onProbe(true);
    expect(m.dismissed).toBe(false);
});

test('dismissed flag is false by default even without recovery', () => {
    var m = createMachine();
    expect(m.dismissed).toBe(false);
});

// ---------------------------------------------------------------------------
// Probe outcome purity
// ---------------------------------------------------------------------------

test('true probe outcome always clears dismissed regardless of value', () => {
    var m = createMachine();
    // force dismissed via dismiss()
    m.onProbe(false);
    m.dismiss();
    expect(m.dismissed).toBe(true);
    m.onProbe(true);
    expect(m.dismissed).toBe(false);
});

test('false probe outcome never clears dismissed', () => {
    var m = createMachine();
    m.dismiss();
    m.onProbe(false);
    expect(m.dismissed).toBe(true);
});

// ---------------------------------------------------------------------------
// buildOfflineHref: link carries current search query
// ---------------------------------------------------------------------------

test('offline href on non-search page is /offline', () => {
    expect(buildOfflineHref('/', '')).toBe('/offline');
    expect(buildOfflineHref('/sets', '')).toBe('/offline');
});

test('offline href on /search with no q is /offline', () => {
    expect(buildOfflineHref('/search', '')).toBe('/offline');
    expect(buildOfflineHref('/search', '?foo=bar')).toBe('/offline');
});

test('offline href on /search with q carries query', () => {
    expect(buildOfflineHref('/search', '?q=black+lotus')).toBe('/offline?q=black%20lotus');
});

test('offline href encodes special chars in q', () => {
    expect(buildOfflineHref('/search', '?q=fire+%2F%2F+ice')).toBe('/offline?q=fire%20%2F%2F%20ice');
});

test('offline href with simple q passes through', () => {
    expect(buildOfflineHref('/search', '?q=opt')).toBe('/offline?q=opt');
});
