import { test, expect, afterEach } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const src = readFileSync(join(import.meta.dir, '..', '..', 'js', 'offline', 'offline-settings-mobile.js'), 'utf8');

afterEach(() => { delete globalThis.OfflineMode; delete globalThis.OfflineLive; });

// Runs the script as the page does: deferred, so the document is interactive
// and offline-mode.js, tagged later, has not run yet.
function loadPage() {
    globalThis.OfflineLive = liveSetting(false);
    const listeners = {};
    const el = (extra = {}) => ({
        style: {},
        textContent: '',
        hidden: false,
        classList: { toggle: () => {}, add: () => {}, remove: () => {} },
        ...extra,
    });
    const elements = {
        'm-offline-section': el({ style: { display: 'none' } }),
        'm-offline-usage': el(),
        'm-offline-toggle': el(),
        'm-offline-auth-notice': el(),
        'm-offline-status': el(),
        'm-offline-live-row': el({ hidden: true }),
        'm-offline-live-toggle': el({ on: false, classList: { toggle(_name, on) { elements['m-offline-live-toggle'].on = on; } } }),
    };
    const doc = {
        readyState: 'interactive',
        getElementById: (id) => elements[id] || null,
        addEventListener: (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); },
    };
    const win = { addEventListener: () => {} };
    Object.defineProperty(win, 'OfflineMode', { get: () => globalThis.OfflineMode });
    const binder = {};
    new Function('window', 'self', 'document', src)(win, binder, doc);
    return {
        elements,
        fire: (type, detail) => (listeners[type] || []).forEach((fn) => fn({ detail })),
        binder,
    };
}

// The parts of OfflineMode the binder reads; the status starts unmeasured.
function offlineMode({ enabled = true, available = true } = {}) {
    const state = { bytes: 0, lastSync: null };
    let refreshes = 0;
    return {
        state,
        refreshCount: () => refreshes,
        available: () => available,
        enabled: () => enabled,
        status: () => state,
        usageText: (s) => s.bytes + ' bytes',
        doneStatusText: () => 'done',
        refreshUsage: async () => {
            refreshes++;
            state.bytes = 4300;
        },
        confirmDisable: () => true,
    };
}

test('the section appears at DOM ready when offline-mode.js loads after the script', () => {
    const page = loadPage();
    expect(page.elements['m-offline-section'].style.display).toBe('none');

    globalThis.OfflineMode = offlineMode();
    page.fire('DOMContentLoaded');
    expect(page.elements['m-offline-section'].style.display).toBe('');
});

test('the section stays hidden for an account without offline mode', () => {
    const page = loadPage();
    globalThis.OfflineMode = offlineMode({ available: false });
    page.fire('DOMContentLoaded');
    expect(page.elements['m-offline-section'].style.display).toBe('none');
});

test('the usage line repaints from a fresh measurement after the first paint', async () => {
    const page = loadPage();
    const mode = offlineMode();
    globalThis.OfflineMode = mode;
    page.fire('DOMContentLoaded');
    expect(page.elements['m-offline-usage'].textContent).toBe('0 bytes');

    await mode.refreshUsage();
    await Promise.resolve();
    expect(page.elements['m-offline-usage'].textContent).toBe('4300 bytes');
});

test('a disabled device measures nothing and shows no usage', () => {
    const page = loadPage();
    const mode = offlineMode({ enabled: false });
    globalThis.OfflineMode = mode;
    page.fire('DOMContentLoaded');
    expect(mode.refreshCount()).toBe(0);
    expect(page.elements['m-offline-usage'].textContent).toBe('');
});

test('the usage line waits for the re-measure after a finished sync', () => {
    const page = loadPage();
    const mode = offlineMode();
    globalThis.OfflineMode = mode;
    page.fire('DOMContentLoaded');
    mode.state.bytes = 0;
    page.elements['m-offline-usage'].textContent = 'before';

    page.fire('offline:sync-message', { type: 'done' });
    expect(page.elements['m-offline-usage'].textContent).toBe('before');

    mode.state.bytes = 9000;
    page.fire('offline:synced');
    expect(page.elements['m-offline-usage'].textContent).toBe('9000 bytes');
});

test('turning offline mode off clears the status it set', async () => {
    const page = loadPage();
    const mode = offlineMode();
    globalThis.OfflineMode = mode;
    page.fire('DOMContentLoaded');

    let done;
    const finished = new Promise((resolve) => { done = resolve; });
    mode.disable = () => finished;
    page.binder.OfflineSettingsMobile.handleToggle(page.elements['m-offline-toggle']);
    expect(page.elements['m-offline-status'].textContent).toBe('Disabling...');

    mode.enabled = () => false;
    done();
    await finished;
    await Promise.resolve();
    expect(page.elements['m-offline-status'].textContent).toBe('');
});

function liveSetting(initial) {
    let value = initial;
    return { on: () => value, set: (next) => { value = next; } };
}

test('the live search row shows with offline mode on, and flips the setting', () => {
    const page = loadPage();
    globalThis.OfflineMode = offlineMode();
    globalThis.OfflineLive = liveSetting(false);
    page.fire('DOMContentLoaded');
    expect(page.elements['m-offline-live-row'].hidden).toBe(false);
    expect(page.elements['m-offline-live-toggle'].on).toBe(false);

    page.binder.OfflineSettingsMobile.handleLive();
    expect(globalThis.OfflineLive.on()).toBe(true);
    expect(page.elements['m-offline-live-toggle'].on).toBe(true);
});

test('the live search row stays hidden with offline mode off', () => {
    const page = loadPage();
    globalThis.OfflineMode = offlineMode({ enabled: false });
    globalThis.OfflineLive = liveSetting(false);
    page.fire('DOMContentLoaded');
    expect(page.elements['m-offline-live-row'].hidden).toBe(true);
});
