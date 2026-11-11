import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const html = readFileSync(new URL('../templates/upload.html', import.meta.url), 'utf8');
const submitScript = html.match(/<script type="text\/javascript">(\s*const hiddenBools[\s\S]*?)<\/script\b[^>]*>/i)[1];
const exportsSrc = readFileSync(new URL('../js/upload-exports.js', import.meta.url), 'utf8');
const processingSrc = readFileSync(new URL('../js/upload-processing.js', import.meta.url), 'utf8');
const storePromptSrc = readFileSync(new URL('../js/upload-store-prompt.js', import.meta.url), 'utf8');

// Only a post that comes back as a page may open the overlay: an export
// answers with a file and the page stays, so the overlay would never close.

function submitFormOpens(field) {
    const fields = {};
    for (const id of ['upload', 'download', 'estimate', 'deckbox', 'tcgplayer_csv']) fields[id] = { value: 'false' };
    const form = { target: '', submit: () => {} };
    const document = { getElementById: (id) => (id === 'upload_form' ? form : fields[id]) };
    let shown = false;
    const window = { showUploadProcessing: () => { shown = true; } };
    const submitForm = new Function('window', 'document', 'with (window) {' + submitScript + '}\nreturn submitForm;')(window, document);
    submitForm(field, field === 'estimate');
    return shown;
}

test('Upload opens the overlay', () => {
    expect(submitFormOpens('upload')).toBe(true);
});

test('the input page exports leave it closed', () => {
    for (const field of ['download', 'estimate', 'deckbox', 'tcgplayer_csv']) {
        expect(submitFormOpens(field)).toBe(false);
    }
});

function resultsPage() {
    const els = {};
    for (const id of ['res_mode', 'res_download', 'res_estimate', 'res_deckbox', 'res_tcgplayer_csv', 'res_csvscope', 'res_unpack']) {
        els[id] = { value: id === 'res_mode' ? 'false' : '' };
    }
    els.upload_form = { target: '', submit: () => {}, querySelectorAll: () => [], appendChild: () => {}, removeAttribute: () => {} };
    const document = {
        addEventListener: () => {},
        createElement: () => ({}),
        querySelector: () => null,
        querySelectorAll: () => [],
        getElementById: (id) => els[id] || null,
    };
    const opened = [];
    const window = {
        showUploadProcessing: () => opened.push(true),
        syncUploadOptionsFromSettings: () => {},
        sessionStorage: { setItem: () => {} },
    };
    const api = new Function('window', 'document', 'with (window) {' + exportsSrc + '}\nreturn { runExport, runUnpack, switchUploadMode };')(window, document);
    window.runExport = api.runExport;
    return { window, api, opened, form: els.upload_form };
}

test('Reload, Unpack and the mode switch open the overlay', () => {
    for (const run of [
        (p) => p.window.reprocessUploadResults(),
        (p) => p.api.runUnpack(),
        (p) => p.api.switchUploadMode(),
    ]) {
        const page = resultsPage();
        run(page);
        expect(page.opened.length).toBe(1);
    }
});

test('Reload after a new-tab export comes back in this tab', () => {
    const page = resultsPage();
    page.api.runExport('estimate', 'singles', true);
    page.window.reprocessUploadResults();
    expect(page.opened.length).toBe(1);
    expect(page.form.target).toBe('');
});

test('the results page exports leave it closed', () => {
    for (const field of ['download', 'estimate', 'deckbox', 'tcgplayer_csv']) {
        const page = resultsPage();
        page.api.runExport(field, 'singles', field === 'estimate');
        expect(page.opened.length).toBe(0);
    }
});

test('publishing a store closes its prompt and opens the overlay', () => {
    const prompt = new Set(['open']);
    const fields = { store_name: { value: 'Shop' }, store_shorthand: { value: 'SH' } };
    const els = {
        'store-overlay': {
            classList: { add: (c) => prompt.add(c), remove: (c) => prompt.delete(c) },
            querySelector: (sel) => fields[sel.match(/name="([^"]+)"/)[1]],
            querySelectorAll: () => [],
        },
        res_publishstore: { value: '' },
        upload_form: { target: '_blank', submit: () => {}, querySelectorAll: () => [], appendChild: () => {} },
    };
    const document = { addEventListener: () => {}, getElementById: (id) => els[id] || null };
    const opened = [];
    const window = { showUploadProcessing: () => opened.push(true), ensureHashesLoaded: () => {}, resExportFields: [] };
    const run = new Function('window', 'document', 'with (window) {' + storePromptSrc + '}\nreturn runPublishStore;')(window, document);
    run();
    expect(els.res_publishstore.value).toBe('true');
    expect(prompt.has('open')).toBe(false);
    expect(opened.length).toBe(1);
});

function overlayPage(focusedId) {
    const classes = new Set();
    const document = { body: {} };
    const focusable = () => ({ focus() { document.activeElement = this; } });
    const dialog = focusable();
    const buttons = { submit_default: focusable(), reload: focusable() };
    const overlay = {
        classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c) },
        querySelector: (sel) => (sel === '[role="alertdialog"]' ? dialog : null),
    };
    document.activeElement = focusedId ? buttons[focusedId] : document.body;
    document.getElementById = (id) => (id === 'upload-processing' ? overlay : buttons[id] || null);
    const listeners = {};
    const window = { addEventListener: (type, fn) => { listeners[type] = fn; } };
    new Function('window', 'document', 'with (window) {' + processingSrc + '}')(window, document);
    return { window, document, classes, dialog, buttons, listeners };
}

test('opening moves focus into the dialog', () => {
    const page = overlayPage('reload');
    page.window.showUploadProcessing();
    expect(page.classes.has('open')).toBe(true);
    expect(page.document.activeElement).toBe(page.dialog);
});

test('a page restored from the back/forward cache closes it, a fresh load leaves it', () => {
    const page = overlayPage('reload');
    page.window.showUploadProcessing();
    page.listeners.pageshow({ persisted: false });
    expect(page.classes.has('open')).toBe(true);
    page.listeners.pageshow({ persisted: true });
    expect(page.classes.has('open')).toBe(false);
});

test('closing hands focus back to what had it, or to Upload when nothing did', () => {
    const page = overlayPage('reload');
    page.window.showUploadProcessing();
    page.listeners.pageshow({ persisted: true });
    expect(page.document.activeElement).toBe(page.buttons.reload);

    const safari = overlayPage(null);
    safari.window.showUploadProcessing();
    safari.listeners.pageshow({ persisted: true });
    expect(safari.document.activeElement).toBe(safari.buttons.submit_default);
});
