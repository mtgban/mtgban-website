import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/upload-form.js', import.meta.url), 'utf8');

// Any element but the textarea: every property is another no-op stub.
function stub() {
    const fn = function () { return stub(); };
    return new Proxy(fn, { get: (t, k) => (k === Symbol.toPrimitive ? () => '' : stub()), set: () => true });
}

function load(saved, typed) {
    const textArea = { value: typed, style: {}, addEventListener() {} };
    const document = new Proxy({}, {
        get: (t, k) => (k === 'getElementById' ? (id) => (id === 'textArea' ? textArea : stub()) : stub()),
    });
    const store = { uploadTextArea: saved };
    const localStorage = { getItem: (k) => (k in store ? store[k] : null), setItem() {}, removeItem() {} };
    const window = { BAN_UPLOAD_FORM: { buylist: false } };
    // The script calls its own window.X helpers by bare name, as a browser lets it.
    new Function('window', 'document', 'localStorage', 'with (window) {' + source + '}')(window, document, localStorage);
    window.onload();
    return textArea.value;
}

test('onload restores the saved list into an empty box', () => {
    expect(load('4 Lightning Bolt', '')).toBe('4 Lightning Bolt');
});

test('onload keeps text pasted before it ran', () => {
    expect(load('4 Lightning Bolt', '1 Black Lotus')).toBe('1 Black Lotus');
});
