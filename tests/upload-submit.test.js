import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const html = readFileSync(new URL('../templates/upload.html', import.meta.url), 'utf8');
const script = html.match(/<script type="text\/javascript">(\s*const hiddenBools[\s\S]*?)<\/script\b[^>]*>/i)[1];

function click(field, synced) {
    const fields = {};
    for (const id of ['upload', 'download', 'estimate', 'deckbox', 'tcgplayer_csv']) fields[id] = { value: 'false' };
    const calls = [];
    const form = { target: 'x', submit: () => calls.push('submit') };
    const document = { getElementById: (id) => (id === 'upload_form' ? form : fields[id]) };
    const window = synced ? { syncUploadOptionsFromSettings: () => calls.push('sync') } : {};
    const submitForm = new Function('window', 'document', 'with (window) {' + script + '}\nreturn submitForm;')(window, document);
    submitForm(field, false);
    return { calls, fields };
}

// The button returns false after the call, so a click that does not submit
// here is dropped without a word.
test('a click before the settings sync loads still submits, for the button clicked', () => {
    const { calls, fields } = click('download', false);
    expect(calls).toEqual(['submit']);
    expect(fields.download.value).toBe('true');
    expect(fields.upload.value).toBe('');
});

test('once loaded, the settings are synced before the submit', () => {
    expect(click('upload', true).calls).toEqual(['sync', 'submit']);
});
