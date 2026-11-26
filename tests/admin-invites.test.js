import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/admin-invites.js', import.meta.url), 'utf8');

// A feature row as the partial renders it: the page's checkbox and an
// input per option.
function featureRow(page, options) {
    const box = { type: 'checkbox', checked: false, disabled: false };
    const inputs = options.map(key => ({ value: 'stale', getAttribute: name => (name === 'data-option' ? key : null) }));
    return {
        box, inputs,
        getAttribute: name => (name === 'data-page' ? page : null),
        querySelector: () => box,
        querySelectorAll: () => inputs,
    };
}

function load(tier, rows) {
    const select = { value: tier, addEventListener: () => {} };
    const form = {
        querySelector: () => select,
        querySelectorAll: () => rows,
    };
    const document = {
        getElementById: id => (id === 'admin-invite-form' ? form : null),
        querySelectorAll: () => [],
    };
    const window = { BAN_INVITES: { tiers: {
        Pioneer: { Search: { SearchDownloadCSV: 'false' } },
        Legacy: { Search: { SearchDownloadCSV: 'true' }, Newspaper: {} },
    } } };
    new Function('window', 'document', 'navigator', source)(window, document, {});
    return { api: window.AdminInvites, form, select, tiers: window.BAN_INVITES.tiers };
}

test('the form starts on the tier: its pages ticked and fixed, its values filled', () => {
    const search = featureRow('Search', ['SearchDownloadCSV']);
    const news = featureRow('Newspaper', ['NewsLarge']);
    load('Pioneer', [search, news]);
    expect(search.box.checked).toBe(true);
    expect(search.box.disabled).toBe(true);
    expect(search.inputs[0].value).toBe('false');
    expect(news.box.checked).toBe(false);
    expect(news.box.disabled).toBe(false);
    expect(news.inputs[0].value).toBe('');
});

test('changing the tier refills the features from the new one', () => {
    const search = featureRow('Search', ['SearchDownloadCSV']);
    const news = featureRow('Newspaper', ['NewsLarge']);
    const { api, form, select, tiers } = load('Pioneer', [search, news]);
    select.value = 'Legacy';
    api.applyTier(form, tiers);
    expect(search.inputs[0].value).toBe('true');
    expect(news.box.checked).toBe(true);
    expect(news.inputs[0].value).toBe('');
});
