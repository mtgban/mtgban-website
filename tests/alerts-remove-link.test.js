import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/alerts.js', import.meta.url), 'utf8');

// Loads js/alerts.js over an alerts page opened on ?remove=<removeId>,
// listing rows (id to card name), and runs its DOMContentLoaded. The log
// records the URL rewrite and the confirm in the order they happen.
function arrive(removeId, rows) {
    const log = [];
    const page = { getAttribute: name => (name === 'data-open-remove' ? removeId : null) };
    const row = id => ({
        getAttribute: name => (name === 'data-name' ? rows[id] : null),
        scrollIntoView: () => log.push('scroll ' + id),
    });
    let listener;
    const document = {
        addEventListener: (type, fn) => { if (type === 'DOMContentLoaded') listener = fn; },
        getElementById: id => (id === 'alerts-page' ? page : null),
        querySelector: sel => {
            const m = sel.match(/^\.alerts-table tr\[data-id="(.*)"\]$/);
            return m && m[1] in rows ? row(m[1]) : null;
        },
        querySelectorAll: () => [],
    };
    const window = {
        location: { pathname: '/alerts' },
        history: { replaceState: (state, title, url) => log.push('url ' + url) },
        confirmDialog: (message) => log.push('confirm ' + message),
    };
    new Function('window', 'document', source)(window, document);
    listener();
    return log;
}

test('?remove= drops the query, then asks to delete the row, naming its card', () => {
    expect(arrive('2', { 1: 'Lightning Bolt', 2: 'Sol Ring' })).toEqual([
        'url /alerts',
        'scroll 2',
        'confirm Delete your Sol Ring alert?',
    ]);
});

test('?remove= with no matching row asks with the generic prompt', () => {
    expect(arrive('9', { 1: 'Lightning Bolt' })).toEqual([
        'url /alerts',
        'confirm Delete this alert?',
    ]);
});
