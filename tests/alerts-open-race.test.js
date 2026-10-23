import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/alerts.js', import.meta.url), 'utf8');

// A stand-in for any element the modal touches: it remembers what it is
// told, answers every query with another stand-in and lists nothing.
function element() {
    const classes = new Set();
    const attrs = {};
    const children = {};
    const el = {
        textContent: '', innerHTML: '', value: '', hidden: false, disabled: false,
        classList: {
            add: c => classes.add(c), remove: c => classes.delete(c),
            toggle: (c, on) => { on ? classes.add(c) : classes.delete(c); },
            contains: c => classes.has(c),
        },
        getAttribute: name => (name in attrs ? attrs[name] : null),
        setAttribute: (name, v) => { attrs[name] = String(v); },
        querySelector: sel => children[sel] || (children[sel] = element()),
        querySelectorAll: () => [],
        appendChild: () => {}, addEventListener: () => {}, focus: () => {},
    };
    el.elements = new Proxy({}, { get: (t, name) => t[name] || (t[name] = element()) });
    return el;
}

// Loads js/alerts.js over a document of stand-ins and a fetch whose
// answers the test releases one by one, in the order they were asked.
function load() {
    const byId = {};
    const el = id => byId[id] || (byId[id] = element());
    const document = {
        addEventListener: () => {},
        getElementById: el,
        querySelector: () => null,
        querySelectorAll: () => [],
        createElement: () => element(),
        body: element(),
    };
    const window = {};
    const calls = [];
    const fetch = (path) => new Promise(resolve => {
        calls.push({ path, answer: data => resolve({
            status: 200, ok: true,
            headers: { get: () => 'application/json' },
            json: () => Promise.resolve(data),
        }) });
    });
    new Function('window', 'document', 'fetch', source)(window, document, fetch);
    return { window, el, calls };
}

const settle = () => new Promise(r => setTimeout(r, 0));

test('an open over one still loading renders the second card alone', async () => {
    const { window, el, calls } = load();
    const options = name => ({ card: { name, set: 'SET', number: '1', finish: 'nonfoil' }, stores: [], conditions: ['NM'] });

    window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    window.openAlertModal({ cardId: 'card-b', side: 'retail' });
    expect(calls.map(c => c.path)).toEqual([
        '/api/alerts/options?card=card-a&side=retail',
        '/api/alerts/options?card=card-b&side=retail',
    ]);

    // The second open's answers come back first, and it draws.
    calls[1].answer(options('Card B'));
    await settle();
    calls[2].answer([]);
    await settle();
    calls[3].answer([]);
    await settle();
    expect(el('alert-modal-card').textContent).toBe('Card B, SET #1, nonfoil');

    // The first open's answers arrive late and change nothing on screen.
    calls[0].answer(options('Card A'));
    await settle();
    calls[4].answer([]);
    await settle();
    calls[5].answer([]);
    await settle();
    expect(calls.length).toBe(6);
    expect(el('alert-modal-card').textContent).toBe('Card B, SET #1, nonfoil');
});

test('a load that fails after another open took over stays silent', async () => {
    const { window, el, calls } = load();
    window.openAlertModal({ alertId: '7' });
    window.openAlertModal({ cardId: 'card-b', side: 'buylist' });
    // The edit's alert list no longer has alert 7.
    calls[0].answer([]);
    await settle();
    expect(el('alert-form-error').textContent).toBe('');
    expect(el('alert-modal-card').textContent).toBe('Loading');
});
