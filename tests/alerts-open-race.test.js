import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/alerts.js', import.meta.url), 'utf8');

// A stand-in for any element the modal touches: it remembers what it is
// told, answers every query with another stand-in and lists nothing.
function element() {
    const classes = new Set();
    const attrs = {};
    const children = {};
    const listeners = {};
    const el = {
        listeners,
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
        appendChild: () => {}, focus: () => {}, contains: () => true,
        addEventListener: (type, fn) => { listeners[type] = fn; },
    };
    el.elements = new Proxy({}, { get: (t, name) => t[name] || (t[name] = element()) });
    return el;
}

// Loads js/alerts.js over a document of stand-ins and a fetch whose
// answers the test releases one by one, in the order they were asked.
// The document is the search page's: the modal, and no alerts page.
function load() {
    const byId = {};
    const el = id => (id.startsWith('alerts-') ? null : byId[id] || (byId[id] = element()));
    const listeners = {};
    const document = {
        addEventListener: (type, fn) => { listeners[type] = fn; },
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
        }), fail: error => resolve({
            status: 500, ok: false,
            headers: { get: () => 'application/json' },
            json: () => Promise.resolve({ error }),
        }) });
    });
    new Function('window', 'document', 'fetch', source)(window, document, fetch);
    return { window, el, calls, ready: () => listeners.DOMContentLoaded(), key: e => listeners.keydown(e) };
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

test('a side toggled twice keeps the answer for the side it ends on', async () => {
    const { window, el, calls, ready } = load();
    ready();
    const options = price => ({
        card: { name: 'Card', set: 'SET', number: '1', finish: 'nonfoil' }, conditions: ['NM'],
        stores: [{ shorthand: 'X', name: 'X', prices: { NM: price } }],
    });
    const reference = () => el('alert-form').elements.reference_price.value;
    window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    calls[0].answer(options(10));
    await settle();
    calls[1].answer([]);
    await settle();
    calls[2].answer([]);
    await settle();
    expect(reference()).toBe('10.00');

    const click = side => el('alert-modal').listeners.click({ target: { closest: sel =>
        sel === '.settings-pill[data-value]' ? { getAttribute: () => side, parentNode: { getAttribute: () => 'side' } } : null } });
    click('buylist');
    click('retail');
    expect(calls.slice(3).map(c => c.path)).toEqual([
        '/api/alerts/options?card=card-a&side=buylist',
        '/api/alerts/options?card=card-a&side=retail',
    ]);
    // The retail answer comes back first, the buylist one it left last.
    calls[4].answer(options(10));
    await settle();
    calls[3].answer(options(6));
    await settle();
    expect(reference()).toBe('10.00');
});

test('the latest of two loads for one side is kept, and Save waits for it', async () => {
    const { window, el, calls, ready, key } = load();
    ready();
    const options = price => ({
        card: { name: 'Card', set: 'SET', number: '1', finish: 'nonfoil' }, conditions: ['NM'],
        stores: [{ shorthand: 'X', name: 'X', prices: { NM: price } }],
    });
    const reference = () => el('alert-form').elements.reference_price.value;
    window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    calls[0].answer(options(10));
    await settle();
    calls[1].answer([]);
    await settle();
    calls[2].answer([]);
    await settle();

    const click = side => el('alert-modal').listeners.click({ target: { closest: sel =>
        sel === '.settings-pill[data-value]' ? { getAttribute: () => side, parentNode: { getAttribute: () => 'side' } } : null } });
    click('buylist');
    click('retail');
    click('buylist');
    const save = el('alert-modal').querySelector('[data-role="save"]');
    expect(save.disabled).toBe(true);
    // Enter in a box saves past the button; mid-load it does nothing at all.
    key({ key: 'Enter', target: { tagName: 'INPUT' }, preventDefault() {} });
    expect(el('alert-form-error').textContent).toBe('');
    // The latest buylist answer comes back first, the older one last.
    calls[5].answer(options(6));
    await settle();
    calls[3].answer(options(7));
    await settle();
    calls[4].answer(options(10));
    await settle();
    expect(reference()).toBe('6.00');
});

test('a side whose options fail to load can be picked again', async () => {
    const { window, el, calls, ready } = load();
    ready();
    const options = { card: { name: 'Card', set: 'SET', number: '1', finish: 'nonfoil' }, conditions: ['NM'], stores: [] };
    window.openAlertModal({ cardId: 'card-a', side: 'retail' });
    calls[0].answer(options);
    await settle();
    calls[1].answer([]);
    await settle();
    calls[2].answer([]);
    await settle();

    const click = side => el('alert-modal').listeners.click({ target: { closest: sel =>
        sel === '.settings-pill[data-value]' ? { getAttribute: () => side, parentNode: { getAttribute: () => 'side' } } : null } });
    click('buylist');
    calls[3].fail('options unavailable');
    await settle();
    await settle();
    expect(el('alert-form-error').textContent).toBe('options unavailable');
    // Back on retail, so Buylist asks again.
    click('buylist');
    expect(calls.slice(4).map(c => c.path)).toEqual(['/api/alerts/options?card=card-a&side=buylist']);
});
