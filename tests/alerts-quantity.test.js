import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/alerts.js', import.meta.url), 'utf8');

// A stand-in for any element the modal touches, as in alerts-stores.test.js.
function element() {
    const classes = new Set();
    const attrs = {};
    const found = {};
    const el = {
        children: [],
        textContent: '', value: '', title: '', className: '', hidden: false, disabled: false,
        classList: {
            add: c => classes.add(c), remove: c => classes.delete(c),
            toggle: (c, on) => { on ? classes.add(c) : classes.delete(c); },
            contains: c => classes.has(c),
        },
        getAttribute: name => (name in attrs ? attrs[name] : null),
        setAttribute: (name, v) => { attrs[name] = String(v); },
        querySelector: sel => found[sel] || (found[sel] = element()),
        querySelectorAll: () => [],
        appendChild: child => { el.children.push(child); },
        focus: () => {}, contains: () => true, addEventListener: () => {},
    };
    Object.defineProperty(el, 'innerHTML', { set: () => { el.children = []; } });
    el.elements = new Proxy({}, { get: (t, name) => t[name] || (t[name] = element()) });
    return el;
}

// Opens the modal over stand-ins, answering each request in turn, and
// returns the quantity's label and input.
async function openModal(opts, answers) {
    const byId = {};
    const document = {
        addEventListener: () => {},
        getElementById: id => (id.startsWith('alerts-') ? null : byId[id] || (byId[id] = element())),
        querySelector: () => null,
        querySelectorAll: () => [],
        createElement: () => element(),
        body: element(),
    };
    const fetch = () => Promise.resolve({
        status: 200, ok: true,
        headers: { get: () => 'application/json' },
        json: () => Promise.resolve(answers.shift()),
    });
    const window = {};
    new Function('window', 'document', 'fetch', source)(window, document, fetch);
    window.openAlertModal(opts);
    for (let i = 0; i < 6; i++) await new Promise(r => setTimeout(r, 0));
    return { label: byId['alert-quantity-label'], input: byId['alert-form'].elements.quantity };
}

const options = { card: { name: 'Card', set: 'SET', number: '1', finish: 'nonfoil' }, conditions: ['NM'], stores: [] };

test('a buylist alert asks how many you have, a retail one how many you want', async () => {
    const buylist = await openModal({ cardId: 'card-a', side: 'buylist' }, [options, [], []]);
    expect(buylist.label.textContent).toBe('You have');
    expect(buylist.input.value).toBe('');
    const retail = await openModal({ cardId: 'card-a', side: 'retail' }, [options, [], []]);
    expect(retail.label.textContent).toBe('You want');
});

test('editing an alert shows the quantity it noted', async () => {
    const alert = {
        id: 7, card_id: 'card-a', side: 'retail', condition: 'NM', stores: [], quantity: 3,
        reference_price: 10, above: { kind: 'abs', value: 12 }, below: {}, delivery: 'discord',
    };
    const { label, input } = await openModal({ alertId: 7 }, [[alert], options, []]);
    expect(label.textContent).toBe('You want');
    expect(input.value).toBe(3);
});
