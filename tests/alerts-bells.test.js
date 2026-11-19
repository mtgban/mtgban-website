import { test, expect } from 'bun:test';
import { read } from './metrics-helpers.js';

const source = read('js/alerts.js');
const BELLS = '.alert-link[data-card-id], .m-actions-alert[data-card-id]';

function bell(card, side) {
    const attrs = { 'data-card-id': card };
    if (side) attrs['data-side'] = side;
    const b = { active: false, title: '', getAttribute: name => (name in attrs ? attrs[name] : null) };
    b.classList = { toggle: (c, on) => { b.active = on; } };
    return b;
}

// Loads js/alerts.js on a page with only these bells; section is what
// #opt-not-bought answers, and observers collects each IntersectionObserver.
function load(bells, { section = null, observers } = {}) {
    const listeners = {};
    const document = {
        addEventListener: (type, fn) => { listeners[type] = fn; },
        getElementById: id => (id === 'opt-not-bought' ? section : null),
        querySelector: sel => (sel === BELLS ? bells[0] || null : null),
        querySelectorAll: sel => (sel === BELLS ? bells : []),
    };
    const window = { localStorage: { getItem: () => null, setItem() {} } };
    if (observers) {
        window.IntersectionObserver = function (fn) {
            const o = { fn, observed: [], connected: true, observe: el => o.observed.push(el), disconnect: () => { o.connected = false; } };
            observers.push(o);
            return o;
        };
    }
    const calls = [];
    const fetch = path => new Promise(resolve => {
        calls.push({ path, answer: data => resolve({
            status: 200, ok: true,
            headers: { get: () => 'application/json' },
            json: () => Promise.resolve(data),
        }) });
    });
    new Function('window', 'document', 'fetch', source)(window, document, fetch);
    return { calls, ready: () => listeners.DOMContentLoaded() };
}

const settle = () => new Promise(r => setTimeout(r, 0));

test('a bell with a side fills only for an alert on that side', async () => {
    const any = bell('card-a');
    const buylist = bell('card-a', 'buylist');
    const both = bell('card-b', 'buylist');
    const none = bell('card-c');
    const a = load([any, buylist, both, none]);
    a.ready();
    a.calls[0].answer([{ card_id: 'card-a', side: 'retail' }, { card_id: 'card-b', side: 'retail' }, { card_id: 'card-b', side: 'buylist' }]);
    await settle();
    expect([any.active, buylist.active, both.active, none.active]).toEqual([true, false, true, false]);
    expect([any.title, buylist.title]).toEqual(['Price alert set', 'Set a price alert']);
});

test("Upload reads the alerts when Not bought comes into view, once", async () => {
    const section = {};
    const observers = [];
    const a = load([bell('card-a', 'buylist')], { section, observers });
    a.ready();
    expect(a.calls.length).toBe(0);
    expect(observers[0].observed).toEqual([section]);
    observers[0].fn([{ isIntersecting: false }]);
    expect(a.calls.length).toBe(0);
    observers[0].fn([{ isIntersecting: true }]);
    expect(a.calls.map(c => c.path)).toEqual(['/api/alerts/']);
    expect(observers[0].connected).toBe(false);
});

test('a page without Not bought, or a browser without the observer, reads them at load', () => {
    const search = load([bell('card-a')], { observers: [] });
    search.ready();
    expect(search.calls.length).toBe(1);
    const old = load([bell('card-a', 'buylist')], { section: {} });
    old.ready();
    expect(old.calls.length).toBe(1);
});
