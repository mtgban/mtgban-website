import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'icons.js'), 'utf8');

export function run(opts = {}) {
    const { cards = [], placeholders = [], activeCards = [] } = opts;
    const calls = [];
    const lucideMock = { createIcons: (o) => calls.push(o === undefined ? 'document' : o.root) };
    const lucide = Object.hasOwn(opts, 'lucide') ? opts.lucide : lucideMock;
    const window = { lucide, innerHeight: 800 };
    let readyFn = null;
    const document = {
        addEventListener: (ev, fn) => { if (ev === 'DOMContentLoaded') readyFn = fn; },
        querySelectorAll: (sel) => (sel === '.m-card' ? cards : sel === 'i[data-lucide]' ? placeholders : []),
    };
    let observer = null;
    function IntersectionObserver(cb, ioOpts) {
        observer = { cb, opts: ioOpts, observed: [], unobserved: [], observe(el) { this.observed.push(el); }, unobserve(el) { this.unobserved.push(el); } };
        return observer;
    }
    const io = Object.hasOwn(opts, 'io') ? opts.io : IntersectionObserver;
    new Function('window', 'document', 'IntersectionObserver', source)(window, document, io);
    return { window, calls, ready: () => readyFn && readyFn(), observer: () => observer };
}

function placeholder(inCard) {
    const attrs = { 'data-lucide': 'star' };
    return {
        closest: (sel) => (sel === '.m-card' && inCard ? inCard : null),
        getAttribute: (k) => attrs[k] ?? null,
        setAttribute: (k, v) => { attrs[k] = v; },
        removeAttribute: (k) => { delete attrs[k]; },
        hasAttribute: (k) => k in attrs,
        attrs,
    };
}

test('paintIcons paints the given root, or the document, and tolerates no lucide', () => {
    const { window, calls } = run();
    window.paintIcons();
    window.paintIcons('root1');
    expect(calls).toEqual(['document', 'root1']);
    const { window: w2, calls: calls2 } = run({ lucide: undefined });
    expect(() => w2.paintIcons()).not.toThrow();
    expect(calls2).toEqual([]);
});

test('on DOM ready, with no cards, everything is painted once', () => {
    const { calls, ready } = run();
    ready();
    expect(calls).toEqual(['document']);
});

test('on DOM ready, card icons are parked, the rest painted, and cards observed', () => {
    const card1 = { querySelectorAll: () => [] }, card2 = { querySelectorAll: () => [] };
    const inCard = placeholder(card1), outside = placeholder(null);
    card1.querySelectorAll = (sel) => (sel === 'i[data-lucide-lazy]' ? [inCard] : []);
    const { calls, ready, observer } = run({ cards: [card1, card2], placeholders: [inCard, outside] });
    ready();
    expect(inCard.attrs['data-lucide']).toBeUndefined();
    expect(inCard.attrs['data-lucide-lazy']).toBe('star');
    expect(outside.attrs['data-lucide']).toBe('star');
    expect(calls).toEqual(['document']);
    const io = observer();
    expect(io.observed).toEqual([card1, card2]);
    expect(io.opts.rootMargin).toBe('800px 0px');
    io.cb([{ isIntersecting: true, target: card1 }, { isIntersecting: false, target: card2 }]);
    expect(inCard.attrs['data-lucide']).toBe('star');
    expect(inCard.attrs['data-lucide-lazy']).toBeUndefined();
    expect(calls).toEqual(['document', card1]);
    expect(io.unobserved).toEqual([card1]);
});

test('without IntersectionObserver every card is painted at once', () => {
    const card = { querySelectorAll: () => [] };
    const { calls, ready } = run({ cards: [card], io: undefined });
    ready();
    expect(calls).toEqual(['document', card]);
});
