import { test, expect } from 'bun:test';
import { read, tagsWith, expectTrack, fakeBAN } from './metrics-helpers.js';
import { registry } from './track-registry.js';

const source = read('js/cart-prompt.js');

// load runs the script as tests/cart-prompt.test.js does, with window.BAN added.
function load({ skip = null, ban = true } = {}) {
    const stored = {};
    if (skip !== null) stored.cartPromptSkip = skip;
    const localStorage = {
        getItem: (key) => stored[key] ?? null,
        setItem: (key, value) => { stored[key] = value; },
        removeItem: (key) => { delete stored[key]; },
    };
    const overlay = { classList: { add() {}, remove() {} } };
    const checkbox = { checked: false };
    const document = {
        getElementById: (id) => (id === 'cart-overlay' ? overlay : checkbox),
        querySelectorAll: () => [],
        addEventListener() {},
    };
    const opened = [];
    const f = fakeBAN();
    const window = { open: (...args) => opened.push(args) };
    if (ban) window.BAN = f.BAN;
    const fns = new Function('localStorage', 'document', 'window',
        source + '\nreturn {openCartPrompt, showCartPrompt, openCartStore, CART_PREFIXES};')(localStorage, document, window);
    return { ...fns, opened, calls: f.calls };
}

const link = (store, cart) => ({ href: 'https://example.test/cart#ban=1:2', dataset: { store, cart, buylist: 'true' } });

test('a button press shows the panel and counts prompt_shown for its store', () => {
    const page = load();
    expect(page.openCartPrompt(link('MTG Mint Card', 'MMC'))).toBe(false);
    expect(page.calls).toEqual([['ui.cart', 'prompt_shown', 'MMC']]);
});

test('with the skip flag set the press counts prompt_skip and lets the link open', () => {
    const page = load({ skip: 'true' });
    expect(page.openCartPrompt(link('MTG Mint Card', 'MMC'))).toBe(true);
    expect(page.calls).toEqual([['ui.cart', 'prompt_skip', 'MMC']]);
});

test('the ? opens the panel and makes no call of its own', () => {
    const page = load();
    expect(page.showCartPrompt(link('MTG Mint Card', 'MMC'))).toBe(false);
    expect(page.calls).toEqual([]);
});

test('Continue counts open for the store whose panel is up', () => {
    const page = load();
    page.openCartPrompt(link('Card Kingdom', 'CK'));
    page.openCartStore();
    expect(page.opened.length).toBe(1);
    expect(page.calls).toEqual([['ui.cart', 'prompt_shown', 'CK'], ['ui.cart', 'open', 'CK']]);
});

test('a link with no data-cart counts nothing', () => {
    const page = load();
    const old = { href: 'https://example.test/cart', dataset: { store: 'ABU', buylist: 'true' } };
    page.openCartPrompt(old);
    page.openCartStore();
    expect(page.opened.length).toBe(1);
    expect(page.calls).toEqual([]);
});

test('a data-cart outside the counted stores, inherited names included, counts nothing', () => {
    for (const cart of ['Bob', 'constructor', 'toString', '__proto__', '']) {
        const page = load();
        page.openCartPrompt(link('Bob', cart));
        page.openCartStore();
        expect(page.calls).toEqual([]);
    }
});

test('the script counts exactly the stores the registry scopes ui.cart by', () => {
    expect(load().CART_PREFIXES).toEqual(registry['ui.cart'].scopes);
});

test('with no window.BAN the buttons still work', () => {
    const page = load({ ban: false });
    expect(page.openCartPrompt(link('MTG Mint Card', 'MMC'))).toBe(false);
    page.openCartStore();
    expect(page.opened.length).toBe(1);
});

test.each([
    ['templates/upload.html', 'title="How Load at {{$cart.Store}} works', '{{$cart.Prefix}}'],
    ['templates/arbit.html', 'title="How Load at {{$buyCart.Store}} works', '{{$buyCart.Prefix}}'],
    ['templates/arbit.html', 'title="How Load buylist at {{$sellCart.Store}} works', '{{$sellCart.Prefix}}'],
])('%s: the ? beside a cart counts help by its prefix', (file, marker, scope) => {
    const found = tagsWith(read(file), marker);
    expect(found.length).toBe(1);
    expectTrack(found[0], 'ui.cart', 'help', scope);
});

test.each([
    ['templates/upload.html', 'data-store="{{$cart.Store}}" data-cart="{{$cart.Prefix}}"'],
    ['templates/upload.html', 'data-store="{{.Store}}" data-cart="{{.Prefix}}"'],
    ['templates/arbit.html', 'data-store="{{$buyCart.Store}}" data-cart="{{$buyCart.Prefix}}"'],
    ['templates/arbit.html', 'data-store="{{$sellCart.Store}}" data-cart="{{$sellCart.Prefix}}"'],
])('%s carries the cart prefix after the store: %s', (file, run) => {
    expect(read(file)).toContain(run);
});
