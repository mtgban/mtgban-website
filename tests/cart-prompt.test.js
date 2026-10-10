import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/cart-prompt.js', import.meta.url), 'utf8');

// load runs the script against a stand-in for the upload page, and hands
// back its functions with what they did to the page.
function load({skip = null, storageThrows = false} = {}) {
    const stored = {};
    if (skip !== null) stored.cartPromptSkip = skip;
    const localStorage = {
        getItem: (key) => { if (storageThrows) throw new Error('blocked'); return stored[key] ?? null; },
        setItem: (key, value) => { if (storageThrows) throw new Error('blocked'); stored[key] = value; },
        removeItem: (key) => { if (storageThrows) throw new Error('blocked'); delete stored[key]; },
    };
    const classes = new Set();
    const overlay = {classList: {add: (c) => classes.add(c), remove: (c) => classes.delete(c)}};
    const checkbox = {checked: false};
    const names = [{textContent: ''}, {textContent: ''}];
    const buylistWords = [{hidden: false}];
    const retailWords = [{hidden: false}];
    const document = {
        getElementById: (id) => (id === 'cart-overlay' ? overlay : checkbox),
        querySelectorAll: (sel) => (sel.endsWith('-store') ? names : sel.endsWith('-buylist') ? buylistWords : retailWords),
        addEventListener() {},
    };
    const opened = [];
    const window = {open: (...args) => opened.push(args)};
    const fns = new Function('localStorage', 'document', 'window',
        source + '\nreturn {openCartPrompt, showCartPrompt, closeCartPrompt, openCartStore};')(localStorage, document, window);
    return {...fns, classes, checkbox, names, buylistWords, retailWords, opened, stored};
}

const link = {href: 'https://abugames.com/cartview/buylist#ban=101:2', dataset: {store: 'ABU', buylist: 'true'}};

describe('cart-prompt', () => {
    test('the first press shows the panel, named for the store, instead of opening it', () => {
        const page = load();
        expect(page.openCartPrompt(link)).toBe(false);
        expect(page.classes.has('open')).toBe(true);
        expect(page.names.map((n) => n.textContent)).toEqual(['ABU', 'ABU']);
    });

    test('the panel words itself for the button\'s side', () => {
        const page = load();
        page.openCartPrompt(link);
        expect(page.buylistWords[0].hidden).toBe(false);
        expect(page.retailWords[0].hidden).toBe(true);
        page.showCartPrompt({href: 'https://abugames.com/cartview/shop#ban=301:2', dataset: {store: 'ABU', buylist: 'false'}});
        expect(page.buylistWords[0].hidden).toBe(true);
        expect(page.retailWords[0].hidden).toBe(false);
    });

    test('Continue @ store opens the button\'s link and closes the panel', () => {
        const page = load();
        page.openCartPrompt(link);
        page.openCartStore();
        expect(page.opened).toEqual([[link.href, '_blank', 'noopener']]);
        expect(page.classes.has('open')).toBe(false);
        expect(page.stored.cartPromptSkip).toBeUndefined();
    });

    test('Don\'t show this again lets later presses open the store directly', () => {
        const page = load();
        page.openCartPrompt(link);
        page.checkbox.checked = true;
        page.openCartStore();
        expect(page.stored.cartPromptSkip).toBe('true');
        expect(page.openCartPrompt(link)).toBe(true);
    });

    test('the ? link shows the panel again after it was skipped', () => {
        const page = load({skip: 'true'});
        expect(page.openCartPrompt(link)).toBe(true);
        expect(page.showCartPrompt(link)).toBe(false);
        expect(page.classes.has('open')).toBe(true);
        page.openCartStore();
        expect(page.opened).toEqual([[link.href, '_blank', 'noopener']]);
    });

    test('a box ticked by the browser, not the user, does not skip the panel', () => {
        const page = load();
        page.checkbox.checked = true;
        page.openCartPrompt(link);
        expect(page.checkbox.checked).toBe(false);
        page.openCartStore();
        expect(page.stored.cartPromptSkip).toBeUndefined();
        expect(page.openCartPrompt(link)).toBe(false);
    });

    test('unticking the box from the ? link brings the panel back', () => {
        const page = load({skip: 'true'});
        page.showCartPrompt(link);
        expect(page.checkbox.checked).toBe(true);
        page.checkbox.checked = false;
        page.openCartStore();
        expect(page.stored.cartPromptSkip).toBeUndefined();
        expect(page.openCartPrompt(link)).toBe(false);
    });

    test('blocked storage still shows the panel and opens the store', () => {
        const page = load({storageThrows: true});
        expect(page.openCartPrompt(link)).toBe(false);
        page.checkbox.checked = true;
        page.openCartStore();
        expect(page.opened).toHaveLength(1);
    });
});
