import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/abu-prompt.js', import.meta.url), 'utf8');

// load runs the script against a stand-in for the upload page, and hands
// back its functions with what they did to the page.
function load({skip = null, storageThrows = false} = {}) {
    const stored = {};
    if (skip !== null) stored.abuPromptSkip = skip;
    const localStorage = {
        getItem: (key) => { if (storageThrows) throw new Error('blocked'); return stored[key] ?? null; },
        setItem: (key, value) => { if (storageThrows) throw new Error('blocked'); stored[key] = value; },
    };
    const classes = new Set();
    const overlay = {classList: {add: (c) => classes.add(c), remove: (c) => classes.delete(c)}};
    const checkbox = {checked: false};
    const document = {
        getElementById: (id) => (id === 'abu-overlay' ? overlay : checkbox),
        addEventListener() {},
    };
    const opened = [];
    const window = {open: (...args) => opened.push(args)};
    const fns = new Function('localStorage', 'document', 'window',
        source + '\nreturn {openABUPrompt, showABUPrompt, closeABUPrompt, openABU};')(localStorage, document, window);
    return {...fns, classes, checkbox, opened, stored};
}

const link = {href: 'https://abugames.com/cartview/buylist#mtgban=101%3a2'};

describe('abu-prompt', () => {
    test('the first press shows the panel instead of opening ABU', () => {
        const page = load();
        expect(page.openABUPrompt(link)).toBe(false);
        expect(page.classes.has('open')).toBe(true);
    });

    test('Open @ ABU opens the button\'s link and closes the panel', () => {
        const page = load();
        page.openABUPrompt(link);
        page.openABU();
        expect(page.opened).toEqual([[link.href, '_blank', 'noopener']]);
        expect(page.classes.has('open')).toBe(false);
        expect(page.stored.abuPromptSkip).toBeUndefined();
    });

    test('Don\'t show this again lets later presses open ABU directly', () => {
        const page = load();
        page.openABUPrompt(link);
        page.checkbox.checked = true;
        page.openABU();
        expect(page.stored.abuPromptSkip).toBe('true');
        expect(page.openABUPrompt(link)).toBe(true);
    });

    test('the ? link shows the panel again after it was skipped', () => {
        const page = load({skip: 'true'});
        expect(page.openABUPrompt(link)).toBe(true);
        expect(page.showABUPrompt(link)).toBe(false);
        expect(page.classes.has('open')).toBe(true);
        page.openABU();
        expect(page.opened).toEqual([[link.href, '_blank', 'noopener']]);
    });

    test('blocked storage still shows the panel and opens ABU', () => {
        const page = load({storageThrows: true});
        expect(page.openABUPrompt(link)).toBe(false);
        page.checkbox.checked = true;
        page.openABU();
        expect(page.opened).toHaveLength(1);
    });
});
