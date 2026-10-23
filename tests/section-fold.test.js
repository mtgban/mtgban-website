import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/section-fold.js', import.meta.url), 'utf8');

// load runs the script against a store section holding its fold button and
// returns a click on the button, a click elsewhere, and the two elements.
function load() {
    const classes = new Set();
    const section = {
        classList: { toggle: (c) => (classes.has(c) ? classes.delete(c) : classes.add(c), classes.has(c)) },
        folded: () => classes.has('folded'),
    };
    const attrs = {};
    const btn = {
        title: 'Hide these cards',
        setAttribute: (k, v) => { attrs[k] = v; },
        closest: (sel) => (sel === '[data-fold]' ? section : null),
        attrs,
    };
    const document = {
        addEventListener(type, fn) { this[type] = fn; },
    };
    new Function('document', source)(document);
    const click = (el) => document.click({ target: { closest: (sel) => (sel === '.section-fold' ? el : null) } });
    return { section, btn, clickButton: () => click(btn), clickElsewhere: () => click(null) };
}

test('the button folds its section and unfolds it again', () => {
    const { section, btn, clickButton } = load();
    clickButton();
    expect(section.folded()).toBe(true);
    expect(btn.attrs['aria-expanded']).toBe('false');
    expect(btn.title).toBe('Show these cards');
    clickButton();
    expect(section.folded()).toBe(false);
    expect(btn.attrs['aria-expanded']).toBe('true');
    expect(btn.title).toBe('Hide these cards');
});

test('a click outside a fold button leaves the section alone', () => {
    const { section, clickElsewhere } = load();
    clickElsewhere();
    expect(section.folded()).toBe(false);
});
