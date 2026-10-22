import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'search-type-focus.js'), 'utf8');

// Runs the real js/search-type-focus.js with a fake document holding the
// navbar search box. opts.dialogs lists the page's dialogs, each shown or
// not; opts.boxHidden hides the box itself, and opts.noCheckVisibility
// stands for a browser without Element.checkVisibility.
function load(opts) {
    opts = opts || {};
    let onKey = null;
    const box = {
        tagName: 'INPUT',
        value: 'lightning bolt',
        focused: false,
        selection: null,
        focus() { this.focused = true; },
        setSelectionRange(a, b) { this.selection = [a, b]; },
        checkVisibility: () => !opts.boxHidden,
    };
    const dialogs = (opts.dialogs || []).map(shown => ({ checkVisibility: () => shown }));
    const document = {
        addEventListener: (ev, fn) => { if (ev === 'keydown') onKey = fn; },
        querySelectorAll: sel => (sel === '[role="dialog"], dialog[open]' ? dialogs : []),
        getElementById: id => (id === 'nav-searchbox' ? box : null),
    };
    const Element = { prototype: opts.noCheckVisibility ? {} : { checkVisibility() {} } };
    new Function('document', 'Element', source)(document, Element);
    const press = (key, extra) => onKey && onKey(Object.assign({
        key, target: { tagName: 'BODY' }, defaultPrevented: false,
        isComposing: false, ctrlKey: false, metaKey: false,
        getModifierState: m => !!(extra && extra.altGraph && m === 'AltGraph'),
    }, extra));
    return { box, press };
}

test('a printable key focuses the search box with its query selected', () => {
    const { box, press } = load();
    press('s');
    expect(box.focused).toBe(true);
    expect(box.selection).toEqual([0, box.value.length]);
});

test('a character typed with AltGr (Ctrl+Alt on Windows) still counts', () => {
    const { box, press } = load();
    press('@', { ctrlKey: true, altGraph: true });
    expect(box.focused).toBe(true);
});

test('keys that are not text, or are taken, leave focus alone', () => {
    for (const key of ['Enter', 'Tab', 'Escape', 'ArrowDown', 'PageDown', ' ', '/']) {
        const { box, press } = load();
        press(key);
        expect(box.focused).toBe(false);
    }
    for (const extra of [{ ctrlKey: true }, { metaKey: true }, { defaultPrevented: true }, { isComposing: true }]) {
        const { box, press } = load();
        press('c', extra);
        expect(box.focused).toBe(false);
    }
});

test('a field that has the caret keeps the key', () => {
    for (const target of [{ tagName: 'INPUT' }, { tagName: 'TEXTAREA' }, { tagName: 'SELECT' }, { tagName: 'DIV', isContentEditable: true }]) {
        const { box, press } = load();
        press('a', { target });
        expect(box.focused).toBe(false);
    }
});

test('an open dialog keeps the key, closed ones do not', () => {
    let page = load({ dialogs: [false, true] });
    page.press('a');
    expect(page.box.focused).toBe(false);
    page = load({ dialogs: [false, false] });
    page.press('a');
    expect(page.box.focused).toBe(true);
});

test('a search box the page hides is left alone', () => {
    const { box, press } = load({ boxHidden: true });
    press('a');
    expect(box.focused).toBe(false);
});

test('a browser without checkVisibility leaves keys alone', () => {
    const { box, press } = load({ noCheckVisibility: true, dialogs: [false] });
    press('a');
    expect(box.focused).toBe(false);
});
