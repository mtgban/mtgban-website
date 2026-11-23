import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'search-type-focus.js'), 'utf8');

// Runs the real js/search-type-focus.js with a fake document holding the
// navbar search box. opts.dialogs lists the page's dialogs, each shown or
// not; opts.boxHidden hides the box itself, and opts.noCheckVisibility
// stands for a browser without Element.checkVisibility. opts.noInsertText
// stands for one that refuses the insertText command.
function load(opts) {
    opts = opts || {};
    let onKey = null, onPaste = null;
    const box = {
        tagName: 'INPUT',
        value: 'lightning bolt',
        focused: false,
        selection: null,
        focus() { this.focused = true; },
        setSelectionRange(a, b) { this.selection = [a, b]; },
        checkVisibility: () => !opts.boxHidden,
        maxLength: 1000,
        events: [],
        dispatchEvent(e) { this.events.push(e.type); },
    };
    const dialogs = (opts.dialogs || []).map(shown => ({ checkVisibility: () => shown }));
    const document = {
        addEventListener: (ev, fn) => { if (ev === 'keydown') onKey = fn; if (ev === 'paste') onPaste = fn; },
        // Types over the box's selection, as the browser does.
        execCommand: (cmd, ui, text) => {
            if (opts.noInsertText || cmd !== 'insertText' || !box.focused || !box.selection) return false;
            box.value = box.value.slice(0, box.selection[0]) + text + box.value.slice(box.selection[1]);
            return true;
        },
        querySelectorAll: sel => (sel === '[role="dialog"], dialog[open]' ? dialogs : []),
        getElementById: id => (id === 'nav-searchbox' ? box : null),
    };
    const Element = { prototype: opts.noCheckVisibility ? {} : { checkVisibility() {} } };
    const tracked = [];
    const window = { BAN: { track: (...a) => tracked.push(a) } };
    new Function('window', 'document', 'Element', source)(window, document, Element);
    const press = (key, extra) => onKey && onKey(Object.assign({
        key, target: { tagName: 'BODY' }, defaultPrevented: false,
        isComposing: false, ctrlKey: false, metaKey: false,
        getModifierState: m => !!(extra && extra.altGraph && m === 'AltGraph'),
    }, extra));
    // Answers whether the page took the paste from the browser.
    const paste = (text, extra) => {
        let taken = false;
        if (onPaste) onPaste(Object.assign({
            target: { tagName: 'BODY' }, defaultPrevented: false,
            clipboardData: { getData: type => (type === 'text/plain' ? text : '') },
            preventDefault() { taken = true; },
        }, extra));
        return taken;
    };
    return { box, press, paste, tracked };
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

test('typing to focus the search box is counted; a key it leaves alone is not', () => {
    const { press, tracked } = load();
    press('s');
    press('s', { target: { tagName: 'INPUT' } });
    press('/');
    press('k', { ctrlKey: true });
    expect(tracked).toEqual([['ui.key', 'type_to_focus']]);
});

test('with a dialog open the key is the dialog\'s and nothing is counted', () => {
    const { press, tracked } = load({ dialogs: [true] });
    press('s');
    expect(tracked).toEqual([]);
});

test('a paste with no field selected replaces the query, and is counted', () => {
    const { box, paste, tracked } = load();
    expect(paste('Force of Will')).toBe(true);
    expect(box.focused).toBe(true);
    expect(box.value).toBe('Force of Will');
    expect(tracked).toEqual([['ui.key', 'paste_to_search']]);
});

test('a paste is joined into one line and trimmed', () => {
    const { box, paste } = load();
    paste('\tForce of Will\r\nAlliances\n');
    expect(box.value).toBe('Force of Will Alliances');
});

test('a paste the browser refuses to insert still reaches the box, within its maxlength', () => {
    const { box, paste } = load({ noInsertText: true });
    paste('x'.repeat(1200));
    expect(box.value).toBe('x'.repeat(1000));
    expect(box.events).toEqual(['input']);
});

test('a paste with no text, or already taken, is left to the browser', () => {
    for (const [text, extra] of [['', {}], [' \n', {}], ['x', { defaultPrevented: true }], ['x', { clipboardData: null }]]) {
        const { box, paste, tracked } = load();
        expect(paste(text, extra)).toBe(false);
        expect(box.value).toBe('lightning bolt');
        expect(tracked).toEqual([]);
    }
});

test('a paste into a field, an open dialog or a page with the box hidden is left to the browser', () => {
    const body = { tagName: 'BODY' };
    for (const [opts, target] of [
        [{}, { tagName: 'INPUT' }], [{}, { tagName: 'TEXTAREA' }], [{}, { tagName: 'SELECT' }],
        [{}, { tagName: 'DIV', isContentEditable: true }],
        [{ dialogs: [true] }, body], [{ boxHidden: true }, body], [{ noCheckVisibility: true }, body],
    ]) {
        const { box, paste, tracked } = load(opts);
        expect(paste('Force of Will', { target })).toBe(false);
        expect(box.focused).toBe(false);
        expect(tracked).toEqual([]);
    }
});
