import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const autocomplete = readFileSync(join(import.meta.dir, '..', 'js', 'autocomplete.js'), 'utf8');

// Two boxes on one page, the search box and the pinned filters, each with
// its document click handler: a tap on a box keeps its own list open, and
// only a tap outside closes it.
function page() {
    const lists = [];
    const clicks = [];
    const box = () => {
        const form = {
            children: [],
            querySelector(sel) { return sel === '.ac-dropdown' ? this.children[0] || null : null; },
            removeChild(c) {
                this.children = this.children.filter((x) => x !== c);
                lists.splice(lists.indexOf(c), 1);
            },
        };
        const inp = { value: '', defaultValue: '', parentNode: form, addEventListener() {} };
        return { inp, form };
    };
    const document = {
        activeElement: null,
        addEventListener(type, fn) { if (type === 'click') clicks.push(fn); },
        getElementsByClassName: () => lists.slice(),
    };
    const autocompleteFn = new Function('fetchNames', 'document', 'window', 'self',
        autocomplete + '\n;return autocomplete;')(() => Promise.resolve([]), document, {}, {});
    const a = box();
    const b = box();
    autocompleteFn({}, a.inp, 'false');
    autocompleteFn({}, b.inp, 'false');
    const open = (x) => { const list = { parentNode: x.form }; x.form.children.push(list); lists.push(list); };
    const click = (target) => clicks.forEach((fn) => fn({ target }));
    return { a, b, lists, open, click };
}

test('a tap on a box keeps its own list, though another box listens too', () => {
    const p = page();
    p.open(p.a);
    p.click(p.a.inp);
    expect(p.lists).toHaveLength(1);
});

test('a tap outside every box closes the open list', () => {
    const p = page();
    p.open(p.a);
    p.click({});
    expect(p.lists).toHaveLength(0);
});
