import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const autocomplete = readFileSync(join(import.meta.dir, '..', 'js', 'autocomplete.js'), 'utf8');

// Just enough DOM for the suggestion handler to build its dropdown.
function element(tag) {
    return {
        tagName: tag, childNodes: [], attrs: {}, style: {},
        setAttribute(k, v) { this.attrs[k] = v; if (k === 'id') this.id = v; },
        appendChild(c) { this.childNodes.push(c); c.parentNode = this; return c; },
        removeChild(c) { this.childNodes = this.childNodes.filter((n) => n !== c); },
        hasChildNodes() { return this.childNodes.length > 0; },
        addEventListener() {},
        getElementsByTagName() { return []; },
    };
}

async function suggest(names, typed) {
    const parent = element('div');
    const handlers = [];
    const inp = {
        id: 'searchbox', value: '', defaultValue: '', parentNode: parent,
        addEventListener(type, fn) { if (type === 'input') handlers.push(fn); },
        dispatchEvent() { handlers.forEach((fn) => fn.call(inp, {})); },
        getBoundingClientRect() { return { bottom: 0 }; },
    };
    const documentStub = {
        activeElement: inp, body: { contains: () => true }, addEventListener() {},
        createElement: element, createTextNode: (text) => ({ text }),
        getElementsByClassName: (cls) => parent.childNodes.filter((c) => (c.attrs.class || '').split(' ').includes(cls)),
    };
    const windowStub = { innerHeight: 800, addEventListener() {}, removeEventListener() {} };
    const fn = new Function('fetchNames', 'document', 'window', 'self', autocomplete + '\n;return autocomplete;');
    fn(() => Promise.resolve(names), documentStub, windowStub, {})({}, inp, 'false');

    // The first keystroke fetches the names, then the handler runs again.
    inp.value = typed;
    inp.dispatchEvent();
    await new Promise((resolve) => setTimeout(resolve, 0));
    const list = parent.childNodes.find((c) => c.id === 'searchboxautocomplete-list');
    return list ? list.childNodes.map((row) => row.childNodes.map((n) => n.text || n.textContent).join('')) : [];
}

const goblins = Array.from({ length: 120 }, (_, i) => 'Goblin ' + String(i).padStart(3, '0'));

test('a short prefix draws the first fifty matches, in list order', async () => {
    const rows = await suggest(['Goat', ...goblins], 'gob');
    expect(rows).toEqual(goblins.slice(0, 50));
});

test('a narrower prefix still draws every match under the cap', async () => {
    const rows = await suggest(goblins, 'goblin 11');
    expect(rows).toEqual(goblins.slice(110, 120));
});
