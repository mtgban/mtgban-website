import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const read = (path) => readFileSync(new URL('../' + path, import.meta.url), 'utf8');

// el is an element with classes and attributes, enough for the reveal handlers and updateSidebar.
function el(attrs = {}, classes = []) {
    const set = new Set(classes);
    return {
        attrs: { ...attrs },
        classList: { add: (c) => set.add(c), remove: (c) => set.delete(c), contains: (c) => set.has(c) },
        setAttribute(k, v) { this.attrs[k] = String(v); },
        getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        removeAttribute(k) { delete this.attrs[k]; },
        addEventListener() {},
        replaceChildren() {},
        querySelector: () => null,
        querySelectorAll: () => [],
        focus() {},
        setSelectionRange() {},
    };
}

// onclickOf returns the inline onclick of the one tag the needle picks out, as a function of this.
function onclickOf(path, needle) {
    const src = read(path);
    const at = src.indexOf(needle);
    expect(at).toBeGreaterThan(-1);
    const tag = src.slice(src.lastIndexOf('<', at), src.indexOf('>', at));
    const m = tag.match(/onclick="([^"]*)"/);
    expect(m).not.toBeNull();
    return new Function('document', m[1]);
}

test('the desktop image drops its mark on the click that reveals the warning', () => {
    const run = onclickOf('templates/search.html', 'id="cardImageWrapper"');
    const document = { getElementById: () => Object.assign(el(), { value: '' }) };
    const warned = el({ 'data-track': 'ui.result.image', 'data-track-value': 'reveal_warning' }, ['content-warning']);
    run.call(warned, document);
    expect(warned.classList.contains('cw-revealed')).toBe(true);
    expect(warned.getAttribute('data-track')).toBeNull();
    const plain = el({ 'data-track': 'ui.result.image', 'data-track-value': 'focus_search' });
    run.call(plain, document);
    expect(plain.getAttribute('data-track')).toBe('ui.result.image');
});

test('the mobile landscape and drawer images drop their mark on the reveal', () => {
    for (const needle of ['class="m-card-img-landscape', 'id="m-drawer-img"']) {
        const run = onclickOf('templates/mobile/search.html', needle);
        const img = el({ 'data-track': 'ui.result.image', 'data-track-value': 'reveal_warning' }, ['content-warning']);
        run.call(img, {});
        expect(img.classList.contains('cw-revealed')).toBe(true);
        expect(img.getAttribute('data-track')).toBeNull();
    }
});

test('the sidebar marks the image by what a click on it would do', () => {
    const wrapper = el({ 'data-track': 'ui.result.image', 'data-track-value': 'focus_search' });
    const nodes = { cardImage: el(), cardImageWrapper: wrapper, printings: el() };
    const document = { addEventListener() {}, getElementById: (id) => nodes[id] || null, createElement: () => el() };
    const window = { addEventListener() {}, setCardArtSource() {} };
    const self = { PrintingsPanel: { shouldStashSetValue: () => false } };
    const update = new Function('window', 'document', 'self', read('js/search-sidebar.js') + '\nreturn updateSidebar;')(window, document, self);
    const show = (name, warning) => update('/a.jpg', null, null, false, false, 'SET', warning, 0, '', name);
    const mark = () => [wrapper.getAttribute('data-track'), wrapper.getAttribute('data-track-value')];

    show('one', true);
    expect(mark()).toEqual(['ui.result.image', 'reveal_warning']);
    wrapper.classList.add('cw-revealed');   // what the reveal click leaves behind
    show('two', true);
    expect(wrapper.getAttribute('data-track')).toBeNull();
    show('three', false);
    expect(mark()).toEqual(['ui.result.image', 'focus_search']);
});
