import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// Just enough DOM for collapsePrintings: selectors are a tag and/or classes.
class FakeElement {
    constructor(tag) {
        this.tagName = tag;
        this.children = [];
        this.parent = null;
        this.dataset = {};
        this.attrs = {};
        this.style = {};
        this.textContent = '';
        this.handlers = {};
        this.classes = new Set();
        this.classList = {
            add: c => this.classes.add(c),
            remove: c => this.classes.delete(c),
            contains: c => this.classes.has(c),
        };
    }
    set className(v) { this.classes = new Set(v.split(/\s+/).filter(Boolean)); }
    get className() { return [...this.classes].join(' '); }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    addEventListener(type, fn) { this.handlers[type] = fn; }
    focus() {}
    getBoundingClientRect() { return { left: 0, top: 0, width: 100, height: 20, bottom: 20, right: 100 }; }
    appendChild(child) {
        if (child.parent) child.remove();
        child.parent = this;
        this.children.push(child);
        return child;
    }
    remove() {
        const siblings = this.parent.children;
        siblings.splice(siblings.indexOf(this), 1);
        this.parent = null;
    }
    cloneNode() {
        const clone = new FakeElement(this.tagName);
        clone.classes = new Set(this.classes);
        clone.attrs = { ...this.attrs };
        return clone;
    }
    matches(selector) {
        const [tag, ...classes] = selector.split('.');
        return (!tag || tag === this.tagName) && classes.every(c => this.classes.has(c));
    }
    querySelectorAll(selector) {
        const out = [];
        const walk = el => el.children.forEach(c => {
            if (c.matches(selector)) out.push(c);
            walk(c);
        });
        walk(this);
        return out;
    }
    querySelector(selector) { return this.querySelectorAll(selector)[0] || null; }
}

// load runs the script over a row of count printings, each marked as genCardPrintings marks it.
function load(count, BAN) {
    const container = new FakeElement('div');
    for (let i = 0; i < count; i++) {
        const a = new FakeElement('a');
        a.className = 'printing-symbol';
        a.setAttribute('title', 'Set ' + i);
        a.setAttribute('data-track', 'ui.sidebar.printing');
        a.setAttribute('data-track-value', 'row');
        container.appendChild(a);
    }
    const src = readFileSync(join(import.meta.dir, '..', 'js', 'search-sidebar.js'), 'utf8');
    const document = {
        addEventListener() {},
        getElementById: id => (id === 'printings' ? container : null),
        createElement: tag => new FakeElement(tag),
    };
    const window = { addEventListener() {}, innerHeight: 800, BAN };
    const self = { PrintingsPanel: { placement: () => ({ left: 0, width: 100, top: 20, maxHeight: 300 }) } };
    const collapse = new Function('window', 'document', 'self', src + '\nreturn collapsePrintings;')(window, document, self);
    collapse();
    return { container, collapse };
}

function render(count) {
    return load(count).container;
}

test('seven printings stay on the row, with no panel for one edition', () => {
    const container = render(7);
    expect(container.querySelector('.sidebar-printings-more')).toBeNull();
    expect(container.querySelector('.sidebar-printings-dropdown')).toBeNull();
    expect(container.querySelectorAll('a.sidebar-printings-hidden')).toHaveLength(0);
});

test('eight printings fold the last two into the panel', () => {
    const container = render(8);
    expect(container.querySelector('.sidebar-printings-more').textContent).toBe('+2');
    expect(container.querySelectorAll('a.sidebar-printings-hidden')).toHaveLength(2);
    const list = container.querySelector('.sidebar-printings-list');
    expect(list.querySelectorAll('a.printing-symbol').map(a => a.getAttribute('title'))).toEqual(['Set 6', 'Set 7']);
});

test('overflow symbols say they came from the panel', () => {
    const container = render(9);
    const panel = container.querySelector('.sidebar-printings-list').querySelectorAll('a.printing-symbol');
    expect(panel).toHaveLength(3);
    panel.forEach(a => expect(a.getAttribute('data-track-value')).toBe('overflow'));
    const row = container.children.filter(c => c.tagName === 'a');
    expect(row).toHaveLength(9);
    row.forEach(a => expect(a.getAttribute('data-track-value')).toBe('row'));
});

// recorder is a BAN whose track keeps each call.
function recorder() {
    const calls = [];
    return { calls, track: (...a) => calls.push(a) };
}

test('opening the panel counts once, closing it does not', () => {
    const BAN = recorder();
    const { container } = load(8, BAN);
    const trigger = container.querySelector('.sidebar-printings-more');
    trigger.handlers.click();
    trigger.handlers.click();
    expect(container.querySelector('.sidebar-printings-dropdown').classList.contains('open')).toBe(false);
    expect(BAN.calls).toEqual([['ui.sidebar.printings_more', 'open']]);
});

test('the filter counts its first use on the page', () => {
    const BAN = recorder();
    const { container, collapse } = load(8, BAN);
    const type = (value) => {
        const filter = container.querySelector('.sidebar-printings-filter');
        filter.value = value;
        filter.handlers.input.call(filter);
    };
    type('');
    type('m');
    type('mo');
    collapse();
    type('x');
    expect(BAN.calls).toEqual([['ui.sidebar.printings_more', 'filter_used']]);
});

test('with no BAN the panel still opens and filters', () => {
    const { container } = load(8);
    container.querySelector('.sidebar-printings-more').handlers.click();
    expect(container.querySelector('.sidebar-printings-dropdown').classList.contains('open')).toBe(true);
    const filter = container.querySelector('.sidebar-printings-filter');
    filter.value = 'Set 7';
    filter.handlers.input.call(filter);
    const shown = container.querySelector('.sidebar-printings-list').querySelectorAll('a.printing-symbol').map(a => a.style.display);
    expect(shown).toEqual(['none', '']);
});

test('pressing Available In open counts, pressing it shut does not', () => {
    const BAN = recorder();
    const card = new FakeElement('div');
    card.hasAttribute = k => k in card.attrs;
    card.removeAttribute = k => { delete card.attrs[k]; };
    card.contains = () => true;
    const toggle = new FakeElement('button');
    toggle.contains = () => true;
    const list = new FakeElement('div');
    const caret = new FakeElement('span');
    const byId = { productsCard: card, productsToggle: toggle, products: list };
    const clicks = [];
    const document = {
        addEventListener: (type, fn) => { if (type === 'click') clicks.push(fn); },
        getElementById: id => byId[id] || null,
        querySelector: sel => (sel === '.sidebar-products-caret' ? caret : null),
        createElement: tag => new FakeElement(tag),
    };
    // The list shows while the card holds data-expanded="true".
    const getComputedStyle = el => ({ display: el === list ? (card.attrs['data-expanded'] === 'true' ? 'block' : 'none') : 'inline' });
    const src = readFileSync(join(import.meta.dir, '..', 'js', 'search-sidebar.js'), 'utf8');
    new Function('window', 'document', 'getComputedStyle', src)({ addEventListener() {}, BAN }, document, getComputedStyle);
    const press = () => clicks.forEach(fn => fn({ target: toggle }));
    press();
    expect(card.attrs['data-expanded']).toBe('true');
    press();
    expect(card.attrs['data-expanded']).toBe('false');
    expect(BAN.calls).toEqual([['ui.sidebar.products', 'expand']]);
});
