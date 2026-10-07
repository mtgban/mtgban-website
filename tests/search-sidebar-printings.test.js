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
    addEventListener() {}
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

function render(count) {
    const container = new FakeElement('div');
    for (let i = 0; i < count; i++) {
        const a = new FakeElement('a');
        a.className = 'printing-symbol';
        a.setAttribute('title', 'Set ' + i);
        container.appendChild(a);
    }
    const src = readFileSync(join(import.meta.dir, '..', 'js', 'search-sidebar.js'), 'utf8');
    const document = {
        addEventListener() {},
        getElementById: id => (id === 'printings' ? container : null),
        createElement: tag => new FakeElement(tag),
    };
    const window = { addEventListener() {} };
    const collapse = new Function('window', 'document', src + '\nreturn collapsePrintings;')(window, document);
    collapse();
    return container;
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
