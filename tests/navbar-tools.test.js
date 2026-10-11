import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const navbar = readFileSync(new URL('../js/navbar.js', import.meta.url), 'utf8');
const toggle = navbar.slice(navbar.indexOf('// ── Tools dropdown open/close'), navbar.indexOf('// ── Drag-and-drop'));
const template = readFileSync(new URL('../templates/partials/navbar.html', import.meta.url), 'utf8');

function element() {
    const listeners = {};
    const attrs = {};
    const classes = new Set();
    return {
        inert: false,
        children: [],
        listeners,
        attrs,
        classList: { add: (c) => classes.add(c), remove: (c) => classes.delete(c), contains: (c) => classes.has(c) },
        setAttribute: (k, v) => { attrs[k] = v; },
        addEventListener: (type, fn) => { listeners[type] = fn; },
        contains(el) { return el === this || this.children.includes(el); },
        focus() { doc.activeElement = this; },
    };
}

const doc = { activeElement: null };

function load() {
    const btn = element();
    const dd = element();
    dd.inert = true; // as the template ships it
    const link = element();
    dd.children.push(link);
    Object.assign(doc, {
        activeElement: null,
        listeners: {},
        getElementById: (id) => ({ 'tools-btn': btn, 'tools-dropdown': dd }[id]),
        addEventListener: (type, fn) => { doc.listeners[type] = fn; },
    });
    new Function('document', toggle)(doc);
    return { btn, dd, link };
}

// Closed, the panel is only transparent: inert keeps Tab and screen readers out.
test('the template ships the Tools panel inert', () => {
    expect(template).toMatch(/<div class="tools-dropdown" id="tools-dropdown"[^>]*\binert\b/);
});

test('opening the Tools panel lifts inert; closing puts it back', () => {
    const { btn, dd, link } = load();
    btn.listeners.click({ stopPropagation() {} });
    expect(dd.inert).toBe(false);
    expect(btn.attrs['aria-expanded']).toBe('true');

    btn.listeners.click({ stopPropagation() {} });
    expect(dd.inert).toBe(true);
    expect(btn.attrs['aria-expanded']).toBe('false');

    // Escape from a link inside hands focus back to the button first.
    btn.listeners.click({ stopPropagation() {} });
    link.focus();
    doc.listeners.keydown({ key: 'Escape' });
    expect(dd.inert).toBe(true);
    expect(doc.activeElement).toBe(btn);
});
