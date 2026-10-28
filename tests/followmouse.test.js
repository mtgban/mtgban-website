import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/followmouse.js', import.meta.url), 'utf8');

// A 1000x700 window over a taller page, with the hover image 100x140.
function load() {
    const listeners = {};
    const on = (type, fn) => { listeners[type] = fn; };
    const image = { width: 100, height: 140, addEventListener: on };
    const wrap = { style: {} };
    const window = { innerWidth: 1000, innerHeight: 700, pageXOffset: 0, pageYOffset: 0, addEventListener: on };
    const document = {
        addEventListener: on,
        getElementById: (id) => ({ hoverImage: image, hoverWrap: wrap })[id],
    };
    new Function('window', 'document', source)(window, document);
    return { window, wrap, fire: (type, e) => listeners[type](e) };
}

test('the image follows a still pointer when the page scrolls', () => {
    const t = load();
    t.fire('mousemove', { clientX: 300, clientY: 200 });
    expect(t.wrap.style).toEqual({ left: '310px', top: '210px' });

    t.window.pageYOffset = 600;
    t.fire('scroll');
    expect(t.wrap.style).toEqual({ left: '310px', top: '810px' });
});

test('the image flips above and left of a pointer near the window edges', () => {
    const t = load();
    t.window.pageYOffset = 600;
    t.fire('mousemove', { clientX: 950, clientY: 650 });
    expect(t.wrap.style).toEqual({ left: '840px', top: '1100px' });
});
