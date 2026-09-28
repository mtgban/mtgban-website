import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/tooltips.js', import.meta.url), 'utf8');

// Runs tooltips.js over a stand-in page: elements with attributes, a parent
// chain and a box, and a MutationObserver whose records arrive on flush(),
// the way the microtask after a script's change delivers them.
function loadPage() {
    const observers = [];
    const listeners = {};

    function record(target, attributeName) {
        for (const observer of observers) {
            if (observer.target === target && observer.filter.includes(attributeName)) {
                observer.queue.push({ target, attributeName });
            }
        }
    }

    class FakeMutationObserver {
        constructor(callback) {
            this.callback = callback;
            this.target = null;
            this.queue = [];
            observers.push(this);
        }
        observe(target, options) {
            this.target = target;
            this.filter = options.attributeFilter;
        }
        disconnect() {
            this.target = null;
            this.queue = [];
        }
        takeRecords() {
            const queue = this.queue;
            this.queue = [];
            return queue;
        }
    }

    function flush() {
        for (let delivered = true; delivered;) {
            delivered = false;
            for (const observer of observers) {
                const records = observer.takeRecords();
                if (records.length) {
                    delivered = true;
                    observer.callback(records, observer);
                }
            }
        }
    }

    class FakeElement {
        constructor(attrs = {}, parent = null, text = '') {
            this.attrs = { ...attrs };
            this.ownText = text;
            this.children = [];
            this.style = {};
            this.hidden = false;
            this.rect = { left: 100, top: 100, width: 40, height: 20, right: 140, bottom: 120 };
            if (parent) {
                parent.appendChild(this);
            }
        }
        getAttribute(name) { return name in this.attrs ? this.attrs[name] : null; }
        hasAttribute(name) { return name in this.attrs; }
        setAttribute(name, value) {
            this.attrs[name] = String(value);
            record(this, name);
        }
        removeAttribute(name) {
            if (name in this.attrs) {
                delete this.attrs[name];
                record(this, name);
            }
        }
        appendChild(child) {
            child.parent = this;
            this.children.push(child);
        }
        contains(other) {
            for (let node = other; node; node = node.parent) {
                if (node === this) return true;
            }
            return false;
        }
        closest(selector) {
            const name = selector.slice(1, -1);
            for (let node = this; node; node = node.parent) {
                if (node.hasAttribute(name)) return node;
            }
            return null;
        }
        get textContent() { return this.ownText + this.children.map(child => child.textContent).join(''); }
        set textContent(value) {
            this.ownText = value;
            this.children = [];
        }
        getBoundingClientRect() { return this.rect; }
        // Ten pixels a letter up to the CSS max-width, in no more room than
        // its left leaves: a fixed box shrinks to fit.
        get offsetWidth() { return Math.min(this.ownText.length * 10, 320, 1000 - (parseFloat(this.style.left) || 0)); }
        get offsetHeight() { return 30; }
    }

    const on = (type, fn) => { (listeners[type] = listeners[type] || []).push(fn); };
    const body = new FakeElement();
    const document = {
        body,
        documentElement: { clientWidth: 1000 },
        createElement: () => new FakeElement(),
        addEventListener: on,
    };
    const window = {
        MutationObserver: FakeMutationObserver,
        addEventListener: (type, fn) => on('window:' + type, fn),
    };
    const { banTooltipPlace } = new Function('document', 'window',
        source + '\nreturn { banTooltipPlace };')(document, window);

    function fire(type, event) {
        for (const fn of listeners[type] || []) fn(event);
        flush();
    }

    return {
        body,
        banTooltipPlace,
        flush,
        fire,
        el: (attrs, parent = body, text = '') => new FakeElement(attrs, parent, text),
        // The pointer going from one element to the next, as the browser
        // reports it.
        move(from, to, pointerType = 'mouse') {
            fire('pointerout', { target: from, relatedTarget: to, pointerType });
            fire('pointerover', { target: to, relatedTarget: from, pointerType });
        },
        tip: () => body.children.find(child => child.id === 'ban-tooltip'),
        shown() {
            const tip = this.tip();
            return tip && !tip.hidden ? tip.textContent : null;
        },
    };
}

test('a title shows the moment the pointer is over it, and comes back when it leaves', () => {
    const page = loadPage();
    const button = page.el({ title: 'Sell now' }, page.body, 'Good');
    const inner = page.el({}, button);

    page.move(page.body, inner);
    expect(page.shown()).toBe('Sell now');
    // Aside, so the browser's own tooltip does not follow a second later.
    expect(button.getAttribute('title')).toBeNull();
    expect(button.getAttribute('data-ban-title')).toBe('Sell now');

    page.move(inner, page.body);
    expect(page.shown()).toBeNull();
    expect(button.getAttribute('title')).toBe('Sell now');
    expect(button.hasAttribute('data-ban-title')).toBe(false);
});

test('moving inside the element keeps its tooltip, and a titled child takes over', () => {
    const page = loadPage();
    const row = page.el({ title: 'Row' }, page.body, 'x');
    const plain = page.el({}, row, 'a');
    const titled = page.el({ title: 'Cell' }, row, 'b');

    page.move(page.body, plain);
    page.move(plain, row);
    expect(page.shown()).toBe('Row');
    expect(row.getAttribute('data-ban-title')).toBe('Row');

    page.move(row, titled);
    expect(page.shown()).toBe('Cell');
    expect(row.getAttribute('title')).toBe('Row');

    page.move(titled, plain);
    expect(page.shown()).toBe('Row');
    expect(titled.getAttribute('title')).toBe('Cell');
});

test('touch and blank titles show nothing', () => {
    const page = loadPage();
    const button = page.el({ title: 'Sell now' });
    const blank = page.el({ title: '  ' });

    page.move(page.body, button, 'touch');
    expect(page.shown()).toBeNull();
    expect(button.getAttribute('title')).toBe('Sell now');

    page.move(button, blank);
    expect(page.shown()).toBeNull();
    expect(blank.getAttribute('title')).toBe('  ');
});

test('a title a script sets while the tooltip is up takes over, and stays', () => {
    const page = loadPage();
    const button = page.el({ title: 'Copy' }, page.body, 'x');
    page.move(page.body, button);

    button.setAttribute('title', 'Copied!');
    page.flush();
    expect(page.shown()).toBe('Copied!');

    page.move(button, page.body);
    expect(button.getAttribute('title')).toBe('Copied!');
});

test('a title a script empties while the tooltip is up hides it', () => {
    const page = loadPage();
    const button = page.el({ title: 'Pick a store and a printing first' }, page.body, 'Add');
    page.move(page.body, button);

    button.setAttribute('title', '');
    page.flush();
    expect(page.shown()).toBeNull();
});

test('a title a script removes along with its copy stays removed', () => {
    // What scope.js does when an ignored scope is typed away.
    const page = loadPage();
    const box = page.el({ title: 'Ignored' });
    page.move(page.body, box);

    box.removeAttribute('title');
    box.removeAttribute('data-ban-title');
    page.move(box, page.body);
    expect(box.hasAttribute('title')).toBe(false);
});

test('a click or Escape puts the tooltip away until the pointer comes back', () => {
    const page = loadPage();
    const button = page.el({ title: 'Sell now' }, page.body, 'x');
    page.move(page.body, button);

    page.fire('pointerdown', { target: button });
    expect(page.shown()).toBeNull();
    // Still aside, or the browser's own tooltip would take its place.
    expect(button.getAttribute('title')).toBeNull();

    page.move(button, page.body);
    page.move(page.body, button);
    expect(page.shown()).toBe('Sell now');

    page.fire('keydown', { key: 'Escape' });
    expect(page.shown()).toBeNull();
});

test('scrolling hides the tooltip and gives the title back', () => {
    const page = loadPage();
    const button = page.el({ title: 'Sell now' }, page.body, 'x');
    page.move(page.body, button);

    page.fire('window:scroll', {});
    expect(page.shown()).toBeNull();
    expect(button.getAttribute('title')).toBe('Sell now');
});

test('an icon named only by its title keeps that name while the title is aside', () => {
    const page = loadPage();
    const icon = page.el({ title: 'Random card' });
    const named = page.el({ title: 'Toggle theme', 'aria-label': 'Theme' });
    const text = page.el({ title: "Card Kingdom's latest P90" }, page.body, 'Good');

    page.move(page.body, icon);
    expect(icon.getAttribute('aria-label')).toBe('Random card');

    page.move(icon, named);
    expect(icon.hasAttribute('aria-label')).toBe(false);
    expect(named.getAttribute('aria-label')).toBe('Theme');

    page.move(named, text);
    expect(named.getAttribute('aria-label')).toBe('Theme');
    expect(text.hasAttribute('aria-label')).toBe(false);
});

test('an element named some other way is described by the tooltip while the title is aside', () => {
    const page = loadPage();
    const text = page.el({ title: "Card Kingdom's latest P90" }, page.body, 'Good');
    const named = page.el({ title: 'Toggle theme', 'aria-label': 'Theme' });
    const own = page.el({ title: 'Sell now', 'aria-describedby': 'odds' }, page.body, 'Good');
    const icon = page.el({ title: 'Random card' });

    page.move(page.body, text);
    expect(text.getAttribute('aria-describedby')).toBe('ban-tooltip');
    expect(page.tip().getAttribute('role')).toBe('tooltip');

    page.move(text, named);
    expect(text.hasAttribute('aria-describedby')).toBe(false);
    expect(named.getAttribute('aria-describedby')).toBe('ban-tooltip');

    page.move(named, own);
    expect(named.hasAttribute('aria-describedby')).toBe(false);
    expect(own.getAttribute('aria-describedby')).toBe('odds');

    // An icon's title is its name, which aria-label already carries.
    page.move(own, icon);
    expect(own.getAttribute('aria-describedby')).toBe('odds');
    expect(icon.hasAttribute('aria-describedby')).toBe(false);
});

test('the tooltip sits centred above its element, below it near the top, and inside the viewport', () => {
    const { banTooltipPlace } = loadPage();
    const at = (left, top) => ({ left, top, width: 40, height: 20, right: left + 40, bottom: top + 20 });

    expect(banTooltipPlace(at(100, 100), 120, 30, 1000)).toEqual({ left: 60, top: 64, below: false });
    expect(banTooltipPlace(at(100, 20), 120, 30, 1000)).toEqual({ left: 60, top: 46, below: true });
    expect(banTooltipPlace(at(0, 100), 120, 30, 1000).left).toBe(8);
    expect(banTooltipPlace(at(960, 100), 120, 30, 1000).left).toBe(872);
});

test('a tooltip is measured with the whole viewport, not the room the last one left', () => {
    const page = loadPage();
    const edge = page.el({ title: 'Hi' }, page.body, 'x');
    edge.rect = { left: 960, top: 100, width: 20, height: 20, right: 980, bottom: 120 };
    const middle = page.el({ title: 'A title thirty-two letters long.' }, page.body, 'x');
    middle.rect = { left: 490, top: 100, width: 40, height: 20, right: 530, bottom: 120 };

    page.move(page.body, edge);
    expect(page.tip().style.left).toBe('960px');
    // 320 wide and centred on 510; measured where "Hi" sat, it would be 40.
    page.move(edge, middle);
    expect(page.tip().style.left).toBe('350px');
});
