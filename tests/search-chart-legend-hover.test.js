import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'search-chart.js'), 'utf8');

// The legend's hover replays the row's own hover (image, printings and
// products together) rather than driving img.src directly. It used to do
// that via the row's inline onmouseenter, removed along with the other
// inline hover handlers; it now goes through search-sidebar.js's shared
// window.showHoverFor, trusted the way the scroll hit-test's hover is.
test('the chart legend hover calls showHoverFor and has dropped onmouseenter', () => {
    expect(source).toContain('window.showHoverFor(row, true)');
    expect(source).not.toContain('onmouseenter');
});

// The page's own scripts, in the order search.html and base.html load them;
// search-sidebar.js's hover helpers are stood in for below.
const pageScripts = ['utils.js', 'card-art-fallback.js', 'chartopts.js', 'chart-range.js', 'search-chart.js']
    .map((name) => readFileSync(join(import.meta.dir, '..', 'js', name), 'utf8'))
    .join('\n;\n');

// FakeElement is enough of an element for the legend, its rows and the art
// the legend floats below itself.
class FakeElement {
    constructor(tag, attrs = {}) {
        this.tag = tag;
        this.attrs = { ...attrs };
        this.children = [];
        this.parent = null;
        this.style = {};
        this.dataset = {};
        this.listeners = {};
        this.rect = { left: 0, top: 0, bottom: 0 };
        this.offsetWidth = 100;
        this.offsetHeight = 140;
        this.classes = new Set();
        this.classList = {
            contains: (c) => this.classes.has(c),
            toggle: (c, on) => { if (on ?? !this.classes.has(c)) this.classes.add(c); else this.classes.delete(c); },
        };
    }
    set className(v) { this.classes = new Set(v.split(' ')); }
    appendChild(child) {
        child.parent = this;
        this.children.push(child);
        return child;
    }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    addEventListener(type, fn) { this.listeners[type] = fn; }
    getBoundingClientRect() { return this.rect; }
    // The two selectors closest is asked: the art's wrapper, and a legend
    // entry that names its card.
    closest(sel) {
        for (let el = this; el; el = el.parent) {
            if (sel === '.hoverWrap' && el.classes.has('hoverWrap')) return el;
            if (sel === '.chart-legend-item[data-card-id]' && el.attrs['data-card-id'] !== undefined) return el;
        }
        return null;
    }
}

// An Image that loads every address but the ones listed as broken.
function imageLoading(broken) {
    return function Image() {
        let src = '';
        Object.defineProperty(this, 'src', {
            get: () => src,
            set: (v) => { src = v; if (broken.includes(v)) this.onerror(); else this.onload(); },
        });
    };
}

const ART = 'https://img.example/a.jpg';
const BROKEN = 'https://img.example/broken.jpg';
const BACK = '/img/backs/magic.webp';

// The result rows the legend's entries are matched back to, by chart id, each
// with the data-hover a result header carries: art, foil, etched, set, content
// warning, printings, date, name.
const ROWS = {
    'ban:1': ['Card A|AAA|1|nonfoil', [ART, false, false, 'AAA', false, 0, '2020-01-01', 'Card A']],
    'ban:2': ['Card A|BBB|2|nonfoil', [BROKEN, true, false, 'BBB', false, 0, '2021-01-01', 'Card A']],
    'ban:3': ['Card A|CCC|3|nonfoil', ['', false, false, 'CCC', false, 0, '2022-01-01', 'Card A']],
};

// openRoster loads a roster chart the way search.html does, with one more
// legend entry than there are result rows.
function openRoster() {
    const rows = {};
    const datasets = [];
    for (const [id, [label, hover]] of Object.entries({ ...ROWS, 'ban:4': ['Card A|DDD|4|nonfoil'] })) {
        datasets.push({ cardId: id, label, borderColor: 'red', referenceKey: 'TCG Low', data: [1] });
        if (hover) rows[id] = new FakeElement('div', { 'data-hover': JSON.stringify(hover) });
    }

    // The legend's entries are read back out of its html, one element each,
    // laid out left to right.
    const legend = new FakeElement('div');
    legend.rect = { left: 0, top: 300, bottom: 330 };
    let html = '';
    Object.defineProperty(legend, 'innerHTML', {
        get: () => html,
        set: (v) => {
            html = v;
            legend.children = [...v.matchAll(/data-card-id="([^"]*)"/g)].map(([, id], i) => {
                const item = new FakeElement('button', { 'data-card-id': id });
                item.parent = legend;
                item.rect = { left: 50 + 120 * i, top: 300, bottom: 330 };
                return item;
            });
        },
    });
    legend.querySelectorAll = () => legend.children;

    const body = new FakeElement('body', { 'data-game': 'magic' });
    const elements = { chartLegend: legend, dateRange: { value: '' }, cardChart: { getContext: () => ({}) } };
    const document = {
        body,
        documentElement: new FakeElement('html'),
        getElementById: (id) => elements[id] || null,
        querySelector: (sel) => {
            const m = sel.match(/^\.result-header\[data-chart-id="(.*)"\]$/);
            return m ? rows[m[1]] || null : null;
        },
        querySelectorAll: () => [],
        createElement: (tag) => new FakeElement(tag),
        addEventListener() {},
    };
    const hovered = [];
    const window = {
        BAN_SEARCH_CHART: {
            multi: true, axisLabels: ['2026-10-13'], datasets, references: ['TCG Low'],
            checkpoints: [], ids: Object.keys(rows).join(','), loadedDays: 30, maxDays: 30,
        },
        location: { href: 'https://www.mtgban.com/search' },
        innerWidth: 1200, innerHeight: 900, pageXOffset: 0, pageYOffset: 200,
        getComputedStyle: () => ({ getPropertyValue: () => '' }),
        hoverDataFor: (row) => ({ args: JSON.parse(row.getAttribute('data-hover')) }),
        showHoverFor: (row) => hovered.push(row),
        addEventListener() {},
    };
    function Chart(ctx, config) {
        this.data = config.data;
        this.options = config.options;
    }
    Chart.register = () => {};
    Chart.prototype.update = () => {};
    Chart.prototype.isDatasetVisible = () => true;
    const storage = new Map();
    const localStorage = {
        getItem: (k) => (storage.has(k) ? storage.get(k) : null),
        setItem: (k, v) => storage.set(k, String(v)),
    };
    function MutationObserver() {}
    MutationObserver.prototype.observe = () => {};

    new Function('window', 'document', 'localStorage', 'Chart', 'MutationObserver', 'Image', 'setCookie', pageScripts)(
        window, document, localStorage, Chart, MutationObserver, imageLoading([BROKEN]), () => {});

    const art = body.children[0];
    const entry = (id) => legend.children.find((item) => item.getAttribute('data-card-id') === id);
    return {
        art,
        img: art.children[0],
        hovered,
        rows,
        hover(id) { legend.listeners.mouseover({ target: entry(id) }); },
        leave() { legend.listeners.mouseleave(); },
        left(id) { return entry(id).rect.left + 'px'; },
    };
}

test('hovering a roster legend entry shows that card art below the entry', () => {
    const page = openRoster();
    page.hover('ban:1');

    expect(page.hovered).toEqual([page.rows['ban:1']]);
    expect(page.img.src).toBe(ART);
    expect(page.art.classList.contains('is-visible')).toBe(true);
    expect(page.art.getAttribute('data-name')).toBe('Card A');
    expect(page.art.getAttribute('data-set')).toBe('AAA');
    // Under the entry, just below the legend, in page coordinates.
    expect(page.art.style.left).toBe(page.left('ban:1'));
    expect(page.art.style.top).toBe(330 + 6 + 200 + 'px');

    page.hover('ban:2');
    expect(page.hovered).toEqual([page.rows['ban:1'], page.rows['ban:2']]);
    expect(page.art.getAttribute('data-foil')).toBe('true');
    expect(page.art.style.left).toBe(page.left('ban:2'));
});

test('a card art that fails or is missing falls back to the card back', () => {
    const page = openRoster();
    page.hover('ban:2');
    expect(page.img.src).toBe(BACK);
    expect(page.art.classList.contains('is-visible')).toBe(true);

    page.hover('ban:3');
    expect(page.img.src).toBe(BACK);
    expect(page.art.getAttribute('data-set')).toBe('CCC');
});

test('an entry with no result row, or leaving the legend, hides the art', () => {
    const page = openRoster();
    page.hover('ban:1');
    page.hover('ban:4');
    expect(page.hovered).toEqual([page.rows['ban:1']]);
    expect(page.art.classList.contains('is-visible')).toBe(false);

    page.hover('ban:1');
    expect(page.img.src).toBe(ART);
    page.leave();
    expect(page.art.classList.contains('is-visible')).toBe(false);
});
