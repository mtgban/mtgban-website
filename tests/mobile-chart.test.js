import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'mobile-chart.js'), 'utf8');

// openDrawer evaluates mobile-chart.js against a stubbed page, opens the chart
// drawer on one card, and reports every url it fetched, every chart it drew and
// every error it logged. answer(range) is what /api/chart sends back for that
// range, with a status of its own when it is not a 200. cookie is the page's
// cookie as the drawer opens.
async function openDrawer(answer, cookie = '') {
    const calls = [];
    const charts = [];
    const errors = [];
    const nodes = {
        'm-chart-range': { options: [30, 90, 180, 365, 730, 1825, 3650].map((v) => ({ value: String(v) })) },
        // The legend's buttons are read back out of its html, so a test can
        // tap one.
        'm-chart-legend': {
            innerHTML: '',
            querySelectorAll() {
                this.buttons = [...this.innerHTML.matchAll(/data-index="(\d+)"/g)].map(([, i]) => {
                    const button = { getAttribute: () => i, classList: { toggle() {} } };
                    button.addEventListener = (type, fn) => { button.tap = () => fn.call(button); };
                    return button;
                });
                return this.buttons;
            },
        },
    };
    const document = {
        cookie,
        body: { style: {}, classList: { contains: () => false } },
        documentElement: {},
        head: { appendChild: (script) => script.onload() },
        createElement: () => ({}),
        getElementById: (id) => nodes[id] || (nodes[id] = {
            style: {},
            classList: { add() {}, remove() {} },
            querySelectorAll: () => [],
            getContext: () => ({}),
        }),
    };
    const window = { getComputedStyle: () => ({ getPropertyValue: () => '' }) };
    function Chart(ctx, config) {
        this.data = config.data;
        this.options = config.options;
        this.drawnFrom = config.data.labels;
        charts.push(this);
    }
    // Chart.js keeps what setDatasetVisibility sets on a meta tied to the
    // dataset object, and otherwise reads the dataset's own hidden option.
    const shown = new WeakMap();
    Chart.prototype.isDatasetVisible = function(i) {
        const ds = this.data.datasets[i];
        return shown.has(ds) ? shown.get(ds) : !ds.hidden;
    };
    Chart.prototype.setDatasetVisibility = function(i, visible) {
        shown.set(this.data.datasets[i], visible);
    };
    Chart.prototype.update = () => {};
    Chart.prototype.resetZoom = () => {};
    const fetch = (url) => {
        calls.push(url);
        const reply = answer(Number(url.split('?range=')[1]));
        const status = reply.status || 200;
        return Promise.resolve({ ok: status < 400, status, json: () => Promise.resolve(reply) });
    };
    const localStorage = { getItem: () => null, setItem() {} };
    const console = { error: (err) => errors.push(err) };

    new Function('window', 'document', 'localStorage', 'fetch', 'Chart', 'console', source)(
        window, document, localStorage, fetch, Chart, console);
    window.showChartDrawer('ban:1', false, 'Black Lotus');
    await new Promise((done) => setTimeout(done, 0));

    return {
        calls, charts, errors, window,
        loading: nodes['m-chart-loading'],
        select: nodes['m-chart-range'],
        rangeFailed: nodes['m-chart-range-failed'],
        legend: nodes['m-chart-legend'],
    };
}

const empty = (range) => ({ maxLookbackDays: 3650, loadedDays: range, axisLabels: [], datasets: [] });
const priced = (range) => ({
    maxLookbackDays: 3650,
    loadedDays: range,
    axisLabels: ['2024-01-02', '2024-01-01'],
    datasets: [{ name: 'TCG Low', data: [2, null], color: 'rgb(1, 2, 3)' }],
});
// What /api/chart sends when the archive answered for no card.
const unavailable = () => ({ status: 503, error: 'charts not available' });

// days lists n daily labels, newest first, the way /api/chart sends its axis.
function days(n) {
    const today = Date.UTC(2026, 8, 25);
    return Array.from({ length: n }, (_, i) => new Date(today - i * 86400000).toISOString().slice(0, 10));
}
// A card priced on every day of the range asked for.
const daily = (range) => ({
    maxLookbackDays: 3650,
    loadedDays: range,
    axisLabels: days(range),
    datasets: [{ name: 'TCG Low', data: days(range).map(() => 1), color: 'rgb(1, 2, 3)' }],
});

test('an empty first window asks for all the tier allows, and draws that', async () => {
    const { calls, charts, errors, loading } = await openDrawer((range) => range === 3650 ? priced(range) : empty(range));

    expect(calls).toEqual(['/api/chart/ban%3A1?range=180', '/api/chart/ban%3A1?range=3650']);
    expect(charts.length).toBe(1);
    expect(charts[0].drawnFrom).toEqual(['2024-01-02', '2024-01-01']);
    expect(loading.style.display).toBe('none');
    expect(errors).toEqual([]);
});

test('a first window with prices is drawn, and the rest prefetched', async () => {
    const first = { ...priced(180), axisLabels: ['2026-09-25'], datasets: [{ name: 'TCG Low', data: [3] }] };
    const { calls, charts, errors } = await openDrawer((range) => range === 180 ? first : priced(range));

    expect(calls).toEqual(['/api/chart/ban%3A1?range=180', '/api/chart/ban%3A1?range=3650']);
    expect(charts.length).toBe(1);
    expect(charts[0].drawnFrom).toEqual(['2026-09-25']);
    expect(errors).toEqual([]);
});

test('a card with no prices at all still says so', async () => {
    const { calls, charts, errors, loading } = await openDrawer(empty);

    expect(calls).toEqual(['/api/chart/ban%3A1?range=180', '/api/chart/ban%3A1?range=3650']);
    expect(charts.length).toBe(0);
    expect(loading.textContent).toBe('No chart data available');
    expect(errors).toEqual([]);
});

test('a window that is already the ceiling is not asked for twice', async () => {
    const { calls, errors, loading } = await openDrawer((range) => ({ ...empty(range), maxLookbackDays: 180 }));

    expect(calls).toEqual(['/api/chart/ban%3A1?range=180']);
    expect(loading.textContent).toBe('No chart data available');
    expect(errors).toEqual([]);
});

test('an archive that does not answer is a failure, and is not asked for more', async () => {
    const { calls, charts, errors, loading } = await openDrawer(unavailable);

    expect(calls).toEqual(['/api/chart/ban%3A1?range=180']);
    expect(charts.length).toBe(0);
    expect(loading.textContent).toBe('Failed to load chart');
    expect(errors.length).toBe(1);
});

test('an empty window whose wider read fails says it failed', async () => {
    const { calls, loading } = await openDrawer((range) => range === 3650 ? unavailable() : empty(range));

    expect(calls).toEqual(['/api/chart/ban%3A1?range=180', '/api/chart/ban%3A1?range=3650']);
    expect(loading.textContent).toBe('Failed to load chart');
});

test('a prefetch that fails is asked again when the range widens', async () => {
    const first = { ...priced(180), axisLabels: ['2026-09-25'], datasets: [{ name: 'TCG Low', data: [3] }] };
    const { calls, window } = await openDrawer((range) => range === 180 ? first : unavailable());

    window.changeChartRange(365);
    await new Promise((done) => setTimeout(done, 0));

    expect(calls).toEqual(['/api/chart/ban%3A1?range=180', '/api/chart/ban%3A1?range=3650', '/api/chart/ban%3A1?range=365']);
});

test('the prefetched ceiling is not drawn over the range the select names', async () => {
    const { calls, charts, errors, select } = await openDrawer(daily);

    expect(calls).toEqual(['/api/chart/ban%3A1?range=180', '/api/chart/ban%3A1?range=3650']);
    expect(select.value).toBe('180');
    expect(charts[0].data.labels).toEqual(days(180));
    expect(charts[0].options.scales.x.min).toBeUndefined();
    expect(errors).toEqual([]);
});

test('a wider range draws the prefetched ceiling without asking again', async () => {
    const { calls, charts, errors, select, window } = await openDrawer(daily);

    window.changeChartRange(365);
    await new Promise((done) => setTimeout(done, 0));

    expect(calls.length).toBe(2);
    expect(charts[0].data.labels).toEqual(days(3650));
    expect(charts[0].options.scales.x.min).toBe(days(3650)[364]);
    expect(select.disabled).toBe(false);
    expect(errors).toEqual([]);
});

test('a narrower range only moves the start of what is drawn', async () => {
    const { charts, window } = await openDrawer(daily);

    window.changeChartRange(90);

    expect(charts[0].data.labels).toEqual(days(180));
    expect(charts[0].options.scales.x.min).toBe(days(180)[89]);
});

// Picking a range the drawer cannot load must not leave the select naming it
// over a chart that still draws less: it goes back to what is drawn, where
// picking the range again retries, and a note says why.
test('a wider range that fails to load says so, and names the range drawn', async () => {
    const { charts, rangeFailed, select, window } = await openDrawer((range) => range === 180 ? daily(range) : unavailable());
    expect(rangeFailed.hidden).toBe(true);

    window.changeChartRange(730);
    await new Promise((done) => setTimeout(done, 0));

    expect(rangeFailed.hidden).toBe(false);
    expect(select.value).toBe('180');
    expect(charts[0].data.labels).toEqual(days(180));
    expect(charts[0].options.scales.x.min).toBeUndefined();

    // A range inside what is drawn needs no load, and clears the note.
    window.changeChartRange(90);
    expect(rangeFailed.hidden).toBe(true);
});

// The legacy read still reports an archive error as an empty chart. A wider
// window holds the one drawn, so that is a failed widening, not labels to draw.
test('an empty wider answer is a failed widening too', async () => {
    const { calls, charts, rangeFailed, select, window } = await openDrawer((range) => range === 180 ? daily(range) : empty(range));

    window.changeChartRange(730);
    await new Promise((done) => setTimeout(done, 0));

    expect(calls).toEqual(['/api/chart/ban%3A1?range=180', '/api/chart/ban%3A1?range=3650', '/api/chart/ban%3A1?range=730']);
    expect(charts[0].data.labels).toEqual(days(180));
    expect(rangeFailed.hidden).toBe(false);
    expect(select.value).toBe('180');
});

// Three stores in the order /api/chart lists them, each at a price of its own,
// so a line that draws another store's prices shows it.
const LOW = { name: 'TCGplayer Low', price: 1, color: 'rgb(1, 0, 0)' };
const MARKET = { name: 'TCGplayer Market', price: 2, color: 'rgb(2, 0, 0)' };
const BUYLIST = { name: 'Card Kingdom Buylist', price: 3, color: 'rgb(3, 0, 0)' };

// pricedBy answers with a line for each store given, priced every day of the
// range. The drawer's first window is 180 days, and firstThen answers it apart
// from every wider one.
const pricedBy = (...stores) => (range) => ({
    maxLookbackDays: 3650,
    loadedDays: range,
    axisLabels: days(range),
    datasets: stores.map((s) => ({ name: s.name, data: days(range).map(() => s.price), color: s.color })),
});
const firstThen = (first, wider) => (range) => range === 180 ? first(range) : wider(range);

// lines reads a chart back as, for each line, the store it names, the prices
// it draws, its colour and whether it shows; line is what one store's own
// line reads as.
const lines = (chart) => chart.data.datasets.map((ds, i) => ({
    store: ds.label,
    prices: [...new Set(ds.data)],
    color: ds.borderColor,
    shown: chart.isDatasetVisible(i),
}));
const line = (store, shown = true) => ({ store: store.name, prices: [store.price], color: store.color, shown });

// legendOf reads the drawer's legend back as the stores it names, marking the
// hidden ones.
const legendOf = (legend) => [...legend.innerHTML.matchAll(/class="m-chart-legend-item( hidden)?".*?<\/span>([^<]*)<\/button>/g)]
    .map(([, hidden, name]) => name + (hidden ? ' (hidden)' : ''));

// hiding is the cookie of a viewer who hid these stores on an earlier card.
const hiding = (...stores) => 'MobileChartHidden=' + encodeURIComponent(stores.map((s) => s.name).join(','));

// A store can stop pricing a card before the drawer's first window starts, so
// only the wider window has it.
test('a store only the wider window holds joins the chart and its legend', async () => {
    const { charts, errors, legend, window } = await openDrawer(firstThen(pricedBy(LOW), pricedBy(LOW, MARKET)));
    expect(legendOf(legend)).toEqual(['TCG Low']);

    window.changeChartRange(730);
    await new Promise((done) => setTimeout(done, 0));

    expect(charts[0].data.labels).toEqual(days(3650));
    expect(lines(charts[0])).toEqual([line(LOW), line(MARKET)]);
    expect(legendOf(legend)).toEqual(['TCG Low', 'TCG Market']);
    expect(charts[0].options.scales.x.min).toBe(days(3650)[729]);
    expect(errors).toEqual([]);
});

// /api/chart lists stores in registry order, so one only the wider window holds
// can sort ahead of a store the chart already draws and move it down the list.
test('each line keeps its own store when a new one sorts ahead of it', async () => {
    const { charts, legend, window } = await openDrawer(firstThen(pricedBy(LOW, BUYLIST), pricedBy(LOW, MARKET, BUYLIST)));
    expect(lines(charts[0])).toEqual([line(LOW), line(BUYLIST)]);

    window.changeChartRange(730);
    await new Promise((done) => setTimeout(done, 0));

    expect(lines(charts[0])).toEqual([line(LOW), line(MARKET), line(BUYLIST)]);
    expect(legendOf(legend)).toEqual(['TCG Low', 'TCG Market', 'CK Buylist']);
});

// A hidden store is hidden by name, not by where it sits: one the viewer hides
// stays hidden when the wider window moves it, and one that window adds comes
// in hidden if the viewer hid it on an earlier card.
test('the stores the viewer hid stay hidden in the wider window', async () => {
    const answer = firstThen(pricedBy(LOW, BUYLIST), pricedBy(LOW, MARKET, BUYLIST));

    const tapped = await openDrawer(answer);
    tapped.legend.buttons[1].tap();
    tapped.window.changeChartRange(730);
    await new Promise((done) => setTimeout(done, 0));

    expect(lines(tapped.charts[0])).toEqual([line(LOW), line(MARKET), line(BUYLIST, false)]);
    expect(legendOf(tapped.legend)).toEqual(['TCG Low', 'TCG Market', 'CK Buylist (hidden)']);

    const earlier = await openDrawer(answer, hiding(MARKET));
    earlier.window.changeChartRange(730);
    await new Promise((done) => setTimeout(done, 0));

    expect(lines(earlier.charts[0])).toEqual([line(LOW), line(MARKET, false), line(BUYLIST)]);
    expect(legendOf(earlier.legend)).toEqual(['TCG Low', 'TCG Market (hidden)', 'CK Buylist']);
});
