import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'mobile-chart.js'), 'utf8');

// openDrawer evaluates mobile-chart.js against a stubbed page, opens the chart
// drawer on one card, and reports every url it fetched, every chart it drew and
// every error it logged. answer(range) is what /api/chart sends back for that
// range, with a status of its own when it is not a 200.
async function openDrawer(answer) {
    const calls = [];
    const charts = [];
    const errors = [];
    const nodes = {
        'm-chart-range': { options: [30, 90, 180, 365, 730, 1825, 3650].map((v) => ({ value: String(v) })) },
    };
    const document = {
        cookie: '',
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
    Chart.prototype.isDatasetVisible = () => true;
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
