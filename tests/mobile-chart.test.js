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

    return { calls, charts, errors, window, loading: nodes['m-chart-loading'] };
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
