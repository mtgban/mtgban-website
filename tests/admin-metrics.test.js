import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'admin-metrics.js'), 'utf8');

// load evaluates admin-metrics.js against stubbed globals and returns its two functions.
function load({ win = {}, doc = { getElementById: () => null }, style = () => ({ getPropertyValue: () => '' }) } = {}) {
    return new Function('window', 'document', 'getComputedStyle', source +
        '; return { adminMetricsConfig, drawAdminMetrics };')(win, doc, style);
}

const api = load();
const line = (data) => ({ id: 'metrics-days', kind: 'line', labels: ['11-09', '11-10'], series: [{ label: 'search.sort', data }] });

test('a line chart starts at zero and hides a lone legend', () => {
    const cfg = api.adminMetricsConfig({ id: 'metrics-days', kind: 'line', labels: ['11-09', '11-10'], series: [{ label: 'search.sort', data: [3, 4] }] });
    expect(cfg.type).toBe('line');
    expect(cfg.data.labels).toEqual(['11-09', '11-10']);
    expect(cfg.data.datasets[0].data).toEqual([3, 4]);
    expect(cfg.data.datasets[0].label).toBe('search.sort');
    expect(cfg.options.scales.y.beginAtZero).toBe(true);
    expect(cfg.options.plugins.legend.display).toBe(false);
    expect(cfg.options.animation).toBe(false);
    expect(cfg.options.maintainAspectRatio).toBe(false);
});

test('two series show the legend', () => {
    const cfg = api.adminMetricsConfig({ id: 'x', kind: 'line', labels: ['a'], series: [{ label: 'one', data: [1] }, { label: 'two', data: [2] }] });
    expect(cfg.data.datasets.length).toBe(2);
    expect(cfg.options.plugins.legend.display).toBe(true);
    expect(cfg.data.datasets[0].borderColor).not.toBe(cfg.data.datasets[1].borderColor);
});

test('a spark has no axes, legend, tooltip or points', () => {
    const cfg = api.adminMetricsConfig({ id: 'metrics-spark-0', kind: 'spark', labels: ['a', 'b'], series: [{ label: 'n', data: [1, 2] }] });
    expect(cfg.type).toBe('line');
    expect(cfg.options.scales.x.display).toBe(false);
    expect(cfg.options.scales.y.display).toBe(false);
    expect(cfg.options.plugins.legend.display).toBe(false);
    expect(cfg.options.plugins.tooltip.enabled).toBe(false);
    expect(cfg.data.datasets[0].pointRadius).toBe(0);
    expect(cfg.options.animation).toBe(false);
});

test('bars are horizontal', () => {
    const cfg = api.adminMetricsConfig({ id: 'b', kind: 'bars', labels: ['a', 'b'], series: [{ label: 'n', data: [5, 2] }] });
    expect(cfg.type).toBe('bar');
    expect(cfg.options.indexAxis).toBe('y');
    expect(cfg.options.plugins.legend.display).toBe(false);
    expect(cfg.options.animation).toBe(false);
});

test('an unknown kind draws nothing', () => {
    expect(api.adminMetricsConfig({ kind: 'pie' })).toBe(null);
});

test('malformed or empty charts give no config', () => {
    for (const bad of [
        null, undefined, 3, 'line', [],
        { kind: 'line', labels: 'a', series: [{ label: 'n', data: [1] }] },
        { kind: 'line', labels: ['a'], series: 'n' },
        { kind: 'line', labels: ['a'], series: {} },
        { kind: 'line', labels: ['a'], series: [] },
        { kind: 'line', labels: ['a'], series: [{ label: 'n', data: null }] },
        { kind: 'line', labels: ['a'], series: [{ label: 'n', data: [] }] },
        { kind: 'line', labels: ['a'], series: [null] },
        { kind: 'line', labels: null, series: [{ label: 'n', data: [1] }] },
    ]) {
        expect(api.adminMetricsConfig(bad)).toBe(null);
    }
});

test('a series that does not match its labels gives no config', () => {
    const two = (data) => ({ kind: 'line', labels: ['a', 'b'], series: [{ label: 'n', data }] });
    // more values than labels, fewer values than labels
    expect(api.adminMetricsConfig(two([1, 2, 3]))).toBe(null);
    expect(api.adminMetricsConfig(two([1]))).toBe(null);
    // one good series does not carry a short one
    expect(api.adminMetricsConfig({ kind: 'bars', labels: ['a', 'b'], series: [{ label: 'n', data: [1, 2] }, { label: 'm', data: [1] }] })).toBe(null);
    expect(api.adminMetricsConfig(two([1, 2]))).not.toBe(null);
});

test('a value that is not a finite number gives no config', () => {
    for (const v of [NaN, Infinity, -Infinity, null, undefined, '1', {}, [1], true]) {
        const cfg = api.adminMetricsConfig({ kind: 'spark', labels: ['a', 'b'], series: [{ label: 'n', data: [1, v] }] });
        expect(cfg).toBe(null);
    }
});

test('a skipped chart leaves its canvas alone', () => {
    const drawn = [];
    function Chart(el, cfg) { drawn.push(el.id); }
    const doc = { getElementById: (id) => ({ id }) };
    api.drawAdminMetrics(doc, [
        { id: 'short', kind: 'line', labels: ['a', 'b'], series: [{ label: 'n', data: [1] }] },
        { id: 'nan', kind: 'line', labels: ['a'], series: [{ label: 'n', data: [NaN] }] },
        { id: 'ok', kind: 'line', labels: ['a'], series: [{ label: 'n', data: [1] }] },
    ], Chart);
    expect(drawn).toEqual(['ok']);
});

test('labels go to Chart.js as data, not markup', () => {
    const label = '</script><b>"x" & y\n';
    const cfg = api.adminMetricsConfig({ id: 'x', kind: 'line', labels: [label], series: [{ label, data: [1] }] });
    expect(cfg.data.labels).toEqual([label]);
    expect(cfg.data.datasets[0].label).toBe(label);
});

test('colours come from the page variables, with a grey fallback', () => {
    const vars = { '--chartjs-text': ' #123456 ', '--chartjs-grid': 'rgba(1,2,3,0.5)' };
    const doc = { documentElement: {}, body: { classList: { contains: () => false } }, getElementById: () => null };
    const themed = load({ doc, style: () => ({ getPropertyValue: (n) => vars[n] || '' }) });
    const cfg = themed.adminMetricsConfig(line([1, 2]));
    expect(cfg.options.scales.x.ticks.color).toBe('#123456');
    expect(cfg.options.scales.y.grid.color).toBe('rgba(1,2,3,0.5)');

    const bare = api.adminMetricsConfig(line([1, 2]));
    expect(bare.options.scales.x.ticks.color).toBe('#888888');

    const broken = load({ doc, style: () => { throw new Error('no styles'); } });
    expect(broken.adminMetricsConfig(line([1, 2])).options.scales.x.ticks.color).toBe('#888888');
});

test('each chart is drawn on its own canvas, and a missing one is skipped', () => {
    const made = [];
    const Chart = function (canvas, config) { made.push([canvas.id, config.type]); };
    const doc = { getElementById: (id) => (id === 'gone' ? null : { id }) };
    api.drawAdminMetrics(doc, [
        { id: 'metrics-days', kind: 'line', labels: ['a'], series: [{ label: 'n', data: [1] }] },
        { id: 'gone', kind: 'line', labels: ['a'], series: [{ label: 'n', data: [1] }] },
        { id: 'metrics-spark-0', kind: 'spark', labels: ['a'], series: [{ label: 'n', data: [1] }] },
        { id: 'empty', kind: 'line', labels: [], series: [] },
        { id: 'odd', kind: 'pie', labels: ['a'], series: [{ label: 'n', data: [1] }] },
    ], Chart);
    expect(made).toEqual([['metrics-days', 'line'], ['metrics-spark-0', 'line']]);
});

test('without Chart.js or without charts nothing throws', () => {
    const throws = function () { throw new Error('drawn'); };
    const one = [{ id: 'a', kind: 'line', labels: ['a'], series: [{ label: 'n', data: [1] }] }];
    api.drawAdminMetrics({ getElementById: () => ({}) }, one, undefined);
    api.drawAdminMetrics({ getElementById: () => ({}) }, undefined, throws);
    api.drawAdminMetrics({ getElementById: () => ({}) }, null, throws);
    api.drawAdminMetrics({ getElementById: () => ({}) }, { charts: one }, throws);
    api.drawAdminMetrics({ getElementById: () => ({}) }, 'a', throws);
    api.drawAdminMetrics({ getElementById: () => ({}) }, [], throws);
    api.drawAdminMetrics(undefined, one, throws);
    // a chart that fails to draw leaves the rest drawn
    const made = [];
    let first = true;
    const flaky = function (canvas) { if (first) { first = false; throw new Error('bad'); } made.push(canvas.id); };
    api.drawAdminMetrics({ getElementById: (id) => ({ id }) }, [one[0], Object.assign({}, one[0], { id: 'b' })], flaky);
    expect(made).toEqual(['b']);
});

test('the file draws from window.BAN_ADMIN_METRICS when it loads', () => {
    const made = [];
    const Chart = function (canvas) { made.push(canvas.id); };
    load({ win: { Chart, BAN_ADMIN_METRICS: { charts: [line([1, 2])] } }, doc: { getElementById: (id) => ({ id }) } });
    expect(made).toEqual(['metrics-days']);
    // and does nothing with no object, no Chart or a broken object
    load({ win: { Chart: () => { throw new Error('drawn'); } } });
    load({ win: { BAN_ADMIN_METRICS: { charts: [line([1])] } }, doc: { getElementById: (id) => ({ id }) } });
    load({ win: { Chart, BAN_ADMIN_METRICS: { charts: 7 } } });
    expect(made).toEqual(['metrics-days']);
});

test('the script never touches innerHTML or builds code from strings', () => {
    const code = source.replace(/\/\/.*$/gm, '');
    expect(code).not.toContain('innerHTML');
    expect(code).not.toContain('outerHTML');
    expect(code).not.toContain('insertAdjacentHTML');
    expect(code).not.toMatch(/\beval\b|new Function/);
    // a canvas that throws on innerHTML is drawn on without it
    const canvas = { id: 'metrics-days' };
    Object.defineProperty(canvas, 'innerHTML', { get() { throw new Error('read'); }, set() { throw new Error('written'); } });
    let drawn = 0;
    api.drawAdminMetrics({ getElementById: () => canvas }, [line([1, 2])], function () { drawn++; });
    expect(drawn).toBe(1);
});
