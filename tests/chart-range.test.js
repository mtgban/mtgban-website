import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const source = readFileSync(join(import.meta.dir, '..', 'js', 'chart-range.js'), 'utf8');

// loadRange evaluates chart-range.js against a stubbed fetch, and reports every
// url it asked for, so a test can tell "already loaded" from "went and got it".
function loadRange({ payload = null, fail = false } = {}) {
    const calls = [];
    const fetch = (url) => {
        calls.push(url);
        if (fail) return Promise.reject(new Error('network'));
        return Promise.resolve({ ok: true, json: () => Promise.resolve(payload) });
    };
    const console = { warn() {} };
    const api = new Function('fetch', 'console', source +
        '; return { ChartRangeLoader, chartNumbers, chartDatasetConfig };')(fetch, console);
    return { api, calls };
}

function newLoader(api, opts, over = {}) {
    const installed = [];
    const busy = [];
    const loader = new api.ChartRangeLoader(Object.assign({
        ids: 'ban:1',
        maxDays: 3650,
        loadedDays: 180,
        onData: (d) => installed.push(d),
        onBusy: (b) => busy.push(b),
    }, opts, over));
    return { loader, installed, busy };
}

test('a range inside what was rendered never reaches the network', () => {
    const { api, calls } = loadRange();
    const { loader } = newLoader(api, {});

    let called = 0;
    loader.ensure(30, () => { called++; });
    loader.ensure(180, () => { called++; });

    expect(called).toBe(2);
    expect(calls).toEqual([]);
});

test('a wider range fetches the whole entitlement, once', async () => {
    const payload = { loadedDays: 3650, axisLabels: ['2026-09-24'], datasets: [{ name: 'TCG Low', data: [1] }] };
    const { api, calls } = loadRange({ payload });
    const { loader, installed, busy } = newLoader(api, {});

    await new Promise((done) => loader.ensure(730, done));

    expect(calls).toEqual(['/api/chart/ban%3A1?range=3650']);
    expect(installed).toEqual([payload]);
    expect(busy).toEqual([true, false]);
    expect(loader.loadedDays).toBe(3650);

    // Having gone once, a second widening is already covered.
    await new Promise((done) => loader.ensure(1825, done));
    expect(calls.length).toBe(1);
});

// "All" is the roster default, and is the tier's ceiling rather than an
// unbounded ask - the archive must never be handed a window nobody paid for.
test('the All option asks for the ceiling, not for everything', () => {
    const { api } = loadRange();
    const { loader } = newLoader(api, { maxDays: 730 });

    expect(loader.want(0)).toBe(730);
    expect(loader.want(3650)).toBe(730);
    expect(loader.want(90)).toBe(90);
});

// A chart that cannot widen is a shorter chart, not a broken one, and the
// failure must not be remembered as success or the retry never happens.
test('a failed fetch still draws, and can be retried', async () => {
    const { api, calls } = loadRange({ fail: true });
    const { loader, installed, busy } = newLoader(api, {});

    await new Promise((done) => loader.ensure(730, done));

    expect(installed).toEqual([]);
    expect(busy).toEqual([true, false]);
    expect(loader.loadedDays).toBe(180);

    await new Promise((done) => loader.ensure(730, done));
    expect(calls.length).toBe(2);
});

// The callback is what applies the new range window, so a second ask arriving
// while the first is in flight has to wait on it rather than be dropped - the
// load-time auto-fill and a viewer changing the select race exactly this way,
// and losing one leaves the control saying one range and the chart drawing
// another.
test('an ask made while one is in flight still gets its callback', async () => {
    const payload = { loadedDays: 3650, axisLabels: [], datasets: [{ name: 'TCG Low', data: [] }] };
    const { api, calls } = loadRange({ payload });
    const { loader } = newLoader(api, {});

    const seen = [];
    const first = new Promise((done) => loader.ensure(730, () => { seen.push('first'); done(); }));
    const second = new Promise((done) => loader.ensure(1825, () => { seen.push('second'); done(); }));
    await Promise.all([first, second]);

    expect(seen.sort()).toEqual(['first', 'second']);
    expect(calls.length).toBe(1);
});

// A response narrower than what is already drawn is not a widening, and
// installing it would shrink the chart under the viewer.
test('a narrower response is refused rather than installed', async () => {
    const payload = { loadedDays: 30, axisLabels: [], datasets: [{ name: 'TCG Low', data: [] }] };
    const { api } = loadRange({ payload });
    const { loader, installed } = newLoader(api, {});

    await new Promise((done) => loader.ensure(730, done));

    expect(installed).toEqual([]);
    expect(loader.loadedDays).toBe(180);
});

// Gaps arrive as null now. They used to arrive as the string "Number.NaN", and
// a response from before the change can still be sitting in a browser cache for
// an hour after it, so both have to read back as a hole.
test('a series normalises to numbers and nulls, whichever form it arrives in', () => {
    const { api } = loadRange();

    expect(api.chartNumbers([12.34, null, 0])).toEqual([12.34, null, 0]);
    expect(api.chartNumbers(['12.34', 'Number.NaN', '0'])).toEqual([12.34, null, 0]);
    expect(api.chartNumbers(undefined)).toEqual([]);
});

test('a dataset keeps its roster identity through the conversion', () => {
    const { api } = loadRange();
    const ds = api.chartDatasetConfig({
        name: 'Card A', cardId: 'ban:1', reference: 'TCG Low',
        data: ['1', 'Number.NaN'], color: 'red',
    });

    expect(ds.label).toBe('Card A');
    expect(ds.cardId).toBe('ban:1');
    expect(ds.referenceKey).toBe('TCG Low');
    expect(ds.data).toEqual([1, null]);
    expect(ds.borderColor).toBe('red');
});
