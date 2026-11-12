import { test, expect } from 'bun:test';
import { loadMetrics } from './metrics-loader.js';

const BUILD = '0f'.repeat(20);
const ORIGIN = 'https://www.mtgban.com';
const location = {origin: ORIGIN, href: ORIGIN + '/search?q=bolt', pathname: '/search'};

// load runs the script with its sample pinned, then fires window's load event.
function load({random = 0, performance = {}, PerformanceObserver, page = 'search', docProps = {}} = {}) {
    const globals = {location, performance, PerformanceObserver,
        Math: Object.assign(Object.create(Math), {random: () => random})};
    const m = loadMetrics({cfg: {on: true, page, build: BUILD}, docProps, globals});
    m.emit('load');
    return m;
}
// sent hides the page, then returns every entry that has left it so far.
function sent(m) {
    m.hide('pagehide');
    return m.sent();
}

const perf = entries => entries.filter(e => e.n.startsWith('ui.perf.'));
const nav = (responseStart, domContentLoadedEventEnd, activationStart = 0) => ({
    getEntriesByType: type => (type === 'navigation' ? [{responseStart, domContentLoadedEventEnd, activationStart}] : []),
});
function observer(entries) {
    return class {
        static supportedEntryTypes = ['largest-contentful-paint'];
        constructor(cb) { this.cb = cb; }
        observe(o) {
            if (o.type === 'largest-contentful-paint' && o.buffered) this.cb({getEntries: () => entries});
        }
        disconnect() {}
    };
}

test('one load in ten is sampled', () => {
    for (const [random, want] of [[0, 3], [0.0999, 3], [0.1, 0], [0.5, 0]]) {
        const m = load({random, performance: nav(180, 900), PerformanceObserver: observer([{startTime: 1200}])});
        expect(perf(sent(m)).length).toBe(want);
    }
});

test('the sample is drawn once a load', () => {
    let calls = 0;
    const globals = {location, performance: nav(180, 900),
        Math: Object.assign(Object.create(Math), {random: () => { calls++; return 0; }})};
    const m = loadMetrics({cfg: {on: true, page: 'search', build: BUILD}, globals});
    m.emit('load');
    sent(m);
    expect(calls).toBe(1);
});

test('a sampled load sends the three timings bucketed, scoped to its page', () => {
    const m = load({performance: nav(180, 900),
        PerformanceObserver: observer([{startTime: 1200}, {startTime: 2600}])});
    expect(perf(sent(m)).sort((a, b) => a.n.localeCompare(b.n))).toEqual([
        {n: 'ui.perf.dom_ready', s: 'search', v: '<1s', c: 1},
        {n: 'ui.perf.lcp', s: 'search', v: '<4s', c: 1},
        {n: 'ui.perf.ttfb', s: 'search', v: '<200ms', c: 1},
    ]);
});

test('bucket edges', () => {
    const value = (name, entries) => entries.find(e => e.n === name).v;
    for (const [ms, ttfb] of [[1, '<200ms'], [199.9, '<200ms'], [200, '<500ms'], [799, '<800ms'], [800, '<1.8s'], [1800, '1.8s+'], [60000, '1.8s+']]) {
        const m = load({performance: nav(ms, 100)});
        expect(value('ui.perf.ttfb', sent(m))).toBe(ttfb);
    }
    for (const [ms, dom] of [[499, '<500ms'], [500, '<1s'], [1999, '<2s'], [2000, '<4s'], [7999, '<8s'], [8000, '8s+']]) {
        const m = load({performance: nav(100, ms)});
        expect(value('ui.perf.dom_ready', sent(m))).toBe(dom);
    }
    for (const [ms, lcp] of [[999, '<1s'], [1000, '<2.5s'], [2500, '<4s'], [4000, '<8s'], [8000, '8s+']]) {
        const m = load({performance: nav(100, 100), PerformanceObserver: observer([{startTime: ms}])});
        expect(value('ui.perf.lcp', sent(m))).toBe(lcp);
    }
});

test('the old timing object is the fallback', () => {
    const performance = {timing: {navigationStart: 1000, responseStart: 1450, domContentLoadedEventEnd: 2100}};
    const m = load({performance});
    expect(perf(sent(m)).sort((a, b) => a.n.localeCompare(b.n))).toEqual([
        {n: 'ui.perf.dom_ready', s: 'search', v: '<2s', c: 1},
        {n: 'ui.perf.ttfb', s: 'search', v: '<500ms', c: 1},
    ]);
});

test('a missing API or a zero sends nothing for that metric', () => {
    expect(perf(sent(load({performance: {}})))).toEqual([]);
    expect(perf(sent(load({performance: undefined})))).toEqual([]);
    const m = load({performance: nav(0, NaN)});
    expect(perf(sent(m))).toEqual([]);
    class NoLCP { static supportedEntryTypes = ['paint']; observe() { throw new Error('unsupported'); } }
    const n = load({performance: nav(100, 100), PerformanceObserver: NoLCP});
    expect(perf(sent(n)).map(e => e.n).sort()).toEqual(['ui.perf.dom_ready', 'ui.perf.ttfb']);
});

test('a page with no label or in a background tab is not sampled', () => {
    const args = {performance: nav(180, 900), PerformanceObserver: observer([{startTime: 1200}])};
    expect(sent(load({...args, page: ''}))).toEqual([]); // the chart iframe: no ui.load either
    expect(perf(sent(load({...args, docProps: {visibilityState: 'hidden'}})))).toEqual([]);
    expect(perf(sent(load(args))).length).toBe(3);
});

test('a prerendered page is not sampled', () => {
    const lcp = observer([{startTime: 1200}]);
    expect(perf(sent(load({performance: nav(180, 900), PerformanceObserver: lcp, docProps: {prerendering: true}})))).toEqual([]);
    expect(perf(sent(load({performance: nav(180, 900, 40), PerformanceObserver: lcp})))).toEqual([]);
});

test('with no Math in globals the loader never samples', () => {
    // What keeps 2a's and 2e's tests the same on every run: the loader's own Math.
    const globals = {location, performance: nav(180, 900), PerformanceObserver: observer([{startTime: 1200}])};
    for (let i = 0; i < 50; i++) {
        const m = loadMetrics({cfg: {on: true, page: 'search', build: BUILD}, globals});
        m.emit('load');
        expect(perf(sent(m))).toEqual([]);
    }
});

test('the timer flush does not send lcp early', () => {
    const m = load({performance: nav(180, 900), PerformanceObserver: observer([{startTime: 1200}])});
    const flush = m.live().find(t => t.ms === 10000); // flushTimer, not the snapshot's
    flush.live = false;
    flush.fn();
    expect(perf(m.sent()).map(e => e.n).sort()).toEqual(['ui.perf.dom_ready', 'ui.perf.ttfb']);
    expect(perf(sent(m)).filter(e => e.n === 'ui.perf.lcp').length).toBe(1);
});

test('lcp leaves in the same beacon as the page hide, once', () => {
    const m = load({performance: nav(180, 900), PerformanceObserver: observer([{startTime: 1200}])});
    m.hide('pagehide');
    const beacon = m.beacons[m.beacons.length - 1].body;
    expect(beacon.filter(e => e.n === 'ui.perf.lcp').length).toBe(1);
    const all = perf(sent(m)).filter(e => e.n === 'ui.perf.lcp'); // sent() fires pagehide again
    expect(all.length).toBe(1);
});

test('turned off, nothing is sampled', () => {
    let calls = 0;
    const globals = {location, performance: nav(180, 900), PerformanceObserver: observer([{startTime: 1200}]),
        Math: Object.assign(Object.create(Math), {random: () => { calls++; return 0; }})};
    for (const extra of [{cfg: {on: false, page: 'search', build: BUILD}}, {cfg: {on: true, page: 'search', build: BUILD}, dnt: '1'}, {cfg: {on: true, page: 'search', build: BUILD}, gpc: true}]) {
        const m = loadMetrics({...extra, globals});
        m.emit('load');
        expect(perf(sent(m))).toEqual([]);
        expect(m.win.load).toBeUndefined();
    }
    expect(calls).toBe(0);
});

test('the paint observer stops at the first hide', () => {
    const made = [];
    class Counted {
        static supportedEntryTypes = ['largest-contentful-paint'];
        constructor(cb) { this.cb = cb; this.disconnects = 0; made.push(this); }
        observe() { this.cb({getEntries: () => [{startTime: 1200}]}); }
        disconnect() { this.disconnects++; }
    }
    const m = load({performance: nav(180, 900), PerformanceObserver: Counted});
    const before = perf(sent(m));
    expect(made.length).toBe(1);
    expect(made[0].disconnects).toBe(1);
    made[0].cb({getEntries: () => [{startTime: 9000}]}); // a late entry
    expect(perf(sent(m))).toEqual(before);
    expect(before.filter(e => e.n === 'ui.perf.lcp')).toEqual([{n: 'ui.perf.lcp', s: 'search', v: '<2.5s', c: 1}]);
});

test('a tab hidden before load sends no load timings', () => {
    const globals = {location, performance: nav(180, 900),
        Math: Object.assign(Object.create(Math), {random: () => 0})};
    const m = loadMetrics({cfg: {on: true, page: 'search', build: BUILD}, globals});
    m.document.visibilityState = 'hidden';
    m.emit('load');
    const names = perf(sent(m)).map(e => e.n);
    expect(names).not.toContain('ui.perf.ttfb');
    expect(names).not.toContain('ui.perf.dom_ready');
});
