import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const fetchnames = readFileSync(join(import.meta.dir, '..', 'js', 'fetchnames.js'), 'utf8');
const autocomplete = readFileSync(join(import.meta.dir, '..', 'js', 'autocomplete.js'), 'utf8');

test('fetchNames memoises one request per sealed value', async () => {
    const urls = [];
    const fetch = (url) => { urls.push(url); return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(['Animate Wall']) }); };
    const fn = new Function('fetch', fetchnames + '\n;return fetchNames;');
    const fetchNames = fn(fetch);
    const a = fetchNames('false');
    const b = fetchNames('false');
    const c = fetchNames('true');
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(await a).toEqual(['Animate Wall']);
    expect(urls).toEqual(['/api/suggest?all=true&sealed=false', '/api/suggest?all=true&sealed=true']);
});

test('autocomplete fetches the names on first input, not at init', () => {
    // Source-level: the init does not await fetchNames, and an input
    // listener does the loading.
    const initRegion = autocomplete.slice(autocomplete.indexOf('function autocomplete('), autocomplete.indexOf('function fitToViewport'));
    expect(initRegion).not.toContain('await fetchNames');
    expect(initRegion).toContain("addEventListener('input', loadNames)");
});

function flushMicrotasks() {
    return new Promise((resolve) => setTimeout(resolve, 0));
}

/* A minimal EventTarget that actually honours { once: true } the way a real
 * <input> would, so a regression to { once: true } on the loading listener
 * makes this test fail rather than passing by accident. Handlers run with
 * the target as `this`, and an empty value, which the suggestion handler
 * returns early on. */
function fakeEventTarget() {
    const registry = {};
    const dispatched = {};
    return {
        value: '',
        defaultValue: '',
        addEventListener(type, handler, options) {
            const once = !!(options && options.once);
            (registry[type] = registry[type] || []).push({ handler, once });
        },
        dispatch(type) {
            const entries = (registry[type] || []).slice();
            for (const entry of entries) {
                entry.handler.call(this, {});
                if (entry.once) {
                    registry[type] = registry[type].filter((e) => e !== entry);
                }
            }
        },
        listenerCount(type) {
            return (registry[type] || []).length;
        },
        /* The code under test calls this directly (inp.dispatchEvent(new
         * Event('input'))); recording it is enough to prove the call
         * happened without rebuilding the real input handler's DOM calls. */
        dispatchEvent(event) {
            dispatched[event.type] = (dispatched[event.type] || 0) + 1;
        },
        dispatchedCount(type) {
            return dispatched[type] || 0;
        },
    };
}

test('an input after a failed fetch retries; an input after success does not refetch', async () => {
    let calls = 0;
    let lastPromise;
    let shouldFail = true;
    function fetchNamesStub() {
        calls++;
        lastPromise = shouldFail ? Promise.reject(new Error('network')) : Promise.resolve(['Animate Wall']);
        return lastPromise;
    }
    const inp = fakeEventTarget();
    const documentStub = { activeElement: null, addEventListener() {}, getElementsByClassName: () => [] };
    const fn = new Function('fetchNames', 'document', 'window', 'self',
        autocomplete + '\n;return autocomplete;');
    const autocompleteFn = fn(fetchNamesStub, documentStub, {}, {});
    autocompleteFn({}, inp, 'false');

    expect(calls).toBe(0);

    inp.dispatch('input');
    await lastPromise.catch(() => {});
    await flushMicrotasks();
    expect(calls).toBe(1);

    // The first fetch failed: the next keystroke must retry, not stay
    // silent - this is where { once: true } would have removed the listener.
    shouldFail = false;
    inp.dispatch('input');
    await lastPromise;
    await flushMicrotasks();
    expect(calls).toBe(2);

    // The retry succeeded: a further input must not fetch a third time.
    inp.dispatch('input');
    await flushMicrotasks();
    expect(calls).toBe(2);
});

// The navbar box takes focus on every page, so focus fetches nothing until
// an attempt has failed; then it retries for a query still in the box.
test('a focus retries only a failed fetch, for the query still in the box', async () => {
    let calls = 0;
    let shouldFail = true;
    const fetchNamesStub = () => { calls++; return shouldFail ? Promise.reject(new Error('network')) : Promise.resolve(['Animate Wall']); };
    const inp = fakeEventTarget();
    const documentStub = { activeElement: null, addEventListener() {}, getElementsByClassName: () => [] };
    new Function('fetchNames', 'document', 'window', 'self', autocomplete + '\n;return autocomplete;')(fetchNamesStub, documentStub, {}, {})({}, inp, 'false');

    inp.value = 'ani';
    inp.dispatch('focus');
    expect(calls).toBe(0);

    inp.value = '';
    inp.dispatch('input');
    await flushMicrotasks();
    expect(calls).toBe(1);

    inp.dispatch('focus');
    expect(calls).toBe(1);

    shouldFail = false;
    inp.value = 'ani';
    inp.dispatch('focus');
    await flushMicrotasks();
    expect(calls).toBe(2);

    inp.dispatch('focus');
    expect(calls).toBe(2);
});

/* Builds fetchNames and autocomplete from their real sources sharing one
 * scope, so fetchNames' own memo is the one autocomplete's loadNames hits -
 * no stub standing in for the bug this covers. */
function buildReal(fetchImpl, documentStub, windowStub, selfStub) {
    const fn = new Function('fetch', 'document', 'window', 'self',
        fetchnames + '\n' + autocomplete + '\n;return { fetchNames: fetchNames, autocomplete: autocomplete };');
    return fn(fetchImpl, documentStub || {}, windowStub || {}, selfStub || {});
}

test('a rejected fetchNames promise is retried, not cached forever', async () => {
    let calls = 0;
    let shouldFail = true;
    const fetchImpl = () => {
        calls++;
        if (shouldFail) return Promise.reject(new Error('network'));
        return Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(['Animate Wall']) });
    };
    const inp = fakeEventTarget();
    const documentStub = { activeElement: null, addEventListener() {}, getElementsByClassName: () => [] };
    const real = buildReal(fetchImpl, documentStub, {}, {});
    real.autocomplete({}, inp, 'false');

    inp.dispatch('input');
    await flushMicrotasks();
    await flushMicrotasks();
    expect(calls).toBe(1);

    shouldFail = false;
    inp.dispatch('input');
    await flushMicrotasks();
    await flushMicrotasks();
    expect(calls).toBe(2);

    await expect(real.fetchNames('false')).resolves.toEqual(['Animate Wall']);
});

test('a resolved name list re-runs the input handler for text typed before it arrived', async () => {
    let resolveFetch;
    const fetchImpl = () => new Promise((resolve) => { resolveFetch = resolve; });
    const inp = fakeEventTarget();
    const documentStub = { activeElement: inp, addEventListener() {}, getElementsByClassName: () => [] };
    const real = buildReal(fetchImpl, documentStub, {}, {});
    real.autocomplete({}, inp, 'false');

    inp.dispatch('input');
    inp.value = 'ani';
    await flushMicrotasks();
    expect(inp.dispatchedCount('input')).toBe(0);

    resolveFetch({ ok: true, status: 200, json: () => Promise.resolve(['Animate Wall']) });
    await flushMicrotasks();
    await flushMicrotasks();

    expect(inp.dispatchedCount('input')).toBe(1);
});

// The script is deferred, so a reader can type into the box before it
// attaches; the query a search page fills in is not typing.
test('text typed before autocomplete attaches loads the names; a filled-in query does not', () => {
    for (const [value, defaultValue, want] of [['ani', '', 1], ['Animate Wall', 'Animate Wall', 0]]) {
        let calls = 0;
        const fetchNamesStub = () => { calls++; return new Promise(() => {}); };
        const inp = Object.assign(fakeEventTarget(), { value, defaultValue });
        const documentStub = { activeElement: inp, addEventListener() {}, getElementsByClassName: () => [] };
        const fn = new Function('fetchNames', 'document', 'window', 'self', autocomplete + '\n;return autocomplete;');
        fn(fetchNamesStub, documentStub, {}, {})({}, inp, 'false');
        expect(calls).toBe(want);
    }
});

// The mobile navbar's query arrives in data-autocomplete-value: the page's
// value, not the reader's, so it must not fetch the list either.
test('a data-autocomplete-value query does not load the names', () => {
    let calls = 0;
    const fetchNamesStub = () => { calls++; return new Promise(() => {}); };
    const inp = fakeEventTarget();
    let def = '';
    Object.defineProperty(inp, 'defaultValue', { get: () => def, set: (v) => { def = v; inp.value = v; } });
    Object.assign(inp, {
        form: {},
        hasAttribute: (n) => n === 'data-autocomplete-value',
        getAttribute: (n) => (n === 'data-autocomplete-value' ? 'Animate Wall' : 'false'),
    });
    let ready;
    const documentStub = {
        activeElement: null,
        addEventListener(type, fn) { if (type === 'DOMContentLoaded') ready = fn; },
        querySelectorAll: () => [inp],
        getElementsByClassName: () => [],
    };
    new Function('fetchNames', 'document', 'window', 'self', autocomplete)(fetchNamesStub, documentStub, {}, {});
    ready();
    expect(inp.value).toBe('Animate Wall');
    expect(calls).toBe(0);
});

test('autocomplete initialises every input[data-autocomplete] on DOM ready', () => {
    expect(autocomplete).toContain("input[data-autocomplete]");
    expect(autocomplete).toContain("data-autocomplete-value");
    expect(autocomplete).toContain("'DOMContentLoaded'");
});

test('no template calls autocomplete() inline any more', () => {
    for (const f of ['home.html', 'mobile/home.html', 'mobile/search.html']) {
        const html = readFileSync(join(import.meta.dir, '..', 'templates', f), 'utf8');
        expect(html).not.toMatch(/<script[^>]*>[^<]*autocomplete\(/);
        expect(html).toContain('data-autocomplete=');
    }
    const nav = readFileSync(join(import.meta.dir, '..', 'templates', 'mobile', 'partials', 'navbar.html'), 'utf8');
    expect(nav).toContain('data-autocomplete=');
});
