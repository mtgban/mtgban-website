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

test('autocomplete fetches the names on first focus, not at init', () => {
    // Source-level: the init no longer awaits fetchNames, and a focus
    // listener does the loading.
    const initRegion = autocomplete.slice(autocomplete.indexOf('function autocomplete('), autocomplete.indexOf('function fitToViewport'));
    expect(initRegion).not.toContain('await fetchNames');
    expect(initRegion).toContain("addEventListener('focus'");
    expect(initRegion).toContain('document.activeElement === inp');
});

function flushMicrotasks() {
    return new Promise((resolve) => setTimeout(resolve, 0));
}

/* A minimal EventTarget that actually honours { once: true } the way a real
 * <input> would, so a regression to { once: true } on the focus listener
 * makes this test fail rather than passing by accident. */
function fakeEventTarget() {
    const registry = {};
    const dispatched = {};
    return {
        addEventListener(type, handler, options) {
            const once = !!(options && options.once);
            (registry[type] = registry[type] || []).push({ handler, once });
        },
        dispatch(type) {
            const entries = (registry[type] || []).slice();
            for (const entry of entries) {
                entry.handler();
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

test('a focus after a failed fetch retries; a focus after success does not refetch', async () => {
    let calls = 0;
    let lastPromise;
    let shouldFail = true;
    function fetchNamesStub() {
        calls++;
        lastPromise = shouldFail ? Promise.reject(new Error('network')) : Promise.resolve(['Animate Wall']);
        return lastPromise;
    }
    const inp = fakeEventTarget();
    const documentStub = { activeElement: null, addEventListener() {} };
    const fn = new Function('fetchNames', 'document', 'window', 'self',
        autocomplete + '\n;return autocomplete;');
    const autocompleteFn = fn(fetchNamesStub, documentStub, {}, {});
    autocompleteFn({}, inp, 'false');

    expect(inp.listenerCount('focus')).toBe(1);

    inp.dispatch('focus');
    await lastPromise.catch(() => {});
    await flushMicrotasks();
    expect(calls).toBe(1);

    // The first fetch failed: a later focus must retry, not stay silent -
    // this is where { once: true } would have removed the listener.
    shouldFail = false;
    inp.dispatch('focus');
    await lastPromise;
    await flushMicrotasks();
    expect(calls).toBe(2);

    // The retry succeeded: a further focus must not fetch a third time.
    inp.dispatch('focus');
    await flushMicrotasks();
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
    const documentStub = { activeElement: null, addEventListener() {} };
    const real = buildReal(fetchImpl, documentStub, {}, {});
    real.autocomplete({}, inp, 'false');

    inp.dispatch('focus');
    await flushMicrotasks();
    await flushMicrotasks();
    expect(calls).toBe(1);

    shouldFail = false;
    inp.dispatch('focus');
    await flushMicrotasks();
    await flushMicrotasks();
    expect(calls).toBe(2);

    await expect(real.fetchNames('false')).resolves.toEqual(['Animate Wall']);
});

test('a resolved name list re-runs the input handler for text typed before it arrived', async () => {
    let resolveFetch;
    const fetchImpl = () => new Promise((resolve) => { resolveFetch = resolve; });
    const inp = fakeEventTarget();
    inp.value = 'ani';
    const documentStub = { activeElement: inp, addEventListener() {} };
    const real = buildReal(fetchImpl, documentStub, {}, {});
    real.autocomplete({}, inp, 'false');

    inp.dispatch('focus');
    await flushMicrotasks();
    expect(inp.dispatchedCount('input')).toBe(0);

    resolveFetch({ ok: true, status: 200, json: () => Promise.resolve(['Animate Wall']) });
    await flushMicrotasks();
    await flushMicrotasks();

    expect(inp.dispatchedCount('input')).toBe(1);
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
