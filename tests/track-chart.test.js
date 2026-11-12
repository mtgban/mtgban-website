import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

const modalSource = readFileSync(join(import.meta.dir, '..', 'js', 'search-modal.js'), 'utf8');
const chartSource = readFileSync(join(import.meta.dir, '..', 'js', 'search-chart.js'), 'utf8');

// runModal runs search-modal.js inside the chart modal's iframe, holding
// pending as the batched roster, and returns its click handler and the counts.
function runModal(pending, withBan = true) {
    const calls = [];
    const items = new Map([['chartAddPending', pending]]);
    const localStorage = {
        getItem: (k) => (items.has(k) ? items.get(k) : null),
        setItem: (k, v) => { items.set(k, String(v)); },
    };
    let onClick;
    const document = {
        body: { classList: { toggle() {} }, appendChild() {} },
        querySelectorAll: () => [],
        createElement: () => ({ style: {} }),
        addEventListener: (type, fn) => { if (type === 'click') onClick = fn; },
    };
    const window = {
        BAN_SEARCH_MODAL: { ids: 'a', maxCards: 2 },
        addEventListener() {},
        location: { origin: 'https://example.test' },
    };
    window.parent = window;
    if (withBan) window.BAN = { track: (...a) => calls.push(a) };
    class MutationObserver { observe() {} }
    new Function('window', 'document', 'localStorage', 'sameSiteURL', 'MutationObserver', 'setTimeout', 'clearTimeout', modalSource)(
        window, document, localStorage, () => '', MutationObserver, () => 0, () => {});
    return { calls, items, click: (target) => onClick({ target, preventDefault() {} }) };
}

// addLink is a card's "add to chart" link in a result header, and what it is set to.
function addLink(cardId) {
    const attrs = { 'data-card-id': cardId };
    const a = {
        attrs,
        getAttribute: (k) => (k in attrs ? attrs[k] : null),
        setAttribute: (k, v) => { attrs[k] = v; },
        classList: { add() {}, remove() {} },
        closest: () => null,
    };
    const target = { closest: (sel) => (sel === 'a.chart-add-link' ? a : null) };
    return { a, target };
}

test('the modal counts a roster change and flips the link', () => {
    const modal = runModal('a');
    const { a, target } = addLink('b');

    modal.click(target);

    expect(modal.calls).toEqual([['ui.chart.roster', 'add', 'modal']]);
    expect(a.attrs['data-track-value']).toBe('chart_remove');
    expect(modal.items.get('chartAddPending')).toBe('a,b');
});

test('a card refused for the cap is not counted', () => {
    const modal = runModal('a,c');
    const { a, target } = addLink('b');

    modal.click(target);

    expect(modal.calls).toEqual([]);
    expect(a.attrs['data-track-value']).toBeUndefined();
    expect(modal.items.get('chartAddPending')).toBe('a,c');
});

test('with no metrics script the modal still batches the card', () => {
    const modal = runModal('a', false);
    const { a, target } = addLink('b');

    modal.click(target);

    expect(modal.items.get('chartAddPending')).toBe('a,b');
    expect(a.attrs['data-track-value']).toBe('chart_remove');
});

// fn returns one top-level function's source, from its line to the closing brace.
function fn(name) {
    const src = chartSource.replace(/\r\n/g, '\n');
    const start = src.indexOf('function ' + name + '(');
    expect(start).toBeGreaterThan(-1);
    return src.slice(start, src.indexOf('\n}', start) + 2);
}

test('search-chart.js counts what its functions do', () => {
    expect(chartSource).toContain("window.BAN.track('ui.chart.range', chartRangeValues[rangeDays])");
    expect(chartSource).toContain("window.BAN.track('ui.chart.gaps', cardChart.options.spanGaps ? 'off' : 'on')");
    expect(chartSource).toContain("window.BAN.track('ui.chart.reference')");
    expect(chartSource).toContain("window.BAN.track('ui.chart.add_modal', 'close')");

    // The range a reader picks, not the one restored at load.
    expect(fn('changeRange')).toContain("'ui.chart.range'");
    expect(chartSource.split("'ui.chart.range'").length).toBe(2);
    expect(fn('toggleGaps')).toContain("'ui.chart.gaps'");
    // A close counts only a modal that was open.
    expect(fn('closeChartAddModal')).toContain("if (wasOpen && window.BAN && window.BAN.track) window.BAN.track('ui.chart.add_modal', 'close')");
    // A press on the reference already showing changes nothing.
    expect(chartSource).toContain("if (ref !== currentReference && window.BAN && window.BAN.track) window.BAN.track('ui.chart.reference')");
});

// The range table names every option the select offers, and nothing else.
test('every desktop range option has its count value', () => {
    const tmpl = readFileSync(join(import.meta.dir, '..', 'templates', 'search.html'), 'utf8');
    const select = tmpl.slice(tmpl.indexOf('<select id="dateRange"'), tmpl.indexOf('</select>', tmpl.indexOf('<select id="dateRange"')));
    const options = [...select.matchAll(/<option value="(\d+)"/g)].map((m) => m[1]).sort();
    const table = chartSource.match(/var chartRangeValues = (\{[^}]*\})/)[1];
    const keys = [...table.matchAll(/(\d+):/g)].map((m) => m[1]).sort();
    expect(keys).toEqual(options);
});
