import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';
import { join } from 'path';

// The search page loads both, and a widened single-card chart is rebuilt with
// chart-range.js's chartDatasetConfig.
const scripts = ['chartopts.js', 'chart-range.js']
    .map((name) => readFileSync(join(import.meta.dir, '..', 'js', name), 'utf8'))
    .join('\n');

// legendStorageKey in templates/search.html, for a card that is not sealed.
const KEY = 'BANChart';

// Chart.js keeps what setDatasetVisibility sets on a meta tied to the dataset
// object, and otherwise reads the dataset's own hidden option, so a rebuilt
// dataset starts from its hidden option again.
const shown = new WeakMap();
function Chart(datasets) {
    this.data = { datasets };
}
Chart.register = () => {};
Chart.prototype.isDatasetVisible = function(i) {
    const ds = this.data.datasets[i];
    return shown.has(ds) ? shown.get(ds) : !ds.hidden;
};
Chart.prototype.setDatasetVisibility = function(i, visible) {
    shown.set(this.data.datasets[i], visible);
};
Chart.prototype.update = () => {};

// storage is a viewer's localStorage, which outlives each page.
function storage(saved = {}) {
    const items = new Map(Object.entries(saved));
    return {
        getItem: (key) => (items.has(key) ? items.get(key) : null),
        setItem: (key, value) => { items.set(key, String(value)); },
        removeItem: (key) => { items.delete(key); },
    };
}

// openCard loads the scripts into a fresh page and draws a card's chart the way
// the single-card branch of templates/search.html does: the window it rendered,
// the saved stores hidden, then the legend.
function openCard(localStorage, stores) {
    // The legend's buttons are read back out of its html, so a test can click
    // one by the store it names.
    const legend = {
        innerHTML: '',
        querySelectorAll() {
            this.buttons = [...this.innerHTML.matchAll(/data-index="(\d+)".*?<\/span>([^<]*)<\/button>/g)]
                .map(([, index, name]) => {
                    const button = { name, getAttribute: () => index, classList: { toggle() {} } };
                    button.addEventListener = (type, fn) => { button.click = () => fn.call(button); };
                    return button;
                });
            return this.buttons;
        },
    };
    const document = { getElementById: (id) => (id === 'chartLegend' ? legend : null) };
    const page = new Function('Chart', 'document', 'localStorage', scripts +
        '; return { applySavedLegendState, renderChartLegend, chartDatasetConfig };')(Chart, document, localStorage);

    const chart = new Chart(stores.map((s) => ({ label: s.name, data: [1], borderColor: s.color, fill: 'origin' })));
    page.applySavedLegendState(chart, KEY);
    page.renderChartLegend(chart, 'chartLegend', KEY);

    return {
        chart,
        legend,
        click(store) {
            legend.buttons.find((b) => b.name === store.name).click();
        },
        // widen installs a wider window's answer as installChartPayload does.
        widen(wider) {
            chart.data.datasets = wider.map((s) => page.chartDatasetConfig({ name: s.name, data: [1], color: s.color }));
            page.applySavedLegendState(chart, KEY);
            page.renderChartLegend(chart, 'chartLegend', KEY);
        },
    };
}

// Stores in the order /api/chart lists them.
const LOW = { name: 'TCGplayer Low', color: 'rgb(1, 0, 0)' };
const MARKET = { name: 'TCGplayer Market', color: 'rgb(2, 0, 0)' };
const RETAIL = { name: 'Card Kingdom Retail', color: 'rgb(3, 0, 0)' };
const BUYLIST = { name: 'Card Kingdom Buylist', color: 'rgb(4, 0, 0)' };

// lines reads a chart back as the stores it draws, marking the hidden ones;
// legendOf does the same for its legend.
const lines = ({ chart }) => chart.data.datasets.map((ds, i) => ds.label + (chart.isDatasetVisible(i) ? '' : ' (hidden)'));
const legendOf = ({ legend }) => [...legend.innerHTML.matchAll(/class="chart-legend-item( hidden)?".*?<\/span>([^<]*)<\/button>/g)]
    .map(([, hidden, name]) => name + (hidden ? ' (hidden)' : ''));

// /api/chart lists only the stores with prices for the card, so the store at a
// given position differs from one card to the next.
test('a store hidden on one card is hidden on the next by name', () => {
    const viewer = storage();
    openCard(viewer, [LOW, MARKET, BUYLIST]).click(MARKET);

    const other = openCard(viewer, [LOW, RETAIL, BUYLIST]);
    expect(lines(other)).toEqual(['TCGplayer Low', 'Card Kingdom Retail', 'Card Kingdom Buylist']);
    expect(legendOf(other)).toEqual(['TCGplayer Low', 'Card Kingdom Retail', 'Card Kingdom Buylist']);

    const moved = openCard(viewer, [MARKET, BUYLIST]);
    expect(lines(moved)).toEqual(['TCGplayer Market (hidden)', 'Card Kingdom Buylist']);
    expect(legendOf(moved)).toEqual(['TCGplayer Market (hidden)', 'Card Kingdom Buylist']);

    // Showing it again shows it everywhere.
    moved.click(MARKET);
    expect(lines(openCard(viewer, [LOW, MARKET, BUYLIST]))).toEqual(['TCGplayer Low', 'TCGplayer Market', 'Card Kingdom Buylist']);
});

// A store with prices only before the rendered window joins when the chart
// widens, in registry order, so it can land ahead of one the viewer hid.
test('a store hidden before the chart widens stays hidden when one joins ahead of it', () => {
    const card = openCard(storage(), [LOW, BUYLIST]);
    card.click(BUYLIST);

    card.widen([LOW, MARKET, BUYLIST]);

    expect(lines(card)).toEqual(['TCGplayer Low', 'TCGplayer Market', 'Card Kingdom Buylist (hidden)']);
    expect(legendOf(card)).toEqual(['TCGplayer Low', 'TCGplayer Market', 'Card Kingdom Buylist (hidden)']);
});

// Saving from a chart that does not draw a store must not forget it: the wider
// window can bring it back.
test('a store hidden on an earlier card comes in hidden when the wider window adds it', () => {
    const viewer = storage();
    openCard(viewer, [LOW, MARKET, BUYLIST]).click(MARKET);

    const card = openCard(viewer, [LOW, BUYLIST]);
    card.click(BUYLIST);
    card.widen([LOW, MARKET, BUYLIST]);

    expect(lines(card)).toEqual(['TCGplayer Low', 'TCGplayer Market (hidden)', 'Card Kingdom Buylist (hidden)']);
    expect(legendOf(card)).toEqual(['TCGplayer Low', 'TCGplayer Market (hidden)', 'Card Kingdom Buylist (hidden)']);
});

// The format before this one kept a flag per position, which names no store,
// so it is not applied to whichever store sits there now.
test('flags saved by position hide nothing, and the next click replaces them', () => {
    const viewer = storage({ [KEY]: '[false,true,false]' });

    const card = openCard(viewer, [LOW, MARKET, BUYLIST]);
    expect(lines(card)).toEqual(['TCGplayer Low', 'TCGplayer Market', 'Card Kingdom Buylist']);

    card.click(BUYLIST);
    expect(JSON.parse(viewer.getItem(KEY))).toEqual(['Card Kingdom Buylist']);
});
