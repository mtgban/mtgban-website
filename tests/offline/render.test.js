import { test, expect } from 'bun:test';

// Shared modules attach to self; give bun one.
globalThis.self = globalThis.self || globalThis;
await import('../../js/offline/offline-render.js');

const R = globalThis.OfflineRender;

const CTX = {
    sets: {
        NEO: {n: 'Kamigawa: Neon Dynasty', k: 'neo', d: '2022-02-18'},
    },
    stores: {
        CK:        {n: 'Card Kingdom', c: '', b: true},
        ABU:       {n: 'ABU Games', c: '', b: true},
        MKMLow:    {n: 'MKM Low', c: 'EU', i: true},
        MKMTrend:  {n: 'MKM Trend', c: 'EU', i: true},
        TCGLow:    {n: 'TCG Low', i: true},
        TCGMarket: {n: 'TCG Market', i: true},
        TCGIndex:  {n: 'TCG Direct Low', i: true},
    },
    hiddenSellers: [],
    hiddenVendors: [],
    byStore: false,
};

function result(overrides) {
    return Object.assign({
        uuid: 'uuid-1',
        card: {uuid: 'uuid-1', n: 'Boseiju, Who Endures', num: '177', r: 'rare', set: 'NEO', f: false, e: false, s: false},
        retail: {
            CK: {regular: 30, cond: 'NM', qty: 4,
                 conditions: {NM: 30, SP: 25}, quantities: {NM: 4, SP: 2}},
            TCGLow: {regular: 27.5},
            TCGMarket: {regular: 29.1},
        },
        buylist: {
            CK: {regular: 20, cond: 'NM', qty: 8, conditions: {NM: 20, SP: 16}, quantities: {NM: 8}},
        },
    }, overrides || {});
}

test('header mirrors search.html classes and data attrs', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('class="result-header-cover"');
    expect(html).toContain('class="result-header result-first"');
    expect(html).toContain('data-card-id="uuid-1"');
    expect(html).toContain('data-image-url="/api/offline/images/uuid-1.webp"');
    expect(html).toContain('class="ss ss-neo ss-2x ss-fw result-set-icon"');
    expect(html).toContain('class="result-card-info"');
    expect(html).toContain('class="result-card-name-row"');
    expect(html).toContain('class="result-card-name"');
    expect(html).toContain('class="result-badges"');
    expect(html).toContain('class="result-set-title"');
    expect(html).toContain('Kamigawa: Neon Dynasty - Rare #177');
});

test('body columns and condition grouping', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('class="result-body result-last-body"');
    expect(html).toContain('<div class="result-col-header">Sellers</div>');
    expect(html).toContain('<div class="result-col-header">Buyers</div>');
    expect(html).toContain('<div class="price-cond-header">Condition: NM</div>');
    expect(html).toContain('<div class="price-cond-header">Condition: SP</div>');
    // NM group renders before SP.
    expect(html.indexOf('Condition: NM')).toBeLessThan(html.indexOf('Condition: SP'));
    expect(html).toContain('class="rows-index"');
    expect(html).toContain('class="rows-main"');
});

test('price row shape', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('<span class="store-cell"><a class="store-name dim">Card Kingdom</a></span>');
    expect(html).toContain('<span class="cur">$</span><span class="amt">30.00</span>');
    expect(html).toContain('<span class="qty">4</span>');
});

test('index stores pair into single rows', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('TCG (Low / Market)');
    expect(html).toContain('class="price-right has-secondary"');
    expect(html).toContain('<span class="amt">27.50</span>');
    expect(html).toContain('<span class="secondary"><span class="cur">$</span><span class="amt">29.10</span></span>');
});

test('MKM pair and unpaired index passthrough', () => {
    const r = result();
    r.retail.MKMLow = {regular: 24};
    r.retail.MKMTrend = {regular: 26};
    r.retail.TCGIndex = {regular: 28};
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('CM (Low / Trend)');
    expect(html).toContain('TCG Direct Low');
});

test('index pairing needs both halves', () => {
    const r = result();
    delete r.retail.TCGMarket;
    const html = R.buildHTML([r], CTX);
    expect(html).not.toContain('TCG (Low / Market)');
    expect(html).toContain('TCG Low');
});

test('buylist rows carry ratio against best CK-or-TCG retail', () => {
    const html = R.buildHTML([result()], CTX);
    // ref = min(CK 30, TCGLow 27.5, TCGMarket 29.1) = 27.5; 20/27.5*100 = 72.73
    expect(html).toContain('class="price-right has-buylist-extra"');
    expect(html).toContain('data-ratio="72.73"');
    expect(html).toContain('data-credit=""');
});

test('ratio only on NM rows', () => {
    const html = R.buildHTML([result()], CTX);
    const sp = html.slice(html.lastIndexOf('Condition: SP'));
    expect(sp).toContain('data-ratio=""');
});

test('hidden stores are filtered per side', () => {
    const ctx = Object.assign({}, CTX, {hiddenSellers: ['CK'], hiddenVendors: []});
    const html = R.buildHTML([result()], ctx);
    const sellers = html.slice(html.indexOf('Sellers'), html.indexOf('Buyers'));
    expect(sellers).not.toContain('Card Kingdom');
    expect(html.slice(html.indexOf('Buyers'))).toContain('Card Kingdom');
});

test('foil card uses foil prices, badge, and suffixed condition tags', () => {
    const r = result({
        uuid: 'uuid-1f',
        card: {uuid: 'uuid-1f', n: 'Boseiju, Who Endures', num: '506', r: 'rare', set: 'NEO', f: true, e: false, s: false},
        retail: {CK: {foil: 60, cond: 'NM', qtyFoil: 1, conditions: {NM_foil: 60}, quantities: {NM_foil: 1}}},
        buylist: {},
    });
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('<span class="result-badge foil">Foil</span>');
    expect(html).toContain('<span class="amt">60.00</span>');
    expect(html).toContain('- Foil Rare #506');
});

test('no offers placeholder', () => {
    const r = result({retail: {}, buylist: {}});
    const html = R.buildHTML([r], CTX);
    expect(html.match(/no-offers/g).length).toBe(2);
});

test('country flag rides the store name', () => {
    const r = result();
    r.buylist.ABU = {regular: 15, cond: 'NM', conditions: {NM: 15}};
    const ctx = JSON.parse(JSON.stringify(CTX));
    ctx.stores.ABU.c = 'JP';
    const html = R.buildHTML([r], ctx);
    expect(html).toContain('ABU Games \u{1F1EF}\u{1F1F5}');
});

test('sealed product renders Purchase from / Sell to', () => {
    const r = result({
        uuid: 'uuid-box',
        card: {uuid: 'uuid-box', n: 'NEO Set Booster Box', num: '', r: '', set: 'NEO', f: false, e: false, s: true},
        retail: {CK: {sealed: 99, qtySealed: 2}},
        buylist: {CK: {sealed: 70}},
    });
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('<div class="price-cond-header">Purchase from</div>');
    expect(html).toContain('<div class="price-cond-header">Sell to</div>');
});

test('unknown keyrune falls back to the set code', () => {
    const r = result();
    const ctx = Object.assign({}, CTX, {sets: {}});
    const html = R.buildHTML([r], ctx);
    expect(html).toContain('<span>NEO</span>');
});

test('html is escaped', () => {
    const r = result();
    r.card = Object.assign({}, r.card, {n: 'Fake <img src=x onerror=alert(1)>'});
    const html = R.buildHTML([r], CTX);
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('&lt;img');
});

test('notices: unsupported, missing set, empty', () => {
    const ctx = CTX;
    let html = R.noticesHTML({results: [], unsupported: ['date>2020'], missingSets: [], truncated: false}, ctx);
    expect(html).toContain('offline-notice');
    expect(html).toContain('date&gt;2020');
    html = R.noticesHTML({results: [], unsupported: [], missingSets: ['NEO'], truncated: false}, ctx);
    expect(html).toContain('Kamigawa: Neon Dynasty');
    expect(html).toContain('not synced');
    html = R.noticesHTML({results: [], unsupported: [], missingSets: [], truncated: false}, ctx);
    expect(html).toContain('offline-empty');
});
