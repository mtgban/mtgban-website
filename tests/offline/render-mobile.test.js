import { test, expect } from 'bun:test';

globalThis.self = globalThis.self || globalThis;
await import('../../js/offline/offline-render-mobile.js');

const R = globalThis.OfflineRenderMobile;

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
    },
    hiddenSellers: [],
    hiddenVendors: [],
    byStore: false,
};

function result(overrides) {
    return Object.assign({
        uuid: 'uuid-1',
        i: 'img-key-1',
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

test('card wrapper has m-card class', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('class="m-card"');
});

test('header data attributes', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('data-card-id="uuid-1"');
    expect(html).toContain('data-image-url="/api/offline/images/img-key-1.jpg"');
    expect(html).toContain('data-set-code="NEO"');
    expect(html).toContain('data-card-name="Boseiju, Who Endures"');
});

test('keyrune icon when set.k present', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('class="ss ss-neo ss-fw"');
});

test('set-code span fallback when no keyrune', () => {
    const ctx = Object.assign({}, CTX, {sets: {}});
    const html = R.buildHTML([result()], ctx);
    expect(html).toContain('<span>NEO</span>');
    expect(html).not.toContain('class="ss ss-neo');
});

test('foil badge on foil card', () => {
    const r = result({card: {uuid: 'u2', n: 'Test', num: '1', r: 'rare', set: 'NEO', f: true, e: false, s: false}});
    r.retail = {}; r.buylist = {};
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('class="m-badge foil"');
});

test('etched badge on etched card', () => {
    const r = result({card: {uuid: 'u3', n: 'Test', num: '1', r: 'rare', set: 'NEO', f: false, e: true, s: false}});
    r.retail = {}; r.buylist = {};
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('class="m-badge etched"');
});

test('no finish badge on regular card', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).not.toContain('class="m-badge foil"');
    expect(html).not.toContain('class="m-badge etched"');
});

test('condition pills present and NM first and active', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('class="m-cond-pills"');
    expect(html).toContain('class="m-cond-pill active" data-cond="NM"');
    expect(html).toContain('class="m-cond-pill" data-cond="SP"');
    // NM before SP
    expect(html.indexOf('data-cond="NM"')).toBeLessThan(html.indexOf('data-cond="SP"'));
});

test('no condition pills for sealed product', () => {
    const r = result({
        uuid: 'uuid-box',
        card: {uuid: 'uuid-box', n: 'Box', num: '', r: '', set: 'NEO', f: false, e: false, s: true},
        retail: {CK: {sealed: 99}},
        buylist: {CK: {sealed: 70}},
    });
    const html = R.buildHTML([r], CTX);
    expect(html).not.toContain('class="m-cond-pills"');
});

test('sellers and buyers tabs with correct data-target ids', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('data-target="sellers-uuid-1"');
    expect(html).toContain('data-target="buyers-uuid-1"');
    expect(html).toContain('class="m-tab active"');
});

test('sellers panel id and active class', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('id="sellers-uuid-1"');
    expect(html).toContain('<div class="m-tab-panel active" id="sellers-uuid-1"');
});

test('buyers panel id present', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('id="buyers-uuid-1"');
});

test('first seller row in NM group has m-best-price and m-best-badge', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('m-best-price');
    expect(html).toContain('<span class="m-best-badge">Best</span>');
});

test('seller NM rows show price and qty', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('$ 30.00');
    expect(html).toContain('class="m-vendor-qty">4');
});

test('SYP index buyer row shows hash qty not dollar price', () => {
    const ctx = Object.assign({}, CTX, {
        stores: Object.assign({}, CTX.stores, {SYP: {n: 'TCGplayer SYP', i: true}}),
    });
    const r = result();
    r.buylist = {SYP: {qty: 48, regular: 1.79}};
    const html = R.buildHTML([r], ctx);
    expect(html).toContain('# 48');
    expect(html).not.toContain('$ 1.79');
});

test('buyer NM row has ratio title attribute', () => {
    const html = R.buildHTML([result()], CTX);
    // ref = min(CK 30, TCGLow 27.5, TCGMarket 29.1) = 27.5; 20/27.5*100 = 72.73
    expect(html).toContain('title="Ratio: 72.73%"');
});

test('buyer ratio absent for SP rows', () => {
    const html = R.buildHTML([result()], CTX);
    const buyersHtml = html.slice(html.indexOf('id="buyers-uuid-1"'));
    const spGroup = buyersHtml.slice(buyersHtml.indexOf('data-cond="SP"'));
    expect(spGroup).not.toContain('title="Ratio:');
});

test('hidden sellers filtered from sellers panel', () => {
    const ctx = Object.assign({}, CTX, {hiddenSellers: ['CK']});
    const html = R.buildHTML([result()], ctx);
    const sellersHtml = html.slice(html.indexOf('id="sellers-'), html.indexOf('id="buyers-'));
    expect(sellersHtml).not.toContain('Card Kingdom');
});

test('hidden vendors filtered from buyers panel', () => {
    const ctx = Object.assign({}, CTX, {hiddenVendors: ['CK']});
    const html = R.buildHTML([result()], ctx);
    const buyersHtml = html.slice(html.indexOf('id="buyers-'));
    expect(buyersHtml).not.toContain('Card Kingdom');
});

test('no-offers row when both sides empty', () => {
    const r = result({retail: {}, buylist: {}});
    const html = R.buildHTML([r], CTX);
    expect(html.match(/No offers/g).length).toBeGreaterThanOrEqual(2);
});

test('landscape image stub present', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('class="m-card-img-landscape"');
    expect(html).toContain('src="/api/offline/images/img-key-1.jpg"');
});

test('landscape image omitted when card has no image key', () => {
    const r = result({i: undefined});
    const html = R.buildHTML([r], CTX);
    expect(html).not.toContain('m-card-img-landscape');
});

test('header data-image-url empty when card has no image key', () => {
    const r = result({i: undefined});
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('data-image-url=""');
});

test('html is escaped in card name', () => {
    const r = result();
    r.card = Object.assign({}, r.card, {n: '<script>alert(1)</script>'});
    const html = R.buildHTML([r], CTX);
    expect(html).not.toContain('<script>');
    expect(html).toContain('&lt;script&gt;');
});

test('foil card uses foil price from entry.foil', () => {
    const r = result({
        uuid: 'u-foil',
        card: {uuid: 'u-foil', n: 'Boseiju', num: '506', r: 'rare', set: 'NEO', f: true, e: false, s: false},
        retail: {CK: {foil: 60, conditions: {NM_foil: 60}, quantities: {NM_foil: 1}}},
        buylist: {},
    });
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('$ 60.00');
});

test('INDEX group appears before condition groups in sellers panel', () => {
    const html = R.buildHTML([result()], CTX);
    const sellersHtml = html.slice(html.indexOf('id="sellers-'), html.indexOf('id="buyers-'));
    const idxPos = sellersHtml.indexOf('data-cond="INDEX"');
    const nmPos = sellersHtml.indexOf('data-cond="NM"');
    expect(idxPos).toBeGreaterThan(-1);
    expect(idxPos).toBeLessThan(nmPos);
});

test('notices: unsupported operator escaped', () => {
    const html = R.noticesHTML({results: [], unsupported: ['date>2020'], missingSets: [], truncated: false}, CTX);
    expect(html).toContain('offline-notice-warn');
    expect(html).toContain('date&gt;2020');
});

test('notices: missing set shows set name and link', () => {
    const html = R.noticesHTML({results: [], unsupported: [], missingSets: ['NEO'], truncated: false}, CTX);
    expect(html).toContain('Kamigawa: Neon Dynasty');
    expect(html).toContain('not synced');
    expect(html).toContain('/search?settings=1');
});

test('notices: empty results shows offline-empty', () => {
    const html = R.noticesHTML({results: [], unsupported: [], missingSets: [], truncated: false}, CTX);
    expect(html).toContain('offline-empty');
});

test('notices: truncated shows truncation notice', () => {
    const html = R.noticesHTML({results: [result()], unsupported: [], missingSets: [], truncated: true}, CTX);
    expect(html).toContain('truncated');
});

test('country flag appended to store name', () => {
    const ctx = JSON.parse(JSON.stringify(CTX));
    ctx.stores.ABU = {n: 'ABU Games', c: 'JP', b: true};
    const r = result();
    r.buylist.ABU = {regular: 15, conditions: {NM: 15}};
    const html = R.buildHTML([r], ctx);
    expect(html).toContain('ABU Games \u{1F1EF}\u{1F1F5}');
});

test('index-only card: INDEX m-cond-group gets active class', () => {
    const r = {
        uuid: 'uuid-idx',
        card: {uuid: 'uuid-idx', n: 'Sol Ring', num: '263', r: 'rare', set: 'NEO', f: false, e: false, s: false},
        retail: {TCGLow: {regular: 1.50}, TCGMarket: {regular: 1.75}},
        buylist: {},
    };
    const html = R.buildHTML([r], CTX);
    const sellersStart = html.indexOf('id="sellers-uuid-idx"');
    const sellersHtml = html.slice(sellersStart, html.indexOf('id="buyers-uuid-idx"'));
    expect(sellersHtml).toContain('m-cond-group active');
    expect(sellersHtml).toContain('data-cond="INDEX"');
});
