import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

globalThis.self = globalThis.self || globalThis;
// utils.js is a plain script the page loads, so its helpers are globals.
(0, eval)(readFileSync(new URL('../../js/utils.js', import.meta.url), 'utf8'));
await import('../../js/offline/offline-render-shared.js');
await import('../../js/offline/offline-render.js');
await import('../../js/offline/offline-render-mobile.js');

// What templates/mobile/offline.html's m-offline-parts holds, in short.
const PARTS = {
    'edge-sellers': '<button class="m-edge m-edge-sell"><span class="m-edge-price">{price}</span></button>',
    'edge-buyers': '<button class="m-edge m-edge-buy"><span class="m-edge-price">{price}</span></button>',
    'head-sellers': '<div class="m-pane-head">Sellers</div>',
    'head-buyers': '<div class="m-pane-head">Buyers</div>',
    back: '/img/backs/magic.webp',
};
const R = { buildHTML: (results, ctx) => globalThis.OfflineRenderMobile.buildHTML(results, ctx, PARTS) };

// One of the card's lists: from its panel's id to the next one's.
function list(html, name) {
    const from = html.indexOf('id="' + name + '-');
    if (from < 0) return '';
    const next = html.indexOf('class="m-tab-panel', from);
    return html.slice(from, next < 0 ? undefined : next);
}

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
    expect(html).toContain('data-image-url="/api/offline/images/img-key-1.webp"');
    expect(html).toContain('data-set-code="NEO"');
    expect(html).toContain('data-card-name="Boseiju, Who Endures"');
    // The scrubber names the card by its set and number
    expect(html).toContain('data-number="177"');
});

test('keyrune icon when set.k present', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('class="ss ss-neo ss-rare ss-fw"');
});

test('a set with a mark draws it on its keyrune icon', () => {
    const ctx = Object.assign({}, CTX, {sets: {NEO: {n: 'Kamigawa: Neon Dynasty Promos', k: 'neo', m: '★'}}});
    expect(R.buildHTML([result()], ctx)).toContain('class="ss ss-neo ss-rare ss-fw" data-mark="★"');
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

test('each list is the desktop page\'s column, under its heading', () => {
    const html = R.buildHTML([result()], CTX);
    expect(list(html, 'sellers')).toContain(PARTS['head-sellers'] + globalThis.OfflineRender.sellers(result(), CTX).html);
    expect(list(html, 'buyers')).toContain(PARTS['head-buyers'] + globalThis.OfflineRender.buyers(result(), CTX).html);
});

test('the sellers come before the buyers, as search-cards.js and landscape read them', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('<div class="m-tab-panel active" id="sellers-uuid-1"');
    expect(html).toContain('<div class="m-tab-panel active" id="buyers-uuid-1"');
    expect(html.indexOf('id="sellers-')).toBeLessThan(html.indexOf('id="buyers-'));
});

test('the edge buttons carry the best price of the best condition', () => {
    const r = result();
    r.retail.ABU = {regular: 12, conditions: {SP: 12}};
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('m-edge-sell"><span class="m-edge-price">$ 30.00</span>');
    expect(html).toContain('m-edge-buy"><span class="m-edge-price">$ 20.00</span>');
});

test('a side with only reference prices has an edge button without a price', () => {
    const html = R.buildHTML([result({retail: {TCGLow: {regular: 1.5}}, buylist: {}})], CTX);
    expect(html).toContain('m-edge-sell"></button>');
    expect(html).not.toContain('{price}');
});

test('a side with nothing has no edge button and no list', () => {
    const html = R.buildHTML([result({buylist: {}})], CTX);
    expect(html).toContain('m-edge-sell');
    expect(html).not.toContain('m-edge-buy');
    expect(list(html, 'buyers')).toBe('');
    expect(html).not.toContain('No offers');
});

test('a card with no offers says so once', () => {
    const html = R.buildHTML([result({retail: {}, buylist: {}})], CTX);
    expect(html.match(/No offers/g)).toHaveLength(1);
    expect(html).not.toContain('m-edge');
});

test('the name searches for it, staying in sealed for a product', () => {
    expect(R.buildHTML([result()], CTX)).toContain('href="?q=%22Boseiju%2C%20Who%20Endures%22"');
    const box = result({card: {uuid: 'b', n: 'Box', num: '', r: '', set: 'NEO', f: false, e: false, s: true}});
    expect(R.buildHTML([box], CTX)).toContain('href="?sealed=1&amp;q=%22Box%22"');
});

test('hidden sellers filtered from sellers panel', () => {
    const ctx = Object.assign({}, CTX, {hiddenSellers: ['CK']});
    const html = R.buildHTML([result()], ctx);
    expect(list(html, 'sellers')).toContain('TCG (Low / Market)');
    expect(list(html, 'sellers')).not.toContain('Card Kingdom');
});

test('hidden vendors filtered from buyers panel', () => {
    const ctx = Object.assign({}, CTX, {hiddenVendors: ['CK']});
    const r = result();
    r.buylist.ABU = {regular: 15, conditions: {NM: 15}};
    const html = R.buildHTML([r], ctx);
    expect(list(html, 'buyers')).toContain('ABU Games');
    expect(list(html, 'buyers')).not.toContain('Card Kingdom');
});

test('the first pictures load eagerly, the rest as they come near', () => {
    const html = R.buildHTML([result(), result(), result()], CTX);
    expect(html).toContain('src="/api/offline/images/img-key-1.webp"');
    expect(html.match(/loading="(eager|lazy)"/g)).toEqual(['loading="eager"', 'loading="eager"', 'loading="lazy"']);
});

test('a card the sync holds no picture for shows the card back', () => {
    const html = R.buildHTML([result({i: undefined})], CTX);
    expect(html).toContain('class="m-card-img-landscape"');
    expect(html).toContain('src="/img/backs/magic.webp"');
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
    expect(html).toContain('<span class="amt">60.00</span>');
});

test('country flag appended to store name', () => {
    const ctx = JSON.parse(JSON.stringify(CTX));
    ctx.stores.ABU = {n: 'ABU Games', c: 'JP', b: true};
    const r = result();
    r.buylist.ABU = {regular: 15, conditions: {NM: 15}};
    const html = R.buildHTML([r], ctx);
    expect(html).toContain('ABU Games \u{1F1EF}\u{1F1F5}');
});

// A row priceRows left unpriced carries no price objects, and renders as no offers.
test('a row with no price objects renders as no offers', () => {
    const empty = R.buildHTML([result({retail: {}, buylist: {}})], CTX);
    expect(R.buildHTML([result({retail: null, buylist: null})], CTX)).toBe(empty);
    expect(R.buildHTML([result({retail: null})], CTX))
        .toBe(R.buildHTML([result({retail: {}})], CTX));
});

test('a graded store lists each slab with its name', () => {
    const ctx = Object.assign({}, CTX, {stores: Object.assign({}, CTX.stores, {CKG: {n: 'Card Kingdom Graded'}})});
    const html = R.buildHTML([result({retail: {CKG: {regular: 10, cond: 'NM', conditions: {'NM|PSA 9': 10}}}})], ctx);
    expect(html).toContain('<span class="slab-name" title="PSA 9">PSA 9</span>');
    expect(html.split('Card Kingdom Graded').length - 1).toBe(1);
});
