import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

// Shared modules attach to self; give bun one.
globalThis.self = globalThis.self || globalThis;
// utils.js is a plain script the page loads, so its helpers are globals.
(0, eval)(readFileSync(new URL('../../js/utils.js', import.meta.url), 'utf8'));
await import('../../js/offline/offline-render-shared.js');
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

test('header mirrors search.html classes and data attrs', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('class="result-header-cover"');
    expect(html).toContain('class="result-header result-first"');
    expect(html).toContain('data-card-id="uuid-1"');
    expect(html).toContain('data-image-url="/api/offline/images/img-key-1.webp"');
    expect(html).toContain('data-foil="false"');
    expect(html).toContain('data-etched="false"');
    expect(html).toContain('class="ss ss-neo ss-rare ss-2x ss-fw result-set-icon"');
    expect(html).toContain('class="result-card-info"');
    expect(html).toContain('class="result-card-name-row"');
    expect(html).toContain('class="result-card-name"');
    expect(html).toContain('class="result-badges"');
    expect(html).toContain('class="result-set-title"');
    expect(html).toContain('Kamigawa: Neon Dynasty - Rare #177');
});

test('header and body carry data-foil/data-etched for foil and etched cards', () => {
    const foil = result({
        uuid: 'uuid-foil',
        card: Object.assign({}, result().card, {uuid: 'uuid-foil', f: true, e: false}),
    });
    const foilHtml = R.buildHTML([foil], CTX);
    expect(foilHtml).toContain('data-foil="true"');
    expect(foilHtml).toContain('data-etched="false"');

    const etched = result({
        uuid: 'uuid-etched',
        card: Object.assign({}, result().card, {uuid: 'uuid-etched', f: false, e: true}),
    });
    const etchedHtml = R.buildHTML([etched], CTX);
    expect(etchedHtml).toContain('data-foil="false"');
    expect(etchedHtml).toContain('data-etched="true"');

    const plainHtml = R.buildHTML([result()], CTX);
    expect(plainHtml).toContain('data-foil="false"');
    expect(plainHtml).toContain('data-etched="false"');
});

test('body columns and condition grouping', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).toContain('data-image-url="/api/offline/images/img-key-1.webp"');
    expect(html).toContain('class="result-body result-last-body"');
    expect(html).toContain('data-set-code="NEO"');
    expect(html).toContain('<div class="result-col-header">Sellers</div>');
    expect(html).toContain('<div class="result-col-header">Buyers</div>');
    expect(html).toContain('<div class="price-cond-header cond-NM">Condition: NM</div>');
    expect(html).toContain('<div class="price-cond-header cond-SP">Condition: SP</div>');
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
    expect(html).toContain('<div class="price-cond-header cond-NM">Purchase from</div>');
    expect(html).toContain('<div class="price-cond-header">Sell to</div>');
});

test('a sealed result links to sealed searches, a single to plain ones', () => {
    const links = (html) => [...html.matchAll(/href="([^"]*)"/g)].map((m) => m[1]);
    const box = result({card: {uuid: 'uuid-box', n: 'NEO Box', num: '', r: '', set: 'NEO', f: false, e: false, s: true}});
    expect(links(R.buildHTML([box], CTX))).toEqual([
        '?sealed=1&q=s%3ANEO', '?sealed=1&q=%22NEO%20Box%22', '?sealed=1&q=s%3ANEO',
    ]);
    expect(links(R.buildHTML([result()], CTX))[0]).toBe('?q=s%3ANEO');
    // From the Graded page, the mark the exits lead back by rides along
    expect(links(R.buildHTML([result()], {...CTX, graded: true})).slice(0, 2)).toEqual([
        '?q=s%3ANEO&graded=1', '?q=%22Boseiju%2C%20Who%20Endures%22&graded=1',
    ]);
});

// css/search-rows.css hides Poor by these where NM and SP are listed too.
test('seller headers and rows carry their condition, buyers none', () => {
    const r = result({
        retail: {
            CK: {cond: 'NM', conditions: {NM: 30, SP: 25, PO: 5}, quantities: {NM: 4, SP: 2, PO: 1}},
            TCGLow: {regular: 27.5},
        },
    });
    const html = R.buildHTML([r], CTX);
    for (const cond of ['NM', 'SP', 'PO']) {
        expect(html).toContain('<div class="price-cond-header cond-' + cond + '">Condition: ' + cond + '</div>');
        expect(html).toContain('<div class="price-row cond-' + cond + '">');
    }
    expect(html.match(/cond-(NM|SP|PO)/g).length).toBe(6);
    expect(html.slice(html.indexOf('Buyers'))).not.toMatch(/cond-(NM|SP|PO)/);
});

test('a set with a mark draws it on its keyrune icon', () => {
    const ctx = Object.assign({}, CTX, {sets: {NEO: {n: 'Kamigawa: Neon Dynasty Promos', k: 'neo', m: '★'}}});
    expect(R.buildHTML([result()], ctx)).toContain('class="ss ss-neo ss-rare ss-2x ss-fw result-set-icon" data-mark="★"');
    expect(R.buildHTML([result()], CTX)).not.toContain('data-mark="');
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

test('products link appears in result-set-title when card.p is set', () => {
    const r = result();
    r.card = Object.assign({}, r.card, {p: ['sealed-uuid-1', 'sealed-uuid-2', 'sealed-uuid-3']});
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('Found in 3 products');
    expect(html).toContain('/sealed?q=container:uuid-1');
    expect(html).toContain('class="result-set-title"');
});

test('products link singular when card.p has one entry', () => {
    const r = result();
    r.card = Object.assign({}, r.card, {p: ['sealed-uuid-1']});
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('Found in 1 product</a>');
    expect(html).not.toContain('Found in 1 products');
});

test('no products link when card.p is absent', () => {
    const html = R.buildHTML([result()], CTX);
    expect(html).not.toContain('Found in');
    expect(html).not.toContain('/sealed?q=container:');
});

test('SYP buyer row appears before condition headers showing hash-qty', () => {
    const ctx = Object.assign({}, CTX, {
        stores: Object.assign({}, CTX.stores, {
            SYP: {n: 'TCGplayer SYP', i: true, b: true},
        }),
    });
    const r = result();
    r.buylist = {
        SYP: {regular: 1.79, qty: 48, conditions: {NM: 1.79}, quantities: {NM: 48}},
        CK: {regular: 20, conditions: {NM: 20}, quantities: {NM: 8}},
    };
    const html = R.buildHTML([r], ctx);
    // SYP renders # qty not $ price.
    expect(html).toContain('<span class="cur">#</span><span class="amt">48</span>');
    expect(html).not.toContain('1.79');
    // SYP appears before the NM condition header in the buyers column.
    const buyers = html.slice(html.indexOf('class="result-col-header">Buyers'));
    const sypPos = buyers.indexOf('TCGplayer SYP');
    const nmPos = buyers.indexOf('Condition: NM');
    expect(sypPos).toBeGreaterThan(-1);
    expect(nmPos).toBeGreaterThan(-1);
    expect(sypPos).toBeLessThan(nmPos);
});

test('MetadataOnly buyer without SYP shorthand renders price before condition headers', () => {
    const ctx = Object.assign({}, CTX, {
        stores: Object.assign({}, CTX.stores, {
            MINDEX: {n: 'Meta Index', i: true, b: true},
        }),
    });
    const r = result();
    r.buylist = {
        MINDEX: {regular: 5.00},
        CK: {regular: 20, conditions: {NM: 20}},
    };
    const html = R.buildHTML([r], ctx);
    const buyers = html.slice(html.indexOf('class="result-col-header">Buyers'));
    const idxPos = buyers.indexOf('Meta Index');
    const nmPos = buyers.indexOf('Condition: NM');
    expect(idxPos).toBeGreaterThan(-1);
    expect(idxPos).toBeLessThan(nmPos);
});

test('notices: unsupported, empty', () => {
    let html = R.noticesHTML({results: [], unsupported: ['date>2020'], truncated: false});
    expect(html).toContain('offline-notice');
    expect(html).toContain('date&gt;2020');
    html = R.noticesHTML({results: [], unsupported: [], truncated: false});
    expect(html).toContain('offline-empty');
});

test('buylist ratio renders as visible text in the default mode', () => {
    const html = R.buildHTML([result()], Object.assign({}, CTX, {buylistSecondary: ''}));
    expect(html).toContain('data-ratio="72.73"');
    expect(html).toContain('>72.73 %</span>');
});

test('credit secondary modes render a blank buylist cell offline', () => {
    const html = R.buildHTML([result()], Object.assign({}, CTX, {buylistSecondary: 'creditPrice'}));
    expect(html).not.toContain('72.73 %');
    expect(html).toContain('data-ratio="72.73"');
});

test('card without image key renders empty data-image-url', () => {
    const r = result({i: undefined});
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('data-image-url=""');
    expect(html).not.toContain('/api/offline/images/');
});

test('keyruneClasses mirrors keyruneForCardSet rarity/foil mapping', () => {
    expect(R.keyruneClasses({r: 'mythic', f: false, e: false})).toBe(' ss-mythic');
    expect(R.keyruneClasses({r: 'common', f: false, e: false})).toBe('');
    expect(R.keyruneClasses({r: 'rare', f: true, e: false})).toBe(' ss-foil ss-grad');
    expect(R.keyruneClasses({r: 'rare', f: true, e: false})).not.toContain('ss-rare');
    expect(R.keyruneClasses({r: 'rare', f: false, e: true})).toBe(' ss-timeshifted');
    expect(R.keyruneClasses({r: 'token', f: false, e: false})).toBe('');
});

test('mythic card renders ss-mythic on the result icon', () => {
    const r = result({card: Object.assign({}, result().card, {r: 'mythic'})});
    const html = R.buildHTML([r], CTX);
    expect(html).toContain('class="ss ss-neo ss-mythic ss-2x ss-fw result-set-icon"');
});

// A row priceRows left unpriced carries no price objects, and renders as no offers.
test('a row with no price objects renders as no offers', () => {
    const empty = R.buildHTML([result({retail: {}, buylist: {}})], CTX);
    expect(R.buildHTML([result({retail: null, buylist: null})], CTX)).toBe(empty);
    expect(R.buildHTML([result({retail: null})], CTX))
        .toBe(R.buildHTML([result({retail: {}})], CTX));
});

// A graded store, as the payload files it: each slab under the condition it
// folds to, a bar and its name.
const GRADED_CTX = Object.assign({}, CTX, {stores: Object.assign({}, CTX.stores, {CKG: {n: 'Card Kingdom Graded'}})});

function gradedResult(conditions, quantities) {
    return result({retail: {CKG: {regular: 10, cond: 'NM', qty: 1, conditions: conditions, quantities: quantities}}});
}

test('a graded store has a row per slab under the condition it folds to', () => {
    const html = R.buildHTML([gradedResult(
        {'NM|PSA 9': 10, 'NM|CGC 10 Pristine': 30, 'SP|PSA 6': 4},
        {'NM|PSA 9': 3})], GRADED_CTX);
    expect(html).toContain('<span class="store-cell"><a class="store-name dim">Card Kingdom Graded</a><span class="slab-name" title="PSA 9">PSA 9</span></span>');
    expect(html).toContain('<span class="slab-name" title="CGC 10 Pristine">CGC 10 Pristine</span>');
    expect(html).toContain('<span class="qty">3</span>');
    // The base price is the PSA 9, so it adds no row of its own
    expect(html.split('Card Kingdom Graded').length - 1).toBe(3);
    const sp = html.indexOf('Condition: SP');
    expect(html.indexOf('PSA 9')).toBeLessThan(html.indexOf('CGC 10 Pristine'));
    expect(html.indexOf('CGC 10 Pristine')).toBeLessThan(sp);
    expect(html.indexOf('PSA 6')).toBeGreaterThan(sp);
});

test('a foil slab is read off its suffixed tag', () => {
    const r = gradedResult({'NM_foil|PSA 9': 20}, {});
    r.card = Object.assign({}, r.card, {f: true});
    const html = R.buildHTML([r], GRADED_CTX);
    expect(html).toContain('<div class="price-cond-header cond-NM">Condition: NM</div>');
    expect(html).toContain('<span class="slab-name" title="PSA 9">PSA 9</span>');
    expect(html).toContain('<span class="amt">20.00</span>');
});

test('sorted by store, one store\'s slabs go by price', () => {
    const html = R.buildHTML([gradedResult({'NM|PSA 10': 50, 'NM|PSA 9': 10, 'NM|BGS 9': 30})],
        Object.assign({}, GRADED_CTX, {byStore: true}));
    expect(html.indexOf('PSA 9')).toBeLessThan(html.indexOf('BGS 9'));
    expect(html.indexOf('BGS 9')).toBeLessThan(html.indexOf('PSA 10'));
});

test('a slab name is escaped', () => {
    const html = R.buildHTML([gradedResult({'NM|"><img src=x onerror=alert(1)>': 10})], GRADED_CTX);
    expect(html).not.toContain('<img src=x');
    expect(html).toContain('title="&quot;&gt;&lt;img');
});

test('a graded store with no slab tags shows its base price as before', () => {
    const html = R.buildHTML([gradedResult({NM: 10}, {NM: 1})], GRADED_CTX);
    expect(html).toContain('<span class="store-cell"><a class="store-name dim">Card Kingdom Graded</a></span>');
    expect(html).not.toContain('slab-name');
    const bare = R.buildHTML([result({retail: {CKG: {regular: 10, cond: 'NM', qty: 1}}})], GRADED_CTX);
    expect(bare).toContain('<span class="store-cell"><a class="store-name dim">Card Kingdom Graded</a></span>');
});

test('condPrices leaves slab tags to slabPrices', () => {
    const S = globalThis.OfflineRenderShared;
    const entry = {regular: 10, cond: 'NM', conditions: {'NM|PSA 9': 10, 'SP|PSA 6': 4}};
    expect(S.condPrices(entry, {})).toEqual({});
    expect(S.slabPrices(entry)).toEqual([
        {cond: 'NM', slab: 'PSA 9', price: 10, qty: 0},
        {cond: 'SP', slab: 'PSA 6', price: 4, qty: 0},
    ]);
});
