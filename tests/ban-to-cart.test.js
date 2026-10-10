import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';

// The site stamps the version in; these run a copy stamped "test"
const source = readFileSync(new URL('../js/ban-to-cart.js', import.meta.url), 'utf8').replace('__BAN_VERSION__', 'test');

// fakeABU stands in for ABU's cart API: it keeps the cart's lines, answers a
// row ABU does not know with 422 and keeps the rows before it, and skips a
// row it has none of, as ABU's store does.
function fakeABU({cart = [], unknown = [], outOfStock = [], readStatus = 200, emptyBody = false} = {}) {
    const lines = [...cart];
    const posts = [];
    const fetch = async (url, opts = {}) => {
        if (!opts.method) {
            return {
                ok: readStatus === 200,
                status: readStatus,
                json: async () => (emptyBody && lines.length === 0 ?
                    {data: {}} :
                    {data: {relationships: {items: {data: lines.map((id) => ({id}))}}}}),
            };
        }
        const rows = JSON.parse(opts.body);
        posts.push({url, rows});
        for (const row of rows) {
            if (unknown.includes(row.item_id)) {
                return {ok: false, status: 422};
            }
            if (!outOfStock.includes(row.item_id) && !lines.includes(row.item_id)) {
                lines.push(row.item_id);
            }
        }
        return {ok: true, status: 200};
    };
    return {fetch, posts, lines};
}

// fakeCSI stands in for CSI's sell cart: the cart page lists a quantity
// field per row, and the sell list's add skips an id CSI does not buy and
// adds to a row already in the cart, as CSI does.
function fakeCSI({cart = {}, unknown = []} = {}) {
    const lines = {...cart};
    const posts = [];
    const fetch = async (url, opts = {}) => {
        if (!opts.method) {
            const fields = Object.entries(lines).map(([id, q]) => `<input name="bl_q[${id}]" value="${q}">`);
            return {ok: true, status: 200, text: async () => '<form>' + fields.join('') + '</form>'};
        }
        const body = new URLSearchParams(opts.body);
        const rows = [...body.get('ajaxdata').matchAll(/uid_(\d+)qty_(\d+)\|\|/g)].map((m) => ({id: m[1], qty: +m[2]}));
        posts.push({url, type: body.get('ajaxtype'), rows});
        for (const row of rows) {
            if (!unknown.includes(row.id)) {
                lines[row.id] = (lines[row.id] || 0) + row.qty;
            }
        }
        return {ok: true, status: 200};
    };
    return {fetch, posts, lines};
}

// run executes the bookmarklet on a stand-in store page.
async function run({host = 'abugames.com', path = '/cartview/buylist', search = '', hash = '', version = 'test', loggedIn = true, abu = fakeABU(), cookie = '', loginLink = false} = {}) {
    const alerts = [];
    const page = {reloaded: false, url: null};
    if (hash && version !== null) {
        hash += '&v=' + version;
    }
    const location = {hostname: host, pathname: path, search, hash, reload: () => { page.reloaded = true; }};
    page.location = location;
    const storage = {isLoggedIn: loggedIn ? 'true' : 'false', 'accessToken-ABU': 'abc'};
    const localStorage = {getItem: (key) => storage[key] ?? null};
    const document = {
        createElement: () => ({style: {}, remove() {}}),
        body: {appendChild() {}},
        cookie,
        querySelector: (selector) => (loginLink && selector === 'a[href$="/login"]' ? {} : null),
    };
    const history = {replaceState: (state, title, url) => { page.url = url; }};
    // A wait the loader asks for passes at once
    const setTimeout = (resolve) => resolve();
    // The page notes whether leaving it would ask first at each request,
    // alert and reload
    const guards = new Set();
    const window = {
        addEventListener: (type, fn) => type === 'beforeunload' && guards.add(fn),
        removeEventListener: (type, fn) => type === 'beforeunload' && guards.delete(fn),
    };
    page.guarded = {fetches: [], alerts: [], reload: null, href: null};
    location.reload = () => { page.reloaded = true; page.guarded.reload = guards.size > 0; };
    let href;
    Object.defineProperty(location, 'href', {
        get: () => href,
        set: (url) => { href = url; page.guarded.href = guards.size > 0; },
    });
    const fetch = (...args) => { page.guarded.fetches.push(guards.size > 0); return abu.fetch(...args); };
    const alert = (text) => { alerts.push(text); page.guarded.alerts.push(guards.size > 0); };
    const script = new Function('location', 'localStorage', 'fetch', 'alert', 'document', 'history', 'setTimeout', 'window', 'return ' + source);
    await script(location, localStorage, fetch, alert, document, history, setTimeout, window);
    return {alerts, page, posts: abu.posts};
}

function list(n, start = 1000) {
    return Array.from({length: n}, (_, i) => `${start + i}:1`).join(',');
}

describe('ban-to-cart bookmarklet on ABU', () => {
    test('off a store it explains how to install itself', async () => {
        const {alerts, posts} = await run({host: 'www.mtgban.com', hash: '#ban=1:1'});
        expect(alerts[0]).toContain('bookmarks bar');
        expect(posts).toHaveLength(0);
    });

    test('a bookmark older than the link is told to update and sends nothing', async () => {
        for (const version of ['0badc0de', null]) {
            const {alerts, posts} = await run({hash: '#ban=1:1', version});
            expect(alerts[0]).toContain('out of date');
            expect(posts).toHaveLength(0);
        }
    });

    test('leaving the page asks first while cards load, and not once it is done', async () => {
        const {page} = await run({hash: '#ban=' + list(3)});
        expect(page.guarded.fetches.length).toBeGreaterThan(0);
        expect(page.guarded.fetches.every(Boolean)).toBe(true);
        expect(page.guarded.alerts).toEqual([false]);
        expect(page.guarded.reload).toBe(false);
    });

    test('a guest is told to log in and nothing is sent', async () => {
        const {alerts, posts} = await run({hash: '#ban=1:1', loggedIn: false});
        expect(alerts[0]).toContain('Log in to ABU first');
        expect(posts).toHaveLength(0);
    });

    test('the buylist loads in chunks of 300 and the page reloads clean', async () => {
        const {alerts, page, posts} = await run({hash: '#ban=' + list(650)});
        expect(posts.map((p) => p.rows.length)).toEqual([300, 300, 50]);
        expect(posts[0].url).toBe('https://api.abugames.com/buy-list-cart/item');
        expect(alerts[0]).toBe('Loaded 650 cards into your ABU cart.');
        expect(page.url).toBe('/cartview/buylist');
        expect(page.reloaded).toBe(true);
    });

    test('the store loads in chunks of 50', async () => {
        const {posts} = await run({path: '/cartview/shop', hash: '#ban=' + list(120)});
        expect(posts.map((p) => p.rows.length)).toEqual([50, 50, 20]);
        expect(posts[0].url).toBe('https://api.abugames.com/cart/item');
    });

    test('repeated ids add up and malformed pairs are dropped', async () => {
        const {posts} = await run({hash: '#ban=11:2,12:1,11:3,x/y:1,13:0,14'});
        expect(posts[0].rows).toEqual([{item_id: '11', quantity: 5}, {item_id: '12', quantity: 1}]);
    });

    test('the page link\'s percent-encoded separators are read', async () => {
        const {posts} = await run({hash: '#ban=101%3a2%2c102%3a1'});
        expect(posts[0].rows).toEqual([{item_id: '101', quantity: 2}, {item_id: '102', quantity: 1}]);
    });

    test('lines past the cap are left out, cards already in the cart are not', async () => {
        const cart = Array.from({length: 749}, (_, i) => String(5000 + i));
        const abu = fakeABU({cart});
        const {alerts, posts} = await run({hash: '#ban=5000:2,1:1,2:1,3:1', abu});
        expect(posts[0].rows.map((r) => r.item_id)).toEqual(['5000', '1']);
        expect(alerts[0]).toContain('2 did not fit');
    });

    test('an id ABU does not know is dropped and the rest resent', async () => {
        const abu = fakeABU({unknown: ['2']});
        const {alerts, posts} = await run({hash: '#ban=1:1,2:1,3:1', abu});
        expect(posts.map((p) => p.rows.map((r) => r.item_id))).toEqual([['1', '2', '3'], ['2'], ['3']]);
        expect(abu.lines).toEqual(['1', '3']);
        expect(alerts[0]).toBe('Loaded 2 cards into your ABU cart. 1 that ABU no longer lists were left out.');
    });

    test('a store row ABU has none of is not taken for the unknown id', async () => {
        const abu = fakeABU({outOfStock: ['1'], unknown: ['3']});
        const {alerts, posts} = await run({path: '/cartview/shop', hash: '#ban=1:1,2:1,3:1,4:1', abu});
        // the whole chunk, then 1 alone (skipped, not refused), then 3 alone
        // (refused), then the rest after it
        expect(posts.map((p) => p.rows.map((r) => r.item_id))).toEqual([['1', '2', '3', '4'], ['1'], ['3'], ['4']]);
        expect(abu.lines).toEqual(['2', '4']);
        expect(alerts[0]).toBe('Loaded 2 cards into your ABU cart. 1 that ABU no longer lists were left out. 1 were not taken by ABU.');
    });

    test('an empty cart with no item list reads as empty', async () => {
        const {alerts, posts} = await run({hash: '#ban=1:1', abu: fakeABU({emptyBody: true})});
        expect(posts).toHaveLength(1);
        expect(alerts[0]).toBe('Loaded 1 cards into your ABU cart.');
    });

    test('an expired login stops before sending', async () => {
        const {alerts, posts, page} = await run({hash: '#ban=1:1', abu: fakeABU({readStatus: 401})});
        expect(alerts[0]).toContain('logged you out');
        expect(posts).toHaveLength(0);
        expect(page.reloaded).toBe(false);
        expect(page.guarded.alerts).toEqual([false]);
    });
});

describe('ban-to-cart bookmarklet on CSI', () => {
    const csiPage = {host: 'www.coolstuffinc.com', path: '/buylist_cart.php'};

    test('rows go to the sell list\'s add in chunks of 100, CSI\'s way', async () => {
        const csi = fakeCSI();
        const {alerts, page, posts} = await run({...csiPage, hash: '#ban=' + list(230), abu: csi});
        expect(posts.map((p) => p.rows.length)).toEqual([100, 100, 30]);
        expect(posts[0].url).toBe('/ajax_buylist.php');
        expect(posts[0].type).toBe('addtocart');
        expect(posts[0].rows[0]).toEqual({id: '1000', qty: 1});
        expect(alerts[0]).toBe('Loaded 230 cards into your CSI cart.');
        expect(page.url).toBe('/buylist_cart.php');
        expect(page.reloaded).toBe(true);
    });

    test('no ABU login is asked for', async () => {
        const {alerts, posts} = await run({...csiPage, hash: '#ban=1:1', loggedIn: false, abu: fakeCSI()});
        expect(posts).toHaveLength(1);
        expect(alerts[0]).toBe('Loaded 1 cards into your CSI cart.');
    });

    test('an id CSI does not buy is reported, the rest load in one pass', async () => {
        const csi = fakeCSI({unknown: ['2']});
        const {alerts, posts} = await run({...csiPage, hash: '#ban=1:1,2:1,3:2', abu: csi});
        expect(posts).toHaveLength(1);
        expect(csi.lines).toEqual({1: 1, 3: 2});
        expect(alerts[0]).toBe('Loaded 2 cards into your CSI cart. 1 were not taken by CSI.');
    });

    test('a card already in the cart is added to', async () => {
        const csi = fakeCSI({cart: {7: 2}});
        await run({...csiPage, hash: '#ban=7:1', abu: csi});
        expect(csi.lines).toEqual({7: 3});
    });
});

// fakeSCG stands in for SCG's CSV import: it answers an upload with the file
// id SCG's review page is keyed by, or 401 to a visitor not logged in.
function fakeSCG({status = 200} = {}) {
    const uploads = [];
    const fetch = async (url, opts = {}) => {
        uploads.push({url, headers: opts.headers, form: opts.body});
        if (status !== 200) {
            return {ok: false, status, json: async () => ({})};
        }
        return {ok: true, status, json: async () => ({fileId: 7151})};
    };
    return {fetch, uploads, posts: uploads};
}

describe('ban-to-cart bookmarklet on SCG', () => {
    const scgPage = {host: 'sellyourcards.starcitygames.com', path: '/mtg/uploads'};

    test('the list goes up as one CSV of SKUs and SCG\'s review opens', async () => {
        const scg = fakeSCG();
        const {alerts, page} = await run({...scgPage, hash: '#ban=SGL-A1%3a2%2cSGL-B1%3a1',
            abu: scg, cookie: 'other=1; XSRF-TOKEN=abc%3D%3D'});
        expect(scg.uploads).toHaveLength(1);
        const up = scg.uploads[0];
        expect(up.url).toBe('/api/CSV2/upload');
        expect(up.headers['X-XSRF-TOKEN']).toBe('abc==');
        expect(up.form.get('fileFormatId')).toBe('1');
        expect(await up.form.get('file').text()).toBe('quantity,productid\n2,SGL-A1\n1,SGL-B1\n');
        expect(page.location.href).toBe('/mtg/uploads/7151');
        expect(page.guarded.href).toBe(false);
        expect(page.guarded.fetches).toEqual([true]);
        expect(alerts).toHaveLength(0);
    });

    test('a visitor not logged in is told to log in', async () => {
        const {alerts, page} = await run({...scgPage, hash: '#ban=SGL-A1:1', abu: fakeSCG({status: 401})});
        expect(alerts[0]).toContain('Log in to SCG first');
        expect(page.location.href).toBeUndefined();
        expect(page.guarded.alerts).toEqual([false]);
    });
});

// fakeMint stands in for Mint's buylist cart: the cart page names a quantity
// picker per row, and the picker's call sets a row's quantity and skips an
// id Mint does not buy, as Mint does.
function fakeMint({cart = {}, unknown = []} = {}) {
    const lines = {...cart};
    const posts = [];
    const fetch = async (url) => {
        if (url === '/buylist-cart') {
            const fields = Object.keys(lines).map((id) => `<select name="multiple_quantity_${id}"></select>`);
            return {ok: true, status: 200, text: async () => fields.join('')};
        }
        const query = new URLSearchParams(url.split('?')[1]);
        const id = query.get('buylist_cart_product_id');
        posts.push({url, action: query.get('action'), id, qty: +query.get('buylist_cart_product_qty')});
        if (!unknown.includes(id)) {
            lines[id] = +query.get('buylist_cart_product_qty');
        }
        return {ok: true, status: 200};
    };
    return {fetch, posts, lines};
}

describe('ban-to-cart bookmarklet on MTG Mint Card', () => {
    const mintPage = {host: 'www.mtgmintcard.com', path: '/buylist-cart'};

    test('each row goes to the cart page\'s quantity call on its own', async () => {
        const mint = fakeMint();
        const {alerts, page, posts} = await run({...mintPage, hash: '#ban=8137:1,20452:2', abu: mint});
        expect(posts.map((p) => [p.action, p.id, p.qty])).toEqual([
            ['update_buy_list_product', '8137', 1],
            ['update_buy_list_product', '20452', 2],
        ]);
        expect(posts[0].url.startsWith('/ajax_index.php?ajax_main_page=ajax_buylist_cart_detail&')).toBe(true);
        expect(alerts[0]).toBe('Loaded 2 cards into your MTG Mint Card cart.');
        expect(page.url).toBe('/buylist-cart');
        expect(page.reloaded).toBe(true);
    });

    test('a card already in the cart takes the list\'s quantity', async () => {
        const mint = fakeMint({cart: {7: 2}});
        await run({...mintPage, hash: '#ban=7:1', abu: mint});
        expect(mint.lines).toEqual({7: 1});
    });

    test('an id Mint does not buy is reported', async () => {
        const mint = fakeMint({unknown: ['2']});
        const {alerts} = await run({...mintPage, hash: '#ban=1:1,2:1,3:1', abu: mint});
        expect(mint.lines).toEqual({1: 1, 3: 1});
        expect(alerts[0]).toBe('Loaded 2 cards into your MTG Mint Card cart. 1 were not taken by MTG Mint Card.');
    });

    test('a guest is told to log in and nothing is sent', async () => {
        const {alerts, posts} = await run({...mintPage, hash: '#ban=1:1', abu: fakeMint(), loginLink: true});
        expect(alerts[0]).toContain('Log in to MTG Mint Card first');
        expect(posts).toHaveLength(0);
    });
});

// Import ids exported from Strike Zone's cart for these plain codes
const szIDs = {
    'USCIDU-637-F-19290-285-OVN-RMS': '637-C-30571-106',
    'USCIDU-637-F-19290-299-ORM-TTK': '637-C-30571-110',
    'USCIDU-637-F-978240-993-XAK-QHC': '637-C-181059-106',
    'USCIDU-637-F-977135-992-VIA-YUS': '637-C-180944-105',
};
const ankh = 'USCIDU-637-F-19290-285-OVN-RMS';
const ankhHP = 'USCIDU-637-F-19290-299-ORM-TTK';
const awbo = 'USCIDU-637-F-978240-993-XAK-QHC';
const elesh = 'USCIDU-637-F-977135-992-VIA-YUS';

const szExportIDs = Object.fromEntries(Object.entries(szIDs).map(([id, code]) => [code, id]));

// fakeSZ stands in for Strike Zone's cart: its rows are B- for a card sold to
// the store and S- for one bought from it, the CSV export lists every row
// (a buylist one named "Sell to us - ...") or answers an empty cart with its
// page, Sell to Us and Add to Cart links add one copy of a card listed, the
// cart form and the CSV import (Buy # or Sell #) set a row's quantity up to
// what Strike Zone wants or has, the import does nothing to a cart with no
// row, and the cart pages answer "too many requests" once the call limit is
// reached.
function fakeSZ({cart = {}, unknown = [], limit = {}, throttleAt = [], exportPage = null} = {}) {
    const lines = {...cart};
    const posts = [];
    let calls = 0;
    const keep = (row, qty) => {
        lines[row] = Math.min(qty, limit[row.slice(2)] ?? Infinity);
    };
    const fetch = async (url, opts = {}) => {
        calls++;
        if (throttleAt.includes(calls)) {
            return {ok: true, status: 200, text: async () => 'Error: 8134 - too many requests'};
        }
        if (opts.body instanceof FormData) {
            const csv = await opts.body.get('FILE').text();
            const rows = csv.trim().split('\r\n').slice(1).map((line) => line.split(','));
            posts.push({url, tool: opts.body.get('TOOL_SELECT'), rows: rows.map((r) => [r[0], r[3], r[5]])});
            if (Object.keys(lines).length > 0) {
                for (const [id, , , buy, , sell] of rows) {
                    const code = szIDs[id];
                    if (code && !unknown.includes(code)) {
                        if (buy !== 'NC') {
                            keep('B-' + code, +buy);
                        }
                        if (sell !== 'NC') {
                            keep('S-' + code, +sell);
                        }
                    }
                }
            }
            return {ok: true, status: 200, text: async () => ''};
        }
        if (opts.body instanceof URLSearchParams && opts.body.get('TOOL_SELECT') === 'XC') {
            if (exportPage !== null) {
                return {ok: true, status: 200, text: async () => exportPage};
            }
            const rows = Object.keys(lines);
            if (rows.length === 0) {
                return {ok: true, status: 200, text: async () => '<html>You have no items in your cart.</html>'};
            }
            const csv = rows.map((row) => {
                const name = (row.startsWith('B-') ? 'Sell to us - ' : '') + 'Magic the Gathering - Card, With Comma';
                return `${szExportIDs[row.slice(2)] ?? row.slice(2)},${name},Strike Zone Online,NC,1.00,${lines[row]},2.00`;
            });
            return {ok: true, status: 200, text: async () => ['#Usc Id,Inventory Name,Store Name,Buy #,Buy $,Sell #,Sell $', ...csv].join('\r\n') + '\r\n'};
        }
        if (opts.method === 'POST') {
            const rows = [];
            for (let i = 0; opts.body.has(String(i)); i++) {
                rows.push({id: opts.body.get(String(i)), qty: +opts.body.get(i + 'Q')});
            }
            posts.push({url, cmd: opts.body.get('CMD'), rows});
            for (const row of rows) {
                if (row.id in lines) {
                    keep(row.id, row.qty);
                }
            }
            return {ok: true, status: 200, text: async () => ''};
        }
        const link = /[?&](Buy|Add)=([\w-]+)/.exec(url);
        if (link) {
            posts.push({url, link: link[1], code: link[2]});
            if (!unknown.includes(link[2])) {
                const row = (link[1] === 'Buy' ? 'B-' : 'S-') + link[2];
                keep(row, (lines[row] || 0) + 1);
            }
            return {ok: true, status: 200, text: async () => ''};
        }
        throw new Error('unexpected call ' + url);
    };
    return {fetch, posts, lines};
}

describe('ban-to-cart bookmarklet on Strike Zone', () => {
    const szPage = {host: 'shop.strikezoneonline.com', path: '/TUser', search: '?MC=CUVC&MF=B&BUID=637'};
    const step = (p) => p.tool ?? p.cmd ?? p.link + ' ' + p.code;

    test('a buylist goes up as one CSV import under Buy #', async () => {
        const sz = fakeSZ({cart: {'B-637-C-30571-110': 1}, limit: {'637-C-181059-106': 4}});
        const {alerts, page, posts} = await run({...szPage,
            hash: `#ban=${ankh}%3a2%2c${awbo}%3a9%2c${elesh}%3a1%2c${ankhHP}%3a3`, abu: sz});
        expect(posts.map(step)).toEqual(['CI']);
        expect(posts[0].rows).toEqual([[ankh, '2', 'NC'], [awbo, '9', 'NC'], [elesh, '1', 'NC'], [ankhHP, '3', 'NC']]);
        expect(sz.lines).toEqual({
            'B-637-C-30571-106': 2, 'B-637-C-181059-106': 4, 'B-637-C-180944-105': 1, 'B-637-C-30571-110': 3,
        });
        expect(alerts[0]).toBe('Loaded 4 cards into your Strike Zone cart.');
        expect(page.url).toBe('/TUser?MC=CUVC&MF=B&BUID=637');
        expect(page.reloaded).toBe(true);
    });

    test('a store list goes up under Sell #, and only store rows count as loaded', async () => {
        const sz = fakeSZ({cart: {'B-637-C-181059-106': 1}, limit: {'637-C-30571-106': 1}});
        const {alerts, posts} = await run({...szPage, hash: `#ban=${ankh}:3,${awbo}:2&side=retail`, abu: sz});
        expect(posts.map(step)).toEqual(['CI']);
        expect(posts[0].rows).toEqual([[ankh, 'NC', '3'], [awbo, 'NC', '2']]);
        expect(sz.lines).toEqual({'B-637-C-181059-106': 1, 'S-637-C-30571-106': 1, 'S-637-C-181059-106': 2});
        expect(alerts[0]).toBe('Loaded 2 cards into your Strike Zone cart.');
    });

    test('an empty cart gets one card through its link before the import', async () => {
        const sz = fakeSZ();
        const {alerts, posts} = await run({...szPage, hash: `#ban=${ankh}:2,${awbo}:1`, abu: sz});
        expect(posts.map(step)).toEqual(['Buy 637-C-30571-106', 'CI']);
        expect(sz.lines).toEqual({'B-637-C-30571-106': 2, 'B-637-C-181059-106': 1});
        expect(alerts[0]).toBe('Loaded 2 cards into your Strike Zone cart.');

        const store = fakeSZ();
        await run({...szPage, hash: `#ban=${ankh}:1&side=retail`, abu: store});
        expect(store.posts.map(step)).toEqual(['Add 637-C-30571-106', 'CI']);
    });

    test('an empty cart is filled from the next card when Strike Zone skips the first', async () => {
        const sz = fakeSZ({unknown: ['637-C-30571-106']});
        const {alerts, posts} = await run({...szPage, hash: `#ban=${ankh}:2,${awbo}:1,${elesh}:1`, abu: sz});
        expect(posts.map(step)).toEqual(['Buy 637-C-30571-106', 'Buy 637-C-181059-106', 'CI']);
        expect(sz.lines).toEqual({'B-637-C-181059-106': 1, 'B-637-C-180944-105': 1});
        expect(alerts[0]).toBe('Loaded 2 cards into your Strike Zone cart. 1 were not taken by Strike Zone.');
    });

    test('no import goes up when Strike Zone takes none of the cards', async () => {
        const sz = fakeSZ({unknown: ['637-C-30571-106', '637-C-181059-106']});
        const {alerts, posts} = await run({...szPage, hash: `#ban=${ankh}:1,${awbo}:1`, abu: sz});
        expect(posts.map(step)).toEqual(['Buy 637-C-30571-106', 'Buy 637-C-181059-106']);
        expect(alerts[0]).toBe('Loaded 0 cards into your Strike Zone cart. 2 were not taken by Strike Zone.');
    });

    test('a plain code goes through its link, quantities through the cart form', async () => {
        const sz = fakeSZ({cart: {'B-637-C-7-106': 2}});
        const {alerts, posts} = await run({...szPage, hash: '#ban=637-C-1-106%3a1%2c637-C-2-105%3a3%2c637-C-7-106%3a1', abu: sz});
        expect(posts.map(step)).toEqual(['Buy 637-C-1-106', 'Buy 637-C-2-105', 'Update']);
        expect(posts[0].url).toBe('/TUser?MC=CUVC&Buy=637-C-1-106&MF=B&BUID=637');
        expect(posts[2].rows).toEqual([{id: 'B-637-C-2-105', qty: 3}, {id: 'B-637-C-7-106', qty: 1}]);
        expect(sz.lines).toEqual({'B-637-C-1-106': 1, 'B-637-C-2-105': 3, 'B-637-C-7-106': 1});
        expect(alerts[0]).toBe('Loaded 3 cards into your Strike Zone cart.');

        const store = fakeSZ();
        await run({...szPage, hash: '#ban=637-C-1-106:2&side=retail', abu: store});
        expect(store.posts.map(step)).toEqual(['Add 637-C-1-106', 'Update']);
        expect(store.lines).toEqual({'S-637-C-1-106': 2});
    });

    test('an id Strike Zone does not list is reported, and quantities stop at what it wants', async () => {
        const sz = fakeSZ({cart: {'B-637-C-30571-110': 1}, unknown: ['637-C-181059-106'], limit: {'637-C-30571-106': 2}});
        const {alerts} = await run({...szPage, hash: `#ban=${ankh}:5,${awbo}:1`, abu: sz});
        expect(sz.lines).toEqual({'B-637-C-30571-110': 1, 'B-637-C-30571-106': 2});
        expect(alerts[0]).toBe('Loaded 1 cards into your Strike Zone cart. 1 were not taken by Strike Zone.');
    });

    test('the cart is read through its export, past the 800 rows its page lists', async () => {
        const cart = {};
        for (let i = 0; i < 900; i++) {
            cart[`B-637-C-${50000 + i}-106`] = 1;
        }
        cart['B-637-C-181059-106'] = 1;
        const sz = fakeSZ({cart});
        const {alerts, posts} = await run({...szPage, hash: `#ban=${awbo}:3,${ankh}:1`, abu: sz});
        expect(posts.map(step)).toEqual(['CI']);
        expect(sz.lines['B-637-C-181059-106']).toBe(3);
        expect(alerts[0]).toBe('Loaded 2 cards into your Strike Zone cart.');
    });

    test('an export that is neither a list nor the empty cart stops the load', async () => {
        const sz = fakeSZ({exportPage: '<html>Something went wrong</html>'});
        const {alerts, posts} = await run({...szPage, hash: `#ban=${ankh}:1`, abu: sz});
        expect(posts).toHaveLength(0);
        expect(alerts[0]).toBe("Strike Zone's cart could not be read.");
    });

    test('only rows on the link\'s side count as loaded', async () => {
        const sz = fakeSZ({cart: {'S-637-C-30571-106': 1}});
        const {alerts} = await run({...szPage, hash: `#ban=${ankh}:1`, abu: sz});
        expect(sz.lines).toEqual({'S-637-C-30571-106': 1, 'B-637-C-30571-106': 1});
        expect(alerts[0]).toBe('Loaded 1 cards into your Strike Zone cart.');
    });

    test('a "too many requests" answer is waited out and the call made again', async () => {
        // the cart read, then the first link is turned away once
        const sz = fakeSZ({throttleAt: [2]});
        const {alerts} = await run({...szPage, hash: '#ban=637-C-1-106:1,637-C-2-106:1', abu: sz});
        expect(sz.lines).toEqual({'B-637-C-1-106': 1, 'B-637-C-2-106': 1});
        expect(alerts[0]).toBe('Loaded 2 cards into your Strike Zone cart.');
    });
});

// fakeHA stands in for Hareruya's two carts: each page names a quantity field
// per row, the store form sets or adds any row up to the stock, and the
// buylist adds one card per call (at most 20, as Hareruya refuses more) and
// its form sets only a row already in the cart. Either skips a class it
// does not sell or buy.
function fakeHA({cart = {}, unknown = [], stock = {}, pageLists = Infinity} = {}) {
    const lines = {...cart};
    const posts = [];
    const keep = (id, qty) => {
        if (qty === 0) {
            delete lines[id];
        } else {
            lines[id] = Math.min(qty, stock[id] ?? Infinity);
        }
    };
    const fetch = async (url, opts = {}) => {
        if (!opts.method) {
            const fields = Object.entries(lines).slice(0, pageLists).map(([id, q]) => `<input type="text" name="qty[${id}]" value="${q}">`);
            return {ok: true, status: 200, text: async () => '<form>' + fields.join('') + '</form>'};
        }
        if (url.endsWith('/add')) {
            const id = opts.body.get('product_class_id');
            const qty = +opts.body.get('quantity');
            posts.push({url, id, qty});
            if (qty > 20) {
                return {ok: false, status: 400};
            }
            if (!unknown.includes(id)) {
                keep(id, (lines[id] || 0) + qty);
            }
            return {ok: true, status: 200};
        }
        const rows = [...opts.body.entries()].map(([k, v]) => [/^qty\[(\d+)\]$/.exec(k)[1], +v]);
        posts.push({url, rows});
        for (const [id, qty] of rows) {
            if (!unknown.includes(id) && (url === '/en/cart/update' || id in lines)) {
                keep(id, qty);
            }
        }
        return {ok: true, status: 200};
    };
    return {fetch, posts, lines};
}

describe('ban-to-cart bookmarklet on Hareruya', () => {
    const store = {host: 'www.hareruyamtg.com', path: '/en/cart'};
    const buy = {host: 'www.hareruyamtg.com', path: '/ja/purchase/cart'};

    test('a store list goes up as one form, setting each quantity up to the stock', async () => {
        const ha = fakeHA({cart: {27947: 3}, unknown: ['999'], stock: {27948: 1}});
        const {alerts, page, posts} = await run({...store, hash: '#ban=27947%3a1%2c27948%3a5%2c436375%3a2%2c999%3a1&side=retail', abu: ha});
        expect(posts).toEqual([{url: '/en/cart/update', rows: [['27947', 1], ['27948', 5], ['436375', 2], ['999', 1]]}]);
        expect(ha.lines).toEqual({27947: 1, 27948: 1, 436375: 2});
        expect(alerts[0]).toBe('Loaded 3 cards into your Hareruya cart. 1 were not taken by Hareruya.');
        expect(page.url).toBe('/en/cart');
        expect(page.reloaded).toBe(true);
    });

    test('a long store list goes up 500 cards to a form', async () => {
        const {posts} = await run({...store, hash: '#ban=' + list(1100) + '&side=retail', abu: fakeHA()});
        expect(posts.map((p) => p.rows.length)).toEqual([500, 500, 100]);
    });

    test('a buylist adds each new card, then sets every quantity', async () => {
        const ha = fakeHA({cart: {356866: 4}});
        const {alerts, posts} = await run({...buy, hash: '#ban=356866%3a1%2c360683%3a2%2c436375%3a1', abu: ha});
        expect(posts).toEqual([
            {url: '/ja/purchase/add', id: '360683', qty: 2},
            {url: '/ja/purchase/add', id: '436375', qty: 1},
            {url: '/ja/purchase/update', rows: [['356866', 1], ['360683', 2], ['436375', 1]]},
        ]);
        expect(ha.lines).toEqual({356866: 1, 360683: 2, 436375: 1});
        expect(alerts[0]).toBe('Loaded 3 cards into your Hareruya cart.');
    });

    test('a buylist card the cart page does not list still ends at the list\'s quantity', async () => {
        // the page lists only its first row, so 360683 looks new and is added
        // on top of the 5 already there
        const ha = fakeHA({cart: {356866: 1, 360683: 5}, pageLists: 1});
        await run({...buy, hash: '#ban=360683:2', abu: ha});
        expect(ha.lines).toEqual({356866: 1, 360683: 2});
    });

    test('a list on the other side\'s cart is refused before anything is sent', async () => {
        for (const [where, hash] of [[buy, '#ban=27947:1&side=retail'], [store, '#ban=356866:1']]) {
            const ha = fakeHA();
            const {alerts, posts} = await run({...where, hash, abu: ha});
            expect(posts).toHaveLength(0);
            expect(alerts[0]).toContain('not the Hareruya cart the list is for');
        }
    });

    test('a buylist quantity stops at the 20 Hareruya takes of one card', async () => {
        const ha = fakeHA({cart: {356866: 1}});
        await run({...buy, hash: '#ban=356866:30,360683:25', abu: ha});
        expect(ha.lines).toEqual({356866: 20, 360683: 20});
    });
});

// fakeCK stands in for Card Kingdom's store cart: an add sets a product and
// style's quantity (0 removes it), answers above the stock with 400 and how
// many there are, and answers a product it does not have with a message.
function fakeCK({cart = {}, unknown = [], stock = {}} = {}) {
    const lines = {...cart};
    const posts = [];
    const fetch = async (url, opts = {}) => {
        if (!opts.method) {
            const lineitems = Object.entries(lines).map(([key, qty]) => {
                const [id, style] = key.split('-');
                return {product_id: +id, style, qty};
            });
            return {ok: true, status: 200, json: async () => ({lineitems})};
        }
        const body = JSON.parse(opts.body);
        const key = body.product_id + '-' + body.style;
        posts.push([key, body.quantity]);
        if (unknown.includes(key)) {
            return {ok: true, status: 200, json: async () => ({exception: 'General Exception'})};
        }
        if (body.quantity > (stock[key] ?? Infinity)) {
            return {ok: false, status: 400, json: async () => ({exception: 'MaxQuantityExceeded', available: stock[key]})};
        }
        if (body.quantity === 0) {
            delete lines[key];
        } else {
            lines[key] = body.quantity;
        }
        return {ok: true, status: 200, json: async () => ({})};
    };
    return {fetch, posts, lines};
}

describe('ban-to-cart bookmarklet on Card Kingdom', () => {
    const ck = {host: 'www.cardkingdom.com', path: '/cart'};

    test('each card goes in by product and style, setting its quantity', async () => {
        const fake = fakeCK({cart: {'10190-EX': 3}});
        const {alerts, page, posts} = await run({...ck, hash: '#ban=10190-NM%3a1%2c10190-EX%3a2&side=retail', abu: fake});
        expect(posts).toEqual([['10190-NM', 1], ['10190-EX', 2]]);
        expect(fake.lines).toEqual({'10190-NM': 1, '10190-EX': 2});
        expect(alerts[0]).toBe('Loaded 2 cards into your Card Kingdom cart.');
        expect(page.url).toBe('/cart');
        expect(page.reloaded).toBe(true);
    });

    test('a card above the stock goes again at what CK has, and none left is reported', async () => {
        const fake = fakeCK({stock: {'10190-VG': 2, '26018-G': 0}, unknown: ['999-NM']});
        const {alerts, posts} = await run({...ck, hash: '#ban=10190-VG:5,26018-G:1,999-NM:1&side=retail', abu: fake});
        expect(posts).toEqual([['10190-VG', 5], ['10190-VG', 2], ['26018-G', 1], ['999-NM', 1]]);
        expect(fake.lines).toEqual({'10190-VG': 2});
        expect(alerts[0]).toBe('Loaded 1 cards into your Card Kingdom cart. 2 were not taken by Card Kingdom.');
    });

    test('a long list goes in one add per card', async () => {
        const fake = fakeCK();
        const {alerts} = await run({...ck, hash: '#ban=' + list(25).replace(/(\d+):/g, '$1-NM:') + '&side=retail', abu: fake});
        expect(fake.posts).toHaveLength(25);
        expect(alerts[0]).toBe('Loaded 25 cards into your Card Kingdom cart.');
    });
});

// fakeCSIShop stands in for CSI's store cart: the cart page names a quantity
// field per row id, a GET deletes a row, and the add takes many
// atc[<product>][<row>] pairs, adding to a row already there up to the
// stock and skipping a row CSI does not sell.
function fakeCSIShop({cart = {}, unknown = [], stock = {}} = {}) {
    const lines = {...cart};
    const posts = [];
    const fetch = async (url, opts = {}) => {
        const del = /action=delete-(\d+)/.exec(url);
        if (del) {
            posts.push({delete: del[1]});
            delete lines[del[1]];
            return {ok: true, status: 200, text: async () => ''};
        }
        if (!opts.method) {
            const fields = Object.entries(lines).map(([row, q]) => `<input type="text" name="cartQty[${row}]" value="${q}">`);
            return {ok: true, status: 200, text: async () => '<form>' + fields.join('') + '</form>'};
        }
        const rows = [...decodeURIComponent(opts.body).matchAll(/atc\[(\d+)\]\[(\d+)\]=(\d+)/g)].map((m) => [m[1], m[2], +m[3]]);
        posts.push({add: rows});
        for (const [, row, q] of rows) {
            if (!unknown.includes(row)) {
                lines[row] = Math.min((lines[row] || 0) + q, stock[row] ?? Infinity);
            }
        }
        return {ok: true, status: 200, json: async () => ({})};
    };
    return {fetch, posts, lines};
}

describe('ban-to-cart bookmarklet on CSI\'s store', () => {
    const shop = {host: 'www.coolstuffinc.com', path: '/main_view_cart.php'};

    test('new rows go up as one add, by product and row id', async () => {
        const fake = fakeCSIShop();
        const {alerts, page, posts} = await run({...shop, hash: '#ban=434190-10753983%3a1%2c434190-10753986%3a2&side=retail', abu: fake});
        expect(posts).toEqual([{add: [['434190', '10753983', 1], ['434190', '10753986', 2]]}]);
        expect(fake.lines).toEqual({10753983: 1, 10753986: 2});
        expect(alerts[0]).toBe('Loaded 2 cards into your CSI cart.');
        expect(page.url).toBe('/main_view_cart.php');
        expect(page.reloaded).toBe(true);
    });

    test('a row already in the cart ends at the list\'s quantity', async () => {
        const fake = fakeCSIShop({cart: {10753983: 1, 10753986: 5}});
        const {posts} = await run({...shop, hash: '#ban=434190-10753983:3,434190-10753986:2&side=retail', abu: fake});
        expect(posts).toEqual([{delete: '10753986'}, {add: [['434190', '10753983', 2], ['434190', '10753986', 2]]}]);
        expect(fake.lines).toEqual({10753983: 3, 10753986: 2});
    });

    test('a quantity stops at the stock, and a row CSI does not sell is reported', async () => {
        const fake = fakeCSIShop({stock: {10753983: 1}, unknown: ['999']});
        const {alerts} = await run({...shop, hash: '#ban=434190-10753983:4,1-999:1&side=retail', abu: fake});
        expect(fake.lines).toEqual({10753983: 1});
        expect(alerts[0]).toBe('Loaded 1 cards into your CSI cart. 1 were not taken by CSI.');
    });

    test('a list on the other side\'s cart is refused before anything is sent', async () => {
        const store = fakeCSIShop();
        const onShop = await run({...shop, hash: '#ban=601:1', abu: store});
        expect(store.posts).toHaveLength(0);
        expect(onShop.alerts[0]).toContain('the list is for its sell cart');

        const sell = fakeCSI();
        const onSell = await run({host: 'www.coolstuffinc.com', path: '/buylist_cart.php', hash: '#ban=434190-10753983:1&side=retail', abu: sell});
        expect(sell.posts).toHaveLength(0);
        expect(onSell.alerts[0]).toContain('the list is for its store');
    });
});
