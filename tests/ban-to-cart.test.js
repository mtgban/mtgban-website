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
async function run({host = 'abugames.com', path = '/cartview/buylist', hash = '', version = 'test', loggedIn = true, abu = fakeABU(), cookie = '', loginLink = false} = {}) {
    const alerts = [];
    const page = {reloaded: false, url: null};
    if (hash && version !== null) {
        hash += '&v=' + version;
    }
    const location = {hostname: host, pathname: path, hash, reload: () => { page.reloaded = true; }};
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
    const script = new Function('location', 'localStorage', 'fetch', 'alert', 'document', 'history', 'return ' + source);
    await script(location, localStorage, abu.fetch, (text) => alerts.push(text), document, history);
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
        expect(alerts).toHaveLength(0);
    });

    test('a visitor not logged in is told to log in', async () => {
        const {alerts, page} = await run({...scgPage, hash: '#ban=SGL-A1:1', abu: fakeSCG({status: 401})});
        expect(alerts[0]).toContain('Log in to SCG first');
        expect(page.location.href).toBeUndefined();
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
