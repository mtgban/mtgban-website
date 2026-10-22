import { test, expect, describe } from 'bun:test';
import { readFileSync } from 'fs';

// The site strips the loader as stripLoader in cartload.go does, and stamps
// the version in; these run a copy stripped the same way and stamped "test"
const source = readFileSync(new URL('../js/ban-to-cart.js', import.meta.url), 'utf8')
    .split('\n').map((line) => line.trim()).filter((line) => line && !line.startsWith('//')).join('\n')
    .replace('__BAN_VERSION__', 'test');

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

// fakeLocks stands in for navigator.locks, the one set a store origin's tabs
// share: a request waits for the last holder of its name to let go.
function fakeLocks() {
    const tails = {};
    const names = [];
    const request = (name, fn) => {
        names.push(name);
        const turn = (tails[name] || Promise.resolve()).then(() => fn());
        tails[name] = turn.catch(() => {});
        return turn;
    };
    return {request, names};
}

// run executes the bookmarklet on a stand-in store page.
async function run({host = 'abugames.com', path = '/cartview/buylist', search = '', hash = '', version = 'test', loggedIn = true, abu = fakeABU(), cookie = '', loginLink = false, locks = null, stored = {}, nodes = []} = {}) {
    const alerts = [];
    const page = {reloaded: false, url: null};
    if (hash && version !== null) {
        hash += '&v=' + version;
    }
    const location = {hostname: host, pathname: path, search, hash, reload: () => { page.reloaded = true; }};
    page.location = location;
    const storage = {isLoggedIn: loggedIn ? 'true' : 'false', 'accessToken-ABU': 'abc', ...stored};
    const localStorage = {getItem: (key) => storage[key] ?? null, setItem: (key, value) => { storage[key] = String(value); }};
    page.storage = storage;
    // A store whose page changes it mid-load gets to reach it
    if (abu.attach) {
        abu.attach(page);
    }
    // The banner keeps every text it shows
    const banner = {style: {}, remove() {}, texts: []};
    Object.defineProperty(banner, 'textContent', {get: () => banner.texts[banner.texts.length - 1], set: (text) => banner.texts.push(text)});
    page.banner = banner;
    const document = {
        createElement: () => banner,
        body: {appendChild() {}},
        cookie,
        querySelector: (selector) => (loginLink && selector === 'a[href$="/login"]' ? {} : null),
        querySelectorAll: () => nodes,
    };
    const history = {replaceState: (state, title, url) => { page.url = url; }};
    // A wait the loader asks for passes at once
    const setTimeout = (resolve) => resolve();
    // The page notes whether leaving it would ask first at each request,
    // alert and reload
    const guards = new Set();
    const window = {
        navigator: locks ? {locks} : {},
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

    test('on a store page with no list it sends the user back to BAN', async () => {
        const {alerts, posts} = await run({hash: ''});
        expect(alerts[0]).toBe('This page has no list from BAN. Log in to ABU if you aren\'t, ' +
            'then go back to BAN and press Load at ABU again.');
        expect(posts).toHaveLength(0);
    });

    test('a bookmark from another version than the link is told to update and sends nothing', async () => {
        for (const version of ['0badc0de', null]) {
            const {alerts, posts} = await run({hash: '#ban=1:1', version});
            expect(alerts[0]).toContain('bookmark or this BAN page is from a different version. Reload BAN');
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

    test('a list that does not decode is reported and nothing is sent', async () => {
        const {alerts, posts} = await run({hash: '#ban=1:1%2'});
        expect(alerts[0]).toBe('The list from BAN could not be read: go back to BAN and press Load at ABU again.');
        expect(posts).toHaveLength(0);
    });

    test('rows BAN found no item for are counted in the report', async () => {
        const {alerts} = await run({hash: '#ban=1:1&skip=2'});
        expect(alerts[0]).toBe('Loaded 1 cards into your ABU cart. 2 on BAN have no ABU item and were left out.');
    });

    test('a pair that does not read is left out and counted', async () => {
        const abu = fakeABU();
        const {alerts} = await run({hash: '#ban=1:1,a.b:2,3:0,4:x,5:2', abu});
        expect(abu.lines).toEqual(['1', '5']);
        expect(alerts[0]).toBe('Loaded 2 cards into your ABU cart. 3 in the list from BAN could not be read and were left out.');
    });

    test('a guest is told to log in and nothing is sent', async () => {
        const {alerts, posts} = await run({hash: '#ban=1:1', loggedIn: false});
        expect(alerts[0]).toBe('Log in to ABU first, then go back to BAN and press Load at ABU again.');
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
        expect(alerts[0]).toBe('ABU logged you out. Log in again, then go back to BAN and press Load at ABU again.');
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

    test('a card already in the cart gets only what it lacks', async () => {
        const csi = fakeCSI({cart: {7: 2, 8: 3}});
        const {posts} = await run({...csiPage, hash: '#ban=7:5,8:1,9:1', abu: csi});
        expect(posts[0].rows).toEqual([{id: '7', qty: 3}, {id: '9', qty: 1}]);
        expect(csi.lines).toEqual({7: 5, 8: 3, 9: 1});
    });

    test('loading the same list twice does not double it', async () => {
        const csi = fakeCSI();
        await run({...csiPage, hash: '#ban=1:2,2:1', abu: csi});
        const {alerts, posts} = await run({...csiPage, hash: '#ban=1:2,2:1', abu: csi});
        expect(csi.lines).toEqual({1: 2, 2: 1});
        expect(posts).toHaveLength(1);
        expect(alerts[0]).toBe('Loaded 2 cards into your CSI cart.');
    });

    test('two tabs loading the same list at once take turns and do not double it', async () => {
        const csi = fakeCSI();
        const locks = fakeLocks();
        const tabs = await Promise.all([1, 2].map(() => run({...csiPage, hash: '#ban=1:2,2:1', abu: csi, locks})));
        expect(locks.names).toEqual(['ban-to-cart-csi', 'ban-to-cart-csi']);
        expect(csi.lines).toEqual({1: 2, 2: 1});
        expect(csi.posts).toHaveLength(1);
        expect(tabs.map((tab) => tab.alerts[0])).toEqual(['Loaded 2 cards into your CSI cart.', 'Loaded 2 cards into your CSI cart.']);
    });

    test('a failed load lets the next tab go', async () => {
        const locks = fakeLocks();
        const failing = {fetch: async () => ({ok: false, status: 500}), posts: []};
        const failed = await run({...csiPage, hash: '#ban=1:1', abu: failing, locks});
        expect(failed.alerts[0]).toBe('CSI could not read your sell cart (500).');
        const csi = fakeCSI();
        const {alerts} = await run({...csiPage, hash: '#ban=1:1', abu: csi, locks});
        expect(csi.lines).toEqual({1: 1});
        expect(alerts[0]).toBe('Loaded 1 cards into your CSI cart.');
    });

    test('a lock request the browser refuses loads unlocked', async () => {
        const locks = {request: async () => { throw new DOMException('denied', 'SecurityError'); }};
        const csi = fakeCSI();
        const {alerts} = await run({...csiPage, hash: '#ban=1:1', abu: csi, locks});
        expect(csi.lines).toEqual({1: 1});
        expect(alerts[0]).toBe('Loaded 1 cards into your CSI cart.');
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

    test('rows left out before SCG saw the list are told before its review opens', async () => {
        const scg = fakeSCG();
        const {alerts, page} = await run({...scgPage, hash: '#ban=SGL-A1:2,a.b:1&skip=1', abu: scg});
        expect(await scg.uploads[0].form.get('file').text()).toBe('quantity,productid\n2,SGL-A1\n');
        expect(alerts).toEqual(['Handed 1 cards to SCG for review. 1 in the list from BAN could not be read and were left out. ' +
            '1 on BAN have no SCG item and were left out.']);
        expect(page.guarded.alerts).toEqual([false]);
        expect(page.location.href).toBe('/mtg/uploads/7151');
    });

    test('a visitor not logged in is told to log in', async () => {
        const {alerts, page} = await run({...scgPage, hash: '#ban=SGL-A1:1', abu: fakeSCG({status: 401})});
        expect(alerts[0]).toBe('Log in to SCG first, then go back to BAN and press Load at SCG again.');
        expect(page.location.href).toBeUndefined();
        expect(page.guarded.alerts).toEqual([false]);
    });
});

// fakeMint stands in for Mint's buylist and store carts: each cart page
// names a quantity picker per row, and the picker's call sets a row's
// quantity and skips an id Mint does not take, as Mint does. reads lists
// the cart pages fetched.
function fakeMint({cart = {}, unknown = []} = {}) {
    const lines = {...cart};
    const posts = [];
    const reads = [];
    const fetch = async (url) => {
        if (url === '/buylist-cart' || url === '/shopping-cart') {
            reads.push(url);
            const fields = Object.keys(lines).map((id) => `<select name="multiple_quantity_${id}"></select>`);
            return {ok: true, status: 200, text: async () => fields.join('')};
        }
        const query = new URLSearchParams(url.split('?')[1]);
        const field = query.has('buylist_cart_product_id') ? 'buylist_cart_product_' : 'shopping_cart_product_';
        const id = query.get(field + 'id');
        posts.push({url, page: query.get('ajax_main_page'), action: query.get('action'), id, qty: +query.get(field + 'qty')});
        if (!unknown.includes(id)) {
            lines[id] = +query.get(field + 'qty');
        }
        return {ok: true, status: 200};
    };
    return {fetch, posts, lines, reads};
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
        expect(mint.reads).toEqual(['/buylist-cart', '/buylist-cart']);
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

    test('a store list goes to the store cart page\'s quantity call', async () => {
        const mint = fakeMint({cart: {304456: 3}, unknown: ['999']});
        const {alerts, page, posts} = await run({host: 'www.mtgmintcard.com', path: '/shopping-cart', hash: '#ban=304456%3a1%2c790305%3a2%2c999%3a1&side=retail', abu: mint});
        expect(posts.map((p) => [p.page, p.action, p.id, p.qty])).toEqual([
            ['ajax_shopping_cart', 'update_product', '304456', 1],
            ['ajax_shopping_cart', 'update_product', '790305', 2],
            ['ajax_shopping_cart', 'update_product', '999', 1],
        ]);
        expect(mint.lines).toEqual({304456: 1, 790305: 2});
        expect(alerts[0]).toBe('Loaded 2 cards into your MTG Mint Card cart. 1 were not taken by MTG Mint Card.');
        expect(page.url).toBe('/shopping-cart');
        expect(mint.reads).toEqual(['/shopping-cart', '/shopping-cart']);
    });

    test('a list on the other side\'s cart page is refused and nothing is sent', async () => {
        for (const [path, hash] of [['/buylist-cart', '#ban=8137:1&side=retail'], ['/shopping-cart', '#ban=8137:1']]) {
            const mint = fakeMint();
            const {alerts} = await run({host: 'www.mtgmintcard.com', path, hash, abu: mint});
            expect(alerts[0]).toBe('This is not the MTG Mint Card cart the list is for. Go back to BAN and press its button again.');
            expect(mint.posts).toHaveLength(0);
        }
    });
});

// fakeMP stands in for Mana Pool's optimizer: it fills each product line
// from the listings stock holds, cheapest first, or refuses the whole call
// with a 409 naming every line it cannot fill and what it has, as Mana Pool
// does. A fill streams as one solution per line, a worse one first where
// streamed is set, split over chunks as Mana Pool's stream arrives.
function fakeMP({stock = {}, meanwhile = null, streamed = false, extra = ''} = {}) {
    const posts = [];
    let page;
    const fetch = async (url, opts = {}) => {
        const body = JSON.parse(opts.body);
        posts.push({url, body});
        if (meanwhile) {
            meanwhile(page.storage, posts.length);
        }
        const details = [];
        const cart = [];
        body.cart.forEach((line, index) => {
            const listings = stock[line.product_ids[0]] || [];
            const have = listings.reduce((n, l) => n + l.qty, 0);
            if (have < line.quantity_requested) {
                details.push({item: {...line, index}, total_available: have, reason: have ? 'insufficient_quantity' : 'no_candidates'});
                return;
            }
            let want = line.quantity_requested;
            for (const listing of listings) {
                const take = Math.min(want, listing.qty);
                if (take > 0) {
                    cart.push({inventory_id: listing.id, quantity_selected: take});
                    want -= take;
                }
            }
        });
        if (details.length > 0) {
            return {ok: false, status: 409, text: async () => JSON.stringify({status: 409, message: 'Could not find inventory to satisfy request', details})};
        }
        const best = JSON.stringify({cart, totals: {total_cents: 1500}}) + '\n';
        if (!streamed) {
            return {ok: true, status: 200, text: async () => best};
        }
        const worse = JSON.stringify({cart: [], totals: {total_cents: 2000}}) + '\n';
        const bytes = new TextEncoder().encode(worse + extra + best);
        // The middle cut falls inside the last é's two bytes, if there is
        // one, for the next chunk to complete
        const e = bytes.lastIndexOf(0xc3);
        const cuts = [10, e > worse.length ? e + 1 : worse.length + 5, bytes.length];
        const parts = cuts.map((end, i) => bytes.slice(i ? cuts[i - 1] : 0, end));
        return {ok: true, status: 200, body: {getReader: () => ({read: async () => (parts.length ? {done: false, value: parts.shift()} : {done: true})})}};
    };
    return {fetch, posts, attach: (p) => { page = p; }};
}

describe('ban-to-cart bookmarklet on Mana Pool', () => {
    const cartPage = {host: 'manapool.com', path: '/cart'};
    const cart = (entries, changes = []) => JSON.stringify({version: 5, revision: '00000000-0000-4000-8000-000000000000', cart: {entries}, changes});

    test('the optimizer\'s listings go into the cart the way Mana Pool adds them', async () => {
        const mp = fakeMP({stock: {'p-1': [{id: 'inv-a', qty: 1}, {id: 'inv-b', qty: 5}], 'p-2': [{id: 'inv-c', qty: 9}]}});
        const held = cart([{inventoryId: 'inv-c', quantitySelected: 1, source: 'browse', optimizerTouched: false}]);
        const {alerts, page, posts} = await run({...cartPage, hash: '#ban=p-1%3a3%2cp-2%3a2&side=retail', abu: mp, stored: {'manapool-cart': held}});
        expect(posts).toHaveLength(1);
        expect(posts[0].url).toBe('/api/v1/buyer/optimizer');
        expect(posts[0].body.cart).toEqual([
            {type: 'product', product_type: 'mtg_single', product_ids: ['p-1'], quantity_requested: 3},
            {type: 'product', product_type: 'mtg_single', product_ids: ['p-2'], quantity_requested: 2},
        ]);
        const stored = JSON.parse(page.storage['manapool-cart']);
        expect(stored.cart.entries).toEqual([
            {inventoryId: 'inv-c', quantitySelected: 3, source: 'browse', optimizerTouched: false},
            {inventoryId: 'inv-a', quantitySelected: 1, source: 'optimizer', optimizerTouched: true},
            {inventoryId: 'inv-b', quantitySelected: 2, source: 'optimizer', optimizerTouched: true},
        ]);
        expect(stored.changes).toEqual([['inv-a', 1, 'optimizer', true], ['inv-b', 2, 'optimizer', true], ['inv-c', 2, 'optimizer', true]]);
        expect(alerts).toEqual(['Added 2 cards to your Mana Pool cart, on top of what it held.']);
        expect(page.url).toBe('/cart');
        expect(page.reloaded).toBe(true);
        expect(page.guarded.reload).toBe(false);
    });

    test('a card Mana Pool has fewer of goes at what it has, and one it has none of is left out', async () => {
        const mp = fakeMP({stock: {'p-1': [{id: 'inv-a', qty: 2}], 'p-2': [{id: 'inv-c', qty: 9}]}});
        const {alerts, page, posts} = await run({...cartPage, hash: '#ban=p-1:999,p-2:1,p-9:1&side=retail&skip=1', abu: mp});
        expect(posts.map((p) => p.body.cart.map((l) => [l.product_ids[0], l.quantity_requested]))).toEqual([
            [['p-1', 999], ['p-2', 1], ['p-9', 1]],
            [['p-1', 2], ['p-2', 1]],
        ]);
        expect(JSON.parse(page.storage['manapool-cart']).cart.entries.map((e) => [e.inventoryId, e.quantitySelected])).toEqual([['inv-a', 2], ['inv-c', 1]]);
        expect(alerts).toEqual(['Added 2 cards to your Mana Pool cart, on top of what it held. 1 were cut to the copies Mana Pool has. ' +
            '1 that Mana Pool has none of were left out. 1 on BAN have no Mana Pool item and were left out.']);
    });

    test('a streamed answer is read to its last solution, shown as it comes', async () => {
        const mp = fakeMP({streamed: true, stock: {'p-1': [{id: 'inv-a', qty: 3}]}});
        const {alerts, page} = await run({...cartPage, hash: '#ban=p-1:2&side=retail', abu: mp});
        expect(JSON.parse(page.storage['manapool-cart']).cart.entries.map((e) => [e.inventoryId, e.quantitySelected])).toEqual([['inv-a', 2]]);
        expect(page.banner.texts).toContain('BAN: Mana Pool is finding the cheapest listings for 1 cards, best so far $20.00. Keep this tab open until it finishes.');
        expect(page.banner.texts).toContain('BAN: Mana Pool is finding the cheapest listings for 1 cards, best so far $15.00. Keep this tab open until it finishes.');
        expect(alerts).toEqual(['Added 1 cards to your Mana Pool cart, on top of what it held.']);
    });

    test('a character split between chunks, and a line that is no solution, do not lose the answer', async () => {
        const mp = fakeMP({streamed: true, extra: 'null\n', stock: {'p-1': [{id: 'inv-é', qty: 3}]}});
        const {alerts, page} = await run({...cartPage, hash: '#ban=p-1:1&side=retail', abu: mp});
        expect(JSON.parse(page.storage['manapool-cart']).cart.entries.map((e) => e.inventoryId)).toEqual(['inv-é']);
        expect(alerts).toEqual(['Added 1 cards to your Mana Pool cart, on top of what it held.']);
    });

    test('a card cut by one refusal and cut again or dropped by the next counts once, by how it ends', async () => {
        const stock = {'p-1': [{id: 'inv-a', qty: 2}], 'p-2': [{id: 'inv-b', qty: 3}], 'p-3': [{id: 'inv-c', qty: 1}]};
        // Between the first call and the second, p-1 sells out and p-2 sells one
        const mp = fakeMP({
            stock,
            meanwhile: (storage, call) => {
                if (call === 2) {
                    stock['p-1'] = [];
                    stock['p-2'] = [{id: 'inv-b', qty: 2}];
                }
            },
        });
        const {alerts, page, posts} = await run({...cartPage, hash: '#ban=p-1:5,p-2:5,p-3:1&side=retail', abu: mp});
        expect(posts.map((p) => p.body.cart.map((l) => [l.product_ids[0], l.quantity_requested]))).toEqual([
            [['p-1', 5], ['p-2', 5], ['p-3', 1]],
            [['p-1', 2], ['p-2', 3], ['p-3', 1]],
            [['p-2', 2], ['p-3', 1]],
        ]);
        expect(JSON.parse(page.storage['manapool-cart']).cart.entries.map((e) => [e.inventoryId, e.quantitySelected])).toEqual([['inv-b', 2], ['inv-c', 1]]);
        // The banner counts each line once while it works, as the report does
        expect(page.banner.texts).toContain('BAN: asking Mana Pool for 3 cards, 2 cut or left out so far. Keep this tab open until it finishes.');
        expect(alerts).toEqual(['Added 2 cards to your Mana Pool cart, on top of what it held. 1 were cut to the copies Mana Pool has. ' +
            '1 that Mana Pool has none of were left out.']);
    });

    test('a change made to the cart while the optimizer answers is kept', async () => {
        const mp = fakeMP({
            stock: {'p-1': [{id: 'inv-a', qty: 2}]},
            meanwhile: (storage) => {
                storage['manapool-cart'] = cart([{inventoryId: 'inv-z', quantitySelected: 1, source: 'browse', optimizerTouched: false}]);
            },
        });
        const {page} = await run({...cartPage, hash: '#ban=p-1:1&side=retail', abu: mp});
        expect(JSON.parse(page.storage['manapool-cart']).cart.entries.map((e) => e.inventoryId)).toEqual(['inv-z', 'inv-a']);
    });

    test('a cart kept in a way the loader does not know is left alone', async () => {
        const mp = fakeMP({stock: {'p-1': [{id: 'inv-a', qty: 2}]}});
        const held = JSON.stringify({version: 6, cart: {lines: []}});
        const {alerts, page, posts} = await run({...cartPage, hash: '#ban=p-1:1&side=retail', abu: mp, stored: {'manapool-cart': held}});
        expect(alerts[0]).toContain('Nothing was loaded');
        expect(posts).toHaveLength(0);
        expect(page.storage['manapool-cart']).toBe(held);
    });
});

// fakeStorePass stands in for a StorePass buylist page: its cart component,
// reached through React's fiber on a node of the page, adds to a line or
// makes one as the page's own add does, holding a card to the store's
// limit; the session answers by session_id with what was last saved, and a
// search by product id.
function fakeStorePass({conditionType = 'global', products = [], saved = [], limit = 8} = {}) {
    let session = saved;
    const posts = [];
    const reads = [];
    const component = {
        state: {store: {id: 'OvpVz0pNlL', buylist_settings: {condition_type: conditionType}}, cartProducts: [], posSessionId: null},
        setState(change, done) {
            Object.assign(this.state, change);
            if (done) {
                done();
            }
        },
        didAddToCart(product, qty, condition) {
            const lines = this.state.cartProducts;
            const line = lines.find((l) => l.product_id == product.product_id && l.condition === condition);
            if (line) {
                line.quantity = Math.min(line.quantity + qty, limit);
                this.state.cartProducts = lines.filter((l) => l.quantity > 0);
            } else if (qty > 0) {
                lines.unshift({...product, quantity: Math.min(qty, limit), condition});
            }
        },
    };
    const node = {'__reactFiber$abc': {stateNode: null, return: {stateNode: component}}};
    const fetch = async (url, opts = {}) => {
        if (opts.method === 'POST') {
            posts.push({url, body: JSON.parse(opts.body)});
            session = JSON.parse(opts.body).cartProducts;
            return {ok: true, status: 200, json: async () => ({success: true})};
        }
        reads.push(url);
        if (url.startsWith('/saas/buylist-session?')) {
            return {ok: true, status: 200, json: async () => ({cartProducts: url.includes('session_id=sid%201') ? JSON.parse(JSON.stringify(session)) : []})};
        }
        const id = /product_id=(\d+)/.exec(url)[1];
        return {ok: true, status: 200, json: async () => ({products: products.filter((p) => String(p.product_id) === id)})};
    };
    return {fetch, posts, reads, component, nodes: [node]};
}

describe('ban-to-cart bookmarklet on a StorePass buylist', () => {
    const gnPage = {host: 'buylist.gamenerdz.com', path: '/retailer/buylist', cookie: 'bga-buylist-cart-OvpVz0pNlL=sid%201'};
    const vsPage = {host: 'buylist.vegas.singles', path: '/retailer/buylist', cookie: 'bga-buylist-cart-d4lDsS3ZNf=sid%201'};
    const sphinx = {product_id: 152060, condition: 'New', offer_price: 16.04, store_pass_variant_info: [{id: 151169, title: 'Default Title'}]};
    const consultation = {product_id: 99, condition: 'New', store_pass_variant_info: [{id: 1, title: 'Near Mint'}, {id: 2, title: 'Lightly Played'}]};

    test('each card goes through the page\'s own add, a held one by the difference, and the cart is saved as the page saves it', async () => {
        const sp = fakeStorePass({products: [sphinx], saved: [{...sphinx, quantity: 1, condition: 'New'}]});
        const {alerts, page} = await run({...gnPage, hash: '#ban=152060-151169%3a3%2c777-1%3a1', abu: sp, nodes: sp.nodes});
        expect(sp.reads[0]).toBe('/saas/buylist-session?session_id=sid%201&store_id=OvpVz0pNlL');
        expect(sp.component.state.cartProducts.map((l) => [l.product_id, l.quantity, l.condition])).toEqual([[152060, 3, 'New']]);
        expect(sp.posts).toHaveLength(1);
        expect(sp.posts[0].url).toBe('/saas/buylist-session?store_id=OvpVz0pNlL');
        expect(sp.posts[0].body.sessionId).toBe('sid 1');
        expect(sp.posts[0].body.cartProducts.map((l) => l.quantity)).toEqual([3]);
        expect(alerts[0]).toBe('Loaded 1 cards into your Game Nerdz cart. 1 were not taken by Game Nerdz.');
        expect(page.reloaded).toBe(true);
    });

    test('a store pricing each condition takes the variant\'s own, and a held line goes down to the list\'s', async () => {
        const sp = fakeStorePass({conditionType: 'per-product', products: [consultation], saved: [{...consultation, quantity: 4, condition: 'Lightly Played'}]});
        await run({...vsPage, hash: '#ban=99-1:2,99-2:1', abu: sp, nodes: sp.nodes});
        expect(sp.component.state.cartProducts.map((l) => [l.quantity, l.condition])).toEqual([[2, 'Near Mint'], [1, 'Lightly Played']]);
    });

    test('a store list on the buylist is refused, and a page whose cart BAN cannot find loads nothing', async () => {
        const sp = fakeStorePass({products: [sphinx]});
        const wrong = await run({...gnPage, hash: '#ban=152060-151169:1&side=retail', abu: sp, nodes: sp.nodes});
        expect(wrong.alerts[0]).toBe('This is Game Nerdz\'s buylist, but the list is for its store. Go back to BAN and press its button again.');
        const changed = await run({...gnPage, hash: '#ban=152060-151169:1', abu: sp, nodes: []});
        expect(changed.alerts[0]).toBe('Game Nerdz\'s buylist page has changed, so BAN cannot fill its cart. Nothing was loaded.');
        expect(sp.posts).toHaveLength(0);
    });

    test('two tabs on one store take turns', async () => {
        const sp = fakeStorePass({products: [sphinx]});
        const locks = fakeLocks();
        await Promise.all([1, 2].map(() => run({...gnPage, hash: '#ban=152060-151169:1', abu: sp, nodes: sp.nodes, locks})));
        expect(locks.names).toEqual(['ban-to-cart-OvpVz0pNlL', 'ban-to-cart-OvpVz0pNlL']);
    });
});

// fakeGNShop stands in for Game Nerdz's BigCommerce store: the cart link
// adds a SKU, refusing the whole add above the stock with the product's
// page, which says what is available; the storefront API reads the cart
// and sets a line.
function fakeGNShop({stock = {}, cart = {}} = {}) {
    const lines = {...cart};
    const calls = [];
    const fetch = async (url, opts = {}) => {
        calls.push([opts.method || 'GET', url, opts.body ? JSON.parse(opts.body) : null]);
        if (url.startsWith('/api/storefront/carts/')) {
            const sku = Object.keys(lines).find((k) => url.endsWith('/items/line-' + k));
            lines[sku] = JSON.parse(opts.body).lineItem.quantity;
            return {ok: true, status: 200, json: async () => ({})};
        }
        if (url.startsWith('/api/storefront/carts')) {
            const items = Object.entries(lines).map(([sku, quantity]) => ({id: 'line-' + sku, sku, quantity, productId: 7}));
            return {ok: true, status: 200, json: async () => (items.length ? [{id: 'cart-1', lineItems: {physicalItems: items}}] : [])};
        }
        const query = new URLSearchParams(url.split('?')[1]);
        const sku = query.get('sku');
        const qty = Number(query.get('qty'));
        if (!(sku in stock)) {
            return {ok: true, status: 200, text: async () => '<html>cart</html>'};
        }
        if (qty > stock[sku]) {
            return {ok: true, status: 200, text: async () => '{"instock":true,"available_to_sell":' + stock[sku] + ',"available_on_hand":' + stock[sku] + '}'};
        }
        lines[sku] = (lines[sku] || 0) + qty;
        return {ok: true, status: 200, text: async () => '<html>cart</html>'};
    };
    return {fetch, calls, lines};
}

describe('ban-to-cart bookmarklet on Game Nerdz\'s store', () => {
    const shop = {host: 'www.gamenerdz.com', path: '/cart.php'};

    test('a SKU is added, again at what the store has when it refuses, and a held one is set', async () => {
        const gn = fakeGNShop({stock: {'MTG-A-1': 2, 'MTG-B-2': 9, 'MTG-C-3': 5}, cart: {'MTG-C-3': 4}});
        const {alerts} = await run({...shop, hash: '#ban=MTG-A-1%3a3%2cMTG-B-2%3a1%2cMTG-C-3%3a1%2cMTG-X-9%3a1&side=retail', abu: gn});
        expect(gn.lines).toEqual({'MTG-A-1': 2, 'MTG-B-2': 1, 'MTG-C-3': 1});
        expect(gn.calls.filter(([, url]) => url.startsWith('/cart.php')).map(([, url]) => url)).toEqual([
            '/cart.php?action=add&sku=MTG-A-1&qty=3', '/cart.php?action=add&sku=MTG-A-1&qty=2',
            '/cart.php?action=add&sku=MTG-B-2&qty=1', '/cart.php?action=add&sku=MTG-X-9&qty=1',
        ]);
        expect(gn.calls.find(([method]) => method === 'PUT')).toEqual(['PUT', '/api/storefront/carts/cart-1/items/line-MTG-C-3', {lineItem: {productId: 7, quantity: 1}}]);
        expect(alerts[0]).toBe('Loaded 3 cards into your Game Nerdz cart. 1 were not taken by Game Nerdz.');
    });

    test('a change the store refuses stops the load instead of reporting it loaded', async () => {
        const gn = fakeGNShop({stock: {'MTG-C-3': 5}, cart: {'MTG-C-3': 4}});
        const fetch = gn.fetch;
        gn.fetch = async (url, opts = {}) => (opts.method === 'PUT' ? {ok: false, status: 422} : fetch(url, opts));
        const {alerts, page} = await run({...shop, hash: '#ban=MTG-C-3:1&side=retail', abu: gn});
        expect(alerts).toEqual(['Game Nerdz refused the list (422).']);
        expect(page.reloaded).toBe(false);
    });

    test('a buylist list on the store is refused and nothing is sent', async () => {
        const gn = fakeGNShop({stock: {'MTG-A-1': 2}});
        const {alerts} = await run({...shop, hash: '#ban=MTG-A-1:1', abu: gn});
        expect(alerts[0]).toBe('This is Game Nerdz\'s store, but the list is for its buylist. Go back to BAN and press its button again.');
        expect(gn.calls).toHaveLength(0);
    });
});

// fakeCT stands in for Card Trader: one card's listings answer filtered by
// the property, condition and Zero filters it is sent, as Card Trader's own
// filters do, the 1-Day Ready groups apart, and the add fills the quantity
// from the listings it is given, up to their copies, as Card Trader does.
function fakeCT({listings = [], groups = [], blueprint = '16310', limit = 100} = {}) {
    const posts = [];
    const fetch = async (url, opts = {}) => {
        if (url.includes('/filter.json')) {
            const body = new URLSearchParams(opts.body);
            posts.push({url, body: [...body]});
            if (!url.includes('/cards/' + blueprint + '/')) {
                return {ok: true, status: 200, json: async () => ({products: [], odr_product_groups: []})};
            }
            // A key's keyword terms admit any of their values; a term, its one
            const terms = {};
            const flags = [];
            for (const [k, v] of body) {
                const keyword = /^q\[terms\]\[properties_hash\.(\w+)\.keyword\]/.exec(k);
                const flag = /^q\[term\]\[properties_hash\.(\w+)\]$/.exec(k);
                if (keyword) {
                    (terms[keyword[1]] = terms[keyword[1]] || []).push(v);
                } else if (flag) {
                    flags.push([flag[1], v === 'true']);
                }
            }
            const hub = body.get('q[term][user.can_sell_via_hub]');
            const fits = (p) => Object.entries(terms).every(([k, vs]) => vs.includes(p.properties_hash[k])) &&
                flags.every(([k, on]) => !!p.properties_hash[k] === on);
            return {ok: true, status: 200, json: async () => ({
                products: listings.filter((p) => fits(p) && (hub === null || String(p.user.can_sell_via_hub) === hub))
                    .sort((a, b) => a.layered_price_cents - b.layered_price_cents).slice(0, limit),
                odr_product_groups: groups.filter(fits),
            })};
        }
        const query = new URLSearchParams(url.split('?')[1]);
        const ids = query.getAll('product_ids[]').map(Number);
        posts.push({url, quantity: Number(query.get('quantity')), ids, future: query.get('future_order')});
        let want = Number(query.get('quantity'));
        let delta = 0;
        for (const p of [...listings, ...groups.map((g) => ({id: g.all_ids[0], quantity: g.quantity}))]) {
            if (ids.includes(p.id) && want > 0) {
                const take = Math.min(want, p.quantity);
                want -= take;
                delta += take;
            }
        }
        return {ok: true, status: 200, json: async () => ({delta_changed_quantity: delta})};
    };
    return {fetch, posts};
}

// listing is one Card Trader listing as its card page answers, a Magic one
// unless props says otherwise
function listing(id, cents, {condition = 'Near Mint', lang = 'en', foil = false, hub = true, qty = 1, currency = 'EUR', props = null, ...rest} = {}) {
    return {id, layered_price_cents: cents, price_currency: currency, quantity: qty, description: rest.description || null,
        on_vacation: false, graded: false,
        properties_hash: {condition, altered: !!rest.altered, signed: false, ...(props || {mtg_language: lang, mtg_foil: foil})},
        user: {can_sell_via_hub: hub, country_code: rest.country || 'IT', user_type: rest.type || 'pro'}};
}

// ctID names a row as the site does: <blueprint>-<grade>-<price>-<split>-<base64url properties>
function ctID(price, split, props = 'mtg_foil=&mtg_language=en', grade = 'NM', blueprint = '16310') {
    return [blueprint, grade, price, split, Buffer.from(props).toString('base64url')].join('-');
}

describe('ban-to-cart bookmarklet on Card Trader', () => {
    const cartPage = {host: 'www.cardtrader.com', path: '/it-IT/cart/edit'};

    test('a Zero row goes to every live Zero listing at or under BAN\'s price, in its grade and properties', async () => {
        const ct = fakeCT({listings: [
            listing(1, 14), listing(2, 19, {qty: 6}), listing(3, 20, {qty: 9}),
            listing(4, 12, {condition: 'Slightly Played'}), listing(5, 10, {altered: true}),
            listing(6, 10, {description: 'Italian copy'}), listing(7, 10, {currency: 'USD'}),
            listing(8, 10, {hub: false}), listing(9, 10, {foil: true}), listing(10, 10, {lang: 'it'}),
        ]});
        const {alerts, page, posts} = await run({...cartPage, hash: '#ban=' + ctID('19EUR', 'z') + '%3a3&side=retail', abu: ct});
        expect(posts[0].url).toBe('/it-IT/cards/16310/filter.json');
        expect(posts[0].body).toEqual([
            ['q[terms][properties_hash.mtg_language.keyword][]', 'en'],
            ['q[terms][properties_hash.condition.keyword][]', 'Mint'],
            ['q[terms][properties_hash.condition.keyword][]', 'Near Mint'],
            ['q[term][user.can_sell_via_hub]', 'true'],
        ]);
        expect(posts[1]).toEqual({url: '/it-IT/cart/add.json?quantity=3&product_ids[]=1&product_ids[]=2&future_order=1', quantity: 3, ids: [1, 2], future: '1'});
        expect(alerts).toEqual(['Added 1 cards to your Card Trader cart, on top of what it held.']);
        expect(page.url).toBe('/it-IT/cart/edit');
        expect(page.reloaded).toBe(true);
    });

    test('another game\'s row matches on its own properties, a missing flag reading as off', async () => {
        const fab = (id, cents, props) => listing(id, cents, {props: {fab_language: 'en', ...props}});
        const ct = fakeCT({listings: [
            fab(1, 50, {fab_foil_new: 'Rainbow Foil', first_edition: true}),
            fab(2, 40, {fab_foil_new: 'Rainbow Foil'}),
            fab(3, 30, {fab_foil_new: 'Cold Foil', first_edition: true}),
            fab(4, 45, {fab_foil_new: 'Rainbow Foil', first_edition: false}),
        ]});
        const {posts} = await run({...cartPage, hash: '#ban=' + ctID('50EUR', 'z', 'fab_foil_new=Rainbow+Foil&fab_language=en&first_edition=true') + ':1,' +
            ctID('50EUR', 'z', 'fab_foil_new=Rainbow+Foil&fab_language=en&first_edition=') + ':1&side=retail', abu: ct});
        expect(posts[0].body.slice(0, 3)).toEqual([
            ['q[terms][properties_hash.fab_foil_new.keyword][]', 'Rainbow Foil'],
            ['q[terms][properties_hash.fab_language.keyword][]', 'en'],
            ['q[term][properties_hash.first_edition]', 'true'],
        ]);
        expect(posts.filter((p) => p.ids).map((p) => p.ids)).toEqual([[1], [2, 4]]);
    });

    test('a 1-Day Ready row goes to its groups, and the storefront without Zero to its own sellers', async () => {
        const ct = fakeCT({
            listings: [listing(1, 30, {hub: false}), listing(2, 30, {hub: false, country: 'GB', type: 'normal'}), listing(3, 30, {hub: false, country: 'GB'})],
            groups: [{...listing(50, 11, {qty: 4}), all_ids: [50, 51, 52, 53], user: null}],
        });
        const {alerts, posts} = await run({...cartPage, hash: '#ban=' + ctID('12EUR', 'd') + ':2,' + ctID('30EUR', 'm') + ':1&side=retail', abu: ct});
        const hubOf = (post) => (post.body.find(([k]) => k === 'q[term][user.can_sell_via_hub]') || [])[1];
        expect(hubOf(posts[0])).toBeUndefined();
        expect(posts[1].ids).toEqual([50, 51, 52, 53]);
        expect(hubOf(posts[2])).toBe('false');
        expect(posts[3].ids).toEqual([1, 3]);
        expect(alerts).toEqual(['Added 2 cards to your Card Trader cart, on top of what it held.']);
    });

    test('a card it has fewer of is cut, and one with nothing at or under BAN\'s price left out', async () => {
        const ct = fakeCT({listings: [listing(1, 14, {qty: 2}), listing(2, 50)]});
        const rows = [ctID('14EUR', 'z') + ':5', ctID('14EUR', 'z', undefined, 'NM', '99') + ':1', ctID('14GBP', 'z') + ':1'];
        const {alerts, posts} = await run({...cartPage, hash: '#ban=' + rows.join(',') + '&side=retail', abu: ct});
        expect(posts.filter((p) => p.ids)).toHaveLength(1);
        expect(alerts).toEqual(['Added 1 cards to your Card Trader cart, on top of what it held. 1 were cut to the copies Card Trader has at or under BAN\'s price. ' +
            '2 that Card Trader has none of at or under BAN\'s price were left out.']);
    });

    test('a foil row finds its listings behind the cheaper ones Card Trader would answer first', async () => {
        const ct = fakeCT({limit: 2, listings: [listing(1, 10), listing(2, 11), listing(3, 12), listing(4, 90, {foil: true})]});
        const {posts} = await run({...cartPage, hash: '#ban=' + ctID('100EUR', 'z', 'mtg_foil=true&mtg_language=en') + ':1&side=retail', abu: ct});
        expect(posts[1].ids).toEqual([4]);
    });

    test('a Poor row sends no condition, since a signed or stamped copy reads as Poor too', async () => {
        const ct = fakeCT({listings: [listing(1, 10, {condition: 'Near Mint', description: 'signed by the artist'})]});
        const {posts} = await run({...cartPage, hash: '#ban=' + ctID('10EUR', 'z', undefined, 'PO') + ':1&side=retail', abu: ct});
        expect(posts[0].body.some(([k]) => k.includes('condition'))).toBe(false);
        expect(posts[1].ids).toEqual([1]);
    });

    test('a refusal partway says what was added and leaves only the rest on the page, so a retry adds nothing twice', async () => {
        const ct = fakeCT({listings: [listing(1, 14, {qty: 9})]});
        const fetch = ct.fetch;
        let adds = 0;
        ct.fetch = async (url, opts) => (url.includes('/cart/add.json') && ++adds === 2 ? {ok: false, status: 503} : fetch(url, opts));
        const rows = [ctID('14EUR', 'z') + ':1', ctID('15EUR', 'z') + ':2', ctID('16EUR', 'z') + ':1'];
        const {alerts, page} = await run({...cartPage, hash: '#ban=' + rows.join(',') + '&side=retail', abu: ct});
        expect(alerts).toEqual(['Card Trader refused the list (503). Added 1 cards to your Card Trader cart, on top of what it held. ' +
            'The other 2 were not added, and this page now holds only those: click BAN-to-Cart again to load them.']);
        expect(page.url).toBe('/it-IT/cart/edit#ban=' + encodeURIComponent(rows.slice(1).join(',')) + '&side=retail&v=test');
        expect(page.reloaded).toBe(false);

        const retry = fakeCT({listings: [listing(1, 14, {qty: 9})]});
        const again = await run({...cartPage, hash: page.url.slice(page.url.indexOf('#')).replace('&v=test', ''), abu: retry});
        expect(retry.posts.filter((p) => p.ids).map((p) => p.quantity)).toEqual([2, 1]);
        expect(again.alerts).toEqual(['Added 2 cards to your Card Trader cart, on top of what it held.']);
    });

    test('a refusal before anything was added leaves the list as it was', async () => {
        const ct = fakeCT({listings: [listing(1, 14, {qty: 9})]});
        ct.fetch = async () => ({ok: false, status: 503});
        const {alerts, page} = await run({...cartPage, hash: '#ban=' + ctID('14EUR', 'z') + ':1&side=retail', abu: ct});
        expect(alerts).toEqual(['Card Trader refused the list (503).']);
        expect(page.url).toBe(null);
    });

    test('a refusal after rows that added nothing leaves the list as it was', async () => {
        const ct = fakeCT({listings: [listing(1, 14, {qty: 9})]});
        ct.fetch = async (url, opts) => (url.includes('/cart/add.json') ? {ok: false, status: 503} : fakeCT({listings: [listing(1, 14, {qty: 9})]}).fetch(url, opts));
        const rows = [ctID('10EUR', 'z') + ':1', ctID('14EUR', 'z') + ':1'];
        const {alerts, page} = await run({...cartPage, hash: '#ban=' + rows.join(',') + '&side=retail', abu: ct});
        expect(alerts).toEqual(['Card Trader refused the list (503).']);
        expect(page.url).toBe(null);
    });

    test('a refusal partway still counts the pairs that did not read', async () => {
        const ct = fakeCT({listings: [listing(1, 14, {qty: 9})]});
        const fetch = ct.fetch;
        let adds = 0;
        ct.fetch = async (url, opts) => (url.includes('/cart/add.json') && ++adds === 2 ? {ok: false, status: 503} : fetch(url, opts));
        const rows = [ctID('14EUR', 'z') + ':1', ctID('15EUR', 'z') + ':2'];
        const {alerts} = await run({...cartPage, hash: '#ban=' + rows.join(',') + ',a.b:2&side=retail', abu: ct});
        expect(alerts[0]).toEndWith('click BAN-to-Cart again to load them. 1 in the list from BAN could not be read and were left out.');
    });

    test('two tabs loading at once take turns', async () => {
        const ct = fakeCT({listings: [listing(1, 14, {qty: 9})]});
        const locks = fakeLocks();
        await Promise.all([1, 2].map(() => run({...cartPage, hash: '#ban=' + ctID('14EUR', 'z') + ':1&side=retail', abu: ct, locks})));
        expect(locks.names).toEqual(['ban-to-cart-ct', 'ban-to-cart-ct']);
    });
});

// fakeML stands in for Manaleak: each product page names its Near Mint
// option, its HTML breaking lines inside tags, with the store's copies; a
// cart page lists a quantity field per line, keyed by product and options;
// an add adds to a line and the cart form sets one, as Manaleak does. A
// cart is held as {line: qty}, a line being <id> for Near Mint or <id>:lp
// for Light Play.
function fakeML({products = {}, store = {}, buy = {}} = {}) {
    const carts = {'checkout/cart': {...store}, 'buylist/cart': {...buy}};
    const posts = [];
    const reads = [];
    const value = (line) => {
        const [id, grade] = line.split(':');
        return grade === 'lp' ? '9' + products[id].nm : products[id].nm;
    };
    const key = (line) => line.split(':')[0] + ':' + btoa(`a:1:{i:${products[line.split(':')[0]].option};s:5:"${value(line)}";}`) + ':';
    const fetch = async (url, opts = {}) => {
        const route = /route=([^&]+)/.exec(url)[1];
        if (!opts.method) {
            reads.push(route);
            if (route === 'product/product') {
                const p = products[/product_id=(\d+)/.exec(url)[1]];
                const page = p ? `<select\nname="option[${p.option}]"><option\nvalue=""> --- Please Select ---</option>` +
                    `<option\nvalue="${p.nm}" data-image="x.jpg">Mint/Near Mint    (£0.15)\n- ${p.stock ? 'Qty:' + p.stock : 'Out of Stock'}</option>` +
                    `<option\nvalue="9${p.nm}">Light Play (£0.15)\n- Qty:6</option></select>` : 'Product not found!';
                return {ok: true, status: 200, text: async () => page};
            }
            const fields = Object.entries(carts[route]).map(([line, q]) => `<input\ntype="text" name="quantity[${key(line)}]" value="${q}" size="1" />`);
            return {ok: true, status: 200, text: async () => fields.join('')};
        }
        const body = new URLSearchParams(opts.body);
        posts.push({route, body: Object.fromEntries(body)});
        if (route.endsWith('/add')) {
            const id = body.get('product_id');
            const cartRoute = route.slice(0, -'/add'.length);
            const qty = Number(body.get(cartRoute === 'buylist/cart' ? 'buylist_quantity' : 'quantity'));
            const sent = body.get(`option[${products[id].option}]`);
            const line = sent === products[id].nm ? id : sent === '9' + products[id].nm ? id + ':lp' : null;
            if (line) {
                carts[cartRoute][line] = (carts[cartRoute][line] || 0) + qty;
            }
        } else {
            for (const [name, q] of body) {
                const line = Object.keys(carts[route]).find((l) => 'quantity[' + key(l) + ']' === name);
                carts[route][line] = Number(q);
            }
        }
        return {ok: true, status: 200, text: async () => '{"success":"ok"}'};
    };
    return {fetch, posts, reads, carts};
}

describe('ban-to-cart bookmarklet on Manaleak', () => {
    const products = {
        7090: {option: 7090, nm: '35446', stock: 4},
        178453: {option: 165360, nm: '82443', stock: 1},
        500: {option: 500, nm: '11111', stock: 0},
    };
    const storePage = {host: 'www.manaleak.com', path: '/index.php', search: '?route=checkout/cart'};
    const buyPage = {host: 'www.manaleak.com', path: '/index.php', search: '?route=buylist/cart'};

    test('a store list adds each card\'s Near Mint copies up to the stock, and sets a card already there', async () => {
        const ml = fakeML({products, store: {178453: 3}});
        const {alerts, page, posts} = await run({...storePage, hash: '#ban=7090%3a10%2c178453%3a1%2c500%3a1%2c42%3a1&side=retail', abu: ml});
        expect(posts).toEqual([
            {route: 'checkout/cart/add', body: {product_id: '7090', quantity: '4', 'option[7090]': '35446'}},
            {route: 'checkout/cart', body: {['quantity[178453:' + btoa('a:1:{i:165360;s:5:"82443";}') + ':]']: '1'}},
        ]);
        expect(ml.carts['checkout/cart']).toEqual({7090: 4, 178453: 1});
        expect(ml.reads[0]).toBe('checkout/cart');
        expect(alerts[0]).toBe('Loaded 2 cards into your Manaleak cart. 2 were not taken by Manaleak.');
        expect(page.url).toBe('/index.php?route=checkout/cart');
    });

    test('a card the cart holds only in another condition is not counted as loaded', async () => {
        const ml = fakeML({products, store: {'500:lp': 2}});
        const {alerts, posts} = await run({...storePage, hash: '#ban=500:1&side=retail', abu: ml});
        expect(posts).toHaveLength(0);
        expect(alerts[0]).toBe('Loaded 0 cards into your Manaleak cart. 1 were not taken by Manaleak.');
    });

    test('a buylist list goes to the buylist cart whatever the stock', async () => {
        const ml = fakeML({products});
        const {alerts, posts} = await run({...buyPage, hash: '#ban=500:3', abu: ml});
        expect(posts).toEqual([{route: 'buylist/cart/add', body: {product_id: '500', buylist_quantity: '3', 'option[500]': '11111'}}]);
        expect(ml.carts['buylist/cart']).toEqual({500: 3});
        expect(ml.reads).toEqual(['buylist/cart', 'product/product', 'buylist/cart']);
        expect(alerts[0]).toBe('Loaded 1 cards into your Manaleak cart.');
    });

    test('two tabs loading the same list at once take turns and do not double it', async () => {
        const ml = fakeML({products});
        const locks = fakeLocks();
        const tabs = await Promise.all([1, 2].map(() => run({...buyPage, hash: '#ban=7090:2', abu: ml, locks})));
        expect(locks.names).toEqual(['ban-to-cart-ml', 'ban-to-cart-ml']);
        expect(ml.carts['buylist/cart']).toEqual({7090: 2});
        expect(ml.posts.map((p) => p.route)).toEqual(['buylist/cart/add', 'buylist/cart']);
        expect(tabs.map((tab) => tab.alerts[0])).toEqual(['Loaded 1 cards into your Manaleak cart.', 'Loaded 1 cards into your Manaleak cart.']);
    });

    test('a list on the other side\'s cart page is refused and nothing is sent', async () => {
        for (const [where, hash] of [[buyPage, '#ban=7090:1&side=retail'], [storePage, '#ban=7090:1']]) {
            const ml = fakeML({products});
            const {alerts} = await run({...where, hash, abu: ml});
            expect(alerts[0]).toBe('This is not the Manaleak cart the list is for. Go back to BAN and press its button again.');
            expect(ml.posts).toHaveLength(0);
        }
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

    test('two tabs loading the same list at once take turns and do not double it', async () => {
        const fake = fakeCSIShop();
        const locks = fakeLocks();
        await Promise.all([1, 2].map(() => run({...shop, hash: '#ban=434190-10753983:2&side=retail', abu: fake, locks})));
        expect(locks.names).toEqual(['ban-to-cart-csi', 'ban-to-cart-csi']);
        expect(fake.lines).toEqual({10753983: 2});
        expect(fake.posts).toHaveLength(1);
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
