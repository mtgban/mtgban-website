import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/metrics.js', import.meta.url), 'utf8');
export const KEY = 'mtgban_metrics_queue';
export const DAY = 86400000;

// Runs metrics.js on a page of fakes, with its timers and clock in the test's hands.
// net is 'ok' (204), 'down' (fetch rejects) or the status a fetch resolves with.
export function loadMetrics({ cfg = { on: true, page: 'search', build: 'abc' }, ban, online = true, dnt, gpc, stored = {}, day = 20000, net = 'ok', beaconOk = true, storage = 'ok', nav = {}, win: winProps = {}, docProps = {}, globals = {} } = {}) {
    const m = { ...stored };
    const writes = [];
    const denied = () => { if (storage === 'throws') throw new Error('denied'); };
    const localStorage = {
        getItem: (k) => { denied(); return k in m ? m[k] : null; },
        setItem: (k, v) => { denied(); m[k] = String(v); writes.push(k); },
        removeItem: (k) => { denied(); delete m[k]; },
    };
    const doc = {}, win = {};
    const listen = (map) => (type, fn, opt) => { (map[type] = map[type] || []).push({ fn, capture: opt === true || !!(opt && opt.capture) }); };
    const document = { visibilityState: 'visible', addEventListener: listen(doc), ...docProps };
    const beacons = [], fetches = [];
    const navigator = {
        onLine: online, doNotTrack: dnt, globalPrivacyControl: gpc,
        sendBeacon: (url, body) => { beacons.push({ url, type: typeof body, raw: body, body: JSON.parse(body) }); return beaconOk; },
        ...nav,
    };
    const window = { addEventListener: listen(win), ...winProps };
    if (cfg) window.BAN_METRICS = cfg;
    if (ban) window.BAN = ban;
    const page = { m, writes, doc, win, document, navigator, window, beacons, fetches, net, day };
    const fetch = (url, opts) => {
        fetches.push({ url, opts, body: JSON.parse(opts.body) });
        return page.net === 'down' ? Promise.reject(new TypeError('no network')) : Promise.resolve({ status: page.net === 'ok' ? 204 : page.net });
    };
    const timers = [];
    const setTimeout = (fn, ms) => { timers.push({ fn, ms, live: true }); return timers.length; };
    const clearTimeout = (id) => { if (timers[id - 1]) timers[id - 1].live = false; };
    const DateStub = { now: () => page.day * DAY + 1000 };
    const scope = { window, document, navigator, localStorage, fetch, setTimeout, clearTimeout, Date: DateStub, Math: Object.assign(Object.create(Math), { random: () => 1 }), ...globals };
    new Function(...Object.keys(scope), source)(...Object.values(scope));
    page.live = () => timers.filter((t) => t.live);
    // fire runs the pending timer.
    page.fire = () => { const t = page.live()[0]; t.live = false; t.fn(); };
    // emit runs every listener of a type, window's then document's.
    page.emit = (type, ev = {}) => { for (const l of [...(win[type] || []), ...(doc[type] || [])]) l.fn(ev); };
    page.hide = (type) => {
        document.visibilityState = 'hidden';
        if (type !== 'pagehide') for (const l of doc.visibilitychange || []) l.fn({});
        if (type !== 'visibilitychange') for (const l of win.pagehide || []) l.fn({ persisted: false });
    };
    // sent is every entry that has left the page, by beacon or by fetch.
    page.sent = () => [...beacons, ...fetches].flatMap((x) => x.body);
    page.track = (...a) => window.BAN.track(...a);
    page.bump = (...a) => window.BAN.metrics.bump(...a);
    return page;
}

// matches answers a selector list of tag, [attr] and tag[attr] parts, the forms the script uses.
const matches = (n, sel) => sel.split(',').some((part) => {
    const [, tag, at] = part.trim().match(/^([a-z]*)(?:\[([a-z-]+)\])?$/);
    return (!tag || n.tagName === tag.toUpperCase()) && (!at || n.getAttribute(at) !== null);
});

// el is an element that answers closest() and contains(); props adds fields such as control.
export function el(attrs = {}, parent = null, tag = 'button', props = {}) {
    const node = {
        tagName: tag.toUpperCase(), parent, handlers: [],
        getAttribute: (k) => (k in attrs ? attrs[k] : null),
        closest(sel) {
            for (let n = node; n; n = n.parent) if (matches(n, sel)) return n;
            return null;
        },
        contains(other) {
            for (let n = other; n; n = n.parent) if (n === node) return true;
            return false;
        },
        ...props,
    };
    return node;
}

// dispatch runs an event as a browser orders it: document capture, the
// target's own handlers, then document bubble unless one of them stopped it.
export function dispatch(page, type, target, init = {}) {
    let stopped = false;
    const ev = { type, target, button: 0, ...init, stopPropagation() { stopped = true; } };
    for (const l of page.doc[type] || []) if (l.capture) l.fn(ev);
    for (const h of target.handlers || []) h(ev);
    if (!stopped) for (const l of page.doc[type] || []) if (!l.capture) l.fn(ev);
}

export const settle = async () => { for (let i = 0; i < 10; i++) await Promise.resolve(); };
