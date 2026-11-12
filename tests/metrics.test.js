import { test, expect } from 'bun:test';
import { loadMetrics as load, el, dispatch, settle, KEY } from './metrics-loader.js';

const LOAD = { n: 'ui.load', s: 'search', c: 1 };
const NO_LOAD = { cfg: { on: true, page: '', build: 'abc' } };

test('a page load is counted once, under the page label, and sent ten seconds on', () => {
    const p = load();
    expect(p.fetches).toEqual([]);
    expect(p.live().map((t) => t.ms)).toEqual([10000]);
    p.fire();
    expect(p.fetches.length).toBe(1);
    expect(p.fetches[0].url).toBe('/api/metrics');
    expect(p.fetches[0].body).toEqual([LOAD]);
    const o = p.fetches[0].opts;
    expect([o.method, o.keepalive, o.credentials, o.headers['Content-Type']]).toEqual(['POST', true, 'same-origin', 'text/plain;charset=UTF-8']);
    expect(p.live()).toEqual([]);
    expect(p.beacons).toEqual([]);
});

test('a page with no label sends no load, and track still works on it', () => {
    const p = load(NO_LOAD);
    expect(p.live()).toEqual([]);
    p.hide();
    expect(p.beacons).toEqual([]);
    p.track('ui.x');
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.x', c: 1 }]);
});

test('track is set on a BAN object that was already there', () => {
    const ban = { snapshot: 'kept' };
    const p = load({ ban });
    expect(p.window.BAN).toBe(ban);
    expect(ban.snapshot).toBe('kept');
    expect(typeof ban.track).toBe('function');
});

test('nested tracked elements count the innermost, once, with its value and scope', () => {
    const p = load();
    const outer = el({ 'data-track': 'ui.outer' }, null, 'div');
    const link = el({ 'data-track': 'ui.row.store', 'data-track-value': 'CK', 'data-track-scope': 'seller', href: '/go/x' }, outer, 'a');
    dispatch(p, 'click', el({}, link, 'img'));   // an untracked child of the inner one
    dispatch(p, 'click', el({}, null, 'div'));   // nothing tracked above it
    p.hide();
    expect(p.beacons[0].body).toEqual([LOAD, { n: 'ui.row.store', s: 'seller', v: 'CK', c: 1 }]);
});

test('the attributes are read before the control\'s own handler changes them', () => {
    const p = load();
    const attrs = { 'data-track': 'ui.pill', 'data-track-value': 'off' };
    const pill = el(attrs);
    pill.handlers.push(() => { attrs['data-track-value'] = 'on'; });
    dispatch(p, 'click', pill);
    p.hide();
    expect(p.beacons[0].body).toContainEqual({ n: 'ui.pill', v: 'off', c: 1 });
});

test('a click whose own handler stops propagation is still counted', () => {
    const p = load();
    const kebab = el({ 'data-track': 'ui.result.icon_menu', 'data-track-value': 'open' });
    kebab.handlers.push((e) => e.stopPropagation());
    dispatch(p, 'click', kebab);
    p.hide();
    expect(p.beacons[0].body).toContainEqual({ n: 'ui.result.icon_menu', v: 'open', c: 1 });
    for (const type of ['click', 'auxclick', 'submit']) {
        expect(p.doc[type].length).toBe(1);
        expect(p.doc[type][0].capture).toBe(true);
        expect(p.doc[type][0].fn).toBe(p.doc.click[0].fn);
    }
});

test('a middle click counts on a link and nowhere else', () => {
    const p = load();
    const link = el({ 'data-track': 'ui.a', href: '/go/x' }, null, 'a');
    const button = el({ 'data-track': 'ui.b' });
    dispatch(p, 'auxclick', link, { button: 1 });
    dispatch(p, 'auxclick', link, { button: 2 });
    dispatch(p, 'auxclick', button, { button: 1 });
    p.hide();
    expect(p.beacons[0].body).toEqual([LOAD, { n: 'ui.a', c: 1 }]);
});

test('a middle click counts the marked element only when it is or sits inside a link', () => {
    const p = load(NO_LOAD);
    const row = el({ 'data-track': 'ui.row' }, null, 'div');
    dispatch(p, 'auxclick', el({ href: '/go/x' }, row, 'a'), { button: 1 });   // untracked link in a tracked row
    const link = el({ 'data-track': 'ui.link', href: '/go/y' }, null, 'a');
    dispatch(p, 'auxclick', el({}, link, 'img'), { button: 1 });              // a child of a tracked link
    const outer = el({ href: '/go/z' }, null, 'a');
    dispatch(p, 'auxclick', el({ 'data-track': 'ui.inner' }, outer, 'span'), { button: 1 });  // tracked inside a link
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.link', c: 1 }, { n: 'ui.inner', c: 1 }]);
});

test('a form counts when it submits, once, and not when it is clicked', () => {
    const p = load();
    const form = el({ 'data-track': 'ui.searchbar.submit', 'data-track-value': 'nav' }, null, 'form');
    const box = el({}, form, 'input');
    const go = el({}, form, 'button');
    const clear = el({ 'data-track': 'ui.searchbar.clear' }, form, 'button');
    form.handlers.push((e) => e.stopPropagation());
    dispatch(p, 'click', box);     // focusing the box
    dispatch(p, 'click', go);      // the click a browser fires before the submit
    dispatch(p, 'submit', form);
    dispatch(p, 'click', clear);   // a tracked control inside the form is its own count
    dispatch(p, 'submit', el({}, null, 'form'));  // a form with no data-track
    p.hide();
    expect(p.beacons[0].body).toEqual([LOAD, { n: 'ui.searchbar.submit', v: 'nav', c: 1 }, { n: 'ui.searchbar.clear', c: 1 }]);
});

// labelClick runs a click on a label's text, then the click the browser relays to its control.
const labelClick = (p, text, control) => {
    dispatch(p, 'click', text);
    if (control) dispatch(p, 'click', control);
};

test('a marked label wrapping a checkbox counts once per click', () => {
    const p = load(NO_LOAD);
    const lab = el({ 'data-track': 'ui.toggle' }, null, 'label');
    const box = el({ type: 'checkbox' }, lab, 'input', { type: 'checkbox' });
    lab.control = box;
    labelClick(p, el({}, lab, 'span'), box);
    labelClick(p, lab, box);
    dispatch(p, 'click', box);   // a click on the box itself
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.toggle', c: 3 }]);
});

test('a marked row holding a label and its control counts once', () => {
    const p = load(NO_LOAD);
    const row = el({ 'data-track': 'ui.row' }, null, 'div');
    const box = el({}, row, 'input', { type: 'checkbox' });
    const lab = el({ for: 'x' }, row, 'label', { control: box });
    labelClick(p, lab, box);
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.row', c: 1 }]);
});

test('a label with no control, or one the browser will not click, counts its own click', () => {
    const p = load(NO_LOAD);
    const bare = el({ 'data-track': 'ui.bare' }, null, 'label', { control: null });
    dispatch(p, 'click', bare);
    const off = el({}, null, 'input', { disabled: true });
    const offLab = el({ 'data-track': 'ui.off' }, null, 'label', { control: off });
    off.parent = offLab;
    dispatch(p, 'click', offLab);
    const away = el({}, null, 'input');   // a control outside the marked label
    dispatch(p, 'click', el({ 'data-track': 'ui.away' }, null, 'label', { control: away }));
    dispatch(p, 'click', away);
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.bare', c: 1 }, { n: 'ui.off', c: 1 }, { n: 'ui.away', c: 1 }]);
});

test('a direct click on a labelled control or a link inside the label counts once', () => {
    const p = load(NO_LOAD);
    const lab = el({ 'data-track': 'ui.toggle' }, null, 'label');
    const box = el({}, lab, 'input');
    lab.control = box;
    dispatch(p, 'click', box);
    dispatch(p, 'click', el({ href: '/help' }, lab, 'a'));   // a link in a label does not click the control
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.toggle', c: 2 }]);
});

test('without label.control the for attribute or a descendant input names the control', () => {
    const p = load(NO_LOAD);
    const row = el({ 'data-track': 'ui.row' }, null, 'div');
    const box = el({}, row, 'input');
    const forLab = el({ for: 'box' }, row, 'label');
    p.document.getElementById = (id) => (id === 'box' ? box : null);
    labelClick(p, forLab, box);
    const wrap = el({ 'data-track': 'ui.wrap' }, null, 'label');
    const hidden = el({}, wrap, 'input', { type: 'hidden' });
    const inner = el({}, wrap, 'input', { type: 'checkbox' });
    wrap.querySelectorAll = () => [hidden, inner];
    labelClick(p, wrap, inner);
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.row', c: 1 }, { n: 'ui.wrap', c: 1 }]);
});

test('a label that throws while its control is looked up still counts', () => {
    const p = load(NO_LOAD);
    const lab = el({ 'data-track': 'ui.odd' }, null, 'label', { contains() { throw new Error('old browser'); } });
    dispatch(p, 'click', el({}, lab, 'input'));
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.odd', c: 1 }]);
});

test('a prerendered page counts its load only once it is shown', () => {
    const p = load({ docProps: { prerendering: true } });
    expect(p.live()).toEqual([]);
    p.document.prerendering = false;
    p.emit('prerenderingchange');
    p.emit('prerenderingchange');
    p.hide();
    expect(p.sent()).toEqual([LOAD]);
});

test('a page that is not prerendered counts its load at start-up', () => {
    for (const prerendering of [false, undefined]) {
        const p = load({ docProps: { prerendering } });
        expect(p.live().length).toBe(1);
        p.hide();
        expect(p.sent()).toEqual([LOAD]);
    }
});

test('counts add up in memory and each one pushes the timer back', () => {
    const p = load();
    p.track('ui.x', 'a');
    p.track('ui.x', 'a');
    p.track('ui.x', 'b', 'menu');
    expect(p.live().length).toBe(1);
    p.fire();
    expect(p.fetches[0].body).toEqual([LOAD, { n: 'ui.x', v: 'a', c: 2 }, { n: 'ui.x', s: 'menu', v: 'b', c: 1 }]);
});

test('hiding the page sends once, by beacon, as a string', () => {
    for (const type of ['pagehide', 'visibilitychange', 'both']) {
        const p = load();
        p.track('ui.x');
        p.hide(type);
        p.hide(type);
        expect(p.beacons.length).toBe(1);
        expect(p.beacons[0].url).toBe('/api/metrics');
        expect(p.beacons[0].type).toBe('string');
        expect(p.beacons[0].body).toEqual([LOAD, { n: 'ui.x', c: 1 }]);
        expect(p.fetches).toEqual([]);
        expect(p.live()).toEqual([]);
    }
});

test('becoming visible sends nothing', () => {
    const p = load();
    for (const l of p.doc.visibilitychange) l.fn({});
    expect(p.beacons).toEqual([]);
});

test('the caps: 50 a key, 40 characters, printable ASCII', () => {
    const p = load(NO_LOAD);
    for (let i = 0; i < 60; i++) p.track('ui.many');
    p.track('ui.' + 'x'.repeat(38));
    p.track('ui.x', 'v'.repeat(41));
    p.track('ui.x', '', 's'.repeat(41));
    p.track('ui.x', 'café');
    p.track('ui.x', 'a\nb');
    p.track('');
    p.track(undefined);
    p.track('ui.ok', 'v'.repeat(40), 's'.repeat(40));
    p.fire();
    expect(p.fetches.map((f) => f.body)).toEqual([[{ n: 'ui.many', c: 50 }, { n: 'ui.ok', s: 's'.repeat(40), v: 'v'.repeat(40), c: 1 }]]);
});

test('a buffer of 250 entries goes out whole, 50 a post, in order', () => {
    for (const how of ['timer', 'hide']) {
        const p = load(NO_LOAD);
        for (let i = 0; i < 250; i++) p.track('ui.key', 'v' + i);
        if (how === 'timer') p.fire(); else p.hide();
        const posts = how === 'timer' ? p.fetches : p.beacons;
        expect(posts.map((x) => x.body.length)).toEqual([50, 50, 50, 50, 50]);
        expect(posts.flatMap((x) => x.body)).toEqual(Array.from({ length: 250 }, (_, i) => ({ n: 'ui.key', v: 'v' + i, c: 1 })));
        expect(p.live()).toEqual([]);
        p.hide();
        expect(p.sent().length).toBe(250);
    }
});

test('a post closes early before it would pass 7,500 characters', () => {
    const p = load(NO_LOAD);
    const wide = { a: 'a'.repeat(80), b: 'b'.repeat(80) };
    for (let i = 0; i < 100; i++) p.bump('ui.' + 'n'.repeat(37), 'v'.repeat(37) + (100 + i), 's'.repeat(40), wide);
    p.hide();
    expect(p.beacons.length).toBeGreaterThan(2);
    expect(p.beacons.every((b) => b.raw.length <= 7500 && b.body.length <= 50)).toBe(true);
    expect(p.sent().length).toBe(100);
});

test('the runaway guard stops a buffer at 500 keys', () => {
    const p = load(NO_LOAD);
    for (let i = 0; i < 600; i++) p.track('ui.key', 'v' + i);
    p.hide();
    expect(p.sent().length).toBe(500);
    expect(p.sent()[499]).toEqual({ n: 'ui.key', v: 'v499', c: 1 });
});

test('an extra object is part of the key and rides on the wire entry', () => {
    const p = load(NO_LOAD);
    expect(p.bump('ui.e', 'TypeError', 'navbar.js', { l: 42, b: 'abc' })).toBe(true);
    p.bump('ui.e', 'TypeError', 'navbar.js', { l: 42, b: 'abc' });
    p.bump('ui.e', 'TypeError', 'navbar.js', { l: 43, b: 'abc' });
    p.bump('ui.e', 'TypeError', 'navbar.js');
    p.bump('ui.x', '', '', { n: 'ui.other', c: 9, l: 1 });  // the four wire keys cannot be overwritten
    p.hide();
    expect(p.beacons[0].body).toEqual([
        { n: 'ui.e', s: 'navbar.js', v: 'TypeError', c: 2, l: 42, b: 'abc' },
        { n: 'ui.e', s: 'navbar.js', v: 'TypeError', c: 1, l: 43, b: 'abc' },
        { n: 'ui.e', s: 'navbar.js', v: 'TypeError', c: 1 },
        { n: 'ui.x', c: 1, l: 1 },
    ]);
});

test('an extra that is not short plain data drops the call', () => {
    const p = load(NO_LOAD);
    for (const bad of [{ b: 'x'.repeat(81) }, { b: 'café' }, { l: NaN }, { l: {} }, { a: 1, b: 2, d: 3, e: 4, f: 5 }, 'text', [1]]) {
        expect(p.bump('ui.e', '', '', bad)).toBe(false);
    }
    p.hide();
    expect(p.sent()).toEqual([]);
});

test('BAN.track takes three arguments and no extra', () => {
    const p = load(NO_LOAD);
    p.track('ui.x', 'v', 's', { l: 1 });
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.x', s: 's', v: 'v', c: 1 }]);
});

test('a target with no closest counts nothing and throws nothing', () => {
    const p = load(NO_LOAD);
    const text = { nodeType: 3, parentNode: el({ 'data-track': 'ui.x' }) };
    const svg = { tagName: 'use', closest: 'not a function' };
    for (const type of ['click', 'auxclick', 'submit']) {
        for (const target of [text, svg, p.document, null, undefined]) {
            expect(() => dispatch(p, type, target || {}, { target })).not.toThrow();
        }
        expect(() => p.doc[type][0].fn(undefined)).not.toThrow();
    }
    const thrower = { closest() { throw new Error('boom'); } };
    expect(() => dispatch(p, 'click', thrower)).not.toThrow();
    p.hide();
    expect(p.sent()).toEqual([]);
});

test('track and bump never throw, whatever they are handed', () => {
    const p = load(NO_LOAD);
    const hostile = { toString() { throw new Error('boom'); } };
    expect(() => p.track(hostile)).not.toThrow();
    expect(() => p.track('ui.x', hostile)).not.toThrow();
    expect(() => p.track('ui.x', '', hostile)).not.toThrow();
    expect(p.bump('ui.x', hostile)).toBe(false);
    expect(p.bump('ui.x', '', '', { get l() { throw new Error('boom'); } })).toBe(false);
    expect(p.track('ui.x')).toBe(undefined);
    p.hide();
    expect(p.sent()).toEqual([{ n: 'ui.x', c: 1 }]);
});

test('no sendBeacon, a throwing sendBeacon and a rejected fetch are silent', async () => {
    const none = load({ nav: { sendBeacon: undefined } });
    expect(() => none.hide()).not.toThrow();
    expect(none.beacons).toEqual([]);

    const thrown = load();
    thrown.navigator.sendBeacon = () => { throw new Error('blocked'); };
    expect(() => thrown.hide()).not.toThrow();

    const down = load({ net: 'down' });
    expect(() => down.fire()).not.toThrow();
    await settle();
    expect(down.fetches.length).toBe(1);

    const noFetch = load({ globals: { fetch: undefined } });
    expect(() => noFetch.fire()).not.toThrow();
});

test('the send is the label and the counts, and nothing else', () => {
    const p = load({ win: { location: { href: 'https://example.test/search?q=secret' } }, globals: { location: { href: 'https://example.test/search?q=secret' } } });
    const box = el({ 'data-track': 'ui.box', value: 'typed text' }, null, 'input');
    dispatch(p, 'click', box);
    p.hide();
    expect(p.beacons[0].raw).toBe('[{"n":"ui.load","s":"search","c":1},{"n":"ui.box","c":1}]');
});

test('a page restored from the back-forward cache does not count its load again', () => {
    const p = load();
    p.emit('pagehide', { persisted: true });
    p.document.visibilityState = 'visible';
    p.emit('pageshow', { persisted: true });
    p.track('ui.x');
    p.hide();
    expect(p.sent()).toEqual([LOAD, { n: 'ui.x', c: 1 }]);
});

const queued = (p) => (KEY in p.m ? JSON.parse(p.m[KEY]) : null);

test('with no network a hide parks the counts instead of sending them', () => {
    const p = load({ online: false, cfg: { on: true, page: 'offline', build: 'abc' } });
    p.track('ui.offline.search');
    p.hide();
    expect(p.beacons).toEqual([]);
    expect(queued(p)).toEqual({ d: 20000, e: [['ui.load', 'offline', '', 1], ['ui.offline.search', '', '', 1]] });
    expect(Object.keys(p.m)).toEqual([KEY]);
});

test('a refused beacon and a failed fetch are parked too', async () => {
    const refused = load({ beaconOk: false });
    refused.hide();
    expect(queued(refused).e).toEqual([['ui.load', 'search', '', 1]]);

    const down = load({ net: 'down' });  // onLine says true; the server is unreachable
    down.fire();
    await settle();
    expect(down.fetches.length).toBe(1);
    expect(queued(down).e).toEqual([['ui.load', 'search', '', 1]]);
});

test('a response of any status is not retried', async () => {
    const p = load();
    p.fire();
    await settle();
    expect(queued(p)).toBe(null);
});

test('the next load with a network sends the queue and clears it', async () => {
    const stored = { [KEY]: JSON.stringify({ d: 19995, e: [['ui.offline.failover', '', '', 2]] }) };
    const p = load({ stored, day: 20000 });
    expect(p.fetches.map((f) => f.body)).toEqual([[{ n: 'ui.offline.failover', c: 2 }]]);
    expect(queued(p)).toBe(null);
    await settle();
    expect(queued(p)).toBe(null);
});

test('a queue that fails to send goes back with its own day', async () => {
    const stored = { [KEY]: JSON.stringify({ d: 19995, e: [['ui.offline.failover', '', '', 2]] }) };
    const p = load({ stored, day: 20000, net: 'down' });
    await settle();
    expect(queued(p)).toEqual({ d: 19995, e: [['ui.offline.failover', '', '', 2]] });
});

test('seven days is kept, eight is dropped, and a broken value is removed', () => {
    const at = (d) => ({ [KEY]: JSON.stringify({ d, e: [['ui.x', '', '', 1]] }) });
    expect(load({ stored: at(19993), day: 20000 }).fetches.length).toBe(1);
    const old = load({ stored: at(19992), day: 20000 });
    expect(old.fetches).toEqual([]);
    expect(queued(old)).toBe(null);
    for (const bad of ['{not json', '[]', '{"d":"x","e":[]}', '{"d":20000,"e":"x"}']) {
        const p = load({ stored: { [KEY]: bad }, day: 20000 });
        expect(p.fetches).toEqual([]);
        expect(KEY in p.m).toBe(false);
    }
});

test('a load with no network leaves the queue alone', () => {
    const value = JSON.stringify({ d: 19999, e: [['ui.x', '', '', 1]] });
    const p = load({ stored: { [KEY]: value }, online: false, cfg: { on: true, page: '', build: 'abc' } });
    expect(p.fetches).toEqual([]);
    expect(p.m[KEY]).toBe(value);
});

test('the queue stops at 100 entries and 50 a key, and keeps its oldest day', () => {
    const e = [];
    for (let i = 0; i < 100; i++) e.push(['ui.key', '', 'v' + i, 49]);
    const p = load({ stored: { [KEY]: JSON.stringify({ d: 19999, e }) }, online: false, day: 20000, cfg: { on: true, page: '', build: 'abc' } });
    p.track('ui.key', 'v0');
    p.track('ui.key', 'v0');
    p.track('ui.new');
    p.hide();
    const q = queued(p);
    expect(q.d).toBe(19999);
    expect(q.e.length).toBe(100);
    expect(q.e[0]).toEqual(['ui.key', '', 'v0', 50]);
    expect(q.e.some((x) => x[0] === 'ui.new')).toBe(false);
});

test('storage that throws costs the counts and nothing else', () => {
    const offline = load({ storage: 'throws', online: false });
    expect(() => offline.hide()).not.toThrow();
    expect(offline.beacons).toEqual([]);

    const online = load({ storage: 'throws' });
    online.fire();
    expect(online.fetches.map((f) => f.body)).toEqual([[LOAD]]);

    const noBeacon = load();
    noBeacon.navigator.sendBeacon = () => { throw new Error('blocked'); };
    expect(() => noBeacon.hide()).not.toThrow();
    expect(queued(noBeacon).e).toEqual([['ui.load', 'search', '', 1]]);
});

test('Do Not Track, Global Privacy Control, the switch off and no config are all inert', () => {
    const stored = { [KEY]: JSON.stringify({ d: 20000, e: [['ui.x', '', '', 1]] }) };
    for (const opts of [{ dnt: '1' }, { gpc: true }, { cfg: { on: false, page: 'search', build: 'abc' } }, { cfg: null }]) {
        const ban = { other: 1 };
        const p = load({ ...opts, ban, stored: { ...stored } });
        expect(p.window.BAN).toBe(ban);
        expect(typeof ban.track).toBe('function');
        p.track('ui.x');
        expect(p.bump('ui.x', '', '', { l: 1 })).toBe(false);
        p.emit('pagehide');
        expect(p.doc).toEqual({});
        expect(p.win).toEqual({});
        expect(p.live()).toEqual([]);
        expect(p.fetches).toEqual([]);
        expect(p.beacons).toEqual([]);
        expect(p.writes).toEqual([]);                  // neither key, nor any other
        expect(Object.keys(p.m)).toEqual([]);
    }
});

test('an entry with an extra keeps it through the queue', async () => {
    const off = load({ online: false, cfg: { on: true, page: '', build: 'abc' } });
    off.bump('ui.e', 'TypeError', 'navbar.js', { l: 42, b: 'abc' });
    off.bump('ui.e', 'TypeError', 'navbar.js', { l: 42, b: 'abc' });
    off.bump('ui.e', 'TypeError', 'navbar.js', { l: 43, b: 'abc' });
    off.hide();
    expect(queued(off).e).toEqual([
        ['ui.e', 'navbar.js', 'TypeError', 2, { l: 42, b: 'abc' }],
        ['ui.e', 'navbar.js', 'TypeError', 1, { l: 43, b: 'abc' }],
    ]);

    const back = load({ stored: { [KEY]: off.m[KEY] }, cfg: { on: true, page: '', build: 'abc' } });
    expect(back.fetches.map((f) => f.body)).toEqual([[
        { n: 'ui.e', s: 'navbar.js', v: 'TypeError', c: 2, l: 42, b: 'abc' },
        { n: 'ui.e', s: 'navbar.js', v: 'TypeError', c: 1, l: 43, b: 'abc' },
    ]]);
    await settle();
    expect(queued(back)).toBe(null);
});

test('250 entries hidden with no network keep the queue\'s first 100', () => {
    const p = load({ online: false, cfg: { on: true, page: '', build: 'abc' } });
    for (let i = 0; i < 250; i++) p.track('ui.key', 'v' + i);
    p.hide();
    expect(queued(p).e.length).toBe(100);
    expect(queued(p).e[99]).toEqual(['ui.key', '', 'v99', 1]);
});

test('Do Not Track set to 0 or unspecified does not turn it off', () => {
    for (const dnt of ['0', 'unspecified', null, undefined]) {
        expect(load({ dnt }).live().length).toBe(1);
    }
});

test('every form of Do Not Track a browser exposes is inert', () => {
    const stored = { [KEY]: JSON.stringify({ d: 20000, e: [['ui.x', '', '', 1]] }) };
    const forms = [{ dnt: 'yes' }, { win: { doNotTrack: '1' } }, { win: { doNotTrack: 'yes' } }, { nav: { msDoNotTrack: '1' } }, { nav: { msDoNotTrack: 'yes' } }];
    for (const opts of forms) {
        const p = load({ ...opts, stored: { ...stored } });
        p.track('ui.x');
        p.emit('pagehide');
        expect(p.doc).toEqual({});
        expect(p.win).toEqual({});
        expect(p.live()).toEqual([]);
        expect(p.sent()).toEqual([]);
        expect(p.writes).toEqual([]);
        expect(Object.keys(p.m)).toEqual([]);
    }
    for (const gpc of [false, 'true', 1]) {
        expect(load({ gpc }).live().length).toBe(1);
    }
});

test('the network coming back sends what was parked', async () => {
    const p = load({ online: false });
    p.track('ui.x');
    p.hide();
    expect(queued(p).e.length).toBe(2);
    p.navigator.onLine = true;
    p.emit('online');
    expect(p.fetches.map((f) => f.body)).toEqual([[LOAD, { n: 'ui.x', c: 1 }]]);
    await settle();
    expect(queued(p)).toBe(null);
    p.emit('online');
    expect(p.fetches.length).toBe(1);
});

test('a queue that is malformed, oversized or from a later day is removed', () => {
    const shapes = [
        { d: 20001, e: [['ui.x', '', '', 1]] },
        { d: 20000, e: [['ui.x', '', '']] },
        { d: 20000, e: [['ui.x', '', '', '1']] },
        { d: 20000, e: [['ui.x', '', '', 0]] },
        { d: 20000, e: [['ui.x', '', '', 51]] },
        { d: 20000, e: [['ui.x', '', '', 1.5]] },
        { d: 20000, e: [['', '', '', 1]] },
        { d: 20000, e: [['ui.x', 'v'.repeat(41), '', 1]] },
        { d: 20000, e: [['ui.x', 'café', '', 1]] },
        { d: 20000, e: [['ui.x', '', '', 1, [1]]] },
        { d: 20000, e: [['ui.x', '', '', 1, { b: 'x'.repeat(81) }]] },
        { d: 20000, e: [['ui.x', '', '', 1, {}, 'more']] },
        { d: 20000, e: [null] },
        { d: 20000, e: Array.from({ length: 101 }, (_, i) => ['ui.x', '', 'v' + i, 1]) },
        { d: 20000, e: [['ui.x', '', '', 1]], pad: 'x'.repeat(70000) },
    ];
    for (const q of shapes) {
        const p = load({ stored: { [KEY]: JSON.stringify(q) }, cfg: { on: true, page: '', build: 'abc' } });
        expect(p.fetches).toEqual([]);
        expect(KEY in p.m).toBe(false);
    }
});

test('a corrupt queue is replaced, not thrown on, when counts are parked', () => {
    const p = load({ stored: { [KEY]: '{not json' }, online: false, cfg: { on: true, page: '', build: 'abc' } });
    p.track('ui.x');
    p.hide();
    expect(queued(p)).toEqual({ d: 20000, e: [['ui.x', '', '', 1]] });
});

test('a storage object that throws on any touch is survived', () => {
    const hostile = new Proxy({}, { get() { throw new Error('SecurityError'); } });
    for (const opts of [{}, { online: false }, { dnt: '1' }]) {
        let p;
        expect(() => { p = load({ ...opts, globals: { localStorage: hostile } }); }).not.toThrow();
        expect(() => p.track('ui.x')).not.toThrow();
        expect(() => p.hide()).not.toThrow();
        expect(() => p.emit('online')).not.toThrow();
    }
});

test('a privacy signal turned on mid-page discards the buffer and the queue', async () => {
    const turnOn = [
        (p) => { p.navigator.doNotTrack = '1'; },
        (p) => { p.window.doNotTrack = 'yes'; },
        (p) => { p.navigator.msDoNotTrack = '1'; },
        (p) => { p.navigator.globalPrivacyControl = true; },
    ];
    for (const on of turnOn) {
        for (const how of ['timer', 'hide', 'offline', 'rejected']) {
            const stored = { [KEY]: JSON.stringify({ d: 20000, e: [['ui.q', '', '', 1]] }) };
            const p = load({ stored, online: how !== 'offline', net: how === 'rejected' ? 'down' : 'ok' });
            p.fetches.length = 0;
            p.track('ui.x');
            if (how === 'rejected') {
                p.fire();
                on(p);
                await settle();
            } else {
                on(p);
                if (how === 'hide' || how === 'offline') p.hide(); else p.fire();
            }
            if (how !== 'rejected') expect(p.sent()).toEqual([]);
            expect(KEY in p.m).toBe(false);
            expect(p.live()).toEqual([]);
            p.track('ui.y');
            p.hide();
            expect(p.beacons).toEqual([]);
            expect(KEY in p.m).toBe(false);
        }
    }
});

test('the network coming back with a privacy signal on removes the queue unsent', () => {
    const p = load({ online: false });
    p.hide();
    expect(KEY in p.m).toBe(true);
    p.navigator.onLine = true;
    p.navigator.globalPrivacyControl = true;
    p.emit('online');
    expect(p.fetches).toEqual([]);
    expect(KEY in p.m).toBe(false);
});

test('a response with an error status is dropped, neither parked nor retried', async () => {
    for (const net of [400, 413, 429, 500, 503]) {
        const p = load({ net });
        p.track('ui.x');
        p.fire();
        await settle();
        expect(p.fetches.length).toBe(1);
        expect(queued(p)).toBe(null);
        expect(p.live()).toEqual([]);
        p.hide();
        expect(p.beacons).toEqual([]);
        expect(p.fetches.length).toBe(1);
    }
});

test('only a rejected fetch or a refused beacon parks', async () => {
    const rejected = load({ net: 'down' });
    rejected.fire();
    await settle();
    expect(queued(rejected).e).toEqual([['ui.load', 'search', '', 1]]);

    const refused = load({ beaconOk: false });
    refused.hide();
    expect(queued(refused).e).toEqual([['ui.load', 'search', '', 1]]);

    const accepted = load();
    accepted.hide();
    expect(accepted.beacons.length).toBe(1);
    expect(queued(accepted)).toBe(null);
});
