import { test, expect } from 'bun:test';
import { readdirSync } from 'fs';
import { join } from 'path';
import { loadMetrics } from './metrics-loader.js';

const BUILD = '0f'.repeat(20);
const ORIGIN = 'https://www.mtgban.com';
const location = {origin: ORIGIN, href: ORIGIN + '/search?q=bolt', pathname: '/search'};
const unsampled = Object.assign(Object.create(Math), {random: () => 0.99});

function load(on = true, build = BUILD) {
    return loadMetrics({
        cfg: {on, page: 'search', build},
        globals: {location, Math: unsampled, performance: {}, PerformanceObserver: undefined},
    });
}
// sent hides the page, then returns every entry that left it.
function sent(m) {
    m.hide('pagehide');
    return m.sent();
}

const errors = entries => entries.filter(e => e.n === 'ui.js.error' || e.n === 'ui.js.rejection');

test('an error in a site script is sent with its file, line, class and build', () => {
    const m = load();
    m.emit('error', {filename: ORIGIN + '/js/navbar.js?hash=' + BUILD, lineno: 42, colno: 7,
        message: 'secret is not a function', error: new TypeError('secret is not a function')});
    expect(errors(sent(m))).toEqual([{n: 'ui.js.error', s: 'navbar.js', v: 'TypeError', c: 1, l: 42, b: BUILD}]);
});

test('nothing sent carries the message, the stack or a URL', () => {
    const m = load();
    const err = new TypeError('secret-message');
    err.stack = 'TypeError: secret-message\n    at go (' + ORIGIN + '/js/offline/offline-db.js?hash=x:9:1)';
    m.emit('error', {filename: ORIGIN + '/js/navbar.js', lineno: 1, message: 'secret-message', error: err});
    m.emit('unhandledrejection', {reason: err});
    const body = JSON.stringify(sent(m));
    expect(body).not.toContain('secret-message');
    expect(body).not.toContain('http');
    expect(body).not.toContain(' at ');
});

test('a cross-origin script error is ScriptError in other at line 0', () => {
    for (const filename of ['', 'https://cdn.example/lib.js']) {
        const m = load();
        m.emit('error', {filename, lineno: 3, message: 'Script error.', error: null});
        expect(errors(sent(m))).toEqual([{n: 'ui.js.error', s: 'other', v: 'ScriptError', c: 1, l: 0, b: BUILD}]);
    }
});

test('where a script is', () => {
    const cases = [
        [ORIGIN + '/js/offline/offline-db.js?hash=abc', 12, 'offline-db.js', 12],
        [ORIGIN + '/js/vendor/fflate.min.js', 1, 'fflate.min.js', 1],
        [ORIGIN + '/search?q=bolt', 913, 'inline', 0],
        ['https://unpkg.com/lucide@1.47.0/dist/umd/lucide.js', 77, 'other', 0],
        ['https://evil.example/js/navbar.js', 5, 'other', 0],
        [ORIGIN + '/js/../admin', 5, 'inline', 0],
        ['chrome-extension://abcdef/content.js', 5, 'other', 0],
        [ORIGIN + '/js/navbar.js', 0, 'navbar.js', 0],
        [ORIGIN + '/js/navbar.js', 2000000, 'navbar.js', 0],
        [ORIGIN + '/js/navbar.js', 3.5, 'navbar.js', 0],
    ];
    for (const [filename, lineno, script, line] of cases) {
        const m = load();
        m.emit('error', {filename, lineno, error: new RangeError('x')});
        expect(errors(sent(m))).toEqual([{n: 'ui.js.error', s: script, v: 'RangeError', c: 1, l: line, b: BUILD}]);
    }
});

test('an unknown error name is other', () => {
    for (const error of [{name: 'MyAppError'}, {name: 42}, null, 'a string', undefined]) {
        const m = load();
        m.emit('error', {filename: ORIGIN + '/js/navbar.js', lineno: 3, error});
        expect(errors(sent(m))[0].v).toBe('other');
    }
});

test('a rejection is placed by the top frame of its stack', () => {
    const chrome = 'TypeError: x\n    at load (' + ORIGIN + '/js/favorites.js?hash=abc:88:13)\n    at ' + ORIGIN + '/js/utils.js:5:1';
    const firefox = 'load@' + ORIGIN + '/js/favorites.js?hash=abc:88:13\n@' + ORIGIN + '/js/utils.js:5:1\n';
    for (const stack of [chrome, firefox]) {
        const m = load();
        const reason = new TypeError('x');
        reason.stack = stack;
        m.emit('unhandledrejection', {reason});
        expect(errors(sent(m))).toEqual([{n: 'ui.js.rejection', s: 'favorites.js', v: 'TypeError', c: 1, l: 88, b: BUILD}]);
    }
});

test('a message line that looks like a frame is skipped', () => {
    const m = load();
    const reason = new TypeError('x');
    reason.stack = 'TypeError: failed ' + ORIGIN + '/js/navbar.js:1:2\n    at load (' + ORIGIN + '/js/favorites.js:88:13)';
    m.emit('unhandledrejection', {reason});
    expect(errors(sent(m))).toEqual([{n: 'ui.js.rejection', s: 'favorites.js', v: 'TypeError', c: 1, l: 88, b: BUILD}]);
});

test('a script not on the site list is other at line 0', () => {
    const m = load();
    m.emit('error', {filename: ORIGIN + '/js/not-a-site-file.js', lineno: 12, error: new TypeError('x')});
    expect(errors(sent(m))).toEqual([{n: 'ui.js.error', s: 'other', v: 'TypeError', c: 1, l: 0, b: BUILD}]);
});

test('a V8 message holding @ is not read as a frame', () => {
    const m = load();
    const reason = new TypeError('x');
    reason.stack = 'TypeError: a@b.c sent to ' + ORIGIN + '/js/navbar.js:12:3\n    at f (' + ORIGIN + '/js/favorites.js:5:1)';
    m.emit('unhandledrejection', {reason});
    expect(errors(sent(m))).toEqual([{n: 'ui.js.rejection', s: 'favorites.js', v: 'TypeError', c: 1, l: 5, b: BUILD}]);
});

test('a Firefox frame is still read', () => {
    const m = load();
    const reason = new TypeError('x');
    reason.stack = 'f@' + ORIGIN + '/js/navbar.js:5:1\n';
    m.emit('unhandledrejection', {reason});
    expect(errors(sent(m))).toEqual([{n: 'ui.js.rejection', s: 'navbar.js', v: 'TypeError', c: 1, l: 5, b: BUILD}]);
});

// siteScripts walks js/ for the basenames a report may name.
function siteScripts() {
    const out = new Set();
    const walk = dir => {
        for (const d of readdirSync(dir, {withFileTypes: true})) {
            if (d.isDirectory()) walk(join(dir, d.name));
            else if (d.name.endsWith('.js')) out.add(d.name);
        }
    };
    walk(join(import.meta.dir, '..', 'js'));
    return out;
}

test('only closed words and integers reach the wire', () => {
    const scripts = siteScripts();
    const classes = new Set(['Error', 'TypeError', 'ReferenceError', 'RangeError', 'SyntaxError', 'URIError', 'EvalError', 'AggregateError', 'AbortError', 'NetworkError', 'QuotaExceededError', 'NotAllowedError', 'SecurityError', 'InvalidStateError', 'NotFoundError', 'TimeoutError', 'ScriptError', 'other']);
    const filenames = [
        ORIGIN + '/js/secret-user-token.js?x=1',
        ORIGIN + '/js/secret-user-token.js',
        ORIGIN + '/js/constructor.js', ORIGIN + '/js/hasownproperty.js', ORIGIN + '/js/valueof.js',
        ORIGIN + '/js/tostring.js', ORIGIN + '/js/__proto__.js', ORIGIN + '/js/length.js',
    ];
    const msgFrame = (msg, frames) => {
        const r = new TypeError(msg);
        r.stack = 'TypeError: ' + msg + frames;
        return r;
    };
    const reasons = [
        msgFrame('a@b.c sent to ' + ORIGIN + '/js/leak-me.js:12:3', '\n    at f (' + ORIGIN + '/js/navbar.js:5:1)'),
        msgFrame('a@b.c sent to ' + ORIGIN + '/js/navbar.js:4242:3', ''),
        msgFrame('boom\n    at ' + ORIGIN + '/js/navbar.js:777:1', '\n    at f (' + ORIGIN + '/js/favorites.js:5:1)'),
        msgFrame('boom\nx@' + ORIGIN + '/js/navbar.js:778:1', ''),
        msgFrame('at ' + ORIGIN + '/js/secret-user-token.js:12:3', '\n    at f (' + ORIGIN + '/js/secret-user-token.js:9:1)'),
        {name: 'TypeError', stack: 'g@' + ORIGIN + '/js/secret-user-token.js:3:1\n'},
        {name: 'constructor', stack: '    at ' + ORIGIN + '/js/constructor.js:3:1'},
    ];
    const seen = [];
    for (const filename of filenames) {
        const m = load();
        m.emit('error', {filename, lineno: 12, message: 'secret', error: new TypeError('secret')});
        seen.push(...errors(sent(m)));
    }
    for (const reason of reasons) {
        const m = load();
        m.emit('unhandledrejection', {reason});
        seen.push(...errors(sent(m)));
    }
    expect(seen.length).toBe(filenames.length + reasons.length);
    for (const e of seen) {
        expect(Object.keys(e).sort()).toEqual(['b', 'c', 'l', 'n', 's', 'v']);
        expect(e.s === 'inline' || e.s === 'other' || scripts.has(e.s)).toBe(true);
        expect(classes.has(e.v)).toBe(true);
        expect(Number.isInteger(e.l) && Number.isInteger(e.c)).toBe(true);
        expect(e.b).toBe(BUILD);
        expect([12, 777, 778, 4242]).not.toContain(e.l);
    }
    expect(seen.filter(e => e.s === 'navbar.js' || e.s === 'favorites.js').map(e => [e.s, e.l])).toEqual([['navbar.js', 5], ['favorites.js', 5]]);
});

test('a rejection with no usable stack is other at line 0', () => {
    for (const reason of ['failed', undefined, {name: 'AbortError'}, {name: 'TypeError', stack: 'TypeError: x'}]) {
        const m = load();
        m.emit('unhandledrejection', {reason});
        const got = errors(sent(m));
        expect(got.length).toBe(1);
        expect(got[0].s).toBe('other');
        expect(got[0].l).toBe(0);
    }
    const m = load();
    m.emit('unhandledrejection', {reason: {name: 'AbortError'}});
    expect(errors(sent(m))[0].v).toBe('AbortError');
});

test('at most five errors a page, errors and rejections together', () => {
    const m = load();
    for (let i = 1; i <= 4; i++) {
        m.emit('error', {filename: ORIGIN + '/js/navbar.js', lineno: i, error: new Error('x')});
    }
    for (let i = 0; i < 4; i++) {
        m.emit('unhandledrejection', {reason: new Error('x')});
    }
    const total = errors(sent(m)).reduce((sum, e) => sum + e.c, 0);
    expect(total).toBe(5);
});

test('the same error twice is one entry with a count of two', () => {
    const m = load();
    const e = {filename: ORIGIN + '/js/navbar.js', lineno: 9, error: new TypeError('x')};
    m.emit('error', e);
    m.emit('error', e);
    expect(errors(sent(m))).toEqual([{n: 'ui.js.error', s: 'navbar.js', v: 'TypeError', c: 2, l: 9, b: BUILD}]);
});

test('a failed image is not a script error', () => {
    const m = load();
    expect(m.win.error.every(h => !h.capture)).toBe(true); // the loader records capture as a boolean
    expect(m.doc.error).toBeUndefined();
    m.emit('error', {target: {tagName: 'IMG'}});
    expect(errors(sent(m))).toEqual([]);
});

test('a handler that throws does not escape', () => {
    const m = load();
    const hostile = {get filename() { throw new Error('boom'); }};
    expect(() => m.emit('error', hostile)).not.toThrow();
    expect(() => m.emit('unhandledrejection', {get reason() { throw new Error('boom'); }})).not.toThrow();
});

test('no listener when metrics are off', () => {
    const m = load();
    const off = load(false);
    expect(m.win.error.length).toBe(1);
    expect(m.win.unhandledrejection.length).toBe(1);
    expect(off.win.error).toBeUndefined();
    expect(off.win.unhandledrejection).toBeUndefined();
});

test('no listener on a build with no commit hash', () => {
    for (const build of ['', '-1731300000000000000', 'abc', null]) {
        const m = load(true, build);
        expect(m.win.error).toBeUndefined();
        expect(m.win.unhandledrejection).toBeUndefined();
    }
    expect(load(true, BUILD + '-1731300000000000000').win.error.length).toBe(1);
});
