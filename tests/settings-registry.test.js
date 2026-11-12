import { test, expect } from 'bun:test';
import { readFileSync, readdirSync } from 'fs';
import { join, relative, sep } from 'path';

// Every stored key a script writes is a registered setting, a mirror, or
// listed as not a setting in observability/settings.go, and the reverse.

const root = join(import.meta.dir, '..');
const read = (p) => readFileSync(join(root, p), 'utf8');

function walk(dir, ext) {
    return readdirSync(join(root, dir), { withFileTypes: true }).flatMap((e) => {
        const p = dir + '/' + e.name;
        return e.isDirectory() ? walk(p, ext) : e.name.endsWith(ext) ? [p] : [];
    });
}

const SOURCES = walk('js', '.js').concat(walk('templates', '.html')).map((path) => ({ path, src: read(path) }));

// The registry, read with the expressions TestSettingsSourceIsParseable pins.
const registrySrc = read('observability/settings.go');
const entries = [...registrySrc.matchAll(/^\s*\{Name: "([^"]+)"(.*)$/gm)].map((m) => {
    const mirror = m[2].match(/Mirror: "([^"]+)"/);
    const def = m[2].match(/Default: (?:"((?:[^"\\]|\\.)*)"|`([^`]*)`)/);
    return { name: m[1], mirror: mirror ? mirror[1] : '', def: def ? (def[1] !== undefined ? JSON.parse('"' + def[1] + '"') : def[2]) : '' };
});
const names = new Set(entries.map((e) => e.name));
const mirrors = new Set(entries.map((e) => e.mirror).filter(Boolean));
const notBlock = registrySrc.match(/var notSettings = \[\]string\{([\s\S]*?)\r?\n\}/);
const notSettings = new Set(notBlock ? [...notBlock[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]) : []);
const registered = (n) => entries.find((e) => e.name === n);

function known(x) {
    return names.has(x) || mirrors.has(x) || entries.some((e) => e.name.startsWith(x + '.'));
}

const quoted = (s) => [...s.matchAll(/'([^'\\\r\n]*)'|"([^"\\\r\n]*)"|`([^`]*)`/g)].map((m) => m[1] ?? m[2] ?? m[3]);
const lineOf = (src, i) => src.slice(0, i).split('\n').length;

// Names an identifier holds: var/let/const X = 'a', or X = cond ? 'a' : 'b', in the same file.
function resolve(src, id) {
    const out = [];
    const decl = new RegExp('(?:var|let|const)\\s+' + id.replace(/\$/g, '\\$') + '\\s*=\\s*([^;\\n]*)', 'g');
    for (const m of src.matchAll(decl)) {
        const v = m[1].trim();
        const one = v.match(/^(['"])([^'"]*)\1$/);
        const two = v.match(/\?\s*(['"])([^'"]*)\1\s*:\s*(['"])([^'"]*)\3$/);
        if (one) out.push(one[2]);
        else if (two) out.push(two[2], two[4]);
    }
    return out;
}

// The first argument after a call's opening: a literal, an identifier, or neither.
function firstArg(rest) {
    const lit = rest.match(/^(['"])([^'"\\]*)\1\s*[,)]/);
    if (lit) return { lit: lit[2] };
    const id = rest.match(/^([A-Za-z_$][\w$]*)\s*[,)]/);
    if (id) return { id: id[1] };
    return {};
}

const COOKIE_CALL = /(?<![\w$])(?<!function\s+)(?:setCookie|writeCookie|writeSetting)\(\s*/g;
const COOKIE_ASSIGN = /document\.cookie\s*=(?!=)\s*/g;
const LOCAL_WRITE = /(?:localStorage\.setItem|(?<![\w$.])rawSetItem)\(\s*/g;

// Files whose writes pass a name through; each supplies the names it carries.
const COOKIE_INDIRECT = {
    'js/cookies.js': () => [],
    'js/settings.js': () => {
        const block = read('js/settings.js').match(/const BINDINGS = \{([\s\S]*?)\r?\n {4}\};/);
        const out = quoted(block ? block[1] : '').filter((s) => /^[A-Z]/.test(s));
        for (const p of walk('templates/settings', '.html')) {
            const html = read(p);
            for (const m of html.matchAll(/data-cookie="([^"]+)"/g)) out.push(m[1]);
            for (const m of html.matchAll(/"CookieName" "([^"]+)"/g)) out.push(m[1]);
        }
        return out;
    },
    'js/arbit-filters.js': () => {
        const block = read('js/arbit-filters.js').match(/GROUPS = \{([^}]*)\}/);
        return quoted(block ? block[1] : '');
    },
    'js/upload-presets.js': () => quoted(read('js/upload-presets.js')).filter((s) => /^(Upload|enabled[A-Z])[A-Za-z]*$/.test(s)),
    'js/upload-tabs.js': () => quoted(read('js/upload-tabs.js')).filter((s) => /^Upload[A-Za-z]*$/.test(s)),
};
const LOCAL_INDIRECT = {
    'js/chartopts.js': () => ['BANChart', 'BANChartSealed'],
    'js/command-palette.js': () => ['mtgban_recent_searches', 'mtgban_saved_commands'],
    'js/list-storage.js': () => ['mtgban_favorites', 'mtgban_recent_searches', 'mtgban_backpack'],
    'js/offline/offline-mode.js': () => ['offline_mode', 'offline_available'],
    'js/user-state.js': () => [],
};
// Unreadable write sites per file today: a new one fails until its names are added above.
const COOKIE_INDIRECT_SITES = { 'js/cookies.js': 3, 'js/settings.js': 9, 'js/arbit-filters.js': 1, 'js/upload-presets.js': 4, 'js/upload-tabs.js': 1 };
const LOCAL_INDIRECT_SITES = { 'js/chartopts.js': 1, 'js/command-palette.js': 1, 'js/list-storage.js': 1, 'js/offline/offline-mode.js': 1, 'js/user-state.js': 2 };

// Runs one collector over sources; an indirect write in a file with no entry is an error.
function collect(sources, patterns, table, assign) {
    const found = [];
    const errors = [];
    const indirect = new Set();
    const sites = {};
    for (const { path, src } of sources) {
        for (const re of patterns) {
            for (const m of src.matchAll(re)) {
                const rest = src.slice(m.index + m[0].length);
                let arg = firstArg(rest);
                if (re === assign) {
                    const lit = rest.match(/^(['"])([^'"=]*)=/);
                    const id = rest.match(/^([A-Za-z_$][\w$]*)/);
                    arg = lit ? { lit: lit[2] } : id ? { id: id[1] } : {};
                }
                const where = path + ':' + lineOf(src, m.index);
                const got = arg.lit !== undefined ? [arg.lit] : arg.id ? resolve(src, arg.id) : [];
                if (got.length) {
                    got.forEach((name) => found.push({ name, where }));
                    continue;
                }
                indirect.add(path);
                sites[path] = (sites[path] || 0) + 1;
                if (!table[path]) errors.push(where + ': a write whose name is not readable here, and no collector for ' + path);
            }
        }
    }
    for (const path of indirect) {
        if (table[path]) table[path]().forEach((name) => found.push({ name, where: path + ' (collector)' }));
    }
    return { found, errors, indirect, sites };
}

const cookies = collect(SOURCES, [COOKIE_CALL, COOKIE_ASSIGN], COOKIE_INDIRECT, COOKIE_ASSIGN);
const locals = collect(SOURCES, [LOCAL_WRITE], LOCAL_INDIRECT, null);

test('the registry reads as the tests expect', () => {
    expect(entries.length).toBe(108);
    expect(notSettings.size).toBe(11);
});

test('every cookie a script writes is in the settings registry', () => {
    expect(cookies.errors).toEqual([]);
    expect(Object.keys(COOKIE_INDIRECT).filter((p) => !cookies.indirect.has(p))).toEqual([]);
    expect(cookies.sites).toEqual(COOKIE_INDIRECT_SITES);
    expect(cookies.found.length).toBeGreaterThan(20);
    expect(cookies.found.filter((f) => !known(f.name)).map((f) => f.where + ' ' + f.name)).toEqual([]);
});

test('every packed flag in the settings templates is registered, and the reverse', () => {
    const pairs = new Set();
    const toggles = [];
    for (const p of walk('templates', '.html')) {
        let cookie = '';
        for (const line of read(p).split('\n')) {
            const c = line.match(/id="settings-[^"]*"[^>]*data-cookie="([^"]+)"/);
            if (c) cookie = c[1];
            for (const m of line.matchAll(/data-misc="([^"]+)"/g)) pairs.add(cookie + '.' + m[1]);
            for (const m of line.matchAll(/class="m-settings-toggle"[^>]*data-val="([^"]+)"/g)) toggles.push('SearchMiscOpts.' + m[1]);
        }
    }
    const fromModal = new Set(pairs);
    toggles.forEach((t) => pairs.add(t));
    expect(pairs.size).toBeGreaterThan(10);
    expect([...pairs].filter((p) => !names.has(p))).toEqual([]);
    expect([...names].filter((n) => n.includes('.') && !fromModal.has(n))).toEqual([]);
});

test('every synced preference key is in the settings registry', () => {
    const block = read('js/user-state.js').match(/var PREF_KEYS = \[([\s\S]*?)\];/);
    const keys = quoted(block ? block[1] : '');
    expect(keys.length).toBeGreaterThan(10);
    expect(keys.filter((k) => !known(k))).toEqual([]);
});

test('every localStorage key a script writes is registered or listed as not a setting', () => {
    expect(locals.errors).toEqual([]);
    expect(Object.keys(LOCAL_INDIRECT).filter((p) => !locals.indirect.has(p))).toEqual([]);
    expect(locals.sites).toEqual(LOCAL_INDIRECT_SITES);
    expect(locals.found.length).toBeGreaterThan(20);
    expect(locals.found.filter((f) => !known(f.name) && !notSettings.has(f.name)).map((f) => f.where + ' ' + f.name)).toEqual([]);
});

// Built by concatenation, so no quoted string carries it.
const UNQUOTED = { BANChartSealed: "js/search-chart.js builds it as 'BANChart' + 'Sealed'" };
// Registered ahead of the code that writes them; empty once that code lands.
const PENDING = [];

test('every registered setting is still named somewhere in the code', () => {
    const goFiles = readdirSync(root).filter((f) => f.endsWith('.go') && !f.endsWith('_test.go'));
    const strings = new Set();
    for (const { src } of SOURCES) quoted(src).forEach((s) => strings.add(s));
    for (const f of goFiles) quoted(read(f)).forEach((s) => strings.add(s));
    const want = [...new Set(entries.map((e) => e.name.split('.')[0]).concat([...mirrors]))];
    const missing = want.filter((n) => !strings.has(n) && !UNQUOTED[n] && !PENDING.includes(n));
    expect(missing).toEqual([]);
    expect(PENDING.filter((n) => strings.has(n))).toEqual([]);
});

// A preset that writes '' leaves the server's fallback in force.
const EMPTY_IN_PRESETS = { UploadAltPrice: 'readUploadSettings falls back to UploadIndexKeys[0] for an empty cookie' };

test('the upload presets carry the registry defaults', () => {
    const src = read('js/upload-presets.js');
    const triples = [];
    for (const table of ['TEXTS', 'CUSTOM']) {
        const block = src.match(new RegExp('var ' + table + ' = \\[([\\s\\S]*?)\\];'));
        for (const m of (block ? block[1] : '').matchAll(/\[\s*'([^']*)'\s*,\s*'([^']*)'\s*,\s*'([^']*)'\s*\]/g)) triples.push(m);
    }
    expect(triples.length).toBe(17);
    const wrong = [];
    for (const [, , cookie, def] of triples) {
        const e = registered(cookie);
        if (!e) { wrong.push(cookie + ' is not registered'); continue; }
        if (def === '' && EMPTY_IN_PRESETS[cookie]) continue;
        const same = def !== '' && e.def !== '' && !isNaN(Number(def)) && !isNaN(Number(e.def)) ? Number(def) === Number(e.def) : def === e.def;
        if (!same) wrong.push(cookie + ': presets ' + JSON.stringify(def) + ', registry ' + JSON.stringify(e.def));
    }
    expect(wrong).toEqual([]);
    const flags = src.match(/var FLAG_DEFAULTS = \[([^\]]*)\]/);
    const on = entries.filter((e) => e.name.startsWith('UploadOptimizerOpts.') && e.def === 'on').map((e) => e.name.split('.')[1]);
    expect(quoted(flags ? flags[1] : '').sort()).toEqual(on.sort());
});

test('an indirect write in a file with no collector fails', () => {
    const r = collect([{ path: 'js/made-up.js', src: "function f(k){ setCookie(k, '1', 1); }" }], [COOKIE_CALL], COOKIE_INDIRECT, null);
    expect(r.errors.length).toBe(1);
    expect(r.errors[0]).toContain('no collector');
    expect(r.errors[0]).toContain('js/made-up.js:1');
});
