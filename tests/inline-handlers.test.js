import { test, expect } from 'bun:test';
import { readFileSync, readdirSync } from 'fs';
import { join } from 'path';

// Pages stream to the browser and every page script is deferred, so a
// reader can click or type before a handler's function exists. Each name an
// on*= attribute calls must be defined by then, or guarded as `window.X &&`.

const root = join(import.meta.dir, '..');
const SYNC = ['js/cookies.js', 'js/utils.js', 'js/card-art-fallback.js'];
const BUILTINS = new Set([
    'window', 'document', 'this', 'event', 'location', 'localStorage', 'history',
    'Math', 'JSON', 'parseInt', 'encodeURIComponent', 'confirm', 'alert', 'setTimeout',
    'if', 'return', 'typeof', 'function', 'try', 'catch', 'void', 'var', 'e',
]);

function templates(dir) {
    return readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
        e.isDirectory() ? templates(join(dir, e.name)) : e.name.endsWith('.html') ? [join(dir, e.name)] : []);
}

// The globals a script defines: top-level function/var and window.X =
// anywhere, which land on window, and top-level let/const, which a handler
// reaches but a window.X guard never sees. A declaration nested in an IIFE
// or another function stays local, so a handler cannot reach it.
function definedIn(src) {
    const js = src.replace(/\{\{[^}]*\}\}/g, '0');
    const onWindow = new Set();
    const lexical = new Set();
    const decl = /(function|var|let|const)\s+([A-Za-z_$][\w$]*)/y;
    const assign = /window\.([A-Za-z_$][\w$]*)\s*=(?!=)/y;
    let depth = 0;
    let prev = '';
    for (let i = 0; i < js.length;) {
        const c = js[i];
        if (c === '/' && js[i + 1] === '/') { i = js.indexOf('\n', i); if (i < 0) break; continue; }
        if (c === '/' && js[i + 1] === '*') { i = js.indexOf('*/', i + 2) + 2; if (i < 2) break; continue; }
        if (c === '"' || c === "'" || c === '`' || (c === '/' && /(?:^|[(,=:[!&|?{};]|\breturn|\btypeof)\s*$/.test(js.slice(Math.max(0, i - 8), i)))) {
            let inClass = false;
            for (i++; i < js.length && (js[i] !== c || inClass); i++) {
                if (js[i] === '\\') i++;
                else if (c === '/' && js[i] === '[') inClass = true;
                else if (c === '/' && js[i] === ']') inClass = false;
            }
            i++;
            prev = 'x';
            continue;
        }
        if (c === '{') depth++;
        else if (c === '}') depth--;
        if (!/[\w$.]/.test(prev)) {
            decl.lastIndex = assign.lastIndex = i;
            const d = depth === 0 && decl.exec(js);
            const a = assign.exec(js);
            if (d) (d[1] === 'let' || d[1] === 'const' ? lexical : onWindow).add(d[2]);
            if (a) onWindow.add(a[1]);
        }
        if (!/\s/.test(c)) prev = c;
        i++;
    }
    return { onWindow, all: new Set([...onWindow, ...lexical]) };
}

const syncNames = new Set(SYNC.flatMap((f) => [...definedIn(readFileSync(join(root, f), 'utf8')).all]));

// The global names a handler reaches for: calls and member roots, minus
// strings, template actions, locals and the browser's own globals.
function globalsUsed(code) {
    const bare = code.replace(/\{\{[^}]*\}\}/g, '0').replace(/'(?:\\.|[^'\\])*'|"(?:\\.|[^"\\])*"/g, "''");
    const locals = new Set([...bare.matchAll(/\bvar\s+([\w$]+)|,\s*([\w$]+)\s*=/g)].map((m) => m[1] || m[2]));
    const used = new Set();
    for (const m of bare.matchAll(/(?<![\w$.])([A-Za-z_$][\w$]*)\s*[(.]/g)) {
        if (!BUILTINS.has(m[1]) && !locals.has(m[1])) used.add(m[1]);
    }
    return used;
}

function guarded(code, name) {
    return new RegExp('window\\.' + name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + '\\s*(&&|\\)|\\?)').test(code);
}

// What each inline script defines, from where the page has run it: its
// closing tag, since a script runs only once the parser is past it.
function inlineScripts(html) {
    return [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\b[^>]*>/gi)].map((m) => ({
        start: m.index, end: m.index + m[0].length, ...(/\bsrc=/.test(m[1]) ? { onWindow: new Set(), all: new Set() } : definedIn(m[2])),
    }));
}

// The on*= handlers outside any script, each with where it sits.
function handlers(html, scripts) {
    return [...html.matchAll(/\son[a-z]+\s*=\s*(?:"([^"]*)"|'([^']*)')/g)]
        .filter((m) => !scripts.some((s) => m.index > s.start && m.index < s.end))
        .map((m) => ({ at: m.index, code: (m[1] ?? m[2]).replace(/&amp;/g, '&') }));
}

function unguarded(html) {
    const scripts = inlineScripts(html);
    const bad = [];
    for (const h of handlers(html, scripts)) {
        for (const name of globalsUsed(h.code)) {
            if (syncNames.has(name) || guarded(h.code, name)) continue;
            if (scripts.some((s) => s.end <= h.at && s.all.has(name))) continue;
            bad.push(name);
        }
    }
    return bad;
}

test('every inline handler calls only what exists before the deferred scripts run', () => {
    const bad = templates(join(root, 'templates')).flatMap((f) =>
        unguarded(readFileSync(f, 'utf8')).map((name) => f.replace(root + '/templates/', '') + ': ' + name));
    expect([...new Set(bad)].sort()).toEqual([]);
});

// A guard on a name no script puts on window would keep the handler inert:
// a js/ file's or the page's own inline script's.
function unbacked(html, js) {
    const page = new Set(inlineScripts(html).flatMap((s) => [...s.onWindow]));
    const missing = [];
    for (const m of html.matchAll(/\son[a-z]+\s*=\s*"[^"]*"/g)) {
        for (const g of m[0].matchAll(/window\.([A-Za-z_$][\w$]*)\s*(?:&&|\?)/g)) {
            const top = new RegExp('^function ' + g[1] + '\\b|\\b(window|self)\\.' + g[1] + '\\s*=[^=]', 'm');
            if (!top.test(js) && !page.has(g[1])) missing.push(g[1]);
        }
    }
    return missing;
}

test('every guarded name is a global some script defines', () => {
    const js = readdirSync(join(root, 'js'), { recursive: true }).filter((f) => f.endsWith('.js'))
        .map((f) => readFileSync(join(root, 'js', f), 'utf8')).join('\n');
    const missing = templates(join(root, 'templates')).flatMap((f) => unbacked(readFileSync(f, 'utf8'), js));
    expect([...new Set(missing)]).toEqual([]);
});

test('the handler scan sees calls, member roots and guards', () => {
    expect([...globalsUsed("event.stopPropagation(); toggleFavorite(this); closeActionsMenus();")]).toEqual(['toggleFavorite', 'closeActionsMenus']);
    expect([...globalsUsed("Offline && Offline.handleToggle(this)")]).toEqual(['Offline']);
    expect([...globalsUsed("var o=document.getElementById('a'),s=x;if(o&&s){o.classList.add('open')}")]).toEqual([]);
    expect([...globalsUsed("copyAndBlink(this, '{{$card.Name}}')")]).toEqual(['copyAndBlink']);
    expect(guarded('window.toggleFavorite && toggleFavorite(this)', 'toggleFavorite')).toBe(true);
    expect(guarded('toggleFavorite(this)', 'toggleFavorite')).toBe(false);
});

// A closure's helpers are not globals, and a script defines nothing for a
// handler the parser reached first.
test('the definition scan counts only top-level globals, in source order', () => {
    const src = "(function () { function helper() {} var x = '}'; window.pub = 1; })();\nfunction top() { return /[{]/.test(''); }\nvar g = { a: 1 };";
    expect([...definedIn(src).all].sort()).toEqual(['g', 'pub', 'top']);
    expect(unguarded('<button onclick="late()"></button><script>function late() {}</script>')).toEqual(['late']);
    expect(unguarded('<script>function early() {}</script><button onclick="early()"></button>')).toEqual([]);
    expect(unguarded('<script>(function () { function hidden() {} })();</script><button onclick="hidden()"></button>')).toEqual(['hidden']);
});

// A top-level let/const is a shared global but never a window property, so
// a bare call reaches it and a window.X guard never fires.
test('let and const answer a bare call but not a window guard', () => {
    const page = '<script>let lex = () => {}; const k = () => {}; function fn() {}</script>';
    expect([...definedIn("let lex = 1; const k = 2; function fn() {}").onWindow]).toEqual(['fn']);
    expect(unguarded(page + '<button onclick="lex(); k()"></button>')).toEqual([]);
    expect(unbacked(page + '<button onclick="window.lex && lex()"></button>', '')).toEqual(['lex']);
    expect(unbacked(page + '<button onclick="window.fn && fn()"></button>', '')).toEqual([]);
});
