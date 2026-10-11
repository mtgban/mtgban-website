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

function definedIn(src) {
    const names = new Set();
    for (const m of src.matchAll(/\bfunction\s+([A-Za-z_$][\w$]*)|\bwindow\.([A-Za-z_$][\w$]*)\s*=[^=]|\bvar\s+([A-Za-z_$][\w$]*)/g)) {
        names.add(m[1] || m[2] || m[3]);
    }
    return names;
}

const syncNames = new Set(SYNC.flatMap((f) => [...definedIn(readFileSync(join(root, f), 'utf8'))]));

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

test('every inline handler calls only what exists before the deferred scripts run', () => {
    const bad = [];
    for (const f of templates(join(root, 'templates'))) {
        const html = readFileSync(f, 'utf8');
        const inline = definedIn([...html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script\b[^>]*>/gi)].map((m) => m[1]).join('\n'));
        let markup = html;
        for (let prev = ''; prev !== markup;) {
            prev = markup;
            markup = markup.replace(/<script\b[^>]*>[\s\S]*?<\/script\b[^>]*>/gi, '');
        }
        for (const m of markup.matchAll(/\son[a-z]+\s*=\s*(?:"([^"]*)"|'([^']*)')/g)) {
            const code = (m[1] ?? m[2]).replace(/&amp;/g, '&');
            for (const name of globalsUsed(code)) {
                if (syncNames.has(name) || inline.has(name) || guarded(code, name)) continue;
                bad.push(f.replace(root + '/templates/', '') + ': ' + name);
            }
        }
    }
    expect([...new Set(bad)].sort()).toEqual([]);
});

// A guard on a name no script puts on window would keep the handler inert.
test('every guarded name is a global some script defines', () => {
    const js = readdirSync(join(root, 'js'), { recursive: true }).filter((f) => f.endsWith('.js'))
        .map((f) => readFileSync(join(root, 'js', f), 'utf8')).join('\n');
    const missing = [];
    for (const f of templates(join(root, 'templates'))) {
        for (const m of readFileSync(f, 'utf8').matchAll(/\son[a-z]+\s*=\s*"[^"]*"/g)) {
            for (const g of m[0].matchAll(/window\.([A-Za-z_$][\w$]*)\s*(?:&&|\?)/g)) {
                const top = new RegExp('^function ' + g[1] + '\\b|\\b(window|self)\\.' + g[1] + '\\s*=[^=]', 'm');
                if (!top.test(js)) missing.push(g[1]);
            }
        }
    }
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
