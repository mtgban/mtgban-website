import { readFileSync } from 'fs';

const names = readFileSync(new URL('../observability/names.go', import.meta.url), 'utf8');
const strings = (s) => (s ? [...s.matchAll(/"([^"]*)"/g)].map((m) => m[1]) : []);

// registry is each name's value and scope kinds and literal sets, read from observability/names.go.
export const registry = {};
for (const line of names.split('\n')) {
    const name = line.match(/\{Name: "([^"]+)"/);
    if (!name) continue;
    const values = line.match(/Values: (Value\w+)/);
    const scope = line.match(/Scope: (Scope\w+)/);
    const enums = line.match(/Enum: \[\]string\{([^}]*)\}/);
    const scopes = line.match(/Scopes: \[\]string\{([^}]*)\}/);
    registry[name[1]] = {
        values: values ? values[1] : 'ValueNone',
        scope: scope ? scope[1] : 'ScopeNone',
        enum: strings(enums && enums[1]),
        scopes: strings(scopes && scopes[1]),
    };
}

const TAG = /<[a-zA-Z][^>]*\bdata-track(?:-value|-scope)?="[^>]*>/g;
const ATTR = /\bdata-track(-value|-scope)?="([^"]*)"/g;

// marks returns each marked tag's name, value and scope; an absent attribute is undefined.
export function marks(html) {
    return (html.match(TAG) || []).map((tag) => {
        const a = {};
        for (const m of tag.matchAll(ATTR)) a[m[1] || ''] = m[2];
        return { name: a[''], value: a['-value'], scope: a['-scope'] };
    });
}

function valueOk(n, v, stores) {
    switch (n.values) {
        case 'ValueNone': return v === '';
        case 'ValueEnum': case 'ValueBucket': return n.enum.includes(v);
        case 'ValueFlag': return v === 'on' || v === 'off';
        case 'ValueStore': return v === 'other' || stores.includes(v);
        default: return false;
    }
}

function scopeOk(n, s, stores) {
    switch (n.scope) {
        case 'ScopeEnum': return n.scopes.includes(s);
        case 'ScopeStore': return stores.includes(s);
        default: return false;
    }
}

// trackProblems lists each value or scope in html outside its name's registered set.
export function trackProblems(html, stores = []) {
    const out = [];
    for (const m of marks(html)) {
        const n = registry[m.name];
        if (!n) out.push('unregistered ' + m.name);
        else if (m.value !== undefined && !valueOk(n, m.value, stores)) out.push(m.name + ' value ' + m.value);
        else if (m.scope !== undefined && !scopeOk(n, m.scope, stores)) out.push(m.name + ' scope ' + m.scope);
    }
    return out;
}

// trackText joins every data-track, data-track-value and data-track-scope in html.
export function trackText(html) {
    return [...html.matchAll(ATTR)].map((m) => m[2]).join(' ');
}
