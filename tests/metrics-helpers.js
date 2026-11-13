import { expect } from 'bun:test';
import { readFileSync } from 'fs';

// read returns a repo file's text, path relative to the repo root, with LF line endings.
export function read(rel) {
    return readFileSync(new URL('../' + rel, import.meta.url), 'utf8').replace(/\r\n/g, '\n');
}

// tagEnd returns the index of the > closing the tag opened at start, skipping quoted values and {{ }} actions.
function tagEnd(src, start) {
    let quote = null;
    let depth = 0;
    for (let j = start + 1; j < src.length; j++) {
        if (src.startsWith('{{', j)) { depth++; j++; continue; }
        if (depth > 0) {
            if (src.startsWith('}}', j)) { depth--; j++; }
            continue;
        }
        const c = src[j];
        if (quote) {
            if (c === quote) quote = null;
            continue;
        }
        if (c === '"' || c === "'") { quote = c; continue; }
        if (c === '>') return j;
    }
    return -1;
}

// tagsWith returns every opening tag in src that contains marker.
export function tagsWith(src, marker) {
    const out = [];
    const seen = new Set();
    for (let i = src.indexOf(marker); i >= 0; i = src.indexOf(marker, i + marker.length)) {
        const start = src.lastIndexOf('<', i);
        if (start < 0 || seen.has(start)) continue;
        const end = tagEnd(src, start);
        if (end < i) continue;
        seen.add(start);
        out.push(src.slice(start, end + 1));
    }
    return out;
}

// expectTrack asserts a tag's data-track attributes as literal text; undefined means absent.
export function expectTrack(tag, name, value, scope) {
    expect(tag).toContain('data-track="' + name + '"');
    for (const [attr, want] of [['data-track-value', value], ['data-track-scope', scope]]) {
        if (want === undefined) expect(tag).not.toContain(attr + '=');
        else expect(tag).toContain(attr + '="' + want + '"');
    }
}

// fakeBAN stands in for window.BAN and records each track call as [name, value, scope].
export function fakeBAN() {
    const calls = [];
    return { BAN: { track(n, v, s) { calls.push([n, v, s]); } }, calls };
}
