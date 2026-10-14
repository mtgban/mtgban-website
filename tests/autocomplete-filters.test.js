import { test, expect } from "bun:test";

// The file expects a browser; give bun the globals it touches at load time.
globalThis.self = globalThis.self || globalThis;
globalThis.document = globalThis.document || { createElement: () => ({}) };
require("../js/autocomplete.js");

const { liftPools } = self.AutocompleteMatch;

function lift(val) {
    const filters = [];
    const rest = liftPools(val, filters);
    return { filters, rest };
}

test("an in:(...) span is one filter, to its matching paren", () => {
    expect(lift('in:(s:CMR r:rare) dragon')).toEqual({ filters: ['in:(s:CMR r:rare)'], rest: '  dragon' });
    expect(lift('dragon -in:(contents:"A (B)") x')).toEqual({ filters: ['-in:(contents:"A (B)")'], rest: 'dragon   x' });
    expect(lift('IN:(in:(s:CMR) r:rare)')).toEqual({ filters: ['IN:(in:(s:CMR) r:rare)'], rest: ' ' });
});

test("an unbalanced span runs to the end", () => {
    expect(lift('in:(s:CMR dragon')).toEqual({ filters: ['in:(s:CMR dragon'], rest: ' ' });
});

test("a bare quote closed after the next paren is a character, not a span", () => {
    expect(lift('in:(sm:regexp ^"Ach) dark')).toEqual({ filters: ['in:(sm:regexp ^"Ach)'], rest: '  dark' });
    expect(lift('in:(sm:regexp ^"Ach) "Dark Ritual"')).toEqual({ filters: ['in:(sm:regexp ^"Ach)'], rest: '  "Dark Ritual"' });
    expect(lift('in:(s:"A (B)") x')).toEqual({ filters: ['in:(s:"A (B)")'], rest: '  x' });
});

test("a word ending in in: is not a pool", () => {
    expect(lift('Merlin:(x) y')).toEqual({ filters: [], rest: 'Merlin:(x) y' });
});

test("the token list knows in:", () => {
    // Source-level: in:CMR and in:"Name" go through the ordinary filter
    // path, which keys off this list.
    const src = require("fs").readFileSync(new URL("../js/autocomplete.js", import.meta.url), "utf8");
    expect(src).toMatch(/__acFilterToken = \/\^-\?\((?:[a-z_]+\|)*in\|/);
});
