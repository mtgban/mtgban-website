import { test, expect } from "bun:test";

// The file expects a browser; give bun the globals it touches at load time.
globalThis.self = globalThis.self || globalThis;
globalThis.document = globalThis.document || { createElement: () => ({}) };
require("../../js/autocomplete.js");

const { fold, query, matchSpan } = self.AutocompleteMatch;

/* What a row would render: the matched part in brackets. */
function highlight(name, typed) {
    const span = matchSpan(name, fold(name), query(typed));
    if (!span) return null;
    return name.slice(0, span.start) + "[" + name.slice(span.start, span.end) + "]" + name.slice(span.end);
}

test("a name is found by what it starts with", () => {
    expect(highlight("Lightning Bolt", "light")).toBe("[Light]ning Bolt");
});

// The bug this was written for: 762 of the 4,184 sealed names begin "Secret
// Lair Drop ", and typing past that prefix used to embolden the prefix itself.
test("a drop highlights what was typed, not the words nobody types", () => {
    expect(highlight("Secret Lair Drop A Box of Rocks", "a box"))
        .toBe("Secret Lair Drop [A Box] of Rocks");
    expect(highlight("Secret Lair Drop Absolute Annihilation", "absolute"))
        .toBe("Secret Lair Drop [Absolute] Annihilation");
});

test("a leading The is skipped the same way", () => {
    expect(highlight("The Brothers' War", "brothers")).toBe("The [Brothers]' War");
});

// Punctuation is dropped on both sides, so five typed characters can cover six
// of the name and the span has to stretch to hold them.
test("a name found without its punctuation highlights all of it", () => {
    expect(highlight("Jace's Ire", "jaces")).toBe("[Jace's] Ire");
    expect(highlight("Lim-Dûl's Vault", "limduls")).toBe("[Lim-Dûl's] Vault");
});

test("a name found without its diacritics highlights the letters it has", () => {
    expect(highlight("Jötun Grunt", "jotun")).toBe("[Jötun] Grunt");
});

test("typing the prefix itself still matches from the front", () => {
    expect(highlight("Secret Lair Drop A Box of Rocks", "secret lair"))
        .toBe("[Secret Lair] Drop A Box of Rocks");
});

test("a name that does not match is not offered", () => {
    expect(highlight("Lightning Bolt", "counterspell")).toBeNull();
    expect(highlight("Secret Lair Drop A Box of Rocks", "zzz")).toBeNull();
});

test("punctuation alone matches nothing it is not part of", () => {
    expect(highlight("Lightning Bolt", "'")).toBeNull();
    expect(highlight("Lightning Bolt", "")).toBeNull();
});

// One card really is named "_____", and it folds to nothing at all. Comparing
// what folds to nothing against what folds to nothing is what used to match
// every name in the list, so this compares the characters themselves.
test("a name made only of punctuation is found by typing it", () => {
    expect(highlight("_____", "_____")).toBe("[_____]");
    expect(highlight("_____", "___")).toBe("[___]__");
    expect(highlight("Lightning Bolt", "___")).toBeNull();
});

test("the whole name highlights when the whole name is typed", () => {
    expect(highlight("Sol Ring", "sol ring")).toBe("[Sol Ring]");
});

test("folding sets case, diacritics and punctuation aside", () => {
    expect(fold("Jace's Ire")).toBe("JACES IRE");
    expect(fold("Jötun Grunt")).toBe("JOTUN GRUNT");
    expect(fold("Fire // Ice")).toBe("FIRE  ICE");
});

// 357 of the names carry no ASCII letter at all. Folding to A-Z alone would
// leave each of them folding to nothing, findable by nobody.
test("a name in another script is found by typing it", () => {
    expect(highlight("Воин Лакватуса", "воин")).toBe("[Воин] Лакватуса");
    expect(highlight("Κλεοπάτρα, Ἐξόριστος Φαραώ", "κλεο")).toBe("[Κλεο]πάτρα, Ἐξόριστος Φαραώ");
});

// The rule that stripped punctuation compared "" to "" when the typed text had
// no A-Z in it, so a Japanese query used to match every name in the list.
test("text with no letters of its own matches nothing rather than everything", () => {
    expect(highlight("15th Anniversary 2-Player Starter Set", "かさ上")).toBeNull();
    expect(highlight("Lightning Bolt", "!!!")).toBeNull();
    expect(highlight("15th Anniversary 2-Player Starter Set", "_____")).toBeNull();
});

// An accent used to be deleted rather than folded, so "Dríadas" read as
// "Dradas" and answered to "dra" - a word it does not contain.
test("an accented letter folds to its own letter, not to nothing", () => {
    expect(highlight("Dríadas de Shanodín", "dri")).toBe("[Drí]adas de Shanodín");
    expect(highlight("Dríadas de Shanodín", "dra")).toBeNull();
});

// A name whose distinctive part opens with punctuation was reachable by
// neither route before: the prefix rule stopped at the quote.
test("a drop is found past the punctuation its name opens with", () => {
    expect(highlight("Secret Lair Drop “explosion sounds”", "explosion"))
        .toBe("Secret Lair Drop “[explosion] sounds”");
});
