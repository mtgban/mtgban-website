import { test, expect } from "bun:test";

// Shared modules attach to self; give bun one.
globalThis.self = globalThis.self || globalThis;
require("../../js/offline/offline-util.js");

const normName = self.OfflineUtil.normName;

test("lowercases and strips diacritics", () => {
  expect(normName("Jötun Grunt")).toBe("jotun grunt");
  expect(normName("Lim-Dûl's Vault")).toBe("lim dul s vault");
});

test("punctuation collapses to single spaces", () => {
  expect(normName("Fire // Ice")).toBe("fire ice");
  expect(normName("  Ach! Hans, Run!  ")).toBe("ach hans run");
});

test("keeps digits", () => {
  expect(normName("Borrowing 100,000 Arrows")).toBe("borrowing 100 000 arrows");
});

test("empty and symbol-only inputs give empty string", () => {
  expect(normName("")).toBe("");
  expect(normName("///")).toBe("");
});

// Letters of any script stay, as the online fold (internal/suggest) keeps
// them; a mark NFD splits off goes with its letter, not to a space.
test("keeps letters of any script", () => {
  expect(normName("精霊龍、ウギン")).toBe("精霊龍 ウキン");
  expect(normName("Шивский дракон")).toBe("шивскии дракон");
  expect(normName("Ἀθηνᾶ")).toBe("αθηνα");
});

test("Latin names fold as before", () => {
  expect(normName("The Ur-Dragon")).toBe("the ur dragon");
  expect(normName("Jace's Ire")).toBe("jace s ire");
  expect(normName("Ratonhnhaké:ton")).toBe("ratonhnhake ton");
});
