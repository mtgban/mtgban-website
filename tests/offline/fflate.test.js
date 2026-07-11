import { test, expect } from "bun:test";

// Shared modules attach to self; give bun one.
globalThis.self = globalThis.self || globalThis;
const fflate = await import("../../js/vendor/fflate.min.js");

test("fflate zipSync and unzipSync roundtrip", () => {
  const input = { "a.webp": new Uint8Array([1, 2, 3]) };
  const zipped = fflate.zipSync(input);
  const unzipped = fflate.unzipSync(zipped);
  expect(Array.from(unzipped["a.webp"])).toEqual([1, 2, 3]);
});

test("fflate handles multiple files in archive", () => {
  const input = {
    "file1.txt": new Uint8Array([65, 66, 67]),
    "file2.txt": new Uint8Array([88, 89, 90]),
  };
  const zipped = fflate.zipSync(input);
  const unzipped = fflate.unzipSync(zipped);
  expect(Array.from(unzipped["file1.txt"])).toEqual([65, 66, 67]);
  expect(Array.from(unzipped["file2.txt"])).toEqual([88, 89, 90]);
});
