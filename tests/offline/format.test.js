import { test, expect } from "bun:test";

globalThis.self = globalThis.self || globalThis;
require("../../js/offline/offline-format.js");

const decode = self.OfflineFormat.decode;

// Tiny uvarint writer for hand-assembled payloads (values < 2^31 only).
function uv(n) {
  const out = [];
  while (n >= 128) { out.push((n & 0x7f) | 0x80); n = Math.floor(n / 128); }
  out.push(n);
  return out;
}
function bytes(...parts) {
  return new Uint8Array(parts.flat()).buffer;
}

const HEADER = [0x4f, 0x46, 0x50, 0x31, 1, 1];
// Header + "NEO" + snapshot + empty store dict, tag dict, retail, buylist.
const MINIMAL = bytes(HEADER, uv(3), [0x4e, 0x45, 0x4f], uv(1770000000), uv(0), uv(0), uv(0), uv(0));

test("decodes a minimal empty payload", () => {
  const p = decode(MINIMAL);
  expect(p.setCode).toBe("NEO");
  expect(p.snapshot.getTime()).toBe(1770000000 * 1000);
  expect(p.retail).toEqual({});
  expect(p.buylist).toEqual({});
});

test("rejects empty input and bad magic", () => {
  expect(() => decode(new ArrayBuffer(0))).toThrow("bad magic");
  expect(() => decode(bytes([0, 1, 2, 3, 4, 5, 6]))).toThrow("bad magic");
});

test("rejects unknown format version", () => {
  const b = new Uint8Array(MINIMAL.slice(0));
  b[4] = 9;
  expect(() => decode(b.buffer)).toThrow("unsupported format version");
});

test("rejects unknown message type, including reserved delta", () => {
  const b = new Uint8Array(MINIMAL.slice(0));
  b[5] = 2;
  expect(() => decode(b.buffer)).toThrow("unsupported message type");
});

test("rejects truncation", () => {
  expect(() => decode(MINIMAL.slice(0, 8))).toThrow();
});

test("rejects out-of-range store index", () => {
  // One retail uuid "a" with one entry pointing at store index 5 of an empty dict.
  const b = bytes(HEADER, uv(3), [0x4e, 0x45, 0x4f], uv(1770000000),
    uv(0), uv(0), uv(1), uv(1), [0x61], uv(1), uv(5), [1], uv(99), uv(0));
  expect(() => decode(b)).toThrow("store index out of range");
});
