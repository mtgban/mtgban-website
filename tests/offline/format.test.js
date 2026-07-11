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

// stores: ["SCG"] tags (sorted): ["LP"=0, "NM"=1, "SP"=2]
// Entry flags = 1|16|32|64|128 = 241: regular, cond, condmap, qtymap, baseqty.
// Byte order: regular, baseqty x4, cond tagIdx, condmap (n, tagIdx, cents)x2, qtymap (n, tagIdx, qty)x2.
test("retail entry flags=1|16|32|64|128 decodes every field in read order", () => {
  const b = bytes(
    HEADER,
    uv(3), [0x4e, 0x45, 0x4f],
    uv(1770000000),
    uv(1), uv(3), [0x53, 0x43, 0x47],
    uv(3), uv(2), [0x4c, 0x50], uv(2), [0x4e, 0x4d], uv(2), [0x53, 0x50],
    uv(1), uv(2), [0x75, 0x31],
      uv(1),
        uv(0), [241],
        uv(99),
        uv(5), uv(3), uv(1), uv(2),
        uv(1),
        uv(2), uv(0), uv(89), uv(2), uv(75),
        uv(2), uv(1), uv(10), uv(2), uv(3),
    uv(0),
  );
  const p = decode(b);
  const e = p.retail["u1"]["SCG"];
  expect(e.regular).toBe(0.99);
  expect(e.qty).toBe(5);
  expect(e.qtyFoil).toBe(3);
  expect(e.qtyEtched).toBe(1);
  expect(e.qtySealed).toBe(2);
  expect(e.cond).toBe("NM");
  expect(e.conditions).toEqual({ LP: 0.89, SP: 0.75 });
  expect(e.quantities).toEqual({ NM: 10, SP: 3 });
});

// Entry flags = 2|4|8 = 14: foil, etched, sealed. Prices read in bit order 2->4->8.
test("foil/etched/sealed prices decode in bit order flags=2|4|8", () => {
  const b = bytes(
    HEADER,
    uv(3), [0x4e, 0x45, 0x4f],
    uv(1770000000),
    uv(1), uv(3), [0x53, 0x43, 0x47],
    uv(0),
    uv(1), uv(2), [0x75, 0x32],
      uv(1),
        uv(0), [14],
        uv(120),
        uv(75),
        uv(99),
    uv(0),
  );
  const p = decode(b);
  const e = p.retail["u2"]["SCG"];
  expect(e.foil).toBe(1.2);
  expect(e.etched).toBe(0.75);
  expect(e.sealed).toBe(0.99);
  expect(e.regular).toBeUndefined();
});

// Buffer ends on a continuation byte (0x80) inside a varint read for the regular price.
test("throws on truncation mid-varint", () => {
  const b = bytes(
    HEADER,
    uv(3), [0x4e, 0x45, 0x4f],
    uv(1770000000),
    uv(1), uv(1), [0x53],
    uv(0),
    uv(1), uv(1), [0x75],
      uv(1),
        uv(0), [1],
        [0x80],
  );
  expect(() => decode(b)).toThrow();
});

// Tag dict has 1 entry ("NM"), entry cond field references tag index 5 -> out of range.
test("throws on tag index out of range", () => {
  const b = bytes(
    HEADER,
    uv(3), [0x4e, 0x45, 0x4f],
    uv(1770000000),
    uv(1), uv(3), [0x53, 0x43, 0x47],
    uv(1), uv(2), [0x4e, 0x4d],
    uv(1), uv(2), [0x75, 0x31],
      uv(1),
        uv(0), [17],
        uv(99),
        uv(5),
    uv(0),
  );
  expect(() => decode(b)).toThrow("tag index out of range");
});
