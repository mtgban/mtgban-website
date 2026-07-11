import { test, expect } from 'bun:test';
import './offline-query.js';

const Q = globalThis.OfflineQuery;

function p(s) { return Q.parse(s); }

test('bare words become names', () => {
    expect(p('sol ring').names).toEqual(['sol', 'ring']);
});

test('quoted phrase is a single name token', () => {
    expect(p('"fury sliver" foil').names).toEqual(['fury sliver', 'foil']);
});

test('set operator uppercases', () => {
    const r = p('ragavan s:mh2');
    expect(r.set).toBe('MH2');
    expect(r.names).toEqual(['ragavan']);
});

test('cn operator and bare digits both set number', () => {
    expect(p('cn:123').number).toBe('123');
    expect(p('sol ring 4').number).toBe('4');
    expect(p('sol ring 4').names).toEqual(['sol', 'ring']);
});

test('collector numbers with letters need cn:', () => {
    const r = p('cn:234a');
    expect(r.number).toBe('234a');
    expect(p('234a').names).toEqual(['234a']);
});

test('finish aliases normalize', () => {
    expect(p('f:foil').finish).toBe('foil');
    expect(p('f:f').finish).toBe('foil');
    expect(p('f:nf').finish).toBe('nonfoil');
    expect(p('f:nonfoil').finish).toBe('nonfoil');
    expect(p('f:e').finish).toBe('etched');
    expect(p('f:etched').finish).toBe('etched');
});

test('rarity aliases normalize', () => {
    expect(p('r:c').rarity).toBe('common');
    expect(p('r:uncommon').rarity).toBe('uncommon');
    expect(p('r:r').rarity).toBe('rare');
    expect(p('r:m').rarity).toBe('mythic');
});

test('unknown operator values are unsupported', () => {
    expect(p('f:gilded').unsupported).toEqual(['f:gilded']);
    expect(p('r:special').unsupported).toEqual(['r:special']);
});

test('unknown keys are unsupported verbatim', () => {
    const r = p('lotus date>2020 skip:index -s:NEO');
    expect(r.names).toEqual(['lotus']);
    expect(r.unsupported).toEqual(['date>2020', 'skip:index', '-s:NEO']);
});

test('quoted operator value', () => {
    expect(p('s:"MH2"').set).toBe('MH2');
});

test('empty and whitespace input', () => {
    expect(p('')).toEqual({names: [], set: '', number: '', finish: '', rarity: '', unsupported: []});
    expect(p('   ').names).toEqual([]);
});

test('last occurrence wins', () => {
    expect(p('s:NEO s:MH2').set).toBe('MH2');
});
