import { test, expect } from 'bun:test';
import { readFileSync } from 'fs';

const source = readFileSync(new URL('../js/custom-rules.js', import.meta.url), 'utf8');

function load(cookies = {}) {
    const window = {};
    const setCookie = (name, value) => { if (value === '') delete cookies[name]; else cookies[name] = value; };
    const getCookie = (name) => cookies[name] || '';
    new Function('window', 'document', 'setCookie', 'getCookie', 'Event', source)(
        window, {}, setCookie, getCookie, class Event { constructor(t) { this.type = t; } });
    return { R: window.CustomBuylistRules, cookies };
}

const FIELDS = ['rate', 'min', 'seller', 'fallback'];

// A row whose fields hold vals, as querySelector('[data-field="x"]') finds them.
function fakeRow(vals) {
    const fields = {};
    FIELDS.forEach((f, i) => { fields[f] = { value: vals[i] }; });
    return { querySelector: (sel) => fields[sel.match(/data-field="([^"]+)"/)[1]] };
}

function fakeContainer(rows, max = 5, rules = 'UploadCustomRules') {
    return {
        getAttribute: (name) => ({ 'data-max': String(max), 'data-rules': rules })[name] ?? null,
        querySelector: () => null,
        querySelectorAll: (sel) => (sel === '.custom-rule' ? rows.map(fakeRow) : []),
    };
}

test('parse keeps the first four fields of items at a valid rate, as many as follow the first within the tier', () => {
    const { R } = load();
    expect(R.parse('', 5)).toEqual([]);
    expect(R.parse('0.6:2:TCGLow::TCGSealed:', 5)).toEqual([['0.6', '2', 'TCGLow', '']]);
    expect(R.parse('0.6:2:TCGLow,half:2:TCGLow:,0:2:TCGLow:,0.5::CK:', 5)).toEqual([['0.5', '', 'CK', '']]);
    expect(R.parse(Array(6).fill('0.5::CK:').join(','), 5)).toHaveLength(4);
    expect(R.parse(Array(12).fill('0.5::CK:').join(','), 10)).toHaveLength(9);
    expect(R.parse('0.5::CK:', 1)).toEqual([]);
    expect(R.format(R.parse('0.6:2:TCGLow:,0.5::CK:', 5))).toBe('0.6:2:TCGLow:,0.5::CK:');
});

test('collect skips the first rule, drops a bad rate and writes numbers plainly', () => {
    const { R } = load();
    const container = fakeContainer([
        ['0.8', '7', 'CK', 'TCGLow'],
        ['0.60', '2.50', 'TCGLow', ''],
        ['0,5', '1', 'CK', ''],
        ['0.4', '1,5', 'CK', ''],
    ]);
    expect(R.collect(container)).toEqual([
        ['0.6', '2.5', 'TCGLow', ''],
        ['0.4', '', 'CK', ''],
    ]);
});

test('the binding saves the rows after the first to the cookie, none clearing it', () => {
    const { R, cookies } = load({ UploadCustomRules: '0.5::CK:' });
    const two = R.binding(fakeContainer([['0.8', '7', 'CK', ''], ['0.5', '', 'TCGLow', '']]));
    expect(two.serialize()).toBe('UploadCustomRules=0.5::TCGLow:');
    two.save();
    expect(cookies.UploadCustomRules).toBe('0.5::TCGLow:');
    R.binding(fakeContainer([['0.8', '7', 'CK', '']])).save();
    expect('UploadCustomRules' in cookies).toBe(false);
});

test('the sealed rules save to a cookie of their own', () => {
    const { R, cookies } = load({ UploadCustomRules: '0.5::CK:' });
    R.binding(fakeContainer([['0.8', '7', 'TCGSealed', ''], ['0.6', '20', 'SS', '']], 5, 'UploadCustomSealedRules')).save();
    expect(cookies).toEqual({ UploadCustomRules: '0.5::CK:', UploadCustomSealedRules: '0.6:20:SS:' });
});
