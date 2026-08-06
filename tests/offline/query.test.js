import { test, expect } from 'bun:test';

// Shared modules attach to self; give bun one.
globalThis.self = globalThis.self || globalThis;
await import('../../js/offline/offline-query.js');

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

test('garbage inputs never throw', () => {
    expect(p('').names).toEqual([]);
    expect(p(null).names).toEqual([]);
    expect(p(undefined).names).toEqual([]);
    expect(p('\u{1F525}').names).toEqual(['\u{1F525}']);
    expect(p('""').names).toEqual([]);
});

test('unterminated quote degrades to plain tokens', () => {
    expect(p('"fury sliver').names).toEqual(['"fury', 'sliver']);
});

test('remaining rarity and finish aliases', () => {
    expect(p('r:common').rarity).toBe('common');
    expect(p('r:u').rarity).toBe('uncommon');
    expect(p('r:rare').rarity).toBe('rare');
    expect(p('f:premium').unsupported).toEqual(['f:premium']);
});

// ---- execute ----

function fakeEnv() {
    var cards = {
        'u-neo-1':  {uuid: 'u-neo-1',  n: 'Boseiju Reaches',  num: '177', r: 'rare',   set: 'NEO', f: false, e: false, s: false},
        'u-neo-1f': {uuid: 'u-neo-1f', n: 'Boseiju Reaches',  num: '177', r: 'rare',   set: 'NEO', f: true,  e: false, s: false},
        'u-mh2-1':  {uuid: 'u-mh2-1',  n: 'Boseiju Whisper',  num: '12',  r: 'mythic', set: 'MH2', f: false, e: false, s: false},
        'u-old-1':  {uuid: 'u-old-1',  n: 'Boseiju Elder',    num: '9',   r: 'rare',   set: 'OLD', f: false, e: false, s: false},
    };
    var names = [
        {key: 'boseiju reaches', uuids: ['u-neo-1', 'u-neo-1f']},
        {key: 'boseiju whisper', uuids: ['u-mh2-1']},
        {key: 'boseiju elder',   uuids: ['u-old-1']},
    ];
    var payloads = {
        NEO: {setCode: 'NEO', retail: {'u-neo-1': {CK: {regular: 1.5}}, 'u-neo-1f': {CK: {foil: 3}}}, buylist: {'u-neo-1': {CK: {regular: 0.8}}}},
        MH2: {setCode: 'MH2', retail: {'u-mh2-1': {CK: {regular: 20}}}, buylist: {}},
    };
    var env = {
        loads: [],
        normName: function (s) {
            return s.normalize('NFD').replace(/[̀-ͯ]/g, '')
                .toLowerCase().replace(/[^a-z0-9 ]+/g, ' ')
                .replace(/\s+/g, ' ').trim();
        },
        lookupName: async function (key) {
            for (var i = 0; i < names.length; i++) {
                if (names[i].key === key) return names[i].uuids.slice();
            }
            return [];
        },
        allNames: async function () { return names; },
        getCard: async function (uuid) { return cards[uuid] || null; },
        hasSet: async function (code) { return !!payloads[code]; },
        loadSetPayload: async function (code) {
            env.loads.push(code);
            return payloads[code];
        },
    };
    return env;
}

test('exact name lookup plus substring scan', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    const out = await Q.execute(Q.parse('boseiju'), env);
    const uuids = out.results.map(r => r.uuid).sort();
    expect(uuids).toEqual(['u-mh2-1', 'u-neo-1', 'u-neo-1f']);
    expect(out.missingSets).toEqual(['OLD']);
});

test('results carry payload slices', async () => {
    Q.resetCaches();
    const out = await Q.execute(Q.parse('"boseiju reaches" f:nf'), fakeEnv());
    expect(out.results.length).toBe(1);
    expect(out.results[0].retail.CK.regular).toBe(1.5);
    expect(out.results[0].buylist.CK.regular).toBe(0.8);
});

test('result rows carry the image key when present, undefined otherwise', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    env.getCard = async function (uuid) {
        const c = { 'u-neo-1':  {uuid: 'u-neo-1',  n: 'Boseiju Reaches', num: '177', r: 'rare',   set: 'NEO', f: false, e: false, s: false, i: 'abc123'},
                    'u-neo-1f': {uuid: 'u-neo-1f', n: 'Boseiju Reaches', num: '177', r: 'rare',   set: 'NEO', f: true,  e: false, s: false},
                    'u-mh2-1':  {uuid: 'u-mh2-1',  n: 'Boseiju Whisper', num: '12',  r: 'mythic', set: 'MH2', f: false, e: false, s: false} };
        return c[uuid] || null;
    };
    const out = await Q.execute(Q.parse('boseiju'), env);
    const withImg = out.results.find(r => r.uuid === 'u-neo-1');
    const withoutImg = out.results.find(r => r.uuid === 'u-mh2-1');
    expect(withImg.i).toBe('abc123');
    expect(withoutImg.i).toBeUndefined();
});

test('finish, rarity, set, and number filters', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    expect((await Q.execute(Q.parse('boseiju f:foil'), env)).results.map(r => r.uuid)).toEqual(['u-neo-1f']);
    expect((await Q.execute(Q.parse('boseiju r:mythic'), env)).results.map(r => r.uuid)).toEqual(['u-mh2-1']);
    expect((await Q.execute(Q.parse('boseiju s:MH2'), env)).results.map(r => r.uuid)).toEqual(['u-mh2-1']);
    expect((await Q.execute(Q.parse('boseiju cn:12'), env)).results.map(r => r.uuid)).toEqual(['u-mh2-1']);
});

test('set-only query walks the payload uuids', async () => {
    Q.resetCaches();
    const out = await Q.execute(Q.parse('s:NEO'), fakeEnv());
    expect(out.results.map(r => r.uuid).sort()).toEqual(['u-neo-1', 'u-neo-1f']);
});

test('set-only query on an unsynced set reports missing', async () => {
    Q.resetCaches();
    const out = await Q.execute(Q.parse('s:OLD'), fakeEnv());
    expect(out.results).toEqual([]);
    expect(out.missingSets).toEqual(['OLD']);
});

test('payload LRU avoids reloading within the cap', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    await Q.execute(Q.parse('boseiju s:NEO'), env);
    await Q.execute(Q.parse('boseiju s:NEO'), env);
    expect(env.loads).toEqual(['NEO']);
});

test('unsupported tokens pass through execute', async () => {
    Q.resetCaches();
    const out = await Q.execute(Q.parse('boseiju date>2020'), fakeEnv());
    expect(out.unsupported).toEqual(['date>2020']);
});

// A single and a sealed product that share a searchable name prefix.
function sealedEnv() {
    var cards = {
        'u-fin-box': {uuid: 'u-fin-box', n: 'Final Fantasy Booster Box', num: '', r: '', set: 'FIN', f: false, e: false, s: true},
        'u-fin-1':   {uuid: 'u-fin-1',   n: 'Final Fantasy Cloud',       num: '1', r: 'mythic', set: 'FIN', f: false, e: false, s: false},
    };
    var names = [
        {key: 'final fantasy booster box', uuids: ['u-fin-box']},
        {key: 'final fantasy cloud',       uuids: ['u-fin-1']},
    ];
    var payloads = {
        FIN: {setCode: 'FIN', retail: {'u-fin-box': {CK: {sealed: 300}}, 'u-fin-1': {CK: {regular: 20}}}, buylist: {}},
    };
    return {
        loads: [],
        normName: function (s) {
            return s.normalize('NFD').replace(/[̀-ͯ]/g, '')
                .toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim();
        },
        lookupName: async function (key) {
            for (var i = 0; i < names.length; i++) if (names[i].key === key) return names[i].uuids.slice();
            return [];
        },
        allNames: async function () { return names; },
        getCard: async function (uuid) { return cards[uuid] || null; },
        hasSet: async function (code) { return !!payloads[code]; },
        loadSetPayload: async function (code) { return payloads[code]; },
    };
}

test('sealed=false mode excludes sealed products', async () => {
    Q.resetCaches();
    const parsed = Q.parse('final fantasy');
    parsed.sealed = false;
    const out = await Q.execute(parsed, sealedEnv());
    expect(out.results.map(r => r.uuid)).toEqual(['u-fin-1']);
});

test('sealed=true mode shows only sealed products', async () => {
    Q.resetCaches();
    const parsed = Q.parse('final fantasy');
    parsed.sealed = true;
    const out = await Q.execute(parsed, sealedEnv());
    expect(out.results.map(r => r.uuid)).toEqual(['u-fin-box']);
});

test('unset sealed mode returns singles and sealed mixed', async () => {
    Q.resetCaches();
    const out = await Q.execute(Q.parse('final fantasy'), sealedEnv());
    expect(out.results.map(r => r.uuid).sort()).toEqual(['u-fin-1', 'u-fin-box']);
});

// ---- sortResults ----

test('sortResults modes', () => {
    const sets = {NEO: {d: '2022-02-18'}, MH2: {d: '2021-06-18'}};
    const rs = [
        {uuid: 'a', card: {n: 'Zeta', num: '2', set: 'MH2'}, retail: {CK: {regular: 5}}, buylist: {}},
        {uuid: 'b', card: {n: 'Alpha', num: '10', set: 'NEO'}, retail: {CK: {regular: 1}}, buylist: {CK: {regular: 9}}},
    ];
    Q.sortResults(rs, 'alpha', false, sets);
    expect(rs[0].uuid).toBe('b');
    Q.sortResults(rs, 'chrono', false, sets);
    expect(rs[0].uuid).toBe('b'); // NEO is newer
    Q.sortResults(rs, 'number', false, sets);
    expect(rs[0].uuid).toBe('a'); // 2 before 10 numerically
    Q.sortResults(rs, 'retail', false, sets);
    expect(rs[0].uuid).toBe('a'); // highest retail first
    Q.sortResults(rs, 'buylist', false, sets);
    expect(rs[0].uuid).toBe('b'); // highest buylist first
    Q.sortResults(rs, 'alpha', true, sets);
    expect(rs[0].uuid).toBe('a'); // reverse flips
});

test('LRU eviction on 9 sets (size=8)', async () => {
    Q.resetCaches();
    var cards = {};
    var names = [];
    var payloads = {};
    var setCodes = ['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9'];
    setCodes.forEach((code, idx) => {
        var uuid = 'u-' + code + '-1';
        cards[uuid] = {uuid: uuid, n: 'Card' + code, num: '1', r: 'rare', set: code, f: false, e: false, s: false};
        payloads[code] = {setCode: code, retail: {[uuid]: {CK: {regular: 1}}}, buylist: {}};
    });
    names.push({key: 'card', uuids: Object.keys(cards)});
    var env = {
        loads: [],
        normName: function (s) {
            return s.normalize('NFD').replace(/[̀-ͯ]/g, '')
                .toLowerCase().replace(/[^a-z0-9 ]+/g, ' ')
                .replace(/\s+/g, ' ').trim();
        },
        lookupName: async function (key) {
            for (var i = 0; i < names.length; i++) {
                if (names[i].key === key) return names[i].uuids.slice();
            }
            return [];
        },
        allNames: async function () { return names; },
        getCard: async function (uuid) { return cards[uuid] || null; },
        hasSet: async function (code) { return !!payloads[code]; },
        loadSetPayload: async function (code) {
            env.loads.push(code);
            return payloads[code];
        },
    };
    await Q.execute(Q.parse('card'), env);
    var s1LoadCount = env.loads.filter(c => c === 'S1').length;
    var s8LoadCount = env.loads.filter(c => c === 'S8').length;
    var s9LoadCount = env.loads.filter(c => c === 'S9').length;
    expect(s1LoadCount).toBe(1);
    expect(s8LoadCount).toBe(1);
    expect(s9LoadCount).toBe(1);
    expect(env.loads.length).toBe(9);
    await Q.execute(Q.parse('card s:S1'), env);
    s1LoadCount = env.loads.filter(c => c === 'S1').length;
    expect(s1LoadCount).toBe(2);
    var s9LoadCountAfter = env.loads.filter(c => c === 'S9').length;
    expect(s9LoadCountAfter).toBe(1);
});

test('2-char needle: exact match returns, substring scan skipped', async () => {
    Q.resetCaches();
    var allNamesCalls = 0;
    var cards = {
        'u-bo-1':  {uuid: 'u-bo-1',  n: 'Bo',        num: '1', r: 'common', set: 'TST', f: false, e: false, s: false},
        'u-bog-1': {uuid: 'u-bog-1', n: 'Bog Wraith', num: '2', r: 'common', set: 'TST', f: false, e: false, s: false},
    };
    var names = [
        {key: 'bo',         uuids: ['u-bo-1']},
        {key: 'bog wraith', uuids: ['u-bog-1']},
    ];
    var payloads = {
        TST: {setCode: 'TST', retail: {'u-bo-1': {CK: {regular: 0.5}}, 'u-bog-1': {CK: {regular: 0.3}}}, buylist: {}},
    };
    const env = {
        normName: function (s) {
            return s.normalize('NFD').replace(/[̀-ͯ]/g, '')
                .toLowerCase().replace(/[^a-z0-9 ]+/g, ' ')
                .replace(/\s+/g, ' ').trim();
        },
        lookupName: async function (key) {
            for (var i = 0; i < names.length; i++) {
                if (names[i].key === key) return names[i].uuids.slice();
            }
            return [];
        },
        allNames: async function () { allNamesCalls++; return names; },
        getCard: async function (uuid) { return cards[uuid] || null; },
        hasSet: async function (code) { return !!payloads[code]; },
        loadSetPayload: async function (code) { return payloads[code]; },
    };
    const out = await Q.execute(Q.parse('bo'), env);
    // Exact match still returned despite short needle.
    expect(out.results.map(r => r.uuid)).toEqual(['u-bo-1']);
    // allNames not called: substring scan is skipped for needles under 3 chars.
    expect(allNamesCalls).toBe(0);
});

test('rejection degradation: one set fails, others succeed', async () => {
    Q.resetCaches();
    var cards = {
        'u-good-1': {uuid: 'u-good-1', n: 'GoodCard', num: '1', r: 'rare', set: 'GOOD', f: false, e: false, s: false},
        'u-bad-1': {uuid: 'u-bad-1', n: 'BadCard', num: '2', r: 'rare', set: 'BAD', f: false, e: false, s: false},
    };
    var names = [
        {key: 'card', uuids: ['u-good-1', 'u-bad-1']},
    ];
    var payloads = {
        GOOD: {setCode: 'GOOD', retail: {'u-good-1': {CK: {regular: 1}}}, buylist: {}},
    };
    var env = {
        normName: function (s) {
            return s.normalize('NFD').replace(/[̀-ͯ]/g, '')
                .toLowerCase().replace(/[^a-z0-9 ]+/g, ' ')
                .replace(/\s+/g, ' ').trim();
        },
        lookupName: async function (key) {
            for (var i = 0; i < names.length; i++) {
                if (names[i].key === key) return names[i].uuids.slice();
            }
            return [];
        },
        allNames: async function () { return names; },
        getCard: async function (uuid) { return cards[uuid] || null; },
        hasSet: async function (code) { return code === 'GOOD' || code === 'BAD'; },
        loadSetPayload: async function (code) {
            if (code === 'BAD') {
                throw new Error('BAD set fails to load');
            }
            return payloads[code];
        },
    };
    var out = await Q.execute(Q.parse('card'), env);
    expect(out.results.length).toBe(1);
    expect(out.results[0].uuid).toBe('u-good-1');
    expect(out.missingSets).toEqual(['BAD']);
});
