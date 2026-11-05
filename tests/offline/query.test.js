import { test, expect } from 'bun:test';

// Shared modules attach to self; give bun one.
globalThis.self = globalThis.self || globalThis;
await import('../../js/offline/offline-query.js');

const Q = globalThis.OfflineQuery;

// The rarities a Magic catalog lists, rarest first, which a single r: letter
// is read against.
const magic = ['oversize', 'special', 'mythic', 'rare', 'uncommon', 'common', 'token'].map(value => ({value}));

function p(s) { return Q.parse(s, [], magic); }

test('bare words become names', () => {
    expect(p('sol ring').names).toEqual(['sol', 'ring']);
});

test('quoted phrase is a single name token', () => {
    expect(p('"fury sliver" foil').names).toEqual(['fury sliver', 'foil']);
});

test('set operator uppercases', () => {
    const r = p('ragavan s:mh2');
    expect(r.set).toEqual(['MH2']);
    expect(r.names).toEqual(['ragavan']);
});

// The menu offers e: beside s:, and online both are the edition filter,
// as are set: and edition:.
test('every spelling of the set operator is read', () => {
    for (const key of ['e', 'set', 'edition']) {
        expect(p(key + ':mh2')).toMatchObject({set: ['MH2'], unsupported: []});
    }
});

test('cn operator and bare digits both set number', () => {
    expect(p('cn:123').number).toMatchObject([{values: ['123'], strict: false}]);
    expect(p('sol ring 4').number).toMatchObject([{values: ['4'], strict: false}]);
    expect(p('sol ring 4').names).toEqual(['sol', 'ring']);
});

// Every link the site builds for one printing spells the number cns: - it is
// the number the printing prints, marks and all - so offline has to read it,
// against the number the catalog stores as printed.
test('cns is read as the printed number', () => {
    expect(p('cns:1116jpn').number).toMatchObject([{values: ['1116jpn'], strict: true}]);
    expect(p('cns:123').number).toMatchObject([{values: ['123'], strict: true}]);
    expect(p('plaguecrafter s:sld cns:1116jpn f:nonfoil')).toMatchObject({
        set: ['SLD'], number: [{values: ['1116jpn'], strict: true}], finish: [['nonfoil']], names: ['plaguecrafter'],
    });
    // and it is not left sitting in the unsupported pile
    expect(p('cns:1116jpn').unsupported).toEqual([]);
});

test('collector numbers with letters', () => {
    const r = p('cn:234a');
    expect(r.number).toMatchObject([{values: ['234a']}]);
    expect(p('234a')).toMatchObject({names: [], bareNumber: '234a', number: [{values: ['234a'], strict: true}]});
});

test('finish aliases normalize', () => {
    expect(p('f:foil').finish).toEqual([['foil']]);
    expect(p('f:f').finish).toEqual([['foil']]);
    expect(p('f:nf').finish).toEqual([['nonfoil']]);
    expect(p('f:nonfoil').finish).toEqual([['nonfoil']]);
    expect(p('f:e').finish).toEqual([['etched']]);
    expect(p('f:etched').finish).toEqual([['etched']]);
});

// A game's own finish is taken where the catalog names it, folded the way
// the catalog spells it; anything else stays unsupported.
test('a finish the catalog names is read', () => {
    const finishes = [{value: 'rainbowfoil', label: 'Rainbow Foil'}];
    expect(p('f:foil').finish).toEqual([['foil']]);
    expect(Q.parse('f:Rainbow-Foil', finishes).finish).toEqual([['rainbowfoil']]);
    expect(Q.parse('f:galaxy', finishes).unsupported).toEqual(['f:galaxy']);
    expect(p('f:rainbowfoil').unsupported).toEqual(['f:rainbowfoil']);
});

// A short form is read where the catalog files it under a treatment, and
// reaches the cards that list it, as f:galaxy reaches galaxy foils online.
test('a short form the catalog files is read', () => {
    const finishes = [{value: 'galaxyfoil', label: 'Galaxy Foil', aliases: ['galaxy']}];
    expect(Q.parse('f:galaxy', finishes)).toMatchObject({finish: [['galaxy']], unsupported: []});
    expect(Q.parse('f:surge', finishes).unsupported).toEqual(['f:surge']);
});

// A comma list names any of its values, as it does online. A finish list
// offline cannot answer in full is left unsupported, as one value would be.
test('comma lists name any of their values', () => {
    const finishes = [{value: 'galaxyfoil', label: 'Galaxy Foil', aliases: ['galaxy']}];
    expect(Q.parse('s:mh2,MH3 f:foil,galaxy', finishes)).toMatchObject({
        set: ['MH2', 'MH3'], finish: [['foil', 'galaxy']], unsupported: [],
    });
    expect(Q.parse('f:foil,surge', finishes)).toMatchObject({finish: [], unsupported: ['f:foil,surge']});
});

test('rarity aliases normalize', () => {
    expect(p('r:c').rarity).toEqual(['common']);
    expect(p('r:uncommon').rarity).toEqual(['uncommon']);
    expect(p('r:r').rarity).toEqual(['rare']);
    expect(p('r:m').rarity).toEqual(['mythic']);
});

// r: reads as it does online: a comma list, each value a rarity spelled as
// one lower-case word, or a letter naming each of the game's it begins.
test('rarity lists and short forms read as online', () => {
    expect(p('r:s,t,o').rarity).toEqual(['special', 'token', 'oversize']);
    expect(p('r:rare,M').rarity).toEqual(['rare', 'mythic']);
    expect(p('r:special')).toMatchObject({rarity: ['special'], unsupported: []});
    expect(p('r:bonus')).toMatchObject({rarity: ['bonus'], unsupported: []});
});

// Every game's catalog brings its own rarities: a letter names each one it
// begins, and a rarity is one word however a query spaces or cases it.
test('rarity letters come from the catalog game', () => {
    const lorcana = ['special', 'enchanted', 'superrare', 'rare', 'common'].map(value => ({value}));
    expect(Q.parse('r:s', [], lorcana).rarity).toEqual(['special', 'superrare']);
    expect(Q.parse('r:SuperRare,c', [], lorcana).rarity).toEqual(['superrare', 'common']);
    expect(Q.parse('r:x', [], lorcana).rarity).toEqual(['x']);
    expect(Q.parse('r:c').rarity).toEqual(['c']);
});

// cn:, cns: and number: take lists too, compared without case as online
// compares them.
test('number lists read as online', () => {
    expect(p('cn:1,2A').number).toMatchObject([{values: ['1', '2a']}]);
    expect(p('number:OP01-001').number).toMatchObject([{values: ['op01-001']}]);
});

// A range and a set scope read as online reads them: two plain numbers
// around a dash in ascending order, and a set list before a colon. A dashed
// number that is no such range (2002-1, SET-123) stays a number.
test('number ranges and set scopes read as online', () => {
    expect(p('cn:1-50').number).toMatchObject([{range: [1, 50], sets: []}]);
    expect(p('cn:MKM:42').number).toMatchObject([{values: ['42'], sets: ['MKM'], range: null}]);
    expect(p('cns:mkm,otj:1-5').number).toMatchObject([{range: [1, 5], sets: ['MKM', 'OTJ']}]);
    expect(p('cn:2002-1').number).toMatchObject([{values: ['2002-1'], range: null}]);
    expect(p('cn:SET-123').number).toMatchObject([{values: ['set-123'], range: null}]);
    // two number filters both hold, as online
    expect(p('cn:1-50 cn:MKM:42').number).toHaveLength(2);
});

// cn> and cn< compare as online does, against the first number given. cns
// takes no comparison online, and a colon wins the split, so neither
// cns>300 nor cn>MKM:300 is one.
test('number comparisons read as online', () => {
    expect(p('cn>300').number).toMatchObject([{compare: '>', bound: 300}]);
    expect(p('number<10,20').number).toMatchObject([{compare: '<', bound: 10}]);
    expect(p('cn<1-50').number).toMatchObject([{range: [1, 50], compare: null}]);
    expect(p('cns>300').unsupported).toEqual(['cns>300']);
    expect(p('cn>MKM:300').unsupported).toEqual(['cn>MKM:300']);
    expect(p('r>rare').unsupported).toEqual(['r>rare']);
});

// A leading - negates a filter, as it does online. Negated values gather,
// since none of one list and none of another is none of either.
test('negated filters read as online', () => {
    const finishes = [{value: 'galaxyfoil', aliases: ['galaxy']}];
    expect(Q.parse('bolt -s:neo,mh2 -e:lea -f:foil,galaxy -r:c', finishes, magic)).toMatchObject({
        not: {set: ['NEO', 'MH2', 'LEA'], finish: ['foil', 'galaxy'], rarity: ['common']},
        set: [], finish: [], rarity: [], unsupported: [],
    });
    expect(p('-cn:MKM:1-50').number).toMatchObject([{range: [1, 50], sets: ['MKM'], negate: true}]);
    expect(p('-cn>100').number).toMatchObject([{compare: '>', bound: 100, negate: true}]);
    expect(p('-f:gilded').unsupported).toEqual(['-f:gilded']);
});

test('unknown operator values are unsupported', () => {
    expect(p('f:gilded').unsupported).toEqual(['f:gilded']);
});

test('unknown keys are unsupported verbatim', () => {
    const r = p('lotus date>2020 skip:index -skip:retail');
    expect(r.names).toEqual(['lotus']);
    expect(r.unsupported).toEqual(['date>2020', 'skip:index', '-skip:retail']);
});

test('quoted operator value', () => {
    expect(p('s:"MH2"').set).toEqual(['MH2']);
});

test('empty and whitespace input', () => {
    expect(p('')).toEqual({names: [], set: [], number: [], finish: [], rarity: [], not: {set: [], finish: [], rarity: []}, unsupported: []});
    expect(p('   ').names).toEqual([]);
});

test('last occurrence wins', () => {
    expect(p('s:NEO s:MH2').set).toEqual(['MH2']);
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
    expect(p('r:common').rarity).toEqual(['common']);
    expect(p('r:u').rarity).toEqual(['uncommon']);
    expect(p('r:rare').rarity).toEqual(['rare']);
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
        lastSync: async function () { return env.synced; },
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
});

test('a game finish reaches only the printings that carry it', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    const getCard = env.getCard;
    env.getCard = async function (uuid) {
        const card = await getCard(uuid);
        return card && card.uuid === 'u-neo-1f' ? {...card, fin: ['rainbowfoil']} : card;
    };
    const finishes = [{value: 'rainbowfoil', label: 'Rainbow Foil'}];
    const out = await Q.execute(Q.parse('boseiju f:rainbowfoil', finishes), env);
    expect(out.results.map(r => r.uuid)).toEqual(['u-neo-1f']);
});

test('a short form reaches only the cards that list it', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    const getCard = env.getCard;
    env.getCard = async function (uuid) {
        const card = await getCard(uuid);
        return card && card.uuid === 'u-neo-1f' ? {...card, fin: ['galaxyfoil', 'galaxy']} : card;
    };
    const finishes = [{value: 'galaxyfoil', label: 'Galaxy Foil', aliases: ['galaxy']}];
    const out = await Q.execute(Q.parse('boseiju f:galaxy', finishes), env);
    expect(out.results.map(r => r.uuid)).toEqual(['u-neo-1f']);
});

test('a set list reads every set it names', async () => {
    Q.resetCaches();
    let out = await Q.execute(Q.parse('s:neo,mh2'), fakeEnv());
    expect(out.results.map(r => r.uuid).sort()).toEqual(['u-mh2-1', 'u-neo-1', 'u-neo-1f']);

    Q.resetCaches();
    out = await Q.execute(Q.parse('s:neo,old'), fakeEnv());
    expect(out.results.map(r => r.uuid).sort()).toEqual(['u-neo-1', 'u-neo-1f']);
});

test('a finish list keeps a card any of its finishes reaches', async () => {
    Q.resetCaches();
    let out = await Q.execute(Q.parse('"boseiju reaches" f:foil,etched'), fakeEnv());
    expect(out.results.map(r => r.uuid)).toEqual(['u-neo-1f']);

    Q.resetCaches();
    out = await Q.execute(Q.parse('"boseiju reaches" f:nonfoil,foil'), fakeEnv());
    expect(out.results.map(r => r.uuid).sort()).toEqual(['u-neo-1', 'u-neo-1f']);
});

// The catalog spells a card's rarity as its game does ("Super Rare"); a
// query finds it under the one word online compares.
test('a rarity is found however the catalog spells it', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    const getCard = env.getCard;
    env.getCard = async function (uuid) {
        const card = await getCard(uuid);
        return card && card.uuid === 'u-mh2-1' ? Object.assign({}, card, {r: 'Super Rare'}) : card;
    };
    const out = await Q.execute(Q.parse('boseiju r:superrare', [], magic), env);
    expect(out.results.map(r => r.uuid)).toEqual(['u-mh2-1']);
});

test('rarity and number lists keep a card any value reaches', async () => {
    Q.resetCaches();
    let out = await Q.execute(Q.parse('boseiju r:mythic,rare'), fakeEnv());
    expect(out.results.map(r => r.uuid).sort()).toEqual(['u-mh2-1', 'u-neo-1', 'u-neo-1f']);

    Q.resetCaches();
    out = await Q.execute(Q.parse('boseiju cn:12,177'), fakeEnv());
    expect(out.results.map(r => r.uuid).sort()).toEqual(['u-mh2-1', 'u-neo-1', 'u-neo-1f']);

    // A number the catalog prints in capitals is found typed either way
    Q.resetCaches();
    const env = fakeEnv();
    const getCard = env.getCard;
    env.getCard = async function (uuid) {
        const card = await getCard(uuid);
        return card && card.uuid === 'u-mh2-1' ? {...card, num: 'OP01-001'} : card;
    };
    out = await Q.execute(Q.parse('boseiju cn:op01-001'), env);
    expect(out.results.map(r => r.uuid)).toEqual(['u-mh2-1']);
});

// A range reads the plain number the catalog carries where the printed one
// reads differently (OP01-120 reads 120, not 1), and a number with none is in
// no range. A set scope leaves every card outside its sets alone.
test('number ranges, comparisons and set scopes keep what online keeps', async () => {
    const withNumber = (uuid, num, pn) => {
        const env = fakeEnv();
        const getCard = env.getCard;
        env.getCard = async function (id) {
            const card = await getCard(id);
            return card && card.uuid === uuid ? {...card, num, pn} : card;
        };
        return env;
    };
    const uuids = async (query, env) => {
        Q.resetCaches();
        const out = await Q.execute(Q.parse(query), env || fakeEnv());
        return out.results.map(r => r.uuid).sort();
    };

    expect(await uuids('boseiju cn:10-200')).toEqual(['u-mh2-1', 'u-neo-1', 'u-neo-1f']);
    expect(await uuids('boseiju cn:1-50')).toEqual(['u-mh2-1']);
    expect(await uuids('boseiju cn:100-130', withNumber('u-mh2-1', 'OP01-120', '120'))).toEqual(['u-mh2-1']);
    expect(await uuids('boseiju cn:120', withNumber('u-mh2-1', 'OP01-120', '120'))).toEqual(['u-mh2-1']);
    expect(await uuids('boseiju cns:120', withNumber('u-mh2-1', 'OP01-120', '120'))).toEqual([]);
    expect(await uuids('boseiju cn:1-500', withNumber('u-mh2-1', 'P-001', ''))).toEqual(['u-neo-1', 'u-neo-1f']);
    expect(await uuids('boseiju cn:NEO:1')).toEqual(['u-mh2-1']);
    expect(await uuids('boseiju cn:NEO:100-200')).toEqual(['u-mh2-1', 'u-neo-1', 'u-neo-1f']);

    // A comparison counts its bound, reads the plain number, and keeps a
    // number with no digits above every bound, as online
    expect(await uuids('boseiju cn>100')).toEqual(['u-neo-1', 'u-neo-1f']);
    expect(await uuids('boseiju cn>177')).toEqual(['u-neo-1', 'u-neo-1f']);
    expect(await uuids('boseiju cn<12')).toEqual(['u-mh2-1']);
    expect(await uuids('boseiju cn>119', withNumber('u-mh2-1', 'OP01-120', '120'))).toEqual(['u-mh2-1', 'u-neo-1', 'u-neo-1f']);
    expect(await uuids('boseiju cn>100', withNumber('u-mh2-1', 'P-001', ''))).toEqual(['u-mh2-1', 'u-neo-1', 'u-neo-1f']);
    expect(await uuids('boseiju cn<500', withNumber('u-mh2-1', 'P-001', ''))).toEqual(['u-neo-1', 'u-neo-1f']);
});

// Online files each f: token as a filter of its own and keeps a card every
// one of them reaches, so f:foil f:galaxy is the galaxy foils. Within one
// token any value is enough.
test('every f: token holds', async () => {
    const finishes = [{value: 'galaxyfoil', aliases: ['galaxy']}];
    expect(Q.parse('f:foil f:galaxy', finishes).finish).toEqual([['foil'], ['galaxy']]);

    const env = fakeEnv();
    const getCard = env.getCard;
    env.getCard = async function (uuid) {
        const card = await getCard(uuid);
        return card && card.uuid.indexOf('u-neo-1') === 0 ? {...card, fin: ['galaxyfoil', 'galaxy']} : card;
    };
    const uuids = async query => {
        Q.resetCaches();
        const out = await Q.execute(Q.parse(query, finishes), env);
        return out.results.map(r => r.uuid).sort();
    };
    expect(await uuids('boseiju f:galaxy')).toEqual(['u-neo-1', 'u-neo-1f']);
    expect(await uuids('boseiju f:foil f:galaxy')).toEqual(['u-neo-1f']);
    expect(await uuids('boseiju f:foil,nonfoil f:galaxy')).toEqual(['u-neo-1', 'u-neo-1f']);
});

test('negated filters drop what they name', async () => {
    const uuids = async query => {
        Q.resetCaches();
        const out = await Q.execute(Q.parse(query), fakeEnv());
        return out.results.map(r => r.uuid).sort();
    };
    expect(await uuids('boseiju -s:neo')).toEqual(['u-mh2-1']);
    expect(await uuids('boseiju -f:foil')).toEqual(['u-mh2-1', 'u-neo-1']);
    expect(await uuids('boseiju -r:rare')).toEqual(['u-mh2-1']);
    expect(await uuids('boseiju s:neo -f:nonfoil')).toEqual(['u-neo-1f']);
    // A scope still leaves every card outside it alone
    expect(await uuids('boseiju -cn:NEO:177')).toEqual(['u-mh2-1']);
    expect(await uuids('boseiju -cn:12')).toEqual(['u-neo-1', 'u-neo-1f']);
    // A negated comparison is strict the other way, and drops a number
    // with no digits
    expect(await uuids('boseiju -cn>100')).toEqual(['u-mh2-1']);
    expect(await uuids('boseiju -cn<12')).toEqual(['u-neo-1', 'u-neo-1f']);
});

// Online keeps a range's lower bound out of the negation's reach: -cn:10-50
// keeps only what lies past 50, so a card numbered 5 is dropped too.
test('a negated range keeps what lies past its upper bound', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    const getCard = env.getCard;
    env.getCard = async function (uuid) {
        const card = await getCard(uuid);
        return card && card.uuid === 'u-mh2-1' ? {...card, num: '5'} : card;
    };
    let out = await Q.execute(Q.parse('boseiju -cn:10-50'), env);
    expect(out.results.map(r => r.uuid).sort()).toEqual(['u-neo-1', 'u-neo-1f']);
    Q.resetCaches();
    out = await Q.execute(Q.parse('boseiju -cn:10-200'), fakeEnv());
    expect(out.results.map(r => r.uuid)).toEqual([]);
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
        lastSync: async function () {},
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
        lastSync: async function () { return env.synced; },
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
        lastSync: async function () {},
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
        lastSync: async function () {},
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
});

// Online scopes a search with in:(...); offline cannot, and says so as one
// token rather than reading the pool's filters as the query's.
test('an in: pool is one unsupported token', () => {
    const r = p('in:(s:CMR r:rare) sol ring');
    expect(r.unsupported).toEqual(['in:(s:CMR r:rare)']);
    expect(r.names).toEqual(['sol', 'ring']);
    expect(r.set).toEqual([]);
    expect(r.rarity).toEqual([]);
    expect(p('-in:(contents:"A (B)") x').unsupported).toEqual(['-in:(contents:"A (B)")']);
    expect(p('in:CMR').unsupported).toEqual(['in:CMR']);
    expect(p('in:(s:CMR').unsupported).toEqual(['in:(s:CMR']);
    // A bare quote closed after the next paren is a character, so the
    // paren still closes; one after a key opens a value
    const q = p('in:(sm:regexp ^"Ach) "sol ring"');
    expect(q.unsupported).toEqual(['in:(sm:regexp ^"Ach)']);
    expect(q.names).toEqual(['sol ring']);
    expect(p('in:(s:"A (B)") x').unsupported).toEqual(['in:(s:"A (B)")']);
});

// A sync rewrites a set in the database, where the page's cache cannot see it.
test('a finished sync replaces the cached prices', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    const price = async () => (await Q.execute(Q.parse('s:mh2'), env)).results[0].retail.CK.regular;
    expect(await price()).toBe(20);
    expect(await price()).toBe(20);
    expect(env.loads).toEqual(['MH2']);

    const realLoad = env.loadSetPayload;
    env.loadSetPayload = async (code) => {
        await realLoad(code);
        return {setCode: 'MH2', retail: {'u-mh2-1': {CK: {regular: 25}}}, buylist: {}};
    };
    env.synced = '2026-11-05T00:00:00Z';
    expect(await price()).toBe(25);
    expect(await price()).toBe(25);
    expect(env.loads).toEqual(['MH2', 'MH2']);
});

// Searches overlap: one may still be reading a set when the next sees the sync.
test('a load from before the sync does not fill the cache after it', async () => {
    Q.resetCaches();
    const env = fakeEnv();
    const priced = (regular) => ({setCode: 'MH2', retail: {'u-mh2-1': {CK: {regular}}}, buylist: {}});
    const price = (out) => out.results[0].retail.CK.regular;
    const search = () => Q.execute(Q.parse('s:mh2'), env);
    // A stamp of its own, so what earlier tests cached is not in play
    env.synced = 'before overlap';

    let reached, release;
    const reading = new Promise((resolve) => { reached = resolve; });
    const held = new Promise((resolve) => { release = resolve; });
    env.loadSetPayload = async () => {
        reached();
        await held;
        return priced(20);
    };
    const first = search();
    await reading;

    env.synced = 'after overlap';
    let loads = 0;
    env.loadSetPayload = async () => {
        loads++;
        return priced(25);
    };
    expect(price(await search())).toBe(25);
    expect(loads).toBe(1);

    release();
    await first;
    expect(price(await search())).toBe(25);
    expect(loads).toBe(1);
});

// The shortcuts online's parseSearchOptionsDepth reads out of the free words.
const SETS = {
    SPM: {n: "Marvel's Spider-Man"}, NEO: {n: 'Kamigawa: Neon Dynasty'}, PLST: {n: 'The List'},
    '10E': {n: 'Tenth Edition'}, '30A': {n: '30th Anniversary Edition'}, C16: {n: 'Commander 2016'},
    SOI: {n: 'Shadows over Innistrad'}, SIR: {n: 'Shadows over Innistrad Remastered'},
    INFO: {n: 'The Infinite Forbidden'},
};
function ps(q) { return Q.parse(q, [], magic, SETS); }

test('a set code and a number are that printing', () => {
    expect(ps('spm 66')).toMatchObject({names: [], set: ['SPM'], number: [{values: ['66'], strict: false}]});
    expect(ps('SPM #066')).toMatchObject({names: [], set: ['SPM'], number: [{values: ['66'], strict: false}]});
    expect(ps('plst c16-177')).toMatchObject({names: [], set: ['PLST'], number: [{values: ['c16-177'], strict: true}]});
    expect(ps('neo 17a')).toMatchObject({names: [], set: ['NEO'], number: [{values: ['17a'], strict: true}]});
    expect(ps('spm 66 f:foil')).toMatchObject({set: ['SPM'], finish: [['foil']]});
});

// A set filter's own list must not take the place of the catalog's sets.
test('a negated set filter leaves the shortcuts working', () => {
    for (const q of ['spm 66 -s:neo', '-s:neo spm 66']) {
        expect(ps(q)).toMatchObject({names: [], set: ['SPM'], not: {set: ['NEO']}, number: [{values: ['66']}]});
    }
    expect(ps('info-en067 -s:neo')).toMatchObject({names: [], set: ['INFO'], not: {set: ['NEO']}});
    expect(ps('shadows -s:neo').setsNamed).toEqual(['SIR', 'SOI']);
});

test('words that are not a set and a number stay a name', () => {
    expect(ps('neo 10e')).toMatchObject({names: ['neo', '10e'], set: [], number: []});
    expect(ps('neo may').names).toEqual(['neo', 'may']);
    expect(ps('neo 1st').names).toEqual(['neo', '1st']);
    expect(ps('sol ring').set).toEqual([]);
    expect(ps('sol 66')).toMatchObject({names: ['sol'], set: [], number: [{values: ['66']}]});
    // A quoted name is a name, and a set already asked for is not replaced
    expect(ps('"spm" 66')).toMatchObject({names: ['spm'], set: []});
    expect(ps('spm 66 s:neo')).toMatchObject({names: ['spm'], set: ['NEO']});
    // 30A is both a set code and a number's shape: as the second word, a number
    expect(ps('neo 30a')).toMatchObject({names: [], set: ['NEO'], number: [{values: ['30a']}]});
});

test('a number as Yu-Gi-Oh prints it is its set and ordinal', () => {
    expect(ps('info-en067')).toMatchObject({names: [], set: ['INFO'], printed: 'info-en067', number: [{values: ['67', 'info-en067']}]});
    expect(ps('info-067')).toMatchObject({set: ['INFO'], number: [{values: ['67', 'info-067']}]});
    expect(ps('c16-177')).toMatchObject({set: ['C16'], number: [{values: ['177', 'c16-177']}]});
    expect(ps('fire-ice')).toMatchObject({names: ['fire-ice'], set: []});
});

test('a number with its set total reads the number', () => {
    expect(ps('222/236')).toMatchObject({names: [], number: [{values: ['222']}]});
    expect(ps('pikachu 007/100')).toMatchObject({names: ['pikachu'], number: [{values: ['7']}]});
    expect(ps('spm 66/100')).toMatchObject({names: [], set: ['SPM'], number: [{values: ['66']}]});
    expect(ps('fire/ice')).toMatchObject({names: ['fire/ice'], number: []});
});

test('the last character asks for a finish', () => {
    expect(ps('sol ring*')).toMatchObject({names: ['sol', 'ring'], finish: [['foil']], unsupported: []});
    expect(ps('sol ring&').finish).toEqual([['nonfoil']]);
    expect(ps('sol ring~').finish).toEqual([['etched']]);
    expect(ps('sol ring`')).toMatchObject({finish: [['foil']], unsupported: ['`']});
    expect(ps('spm 66*')).toMatchObject({set: ['SPM'], number: [{values: ['66']}], finish: [['foil']]});
});

test('the bot notation spells its filters', () => {
    expect(ps('Lightning Bolt|LEA')).toMatchObject({names: ['Lightning', 'Bolt'], set: ['LEA']});
    expect(ps('bolt|lea|161|foil')).toMatchObject({names: ['bolt'], set: ['LEA'], number: [{values: ['161']}], finish: [['foil']]});
    expect(ps('bolt|lea|161|foil|NM').unsupported).toEqual(['cond:NM']);
    // A field left empty asks for nothing
    expect(ps('bolt|lea|')).toMatchObject({names: ['bolt'], set: ['LEA'], number: []});
    expect(ps('bolt||161')).toMatchObject({names: ['bolt'], set: [], number: [{values: ['161']}]});
});

function numberEnv() {
    const env = fakeEnv();
    const all = [
        {uuid: 's66', n: 'The Soul Stone', num: '66', set: 'SPM', r: 'rare'},
        {uuid: 's67', n: 'Other', num: '67', set: 'SPM', r: 'rare'},
        {uuid: 'n66', n: 'Another', num: '66', set: 'NEO', r: 'rare'},
        {uuid: 'o66', n: 'Unsynced', num: '66', set: 'OLD', r: 'rare'},
        {uuid: 'y1', n: 'Yugi', num: 'INFO-EN067', pn: '67', set: 'INFO', r: 'rare'},
        {uuid: 'y2', n: 'Kaiba', num: 'INFO-E067', pn: '67', set: 'INFO', r: 'rare'},
    ];
    const byId = Object.fromEntries(all.map(c => [c.uuid, c]));
    function bySet(code) {
        const retail = {};
        all.filter(c => c.set === code).forEach(c => { retail[c.uuid] = {CK: {regular: 1}}; });
        return {retail, buylist: {}};
    }
    const payloads = {SPM: bySet('SPM'), NEO: bySet('NEO'), INFO: bySet('INFO')};
    Object.assign(env, {
        getCard: async (uuid) => byId[uuid] || null,
        allCards: async () => all,
        hasSet: async (code) => !!payloads[code],
        loadSetPayload: async (code) => payloads[code],
        lookupName: async () => [],
        allNames: async () => [],
    });
    return env;
}

async function found(q, env) {
    Q.resetCaches();
    const out = await Q.execute(ps(q), env || numberEnv());
    return out.results.map(r => r.uuid).sort();
}

test('a set and a number find the printing', async () => {
    expect(await found('spm 66')).toEqual(['s66']);
});

test('a number alone reaches every synced set, with no notice for the others', async () => {
    expect(await found('66')).toEqual(['n66', 's66']);
    expect(await found('cn:66')).toEqual(['n66', 's66']);
});

test('cards in other sets do not use up the result limit', async () => {
    const env = numberEnv();
    const unsynced = Array.from({length: 10001}, (_, i) => ({uuid: 'old' + i, n: 'Old', num: '66', set: 'OLD', r: 'rare'}));
    env.allCards = async () => unsynced.concat([{uuid: 's66', n: 'The Soul Stone', num: '66', set: 'SPM', r: 'rare'}]);
    Q.resetCaches();
    const out = await Q.execute(ps('66'), env);
    expect(out.results.map(r => r.uuid)).toEqual(['s66']);
    expect(out.truncated).toBe(false);
});

test('a card named the number stays a name', async () => {
    const env = numberEnv();
    env.lookupName = async (key) => key === '66' ? ['s67'] : [];
    expect(await found('66', env)).toEqual(['s67']);
});

test('a number no card carries is read as a name', async () => {
    const env = numberEnv();
    env.allNames = async () => [{key: 'game of 2048', uuids: ['s67']}];
    expect(await found('2048', env)).toEqual(['s67']);
});

test('a printed number a card carries is that number exactly', async () => {
    expect(await found('info-en067')).toEqual(['y1']);
    // One no card carries is the set and ordinal
    expect(await found('info-067')).toEqual(['y1', 'y2']);
});

test('a number after a name is taken only when the whole name finds nothing', async () => {
    const env = numberEnv();
    env.allNames = async () => [{key: 'the soul stone', uuids: ['s66']}];
    env.lookupName = async (key) => key === 'stone 66a' ? ['s67'] : [];
    expect(ps('soul stone #66').trailingNumber).toMatchObject({values: ['66']});
    expect(await found('soul stone #66', env)).toEqual(['s66']);
    expect(await found('soul stone #67', env)).toEqual([]);
    expect(await found('stone 66a', env)).toEqual(['s67']);
});

test('a query no name answers falls back to the sets it names', async () => {
    const env = numberEnv();
    expect(await found('spm', env)).toEqual(['s66', 's67']);
    expect(await found("marvel's spider-man", env)).toEqual(['s66', 's67']);
    // Sets this device lacks answer nothing, and say nothing here
    expect(await found('shadows', env)).toEqual([]);
    // A name found only in a set this device lacks does not hide the set
    env.allNames = async () => [{key: 'wasp mantis spmx', uuids: ['o66']}];
    expect(await found('spm', env)).toEqual(['s66', 's67']);
    env.allNames = async () => [];
    // A set the query narrowed to is not reinterpreted
    expect(await found('shadows s:spm', env)).toEqual([]);
});
