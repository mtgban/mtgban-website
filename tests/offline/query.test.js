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
    expect(p('4 sol ring').number).toMatchObject([{values: ['4'], strict: false}]);
    expect(p('4 sol ring').names).toEqual(['sol', 'ring']);
});

// Online reads "pyromancy 101" as a name before a name and a number, so a
// name's last digits stay in the name, with the number to fall back to.
test('digits after a name stay in the name', () => {
    expect(p('sol ring 4')).toMatchObject({names: ['sol', 'ring', '4'], number: [], trailingNumber: {values: ['4'], strict: false}});
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
        searchState: async function () { return {lastSync: this.synced, stored: Object.keys(payloads)}; },
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
        searchState: async function () { return {lastSync: this.synced, stored: Object.keys(payloads)}; },
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

// One set per code, each holding one findable card plus padding store prices.
function manySetsEnv(codes, padding) {
    const cards = {};
    const payloads = {};
    // One section shared by every set, as only its size matters
    const retail = {};
    for (let i = 0; i < padding; i++) retail['pad' + i] = {CK: {regular: 1}};
    codes.forEach((code) => {
        const uuid = 'u-' + code;
        cards[uuid] = {uuid, n: 'Card' + code, num: '1', r: 'rare', set: code, f: false, e: false, s: false};
        retail[uuid] = {CK: {regular: 1}};
        payloads[code] = {setCode: code, retail, buylist: {}};
    });
    const names = [{key: 'card', uuids: Object.keys(cards)}];
    const env = {
        loads: [],
        searchState: async () => ({lastSync: env.synced, stored: Object.keys(payloads)}),
        normName: (t) => t.toLowerCase().trim(),
        lookupName: async (key) => (key === 'card' ? names[0].uuids.slice() : []),
        allNames: async () => names,
        getCard: async (uuid) => cards[uuid] || null,
        loadSetPayload: async (code) => { env.loads.push(code); return payloads[code]; },
    };
    return env;
}

test('the price cache is limited by how much it holds, not how many sets', async () => {
    Q.resetCaches();
    const many = Array.from({length: 30}, (_, i) => 'T' + i);
    const small = manySetsEnv(many, 0);
    await Q.execute(Q.parse('card'), small);
    await Q.execute(Q.parse('card'), small);
    expect(small.loads).toHaveLength(30);

    Q.resetCaches();
    const big = manySetsEnv(['S1', 'S2', 'S3', 'S4', 'S5', 'S6', 'S7', 'S8', 'S9'], 125000);
    await Q.execute(Q.parse('card'), big);
    expect(big.loads).toHaveLength(9);
    // The oldest went to make room, the newest stayed
    await Q.execute(Q.parse('card s:S9'), big);
    expect(big.loads).toHaveLength(9);
    await Q.execute(Q.parse('card s:S1'), big);
    expect(big.loads).toHaveLength(10);
});

test('the one set in the cache stays, however large', async () => {
    Q.resetCaches();
    const env = manySetsEnv(['HUGE'], 1100000);
    await Q.execute(Q.parse('card'), env);
    await Q.execute(Q.parse('card'), env);
    expect(env.loads).toEqual(['HUGE']);
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
        searchState: async function () { return {lastSync: this.synced, stored: Object.keys(payloads)}; },
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
        searchState: async function () { return {stored: ['GOOD', 'BAD']}; },
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
    expect(ps('sol 66')).toMatchObject({names: ['sol', '66'], set: [], number: [], trailingNumber: {values: ['66']}});
    // A quoted name is a name, and a set already asked for is not replaced
    expect(ps('"spm" 66')).toMatchObject({names: ['spm'], set: []});
    expect(ps('spm 66 s:neo')).toMatchObject({names: ['spm', '66'], set: ['NEO']});
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
        searchState: async () => ({lastSync: env.synced, stored: Object.keys(payloads)}),
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

// A page opens the sets on it and no others, however many the answer reaches.

test('a page opens only the sets its rows are in', async () => {
    Q.resetCaches();
    const env = manySetsEnv(['A1', 'B1', 'C1'], 0);
    const out = await Q.execute(Q.parse('card'), env, {size: 1});
    expect(env.loads).toEqual(['A1']);
    expect(out.results.map(r => r.uuid)).toEqual(['u-A1', 'u-B1', 'u-C1']);
    expect(out.page.map(r => r.uuid)).toEqual(['u-A1']);
    expect(out.page[0].retail).toEqual({CK: {regular: 1}});
    expect(out.results[1].retail).toBeNull();
});

test('a new sort prices the rows it brings onto the page, and only those', async () => {
    Q.resetCaches();
    const env = manySetsEnv(['A1', 'B1', 'C1'], 0);
    const out = await Q.execute(Q.parse('card'), env, {size: 1});
    const backwards = (results) => results.sort((a, b) => (a.uuid < b.uuid ? 1 : -1));
    expect(await Q.showPage(out, env, {size: 1, order: backwards})).toBe(true);
    expect(out.page.map(r => r.uuid)).toEqual(['u-C1']);
    expect(env.loads).toEqual(['A1', 'C1']);
    expect(out.results.find(r => r.uuid === 'u-B1').retail).toBeNull();
});

test('a sort that needs every price gets them before it runs', async () => {
    Q.resetCaches();
    const env = manySetsEnv(['A1', 'B1', 'C1'], 0);
    let priced = null;
    await Q.execute(Q.parse('card'), env, {
        size: 1,
        allPrices: () => true,
        order: (results) => { priced = results.every(r => r.retail); },
    });
    expect(priced).toBe(true);
    expect(env.loads).toEqual(['A1', 'B1', 'C1']);
});

test('results come in set order, whatever order the names found them', async () => {
    Q.resetCaches();
    const env = manySetsEnv(['A1', 'B1', 'C1'], 0);
    env.lookupName = async () => ['u-C1', 'u-A1', 'u-B1'];
    const out = await Q.execute(Q.parse('card'), env);
    expect(out.results.map(r => r.uuid)).toEqual(['u-A1', 'u-B1', 'u-C1']);
});

test('the count leaves out a matching card whose set is not stored', async () => {
    Q.resetCaches();
    const env = manySetsEnv(['A1', 'B1'], 0);
    const state = env.searchState;
    env.searchState = async () => ({...(await state()), stored: ['B1']});
    const out = await Q.execute(Q.parse('card'), env, {size: 10});
    expect(out.results.map(r => r.uuid)).toEqual(['u-B1']);
    expect(env.loads).toEqual(['B1']);
});

function failingEnv(bad) {
    const env = manySetsEnv(['A1', 'B1', 'C1'], 0);
    const load = env.loadSetPayload;
    env.loadSetPayload = async (code) => {
        if (bad.includes(code)) {
            env.loads.push(code);
            throw new Error('decrypt failed');
        }
        return load(code);
    };
    return env;
}

test('a set that fails to open drops out, and the page refills', async () => {
    Q.resetCaches();
    const env = failingEnv(['A1']);
    const out = await Q.execute(Q.parse('card'), env, {size: 1});
    expect(out.results.map(r => r.uuid)).toEqual(['u-B1', 'u-C1']);
    expect(out.page.map(r => r.uuid)).toEqual(['u-B1']);
    expect(out.page[0].retail).toEqual({CK: {regular: 1}});
});

test('a set that fails to open is not tried again until the next sync', async () => {
    Q.resetCaches();
    const env = failingEnv(['A1']);
    await Q.execute(Q.parse('card'), env, {size: 1});
    await Q.execute(Q.parse('card'), env, {size: 1});
    expect(env.loads.filter(code => code === 'A1')).toHaveLength(1);
    env.synced = 'later';
    await Q.execute(Q.parse('card'), env, {size: 1});
    expect(env.loads.filter(code => code === 'A1')).toHaveLength(2);
});

test('a set gone from the database counts as failing to open', async () => {
    Q.resetCaches();
    const env = manySetsEnv(['A1', 'B1'], 0);
    const load = env.loadSetPayload;
    env.loadSetPayload = async (code) => (code === 'A1' ? null : load(code));
    const out = await Q.execute(Q.parse('card'), env, {size: 1});
    expect(out.results.map(r => r.uuid)).toEqual(['u-B1']);
});

test('showPage says when a set would not open, so the search can be asked again', async () => {
    Q.resetCaches();
    const env = failingEnv(['B1']);
    const out = await Q.execute(Q.parse('card'), env, {size: 1});
    expect(out.results).toHaveLength(3);
    const backwards = (results) => results.sort((a, b) => (a.uuid === 'u-B1' ? -1 : b.uuid === 'u-B1' ? 1 : 0));
    expect(await Q.showPage(out, env, {size: 1, order: backwards})).toBe(false);
    const again = await Q.execute(Q.parse('card'), env, {size: 1});
    expect(again.results.map(r => r.uuid)).toEqual(['u-A1', 'u-C1']);
});

test('a name found only in a set that will not open still falls back to the set named', async () => {
    Q.resetCaches();
    const env = numberEnv();
    env.allNames = async () => [{key: 'spm named', uuids: ['y1']}];
    const load = env.loadSetPayload;
    env.loadSetPayload = async (code) => {
        if (code === 'INFO') throw new Error('decrypt failed');
        return load(code);
    };
    expect(await found('spm', env)).toEqual(['s66', 's67']);
});

// The number index narrows the walk; these must read as the filters do without it.
test('numbers read the same through the index', async () => {
    const uuids = async (q) => {
        Q.resetCaches();
        const out = await Q.execute(ps(q), numberEnv());
        return out.results.map(r => r.uuid).sort();
    };
    expect(await uuids('cn:66')).toEqual(['n66', 's66']);
    expect(await uuids('cn:67')).toEqual(['s67', 'y1', 'y2']);
    expect(await uuids('cn:INFO-EN067')).toEqual(['y1']);
    expect(await uuids('cns:67')).toEqual(['s67']);
    expect(await uuids('cn:66,67')).toEqual(['n66', 's66', 's67', 'y1', 'y2']);
    expect(await uuids('cn:66 -s:neo')).toEqual(['s66']);
    expect(await uuids('cn:999')).toEqual([]);
});

// Overlapping searches can both find a set missing and both load it.
test('a set two searches loaded at once counts once against the limit', async () => {
    Q.resetCaches();
    const env = manySetsEnv(['BIG', 'SMALL'], 0);
    const load = env.loadSetPayload;
    const retail = {'u-BIG': {CK: {regular: 1}}};
    for (let i = 0; i < 600000; i++) retail['pad' + i] = {CK: {regular: 1}};
    env.loadSetPayload = async (code) => {
        if (code !== 'BIG') return load(code);
        env.loads.push(code);
        return {setCode: code, retail, buylist: {}};
    };
    await Promise.all([Q.execute(Q.parse('card s:BIG'), env), Q.execute(Q.parse('card s:BIG'), env)]);
    expect(env.loads).toEqual(['BIG', 'BIG']);
    // Counted twice, BIG would be over the limit and go to make room for this
    await Q.execute(Q.parse('card s:SMALL'), env);
    await Q.execute(Q.parse('card s:BIG'), env);
    expect(env.loads.filter(code => code === 'BIG')).toHaveLength(2);
});

// ---- a query still being typed ----

const DRAFT_SETS = {NEO: {n: 'Kamigawa: Neon Dynasty'}, SPM: {n: "Marvel's Spider-Man"}, INFO: {n: 'The Infinite Forbidden'}, OLD: {n: 'Old Set'}};
const DRAFT_FINISHES = [{value: 'foil'}, {value: 'nonfoil'}, {value: 'etched'}];
function draft(q) { return Q.parse(q, DRAFT_FINISHES, magic, DRAFT_SETS, {draft: true}); }

test.each([
    ['s:', {set: []}],
    ['s:n', {set: []}],
    ['s:ne', {set: []}],
    ['-s:ne', {not: {set: [], finish: [], rarity: []}}],
    ['s:neo,', {set: []}],
    ['s:neo,sp', {set: []}],
    ['f:', {finish: []}],
    ['f:fo', {finish: []}],
    ['r:', {rarity: []}],
    ['r:my', {rarity: []}],
    ['r:mythic,', {rarity: []}],
    ['cn:', {number: []}],
    ['cn:1,', {number: []}],
    ['cn:neo:', {number: []}],
    ['cn>', {number: []}],
])('%s is left out until it is finished', (typed, want) => {
    expect(draft('sol ' + typed)).toMatchObject({names: ['sol'], unsupported: [], ...want});
});

test.each([
    ['s:neo', {set: ['NEO']}],
    ['s:neo,spm', {set: ['NEO', 'SPM']}],
    ['-s:neo', {not: {set: ['NEO'], finish: [], rarity: []}}],
    ['f:foil', {finish: [['foil']]}],
    ['f:f', {finish: [['foil']]}],
    ['r:m', {rarity: ['mythic']}],
    ['r:mythic', {rarity: ['mythic']}],
    ['cn:12', {number: [{values: ['12']}]}],
    ['cn>1', {number: [{compare: '>'}]}],
])('%s reads as soon as it is complete', (typed, want) => {
    expect(draft('sol ' + typed)).toMatchObject(want);
});

test('a filter is only held back as the last thing typed', () => {
    expect(draft('s:ne sol').set).toEqual(['NE']);
    expect(draft('f:fo sol').finish).toEqual([]);
});

test('nothing is said about what offline cannot answer until typing stops', () => {
    expect(draft('sol date>2020').unsupported).toEqual([]);
    expect(draft('date>2020 sol').unsupported).toEqual([]);
    expect(draft('sol ring`').unsupported).toEqual([]);
    expect(Q.parse('date>2020 sol', [], magic, DRAFT_SETS).unsupported).toEqual(['date>2020']);
});

test('an ordinary parse is not affected', () => {
    const typed = Q.parse('sol s:ne', DRAFT_FINISHES, magic, DRAFT_SETS);
    expect(typed.set).toEqual(['NE']);
    expect(typed.heldWord).toBeUndefined();
    expect(typed.heldNumber).toBeUndefined();
});

test.each([
    ['sol', true],
    ['sol ring', true],
    ['so', false],
    ['s', false],
    ['', false],
    ['s:', false],
    ['s:ne', false],
    ['f:foil', false],
    ['r:m', false],
    ['s:neo', true],
    ['spm 6', true],
    ['66', true],
    ['6', true],
    ['cn:1', true],
    ['so s:neo', false],
    ['so f:foil', false],
    ['sol f:foil', true],
])('answerable: %s is %p', (typed, want) => {
    expect(Q.answerable(draft(typed), {normName: (t) => t.toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').trim()})).toBe(want);
});

function typingEnv(extra) {
    const all = [
        {uuid: 'sr1', n: 'Sol Ring', num: '161', set: 'NEO', r: 'rare', f: false},
        {uuid: 'sr2', n: 'Sol Ring', num: '66', set: 'SPM', r: 'mythic', f: true},
        {uuid: 'ss', n: 'The Soul Stone', num: '66', set: 'SPM', r: 'mythic', f: false},
        {uuid: 'bolt', n: 'Lightning Bolt', num: '123', set: 'NEO', r: 'common', f: false},
        {uuid: 'cn', n: 'Sol Cn Master', num: '9', set: 'NEO', r: 'rare', f: false},
        {uuid: 'yu', n: 'Yugi', num: 'INFO-EN067', pn: '67', set: 'INFO', r: 'rare', f: false},
        // So that typing 66 passes through a number some card carries, as on any real catalog
        {uuid: 'six', n: 'Six', num: '6', set: 'NEO', r: 'common', f: false},
    ].concat(extra || []);
    const byId = Object.fromEntries(all.map(c => [c.uuid, c]));
    const keys = {};
    all.forEach((c) => {
        const key = c.n.toLowerCase();
        (keys[key] = keys[key] || []).push(c.uuid);
    });
    const names = Object.entries(keys).map(([key, uuids]) => ({key, uuids}));
    const section = (code) => Object.fromEntries(all.filter(c => c.set === code).map(c => [c.uuid, {CK: {regular: 1}}]));
    const payloads = {NEO: {retail: section('NEO'), buylist: {}}, SPM: {retail: section('SPM'), buylist: {}}, INFO: {retail: section('INFO'), buylist: {}}};
    return {
        normName: (t) => t.toLowerCase().replace(/[^a-z0-9 ]+/g, ' ').replace(/\s+/g, ' ').trim(),
        searchState: async () => ({stored: Object.keys(payloads)}),
        lookupName: async (key) => keys[key] || [],
        allNames: async () => names,
        getCard: (uuid) => byId[uuid],
        allCards: () => all,
        loadSetPayload: async (code) => payloads[code],
    };
}

const drafted = async (typed, env) => {
    Q.resetCaches();
    const out = await Q.execute(draft(typed), env);
    return out.results.map(r => r.uuid).sort();
};

test('a last word is dropped only if it finds nothing', async () => {
    const env = typingEnv();
    expect(draft('sol cn').heldWord).toBe(true);
    expect(await drafted('sol cn', env)).toEqual(['cn']);
    expect(await drafted('bolt cn', env)).toEqual(['bolt']);
    expect(await drafted('lightning r', env)).toEqual(['bolt']);
    expect(await drafted('lightning zzz', env)).toEqual(['bolt']);
    expect(draft('sol').heldWord).toBeUndefined();
    expect(draft('"sol" "cn"').heldWord).toBeUndefined();
    expect(draft('sol cn f:foil').heldWord).toBeUndefined();
});

test('a set code and a dash reads as the set, on its way to a printed number', () => {
    expect(draft('info-')).toMatchObject({names: [], set: ['INFO']});
    expect(draft('info-e')).toMatchObject({names: [], set: ['INFO']});
    expect(draft('fire-i')).toMatchObject({names: ['fire-i'], set: []});
    expect(Q.parse('info-e', [], magic, DRAFT_SETS)).toMatchObject({names: ['info-e'], set: []});
});

test('a word on its way to a set falls back to the words before it', () => {
    expect(draft('spm #').setsNamed).toEqual(['SPM']);
    expect(Q.parse('spm #', [], magic, DRAFT_SETS).setsNamed).toEqual([]);
});

test('a last number that finds nothing is dropped while it may be unfinished', async () => {
    const env = typingEnv();
    expect(await drafted('sol ring 1', env)).toEqual(['sr1', 'sr2']);
    expect(await drafted('sol ring 16', env)).toEqual(['sr1', 'sr2']);
    expect(await drafted('sol ring 161', env)).toEqual(['sr1']);
    expect(await drafted('spm 6', env)).toEqual(['sr2', 'ss']);
    expect(await drafted('spm 66', env)).toEqual(['sr2', 'ss']);
    expect(await drafted('s:spm cn:6', env)).toEqual(['sr2', 'ss']);
    expect(await drafted('info-en0', env)).toEqual(['yu']);
    // The finished query keeps its exact answer
    Q.resetCaches();
    expect((await Q.execute(Q.parse('spm 6', [], magic, DRAFT_SETS), env)).results).toEqual([]);
});

const settled = async (typed, env) => {
    Q.resetCaches();
    const out = await Q.execute(Q.parse(typed, DRAFT_FINISHES, magic, DRAFT_SETS), env);
    return out.results.map(r => r.uuid).sort();
};

const numberedNames = [
    {uuid: 'pyro', n: 'Pyromancy 101', num: '120', set: 'NEO', r: 'rare', f: false},
    {uuid: 'sky', n: 'Skyscraper 2 - Hero City', num: 'INFO-EN050', pn: '50', set: 'INFO', r: 'rare', f: false},
];

test('digits after a name are the name first, as online', async () => {
    const env = typingEnv(numberedNames);
    expect(await settled('pyromancy 101', env)).toEqual(['pyro']);
    expect(await settled('pyromancy 10', env)).toEqual(['pyro']);
    expect(await settled('skyscraper 2', env)).toEqual(['sky']);
    // A name no card carries with the number falls back to the number
    expect(await settled('sol ring 161', env)).toEqual(['sr1']);
    expect(await settled('sol ring 66', env)).toEqual(['sr2']);
    expect(await settled('pyromancy 120', env)).toEqual(['pyro']);
});

test('a query settles to what it showed while typed', async () => {
    const env = typingEnv(numberedNames);
    for (const typed of ['pyromancy 10', 'pyromancy 101', '16 sol ring', '161 sol ring', 'sol ring 161']) {
        expect(await drafted(typed, env)).toEqual(await settled(typed, env));
    }
    // Only a number typed last is held
    expect(draft('161 sol ri').heldNumber).toBeUndefined();
    expect(draft('sol ri 161').heldNumber).toBeUndefined();
    expect(draft('sol ri cn:161').heldNumber).toMatchObject({values: ['161']});
});

// Typing to any of these never says anything, and whenever the query is worth
// asking, never shows an empty page the finished query would not.
test.each([
    'sol ring', 'the soul stone', 'lightning bolt', 'sol ring 161', 's:neo sol', 'sol s:neo', 'sol f:foil',
    'sol r:mythic', 'sol cn:161', 'sol cns:161', 'spm 66', 'spm #066', 'info-en067', 's:spm cn:66', '66',
    'sol ring*', 'bolt -s:spm', '-s:spm bolt', 'sol|neo', 'lightning bolt|neo|123', 'sol date>2020',
])('every prefix of %s', async (finished) => {
    const env = typingEnv();
    Q.resetCaches();
    const end = await Q.execute(Q.parse(finished, DRAFT_FINISHES, magic, DRAFT_SETS), env);
    expect(end.results.length).toBeGreaterThan(0);
    for (let i = 1; i <= finished.length; i++) {
        const typed = finished.slice(0, i);
        const parsed = draft(typed);
        expect(parsed.unsupported).toEqual([]);
        if (!Q.answerable(parsed, env)) continue;
        Q.resetCaches();
        const out = await Q.execute(parsed, env);
        if (!out.results.length) throw new Error(typed + ' found nothing on its way to ' + finished);
    }
});


function namedRows(names) {
    return names.map((n, i) => ({ uuid: 'u' + i, card: { n, set: 'S' + i }, retail: null, buylist: null }));
}

test('the best match comes first, each group keeping its order', async () => {
    const env = { normName: (s) => s.toLowerCase(), loadSetPayload: async () => ({ retail: {}, buylist: {} }) };
    const out = {
        needle: 'sol',
        results: namedRows(['Parasol Bird', 'Solemn Simulacrum', 'Blinding Sol', 'Sol', 'Soldier', 'Absolute Sol']),
    };
    await Q.showPage(out, env, { size: 6, bestMatch: true });
    expect(out.results.map((r) => r.card.n)).toEqual(
        ['Sol', 'Solemn Simulacrum', 'Soldier', 'Blinding Sol', 'Absolute Sol', 'Parasol Bird']);
});

test('without a name to match, the order stays', async () => {
    const env = { normName: (s) => s.toLowerCase(), loadSetPayload: async () => ({ retail: {}, buylist: {} }) };
    const out = { needle: '', results: namedRows(['B', 'A']) };
    await Q.showPage(out, env, { size: 2, bestMatch: true });
    expect(out.results.map((r) => r.card.n)).toEqual(['B', 'A']);
});

test('a search nobody is waiting for stops opening sets', async () => {
    Q.resetCaches();
    const opened = [];
    let stale = false;
    const env = {
        normName: (s) => s,
        loadSetPayload: async (code) => {
            opened.push(code);
            stale = true;
            return { retail: {}, buylist: {} };
        },
    };
    const out = { needle: '', results: namedRows(['A', 'B', 'C']) };
    expect(await Q.showPage(out, env, { size: 3, stale: () => stale })).toBe(true);
    expect(opened).toEqual(['S0']);
});
