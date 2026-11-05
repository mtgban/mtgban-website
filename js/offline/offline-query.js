// Offline search query mini-parser and executor.
(function (root) {
    'use strict';

    var FINISH = {
        foil: 'foil', f: 'foil',
        nonfoil: 'nonfoil', nf: 'nonfoil',
        etched: 'etched', e: 'etched'
    };
    // The finish a query's last character asks for, as online
    var SUFFIX_FINISH = {'&': 'nonfoil', '*': 'foil', '~': 'etched', '`': 'foil'};
    // INTEGER is what online's strconv.Atoi takes
    var INTEGER = /^[+-]?\d+$/;

    // rarityName spells a rarity as matcher.RarityName does, which is how
    // online compares one: lower case, without spaces ("superrare").
    function rarityName(rarity) {
        return String(rarity || '').trim().toLowerCase().replace(/ /g, '');
    }

    // readRarities reads an r: list as online's fixupRarityNG does: each word
    // as rarityName spells it, and a single letter as every rarity of the
    // catalog's game it begins; one that begins none stays as written.
    function readRarities(val, ladder) {
        var out = [];
        val.split(',').forEach(function (word) {
            var name = rarityName(word);
            var begun = out.length;
            if (name.length === 1) {
                ladder.forEach(function (value) {
                    if (value.charAt(0) === name) out.push(value);
                });
            }
            if (out.length === begun) out.push(name);
        });
        return out;
    }

    // tokenize splits on whitespace honoring double-quoted phrases and a
    // key:(...) value to its matching paren. Online reads only in:(...) that
    // way; here any key does, so a pool's filters stay one token.
    function tokenize(str) {
        var tokens = [];
        var re = /"([^"]*)"|(-?[a-zA-Z_]+:\()|(\S+)/g;
        var m;
        while ((m = re.exec(str)) !== null) {
            if (m[1] !== undefined) {
                tokens.push({text: m[1], quoted: true});
            } else if (m[2] !== undefined) {
                var depth = 1, quoted = false, k = re.lastIndex;
                for (; k < str.length && depth > 0; k++) {
                    var ch = str.charAt(k);
                    if (ch === '"') {
                        // After a key a quote opens a value; a bare one only
                        // when its closing quote comes before the next paren
                        var closing = str.indexOf('"', k + 1), paren = str.indexOf(')', k + 1);
                        if (quoted) {
                            quoted = false;
                        } else if (/[:<>]/.test(str.charAt(k - 1)) || (closing !== -1 && (paren === -1 || closing < paren))) {
                            quoted = true;
                        }
                    } else if (!quoted && ch === '(') {
                        depth++;
                    } else if (!quoted && ch === ')') {
                        depth--;
                    }
                }
                tokens.push({text: str.slice(m.index, k), quoted: false});
                re.lastIndex = k;
            } else {
                tokens.push({text: m[3], quoted: false});
            }
        }
        return tokens;
    }

    var MONTHS = ['january', 'february', 'march', 'april', 'may', 'june', 'july',
        'august', 'september', 'october', 'november', 'december'];

    // extractNumber reads one word as matcher.ExtractNumberAny does: the
    // number it spells, without its # or padding, or '' when it spells none.
    // limit is the bound the number after a dash is held to, as ExtractNumber.
    function extractNumber(word, limit) {
        if (MONTHS.indexOf(word.toLowerCase()) !== -1) return '';
        var field = word.replace(/[()#]/g, '');
        if (field.split('/').length === 2) field = field.split('/')[0].trim();
        if (/(th|st|nd|rd)$/i.test(field)) return '';
        var num = field.replace(/^0+/, '');
        function under(text) {
            return INTEGER.test(text) && (limit === undefined || parseInt(text, 10) < limit);
        }
        if (under(num)) return num;
        if (num.length < 2) return '';
        if (!/\d$/.test(num) && under(num.replace(/\D.*$/, ''))) return num.toLowerCase();
        if (!/^\d/.test(num) && num.charAt(0) !== 'M' && under(num.slice(1).replace(/^0+/, ''))) return num.toLowerCase();
        var parts = field.split('-');
        if (parts.length === 2 && extractNumber(parts[1], 1993) !== '') {
            return parts[0] + '-' + parts[1].replace(/^0+/, '');
        }
        return '';
    }

    // A code ending in "a" does not count, as online's namesASetCode: 30A is
    // both a set and the shape of a collector number with a letter suffix.
    function namesASetCode(word, sets) {
        return !/a$/i.test(word) && !!sets[word.toUpperCase()];
    }

    // typesSetTotal: a number written with its set total, "222/236", with a
    // digit somewhere so that a name with a slash in it stays a name.
    function typesSetTotal(word) {
        var parts = word.split('/');
        return parts.length === 2 && parts[0] !== '' && parts[1] !== '' && /\d/.test(word);
    }

    // writtenAsNumber: digits, after a # if any, then at most a few marks or
    // letters, "123", "#17a", "107★". An id that starts with a digit is not one.
    function writtenAsNumber(word) {
        var bare = word.replace(/^#/, '');
        var rest = bare.replace(/^\d+/, '');
        return rest.length < bare.length && !/\d/.test(rest) && Array.from(rest).length <= 3;
    }

    // wordNumber is the number filter a word asks for, as online's
    // numberValue: a plain number loosely, one saying more than that exactly
    // as typed, or null for a word that is no number. The catalog carries no
    // set total, so one is read as the number it comes with.
    function wordNumber(word, sets) {
        if (typesSetTotal(word) && !namesASetCode(word, sets)) {
            return readNumber(extractNumber(word) || word.split('/')[0].replace(/^#/, '').toLowerCase(), false);
        }
        var number = extractNumber(word);
        if (number === '' || namesASetCode(word, sets)) return null;
        return /\D/.test(number) ? readNumber(word, true) : readNumber(number, false);
    }

    // setsNamed is the sets a query with no results could have meant, as
    // online's setCodeMatches: an exact code or name alone, else every set
    // whose name carries the query.
    function setsNamed(query, sets) {
        var needle = query.replace(/[ \-_']/g, '').toLowerCase();
        if (needle.length < 3) return [];
        var contains = [];
        var codes = Object.keys(sets).sort();
        for (var i = 0; i < codes.length; i++) {
            var name = String(sets[codes[i]].n || '').replace(/[ \-_']/g, '').toLowerCase();
            if (codes[i].toLowerCase() === needle || name === needle) return [codes[i]];
            if (name.indexOf(needle) !== -1) contains.push(codes[i]);
        }
        return contains;
    }

    // readShortcut reads the free words of a query the way online's
    // parseSearchOptionsDepth does, reporting whether they were all taken:
    // "neo 234" and "plst c16-177" are a set and a number, "info-en067" a
    // number as Yu-Gi-Oh prints it, "222/236" a number with its set total, and
    // "123" or "17a" a number alone. A number after a name is left in the
    // name, for execute to take if the whole name finds nothing.
    function readShortcut(out, words, sets) {
        var last = words[words.length - 1];
        var filter;
        if (words.length === 1 && !out.set.length) {
            var printed = /^([^-]+)-([A-Za-z]{0,2})(\d+)$/.exec(last);
            if (printed && sets[printed[1].toUpperCase()]) {
                filter = readNumber(printed[3].replace(/^0+/, ''), false);
                filter.values.push(last.toLowerCase());
                out.set = [printed[1].toUpperCase()];
                out.printed = last.toLowerCase();
                out.number.push(filter);
                out.names = [];
                return true;
            }
        }
        if (words.length === 2 && !out.set.length && sets[words[0].toUpperCase()]) {
            filter = wordNumber(last, sets);
            if (filter) {
                out.set = [words[0].toUpperCase()];
                out.number.push(filter);
                out.names = [];
                return true;
            }
        }
        if (words.length === 1 && writtenAsNumber(last)) {
            filter = wordNumber(last, sets);
            if (filter) {
                out.bareNumber = last;
                out.number.push(filter);
                out.names = [];
                return true;
            }
        }
        if (typesSetTotal(last) && !namesASetCode(last, sets)) {
            out.number.push(wordNumber(last, sets));
            out.names.pop();
            return false;
        }
        if (words.length > 1 && writtenAsNumber(last) && !/^\d+$/.test(last)) {
            out.trailingNumber = wordNumber(last, sets);
        }
        return false;
    }

    // parse reads a query. finishes is the catalog's finish list: a game's own
    // finish, or a short form of one, is taken where the catalog names it,
    // spelled the way it is stored. A card lists the short forms that reach
    // it, so one is matched as itself. rarities is the catalog's rarity list,
    // which a single r: letter is read against. sets is the catalog's set
    // dictionary, which tells a set code from the first word of a name.
    function parse(str, finishes, rarities, sets) {
        sets = sets || {};
        var ladder = (rarities || []).map(function (rarity) { return rarity && rarity.value; }).filter(Boolean);
        var known = {};
        (finishes || []).forEach(function (finish) {
            if (!finish || !finish.value) return;
            known[finish.value] = true;
            (finish.aliases || []).forEach(function (alias) { known[alias] = true; });
        });
        var out = {names: [], set: [], number: [], finish: [], rarity: [], not: {set: [], finish: [], rarity: []}, unsupported: []};
        var query = String(str || '').trim();
        // A last character asks for a finish, as it does online
        var suffix = query.charAt(query.length - 1);
        if (SUFFIX_FINISH[suffix]) {
            query = query.replace(/[&*~`]+$/, '');
            out.finish.push([SUFFIX_FINISH[suffix]]);
            // The alternate foils are promo types the catalog does not list
            if (suffix === '`') out.unsupported.push(suffix);
        }
        if (query.indexOf('|') !== -1) query = expandBotSyntax(query);
        var tokens = tokenize(query);
        var words = [];
        var digits = [];
        var quoted = false;
        for (var i = 0; i < tokens.length; i++) {
            var tok = tokens[i];
            if (tok.quoted) {
                if (tok.text.trim() !== '') {
                    quoted = true;
                    out.names.push(tok.text);
                }
                continue;
            }
            var colon = tok.text.indexOf(':');
            var operatorish = colon > 0 || /[<>=]/.test(tok.text);
            if (!operatorish) {
                words.push(tok.text);
                if (/^\d+$/.test(tok.text)) {
                    digits.push(tok.text);
                } else {
                    out.names.push(tok.text);
                }
                continue;
            }
            // Split where online does: at the first colon, else the first <,
            // else the first >
            var at = colon !== -1 ? colon : tok.text.indexOf('<');
            if (at === -1) at = tok.text.indexOf('>');
            if (at <= 0) {
                out.unsupported.push(tok.text);
                continue;
            }
            var key = tok.text.slice(0, at).toLowerCase();
            var val = tok.text.slice(at + 1).replace(/^"|"$/g, '');
            // A leading - negates the filter, as it does online
            var negate = key.charAt(0) === '-';
            if (negate) key = key.slice(1);
            if (at !== colon) {
                // Online compares cn: and number: this way (FilterOperations)
                if (key === 'cn' || key === 'number') {
                    out.number.push(readNumber(val, false, tok.text.charAt(at), negate));
                } else {
                    out.unsupported.push(tok.text);
                }
                continue;
            }
            switch (key) {
            case 's':
            case 'e':
            case 'set':
            case 'edition':
                // A comma list names any of its sets, as it does online
                var codes = val.split(',').filter(Boolean).map(function (code) { return code.toUpperCase(); });
                if (negate) {
                    out.not.set = out.not.set.concat(codes);
                } else {
                    out.set = codes;
                }
                break;
            case 'cn':
            case 'cns':
            case 'number':
                out.number.push(readNumber(val, key === 'cns', ':', negate));
                break;
            case 'f':
                var slugs = readFinishes(val, known);
                if (!slugs) {
                    out.unsupported.push(tok.text);
                } else if (negate) {
                    out.not.finish = out.not.finish.concat(slugs);
                } else {
                    // Each f: must hold, as online files one filter per token
                    out.finish.push(slugs);
                }
                break;
            case 'r':
                var named = readRarities(val, ladder);
                if (negate) {
                    out.not.rarity = out.not.rarity.concat(named);
                } else {
                    out.rarity = named;
                }
                break;
            default:
                out.unsupported.push(tok.text);
            }
        }
        if (quoted || !words.length || !readShortcut(out, words, sets)) {
            digits.forEach(function (text) { out.number.push(readNumber(text, false)); });
        }
        if (out.names.length) out.setsNamed = setsNamed(out.names.join(' '), sets);
        return out;
    }

    // expandBotSyntax spells name|set|number|finish|condition with the filters
    // it stands for, as online reads the Pricefall bot's notation.
    function expandBotSyntax(query) {
        var fields = query.split('|');
        var expanded = fields[0].trim();
        ['s:', 'cn:', 'f:', 'cond:'].forEach(function (key, i) {
            var field = (fields[i + 1] || '').trim();
            if (field !== '') expanded += ' ' + key + field;
        });
        return expanded;
    }

    // readFinishes reads f:'s comma list, each value spelled the way the
    // catalog stores it, or null when offline cannot answer one of them.
    function readFinishes(val, known) {
        var values = val.split(',').filter(Boolean);
        if (values.length === 0) return null;
        var out = [];
        for (var i = 0; i < values.length; i++) {
            var lower = values[i].toLowerCase();
            var slug = lower.replace(/[^a-z0-9]/g, '');
            if (FINISH[lower]) {
                out.push(FINISH[lower]);
            } else if (known[slug]) {
                out.push(slug);
            } else {
                return null;
            }
        }
        return out;
    }

    // readNumber reads cn:, cns: and number: as online does: a set list
    // before a colon scopes the number to those sets, two plain numbers
    // around a dash in ascending order are a range, a > or < compares against
    // the first number given, and anything else is a comma list of numbers.
    function readNumber(val, strict, op, negate) {
        var filter = {sets: [], strict: strict, values: [], range: null, compare: null, bound: 0, negate: !!negate};
        var code = val;
        if (code.indexOf(':') !== -1) {
            var parts = code.split(':');
            filter.sets = parts[0].split(',').map(function (set) { return set.replace(/^"|"$/g, '').toUpperCase(); });
            code = parts[1];
        }
        var ends = code.split('-');
        if (ends.length > 1 && INTEGER.test(ends[0]) && INTEGER.test(ends[1]) && parseInt(ends[0], 10) < parseInt(ends[1], 10)) {
            filter.range = [parseInt(ends[0], 10), parseInt(ends[1], 10)];
        } else if (op === '>' || op === '<') {
            filter.compare = op;
            filter.bound = numberValue(code.toLowerCase().split(',')[0]);
        } else {
            filter.values = code.toLowerCase().split(',');
        }
        return filter;
    }

    // numberValue reads a number as online's compareCollectorNumber does:
    // whole, else its first run of digits, and one with no digits sorts past
    // every range.
    function numberValue(num) {
        if (INTEGER.test(num)) return parseInt(num, 10);
        var digits = (/\d+/.exec(num) || [''])[0].replace(/^0+/, '');
        return digits === '' ? Infinity : parseInt(digits, 10);
    }

    // numberMatches answers one number filter as online does. A card outside
    // its sets passes untouched, and a range reads the plain number the
    // catalog carries. A strict number compares the printed one; a loose one
    // takes either, since offline cannot reduce a typed number the way the
    // game would.
    function numberMatches(card, filter) {
        if (filter.sets.length && filter.sets.indexOf(card.set) === -1) return true;
        var printed = (card.num || '').toLowerCase();
        var plain = typeof card.pn === 'string' ? card.pn.toLowerCase() : printed;
        if (filter.range) {
            var value = numberValue(plain);
            // Online files a range's lower bound as a filter of its own that
            // no negation reaches, so a negated range keeps only what lies
            // past its upper bound
            if (filter.negate) return value > filter.range[1];
            return filter.range[0] <= value && value <= filter.range[1];
        }
        var matched;
        // Both ends count, as online's compareCollectorNumber skips only a
        // number past the bound
        if (filter.compare === '>') {
            matched = numberValue(plain) >= filter.bound;
        } else if (filter.compare === '<') {
            matched = numberValue(plain) <= filter.bound;
        } else {
            matched = filter.values.indexOf(printed) !== -1 || (!filter.strict && filter.values.indexOf(plain) !== -1);
        }
        return filter.negate ? !matched : matched;
    }

    // hasFinish answers the three names every game shares off the card's
    // flags, and any other off the names the catalog lists on it.
    function hasFinish(card, finish) {
        switch (finish) {
        case 'foil': return !!card.f && !card.e;
        case 'etched': return !!card.e;
        case 'nonfoil': return !card.f && !card.e;
        }
        return (card.fin || []).indexOf(finish) !== -1;
    }

    // Mirrors MaxSearchTotalResults (search.go:36).
    var MAX_TOTAL = 10000;
    // Store prices kept decoded, most recently used last. A page of 100 rows can
    // need over 500,000, and this many cost roughly 100 MB. Counted rather than
    // sets, as one set can hold a hundred times what another does.
    var CACHE_ENTRIES = 1000000;

    var payloadCache = new Map();
    var payloadCacheEntries = 0;
    // Sets that could not be opened, so a search stops offering their cards.
    var unreadableSets = new Set();

    // The sync the cached payloads were read under.
    var payloadCacheSync;

    function resetCaches() {
        payloadCache = new Map();
        payloadCacheEntries = 0;
        unreadableSets = new Set();
    }

    // payloadEntries counts the store prices a set holds.
    function payloadEntries(payload) {
        var entries = 0;
        [payload.retail, payload.buylist].forEach(function (section) {
            for (var id in section) entries += Object.keys(section[id]).length;
        });
        return entries;
    }

    // dropStalePayloads forgets the cached sets once a sync has finished, here
    // or in another tab: the sync rewrites them in the database, out of this
    // cache's sight, and the stamp is what the banner's refresh time reads.
    function dropStalePayloads(sync) {
        if (sync !== payloadCacheSync) {
            payloadCacheSync = sync;
            resetCaches();
        }
    }

    function usePayload(code) {
        var hit = payloadCache.get(code);
        payloadCache.delete(code);
        payloadCache.set(code, hit);
        return hit.payload;
    }

    // cachedPayload is an LRU over decoded set payloads. It rejects for a set
    // that has gone from the database as well as one that won't decode.
    async function cachedPayload(code, env) {
        if (payloadCache.has(code)) return usePayload(code);
        // A load the cache was reset under may hold what the sync replaced, so
        // it answers its own search and is not kept.
        var cache = payloadCache;
        var payload = await env.loadSetPayload(code);
        if (!payload) throw new Error('no stored set ' + code);
        if (cache !== payloadCache) return payload;
        // Another search loaded this set in the meantime
        if (payloadCache.has(code)) return usePayload(code);
        var entries = payloadEntries(payload);
        payloadCache.set(code, {payload: payload, entries: entries});
        payloadCacheEntries += entries;
        while (payloadCacheEntries > CACHE_ENTRIES && payloadCache.size > 1) {
            var oldest = payloadCache.keys().next().value;
            payloadCacheEntries -= payloadCache.get(oldest).entries;
            payloadCache.delete(oldest);
        }
        return payload;
    }

    // candidateUUIDs unions the exact-key hit with a substring scan.
    async function candidateUUIDs(parsed, env, out) {
        var needle = env.normName(parsed.names.join(' '));
        if (needle === '') {
            return [];
        }
        var uuids = [];
        var seen = {};
        function push(id) {
            if (seen[id]) return;
            if (uuids.length >= MAX_TOTAL) {
                out.truncated = true;
                return;
            }
            seen[id] = true;
            uuids.push(id);
        }
        (await env.lookupName(needle)).forEach(push);
        // Skip substring scan for short needles to avoid a full-index walk.
        if (needle.length >= 3) {
            var list = await env.allNames();
            for (var i = 0; i < list.length && uuids.length < MAX_TOTAL; i++) {
                if (list[i].key !== needle && list[i].key.indexOf(needle) !== -1) {
                    list[i].uuids.forEach(push);
                }
            }
        }
        return uuids;
    }

    function matchesFilters(card, parsed) {
        if (parsed.sealed != null && !!card.s !== parsed.sealed) return false;
        if (parsed.set.length && parsed.set.indexOf(card.set) === -1) return false;
        if (!parsed.number.every(function (filter) { return numberMatches(card, filter); })) return false;
        if (parsed.not.set.indexOf(card.set) !== -1) return false;
        var rarity = rarityName(card.r);
        if (parsed.not.rarity.indexOf(rarity) !== -1) return false;
        if (parsed.not.finish.some(function (finish) { return hasFinish(card, finish); })) return false;
        if (parsed.rarity.length && parsed.rarity.indexOf(rarity) === -1) return false;
        if (!parsed.finish.every(function (slugs) {
            return slugs.some(function (finish) { return hasFinish(card, finish); });
        })) return false;
        return true;
    }

    async function cardsByName(parsed, env, out) {
        var cards = [];
        var uuids = await candidateUUIDs(parsed, env, out);
        for (var i = 0; i < uuids.length; i++) {
            var card = await env.getCard(uuids[i]);
            if (card && matchesFilters(card, parsed)) {
                cards.push(card);
            }
        }
        return cards;
    }

    async function cardsBySet(parsed, env, stored) {
        var cards = [];
        var seen = {};
        for (var n = 0; n < parsed.set.length; n++) {
            var setCode = parsed.set[n];
            if (!stored.has(setCode)) continue;
            var payload;
            try {
                payload = await cachedPayload(setCode, env);
            } catch (err) {
                unreadableSets.add(setCode);
                stored.delete(setCode);
                continue;
            }
            var sections = [payload.retail, payload.buylist];
            for (var s = 0; s < sections.length; s++) {
                for (var id in sections[s]) {
                    if (seen[id]) continue;
                    seen[id] = true;
                    var c = await env.getCard(id);
                    if (c && matchesFilters(c, parsed)) {
                        cards.push(c);
                    }
                }
            }
        }
        return cards;
    }

    // The cards by the number they print and the plain one they reduce to, each
    // list in catalog order, for one list of cards.
    var numberIndexes = new WeakMap();

    function numberIndex(list) {
        var index = numberIndexes.get(list);
        if (index) return index;
        index = new Map();
        function file(key, card) {
            var bucket = index.get(key);
            if (bucket) bucket.push(card);
            else index.set(key, [card]);
        }
        list.forEach(function (card) {
            var printed = (card.num || '').toLowerCase();
            file(printed, card);
            if (typeof card.pn === 'string' && card.pn.toLowerCase() !== printed) file(card.pn.toLowerCase(), card);
        });
        numberIndexes.set(list, index);
        return index;
    }

    // numberCandidates narrows the catalog to one number when a filter asks for
    // exactly that, so a search needn't walk every card. Filters still decide.
    function numberCandidates(list, parsed) {
        for (var i = 0; i < parsed.number.length; i++) {
            var filter = parsed.number[i];
            if (filter.values.length === 1 && !filter.negate && !filter.sets.length) {
                return numberIndex(list).get(filter.values[0]) || [];
            }
        }
        return list;
    }

    // cardsByNumber walks the catalog for a number no name or set narrows,
    // keeping the sets on this device, so the others don't use up the limit.
    async function cardsByNumber(parsed, env, stored, out) {
        var list = await env.allCards();
        var kept = numberCandidates(list, parsed).filter(function (card) {
            return stored.has(card.set) && matchesFilters(card, parsed);
        });
        if (kept.length > MAX_TOTAL) {
            kept = kept.slice(0, MAX_TOTAL);
            out.truncated = true;
        }
        return kept;
    }

    function withoutNumber(parsed, name) {
        return Object.assign({}, parsed, {names: [name], number: [], bareNumber: ''});
    }

    async function findCards(parsed, env, stored, out) {
        if (parsed.bareNumber && !parsed.set.length) {
            // A card's own name, Yu-Gi-Oh's "7", stays a name, and so does a
            // number no card carries
            var asName = withoutNumber(parsed, parsed.bareNumber);
            if ((await env.lookupName(env.normName(parsed.bareNumber))).length) {
                return cardsByName(asName, env, out);
            }
            var numbered = await cardsByNumber(parsed, env, stored, out);
            return numbered.length ? numbered : cardsByName(asName, env, out);
        }
        if (parsed.names.length > 0) {
            var cards = await cardsByName(parsed, env, out);
            if (!cards.length && parsed.trailingNumber) {
                cards = await cardsByName(Object.assign({}, parsed, {
                    names: parsed.names.slice(0, -1),
                    number: parsed.number.concat([parsed.trailingNumber])
                }), env, out);
            }
            return cards;
        }
        if (parsed.set.length > 0) {
            var inSet = await cardsBySet(parsed, env, stored);
            if (parsed.printed && inSet.some(function (card) { return (card.num || '').toLowerCase() === parsed.printed; })) {
                // A word a card of its set carries is that number exactly
                return inSet.filter(function (card) { return (card.num || '').toLowerCase() === parsed.printed; });
            }
            return inSet;
        }
        return parsed.number.length > 0 && env.allCards ? cardsByNumber(parsed, env, stored, out) : [];
    }

    // toRows keeps the cards of stored sets, grouped by set: the sorts break
    // their ties on this order. A row has no prices until priceRows gives it some.
    function toRows(cards, stored) {
        var bySet = {};
        cards.forEach(function (card) {
            (bySet[card.set] = bySet[card.set] || []).push(card);
        });
        var rows = [];
        Object.keys(bySet).sort().forEach(function (code) {
            if (!stored.has(code)) return;
            bySet[code].forEach(function (card) {
                rows.push({uuid: card.uuid, i: card.i, card: card, retail: null, buylist: null});
            });
        });
        return rows;
    }

    // priceRows opens the sets the rows need, and reports whether it could: a set
    // that won't open changes what the search should have found.
    async function priceRows(rows, env) {
        var bySet = {};
        rows.forEach(function (row) {
            if (!row.retail) (bySet[row.card.set] = bySet[row.card.set] || []).push(row);
        });
        var complete = true;
        var codes = Object.keys(bySet);
        for (var k = 0; k < codes.length; k++) {
            var pl;
            try {
                pl = await cachedPayload(codes[k], env);
            } catch (err) {
                unreadableSets.add(codes[k]);
                complete = false;
                continue;
            }
            bySet[codes[k]].forEach(function (row) {
                row.retail = (pl.retail && pl.retail[row.uuid]) || {};
                row.buylist = (pl.buylist && pl.buylist[row.uuid]) || {};
            });
        }
        return complete;
    }

    // find answers a query from the catalog and the list of stored sets, opening
    // only what a set search has to. Its rows aren't priced yet.
    async function find(parsed, env) {
        var state = await env.searchState();
        dropStalePayloads(state.lastSync);
        var stored = new Set(state.stored);
        unreadableSets.forEach(function (code) { stored.delete(code); });
        var out = {results: [], page: [], truncated: false, unsupported: parsed.unsupported};

        out.results = toRows(await findCards(parsed, env, stored, out), stored);

        // A query no name answers may name a set. One the query already
        // narrowed to is not up for reinterpretation.
        if (!out.results.length && !parsed.set.length && (parsed.setsNamed || []).length) {
            out.results = toRows(await cardsBySet(Object.assign({}, parsed, {set: parsed.setsNamed}), env, stored), stored);
        }
        return out;
    }

    // showPage orders an answer and prices what view asks: size rows, or every
    // row if allPrices says a sort needs them. False means a set wouldn't open,
    // and the query has to be asked again.
    async function showPage(out, env, view) {
        if (view.allPrices && view.allPrices() && !(await priceRows(out.results, env))) return false;
        if (view.order) view.order(out.results);
        out.page = view.size === undefined ? out.results : out.results.slice(0, view.size);
        return priceRows(out.page, env);
    }

    // execute answers a query. Without a view every row is priced.
    async function execute(parsed, env, view) {
        for (;;) {
            var out = await find(parsed, env);
            var known = unreadableSets.size;
            if (await showPage(out, env, view || {})) return out;
            // Each round must rule out another set, or asking again won't help
            if (unreadableSets.size === known) throw new Error('offline sets keep failing to open');
        }
    }

    function bestPrice(section) {
        var best = 0;
        for (var store in section) {
            var e = section[store];
            var vals = [e.regular, e.foil, e.etched, e.sealed];
            for (var i = 0; i < vals.length; i++) {
                if (vals[i] > 0 && (best === 0 || vals[i] > best)) {
                    best = vals[i];
                }
            }
        }
        return best;
    }

    function numCompare(a, b) {
        var na = parseInt(a, 10);
        var nb = parseInt(b, 10);
        if (!isNaN(na) && !isNaN(nb) && na !== nb) return na - nb;
        return a < b ? -1 : a > b ? 1 : 0;
    }

    function sortResults(results, mode, reverse, sets) {
        function date(r) {
            var s = sets[r.card.set];
            return (s && s.d) || '';
        }
        var cmp;
        switch (mode) {
        case 'alpha':
            cmp = function (a, b) {
                var an = a.card.n.toLowerCase();
                var bn = b.card.n.toLowerCase();
                if (an !== bn) return an < bn ? -1 : 1;
                return date(b) < date(a) ? -1 : 1;
            };
            break;
        case 'number':
            cmp = function (a, b) { return numCompare(a.card.num || '', b.card.num || ''); };
            break;
        case 'retail':
            cmp = function (a, b) { return bestPrice(b.retail) - bestPrice(a.retail); };
            break;
        case 'buylist':
            cmp = function (a, b) { return bestPrice(b.buylist) - bestPrice(a.buylist); };
            break;
        default: // chrono, newest set first then collector number
            cmp = function (a, b) {
                var da = date(a);
                var db = date(b);
                if (da !== db) return da < db ? 1 : -1;
                return numCompare(a.card.num || '', b.card.num || '');
            };
        }
        results.sort(function (a, b) {
            var v = cmp(a, b);
            return reverse ? -v : v;
        });
    }

    root.OfflineQuery = {
        parse: parse,
        execute: execute,
        showPage: showPage,
        sortResults: sortResults,
        resetCaches: resetCaches,
    };
})(typeof self !== 'undefined' ? self : globalThis);
