// Offline search query mini-parser and executor.
(function (root) {
    'use strict';

    var FINISH = {
        foil: 'foil', f: 'foil',
        nonfoil: 'nonfoil', nf: 'nonfoil',
        etched: 'etched', e: 'etched'
    };
    // INTEGER is what online's strconv.Atoi takes
    var INTEGER = /^[+-]?\d+$/;

    // RARITY is online's short forms (fixupRarityNG). Any other word is a
    // rarity as the catalog writes it, as it is online.
    var RARITY = {
        c: 'common', u: 'uncommon', r: 'rare', m: 'mythic',
        s: 'special', t: 'token', o: 'oversize'
    };

    // tokenize splits on whitespace honoring double-quoted phrases.
    function tokenize(str) {
        var tokens = [];
        var re = /"([^"]*)"|(\S+)/g;
        var m;
        while ((m = re.exec(str)) !== null) {
            if (m[1] !== undefined) {
                tokens.push({text: m[1], quoted: true});
            } else {
                tokens.push({text: m[2], quoted: false});
            }
        }
        return tokens;
    }

    // parse reads a query. finishes is the catalog's finish list: a game's own
    // finish, or a short form of one, is taken where the catalog names it,
    // spelled the way it is stored. A card lists the short forms that reach
    // it, so one is matched as itself.
    function parse(str, finishes) {
        var known = {};
        (finishes || []).forEach(function (finish) {
            if (!finish || !finish.value) return;
            known[finish.value] = true;
            (finish.aliases || []).forEach(function (alias) { known[alias] = true; });
        });
        var out = {names: [], set: [], number: [], finish: [], rarity: [], not: {set: [], finish: [], rarity: []}, unsupported: []};
        var tokens = tokenize(String(str || ''));
        for (var i = 0; i < tokens.length; i++) {
            var tok = tokens[i];
            if (tok.quoted) {
                if (tok.text.trim() !== '') {
                    out.names.push(tok.text);
                }
                continue;
            }
            var colon = tok.text.indexOf(':');
            var operatorish = colon > 0 || /[<>=]/.test(tok.text);
            if (!operatorish) {
                if (/^\d+$/.test(tok.text)) {
                    out.number.push(readNumber(tok.text, false));
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
                var sets = val.split(',').filter(Boolean).map(function (code) { return code.toUpperCase(); });
                if (negate) {
                    out.not.set = out.not.set.concat(sets);
                } else {
                    out.set = sets;
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
                var rarities = val.toLowerCase().split(',').map(function (value) {
                    return RARITY[value] || value;
                });
                if (negate) {
                    out.not.rarity = out.not.rarity.concat(rarities);
                } else {
                    out.rarity = rarities;
                }
                break;
            default:
                out.unsupported.push(tok.text);
            }
        }
        return out;
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
    var LRU_SIZE = 8;

    var payloadCache = new Map();
    var nameCache = null;

    function resetCaches() {
        payloadCache = new Map();
        nameCache = null;
    }

    // cachedPayload is an LRU over decoded set payloads.
    async function cachedPayload(code, env) {
        if (payloadCache.has(code)) {
            var hit = payloadCache.get(code);
            payloadCache.delete(code);
            payloadCache.set(code, hit);
            return hit;
        }
        var payload = await env.loadSetPayload(code);
        payloadCache.set(code, payload);
        while (payloadCache.size > LRU_SIZE) {
            payloadCache.delete(payloadCache.keys().next().value);
        }
        return payload;
    }

    // nameList caches the names store in memory once per session.
    async function nameList(env) {
        if (nameCache === null) {
            nameCache = await env.allNames();
        }
        return nameCache;
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
            var list = await nameList(env);
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
        if (parsed.not.rarity.indexOf(card.r || '') !== -1) return false;
        if (parsed.not.finish.some(function (finish) { return hasFinish(card, finish); })) return false;
        if (parsed.rarity.length && parsed.rarity.indexOf(card.r || '') === -1) return false;
        if (!parsed.finish.every(function (slugs) {
            return slugs.some(function (finish) { return hasFinish(card, finish); });
        })) return false;
        return true;
    }

    async function execute(parsed, env) {
        var out = {results: [], truncated: false, missingSets: [], unsupported: parsed.unsupported};

        var cards = [];
        if (parsed.names.length > 0) {
            var uuids = await candidateUUIDs(parsed, env, out);
            for (var i = 0; i < uuids.length; i++) {
                var card = await env.getCard(uuids[i]);
                if (card && matchesFilters(card, parsed)) {
                    cards.push(card);
                }
            }
        } else if (parsed.set.length > 0) {
            var seen = {};
            for (var n = 0; n < parsed.set.length; n++) {
                var setCode = parsed.set[n];
                if (!(await env.hasSet(setCode))) {
                    out.missingSets.push(setCode);
                    continue;
                }
                var payload;
                try {
                    payload = await cachedPayload(setCode, env);
                } catch (err) {
                    out.missingSets.push(setCode);
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
        } else {
            return out;
        }

        // Group by set so each payload is decoded once.
        var bySet = {};
        cards.forEach(function (card) {
            (bySet[card.set] = bySet[card.set] || []).push(card);
        });
        var codes = Object.keys(bySet).sort();
        for (var k = 0; k < codes.length; k++) {
            var code = codes[k];
            if (!(await env.hasSet(code))) {
                out.missingSets.push(code);
                continue;
            }
            var pl;
            try {
                pl = await cachedPayload(code, env);
            } catch (err) {
                out.missingSets.push(code);
                continue;
            }
            bySet[code].forEach(function (card) {
                out.results.push({
                    uuid: card.uuid,
                    i: card.i,
                    card: card,
                    retail: (pl.retail && pl.retail[card.uuid]) || {},
                    buylist: (pl.buylist && pl.buylist[card.uuid]) || {},
                });
            });
        }
        return out;
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
        sortResults: sortResults,
        resetCaches: resetCaches,
    };
})(typeof self !== 'undefined' ? self : globalThis);
