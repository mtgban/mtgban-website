// Offline search query mini-parser and executor (contract sec 12).
(function (root) {
    'use strict';

    var FINISH = {
        foil: 'foil', f: 'foil',
        nonfoil: 'nonfoil', nf: 'nonfoil',
        etched: 'etched', e: 'etched'
    };
    var RARITY = {
        common: 'common', c: 'common',
        uncommon: 'uncommon', u: 'uncommon',
        rare: 'rare', r: 'rare',
        mythic: 'mythic', m: 'mythic'
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

    function parse(str) {
        var out = {names: [], set: '', number: '', finish: '', rarity: '', unsupported: []};
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
                    out.number = tok.text;
                } else {
                    out.names.push(tok.text);
                }
                continue;
            }
            if (colon <= 0) {
                out.unsupported.push(tok.text);
                continue;
            }
            var key = tok.text.slice(0, colon).toLowerCase();
            var val = tok.text.slice(colon + 1).replace(/^"|"$/g, '');
            switch (key) {
            case 's':
                out.set = val.toUpperCase();
                break;
            case 'cn':
                out.number = val;
                break;
            case 'f':
                if (FINISH[val.toLowerCase()]) {
                    out.finish = FINISH[val.toLowerCase()];
                } else {
                    out.unsupported.push(tok.text);
                }
                break;
            case 'r':
                if (RARITY[val.toLowerCase()]) {
                    out.rarity = RARITY[val.toLowerCase()];
                } else {
                    out.unsupported.push(tok.text);
                }
                break;
            default:
                out.unsupported.push(tok.text);
            }
        }
        return out;
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
        if (parsed.set && card.set !== parsed.set) return false;
        if (parsed.number && card.num !== parsed.number) return false;
        if (parsed.rarity && card.r !== parsed.rarity) return false;
        if (parsed.finish === 'foil' && !(card.f && !card.e)) return false;
        if (parsed.finish === 'etched' && !card.e) return false;
        if (parsed.finish === 'nonfoil' && (card.f || card.e)) return false;
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
        } else if (parsed.set !== '') {
            if (!(await env.hasSet(parsed.set))) {
                out.missingSets.push(parsed.set);
                return out;
            }
            var payload;
            try {
                payload = await cachedPayload(parsed.set, env);
            } catch (err) {
                out.missingSets.push(parsed.set);
                return out;
            }
            var seen = {};
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
