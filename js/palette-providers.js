/* Palette Providers - prefix-driven dropdown candidate suppliers.
 * window.__palette_providers exposes a registry with:
 *   - register(provider)
 *   - detectPrefix(input) -> { prefix, query } | null
 *   - getProvider(prefix) -> provider
 *   - filterEntries(entries, query) -> entries filtered by substring match
 * Providers are registered by individual files (C2-C5) or inline in this file.
 */
(function () {
    'use strict';

    var providers = {};

    var onDataReady = null;
    function setOnDataReady(cb) { onDataReady = cb; }

    function register(p) {
        if (!p || !p.prefix) return;
        providers[p.prefix.toLowerCase()] = p;
    }

    // Given an input string, return { prefix, query } if it starts with a known
    // filter prefix, else null. Longer prefixes take precedence so "buy_price>"
    // matches before "price>".
    function detectPrefix(input) {
        if (!input) return null;
        var lower = input.toLowerCase();
        var keys = Object.keys(providers).sort(function (a, b) {
            return b.length - a.length;
        });
        for (var i = 0; i < keys.length; i++) {
            if (lower.indexOf(keys[i]) === 0) {
                return { prefix: keys[i], query: input.substring(keys[i].length) };
            }
        }
        return null;
    }

    function getProvider(prefix) {
        if (!prefix) return null;
        return providers[prefix.toLowerCase()] || null;
    }

    // Shared substring filter: matches query against label + value + sublabel.
    function filterEntries(entries, query) {
        if (!query) return entries;
        var q = query.toLowerCase();
        var out = [];
        for (var i = 0; i < entries.length; i++) {
            var e = entries[i];
            var hay = (e.label || '') + ' ' + (e.value || '') + ' ' + (e.sublabel || '');
            if (hay.toLowerCase().indexOf(q) >= 0) out.push(e);
        }
        return out;
    }

    // ── Static providers ──────────────────────────────────────────

    // Rarity - narrows by card's rarities when card chip present
    register({
        prefix: 'r:',
        name: 'Rarities',
        icon: 'diamond',
        getCandidates: function (query, ctx) {
            var base = [
                { value: 'mythic', label: 'Mythic', sublabel: 'm', iconColor: '#f59e0b' },
                { value: 'rare', label: 'Rare', sublabel: 'r', iconColor: '#d4af37' },
                { value: 'uncommon', label: 'Uncommon', sublabel: 'u', iconColor: '#c0c0c0' },
                { value: 'common', label: 'Common', sublabel: 'c', iconColor: '#555' },
                { value: 'special', label: 'Special', sublabel: 's', iconColor: '#8b5cf6' },
                { value: 'token', label: 'Token', sublabel: 't', iconColor: '#888' },
                { value: 'oversize', label: 'Oversize', sublabel: 'o', iconColor: '#888' }
            ];
            if (ctx && ctx.cardMeta && ctx.cardMeta.rarities && ctx.cardMeta.rarities.length > 0) {
                var allowed = {};
                for (var i = 0; i < ctx.cardMeta.rarities.length; i++) {
                    allowed[ctx.cardMeta.rarities[i]] = true;
                }
                base = base.filter(function (e) { return allowed[e.value]; });
            }
            return filterEntries(base, query);
        }
    });

    // Finish
    register({
        prefix: 'f:',
        name: 'Finish',
        icon: 'sparkles',
        getCandidates: function (query) {
            var base = [
                { value: 'foil', label: 'Foil', iconColor: '#d4af37' },
                { value: 'nonfoil', label: 'Non-foil', iconColor: '#888' },
                { value: 'etched', label: 'Etched', iconColor: '#06b6d4' }
            ];
            return filterEntries(base, query);
        }
    });

    // Condition
    register({
        prefix: 'cond:',
        name: 'Condition',
        icon: 'shield-check',
        getCandidates: function (query) {
            var base = [
                { value: 'NM', label: 'Near Mint' },
                { value: 'SP', label: 'Slightly Played' },
                { value: 'MP', label: 'Moderately Played' },
                { value: 'HP', label: 'Heavily Played' },
                { value: 'PO', label: 'Poor' }
            ];
            return filterEntries(base, query);
        }
    });

    // Search mode
    register({
        prefix: 'sm:',
        name: 'Search Mode',
        icon: 'scan-search',
        getCandidates: function (query) {
            var base = [
                { value: 'exact', label: 'Exact match (default)' },
                { value: 'prefix', label: 'Names starting with...' },
                { value: 'any', label: 'Names containing...' },
                { value: 'regexp', label: 'Regular expression' },
                { value: 'scryfall', label: 'Forward to Scryfall' }
            ];
            return filterEntries(base, query);
        }
    });

    // Sort
    register({
        prefix: 'sort:',
        name: 'Sort Order',
        icon: 'arrow-up-down',
        getCandidates: function (query) {
            var base = [
                { value: 'chrono', label: 'Chronological (default)' },
                { value: 'hybrid', label: 'Alphabetical, grouped by set' },
                { value: 'alpha', label: 'Alphabetical' },
                { value: 'number', label: 'Collector number' },
                { value: 'retail', label: 'Retail price' },
                { value: 'buylist', label: 'Buylist price' }
            ];
            return filterEntries(base, query);
        }
    });

    // Special lists
    register({
        prefix: 'on:',
        name: 'Lists',
        icon: 'list-checks',
        getCandidates: function (query) {
            var base = [
                { value: 'hotlist', label: 'Hotlist (3mo buylist peak)' },
                { value: 'tcgsyp', label: 'TCGplayer SYP List' },
                { value: 'newspaper', label: 'Newspaper spike scores' }
            ];
            return filterEntries(base, query);
        }
    });

    // Property tags (is: and not: share the same list)
    var isTagOptions = [
        { value: 'reserved', label: 'Reserved List', group: 'Legal' },
        { value: 'token', label: 'Token', group: 'Generic' },
        { value: 'oversize', label: 'Oversize', group: 'Generic' },
        { value: 'funny', label: 'Funny (un-sets)', group: 'Generic' },
        { value: 'commander', label: 'Commander', group: 'Generic' },
        { value: 'gamechanger', label: 'Game Changer', sublabel: 'gc', group: 'Generic' },
        { value: 'fullart', label: 'Full Art', sublabel: 'ea', group: 'Frame' },
        { value: 'extendedart', label: 'Extended Art', group: 'Frame' },
        { value: 'showcase', label: 'Showcase', sublabel: 'sc', group: 'Frame' },
        { value: 'borderless', label: 'Borderless', sublabel: 'bd', group: 'Frame' },
        { value: 'retro', label: 'Retro frame', group: 'Frame' },
        { value: 'japanese', label: 'Japanese', sublabel: 'jp', group: 'Language' },
        { value: 'phyrexian', label: 'Phyrexian', sublabel: 'ph', group: 'Language' },
        { value: 'fetchland', label: 'Fetchland', group: 'Land cycle' },
        { value: 'dual', label: 'Dual land', group: 'Land cycle' },
        { value: 'shockland', label: 'Shockland', group: 'Land cycle' },
        { value: 'painland', label: 'Painland', group: 'Land cycle' },
        { value: 'checkland', label: 'Checkland', group: 'Land cycle' },
        { value: 'fastland', label: 'Fastland', group: 'Land cycle' },
        { value: 'power9', label: 'Power 9', sublabel: 'p9', group: 'Known sets' },
        { value: 'abu4h', label: 'ABU + 4 Horsemen', group: 'Known sets' },
        { value: 'prerelease', label: 'Prerelease promo', group: 'Promo' },
        { value: 'buyabox', label: 'Buy-a-box promo', group: 'Promo' },
        { value: 'serialized', label: 'Serialized', group: 'Promo' },
        { value: 'promo', label: 'Any promo', group: 'Promo' }
    ];
    register({
        prefix: 'is:',
        name: 'Has Tag',
        icon: 'tag',
        getCandidates: function (query) { return filterEntries(isTagOptions, query); }
    });
    register({
        prefix: 'not:',
        name: "Doesn't Have Tag",
        icon: 'tag',
        getCandidates: function (query) { return filterEntries(isTagOptions, query); }
    });

    // Skip
    register({
        prefix: 'skip:',
        name: 'Skip',
        icon: 'filter-x',
        getCandidates: function (query) {
            var base = [
                { value: 'retail', label: 'Retail prices' },
                { value: 'buylist', label: 'Buylist prices' },
                { value: 'empty', label: 'Entries with no prices' },
                { value: 'emptyretail', label: 'Entries with no retail prices' },
                { value: 'emptybuylist', label: 'Entries with no buylist prices' },
                { value: 'index', label: 'Index/aggregate prices' },
                { value: 'indexretail', label: 'Index retail only' },
                { value: 'indexbuylist', label: 'Index buylist only' }
            ];
            return filterEntries(base, query);
        }
    });

    // Region
    register({
        prefix: 'region:',
        name: 'Region',
        icon: 'globe',
        getCandidates: function (query) {
            return filterEntries([
                { value: 'us', label: 'United States' },
                { value: 'eu', label: 'Europe' },
                { value: 'jp', label: 'Japan' }
            ], query);
        }
    });

    // ── Color provider (c: / ci:) ────────────────────────────────

    var colorOptions = [
        { value: 'W', label: 'White', group: 'Primary' },
        { value: 'U', label: 'Blue', group: 'Primary' },
        { value: 'B', label: 'Black', group: 'Primary' },
        { value: 'R', label: 'Red', group: 'Primary' },
        { value: 'G', label: 'Green', group: 'Primary' },
        { value: 'C', label: 'Colorless', group: 'Primary' },
        { value: 'M', label: 'Multicolor', group: 'Primary' },

        { value: 'azorius', label: 'Azorius', sublabel: 'WU', group: 'Guild', colors: 'WU' },
        { value: 'dimir', label: 'Dimir', sublabel: 'UB', group: 'Guild', colors: 'UB' },
        { value: 'rakdos', label: 'Rakdos', sublabel: 'BR', group: 'Guild', colors: 'BR' },
        { value: 'gruul', label: 'Gruul', sublabel: 'RG', group: 'Guild', colors: 'RG' },
        { value: 'selesnya', label: 'Selesnya', sublabel: 'GW', group: 'Guild', colors: 'GW' },
        { value: 'orzhov', label: 'Orzhov', sublabel: 'WB', group: 'Guild', colors: 'WB' },
        { value: 'izzet', label: 'Izzet', sublabel: 'UR', group: 'Guild', colors: 'UR' },
        { value: 'golgari', label: 'Golgari', sublabel: 'BG', group: 'Guild', colors: 'BG' },
        { value: 'boros', label: 'Boros', sublabel: 'RW', group: 'Guild', colors: 'RW' },
        { value: 'simic', label: 'Simic', sublabel: 'GU', group: 'Guild', colors: 'GU' },

        { value: 'bant', label: 'Bant', sublabel: 'GWU', group: 'Shard', colors: 'GWU' },
        { value: 'esper', label: 'Esper', sublabel: 'WUB', group: 'Shard', colors: 'WUB' },
        { value: 'grixis', label: 'Grixis', sublabel: 'UBR', group: 'Shard', colors: 'UBR' },
        { value: 'jund', label: 'Jund', sublabel: 'BRG', group: 'Shard', colors: 'BRG' },
        { value: 'naya', label: 'Naya', sublabel: 'RGW', group: 'Shard', colors: 'RGW' },

        { value: 'abzan', label: 'Abzan', sublabel: 'WBG', group: 'Wedge', colors: 'WBG' },
        { value: 'jeskai', label: 'Jeskai', sublabel: 'URW', group: 'Wedge', colors: 'URW' },
        { value: 'sultai', label: 'Sultai', sublabel: 'BGU', group: 'Wedge', colors: 'BGU' },
        { value: 'mardu', label: 'Mardu', sublabel: 'RWB', group: 'Wedge', colors: 'RWB' },
        { value: 'temur', label: 'Temur', sublabel: 'GUR', group: 'Wedge', colors: 'GUR' },

        { value: 'silverquill', label: 'Silverquill', sublabel: 'WB', group: 'College', colors: 'WB' },
        { value: 'prismari', label: 'Prismari', sublabel: 'UR', group: 'College', colors: 'UR' },
        { value: 'witherbloom', label: 'Witherbloom', sublabel: 'BG', group: 'College', colors: 'BG' },
        { value: 'lorehold', label: 'Lorehold', sublabel: 'RW', group: 'College', colors: 'RW' },
        { value: 'quandrix', label: 'Quandrix', sublabel: 'GU', group: 'College', colors: 'GU' },

        { value: 'chaos', label: 'Chaos', sublabel: 'UBRG', group: 'Four-Color', colors: 'UBRG' },
        { value: 'aggression', label: 'Aggression', sublabel: 'BRGW', group: 'Four-Color', colors: 'BRGW' },
        { value: 'altruism', label: 'Altruism', sublabel: 'RGWU', group: 'Four-Color', colors: 'RGWU' },
        { value: 'growth', label: 'Growth', sublabel: 'GWUB', group: 'Four-Color', colors: 'GWUB' },
        { value: 'artifice', label: 'Artifice', sublabel: 'WUBR', group: 'Four-Color', colors: 'WUBR' }
    ];

    function narrowByCardColors(opts, cardColors) {
        if (!cardColors || cardColors.length === 0) return opts;
        var allowed = {};
        for (var i = 0; i < cardColors.length; i++) {
            allowed[cardColors[i].toUpperCase()] = true;
        }
        return opts.filter(function (o) {
            if (o.group === 'Primary') {
                // Always show C (colorless) and M (multicolor) regardless of card colors;
                // primaries require that color to be part of the card
                if (o.value === 'C' || o.value === 'M') return true;
                return !!allowed[o.value];
            }
            // Multi-color combos: every letter in o.colors must be in card's colors
            if (!o.colors) return false;
            for (var j = 0; j < o.colors.length; j++) {
                if (!allowed[o.colors.charAt(j)]) return false;
            }
            return true;
        });
    }

    var colorProvider = {
        name: 'Colors',
        icon: 'palette',
        getCandidates: function (query, ctx) {
            var opts = colorOptions;
            if (ctx && ctx.cardMeta && ctx.cardMeta.colors) {
                opts = narrowByCardColors(opts, ctx.cardMeta.colors);
            }
            return filterEntries(opts, query);
        }
    };

    // Register both c: and ci: with the same candidates
    register({
        prefix: 'c:',
        name: colorProvider.name,
        icon: colorProvider.icon,
        getCandidates: colorProvider.getCandidates
    });
    register({
        prefix: 'ci:',
        name: 'Color Identity',
        icon: colorProvider.icon,
        getCandidates: colorProvider.getCandidates
    });

    // ── Sets provider (s: / e:) ──────────────────────────────────

    var setsCache = null;
    var setsCacheFetching = null;
    function ensureSets() {
        if (setsCache) return Promise.resolve(setsCache);
        if (setsCacheFetching) return setsCacheFetching;
        setsCacheFetching = fetch('/api/palette/sets.json')
            .then(function (r) { return r.ok ? r.json() : []; })
            .then(function (data) {
                setsCache = data || [];
                setsCacheFetching = null;
                if (typeof onDataReady === 'function') onDataReady();
                return setsCache;
            })
            .catch(function () {
                setsCache = [];
                setsCacheFetching = null;
                if (typeof onDataReady === 'function') onDataReady();
                return setsCache;
            });
        return setsCacheFetching;
    }

    var setsProvider = {
        name: 'Sets',
        icon: 'library',
        getCandidates: function (query, ctx) {
            if (!setsCache) {
                ensureSets();
                return [{ value: '', label: 'Loading…', disabled: true }];
            }
            var opts = [];
            for (var i = 0; i < setsCache.length; i++) {
                var s = setsCache[i];
                opts.push({
                    value: s.code,
                    label: s.name,
                    sublabel: s.code + (s.released ? ' \xb7 ' + s.released.substring(0, 4) : ''),
                    keyrune: s.keyrune || ''
                });
            }
            if (ctx && ctx.cardMeta && ctx.cardMeta.printings) {
                var allowed = {};
                for (var j = 0; j < ctx.cardMeta.printings.length; j++) {
                    allowed[ctx.cardMeta.printings[j]] = true;
                }
                opts = opts.filter(function (o) { return allowed[o.value]; });
            }
            return filterEntries(opts, query);
        }
    };

    register({
        prefix: 's:',
        name: setsProvider.name,
        icon: setsProvider.icon,
        getCandidates: setsProvider.getCandidates
    });
    register({
        prefix: 'e:',
        name: setsProvider.name,
        icon: setsProvider.icon,
        getCandidates: setsProvider.getCandidates
    });

    // ── Stores provider (store: / seller: / vendor:) ─────────────

    var storesCache = null;
    var storesCacheFetching = null;
    function ensureStores() {
        if (storesCache) return Promise.resolve(storesCache);
        if (storesCacheFetching) return storesCacheFetching;
        storesCacheFetching = fetch('/api/palette/stores.json')
            .then(function (r) { return r.ok ? r.json() : { sellers: [], vendors: [] }; })
            .then(function (data) {
                storesCache = data || { sellers: [], vendors: [] };
                storesCacheFetching = null;
                if (typeof onDataReady === 'function') onDataReady();
                return storesCache;
            })
            .catch(function () {
                storesCache = { sellers: [], vendors: [] };
                storesCacheFetching = null;
                if (typeof onDataReady === 'function') onDataReady();
                return storesCache;
            });
        return storesCacheFetching;
    }

    function storesAsEntries(list) {
        var out = [];
        for (var i = 0; i < list.length; i++) {
            var s = list[i];
            out.push({
                value: s.shorthand,
                label: s.name,
                sublabel: s.shorthand + (s.country ? ' ' + s.country : '')
            });
        }
        return out;
    }

    function makeStoresProvider(side) {
        return {
            name: side === 'sellers' ? 'Sellers' : side === 'vendors' ? 'Vendors' : 'Stores',
            icon: 'store',
            getCandidates: function (query) {
                if (!storesCache) {
                    ensureStores();
                    return [{ value: '', label: 'Loading…', disabled: true }];
                }
                var entries;
                if (side === 'sellers') {
                    entries = storesAsEntries(storesCache.sellers || []);
                } else if (side === 'vendors') {
                    entries = storesAsEntries(storesCache.vendors || []);
                } else {
                    // Combined: dedupe by shorthand
                    var seen = {};
                    var combined = (storesCache.sellers || []).concat(storesCache.vendors || []);
                    entries = [];
                    for (var i = 0; i < combined.length; i++) {
                        var c = combined[i];
                        if (seen[c.shorthand]) continue;
                        seen[c.shorthand] = true;
                        entries.push({
                            value: c.shorthand,
                            label: c.name,
                            sublabel: c.shorthand + (c.country ? ' ' + c.country : '')
                        });
                    }
                }
                return filterEntries(entries, query);
            }
        };
    }

    var combinedStoresProvider = makeStoresProvider('combined');
    register({
        prefix: 'store:',
        name: combinedStoresProvider.name,
        icon: combinedStoresProvider.icon,
        getCandidates: combinedStoresProvider.getCandidates
    });

    var sellersProvider = makeStoresProvider('sellers');
    register({
        prefix: 'seller:',
        name: sellersProvider.name,
        icon: sellersProvider.icon,
        getCandidates: sellersProvider.getCandidates
    });

    var vendorsProvider = makeStoresProvider('vendors');
    register({
        prefix: 'vendor:',
        name: vendorsProvider.name,
        icon: vendorsProvider.icon,
        getCandidates: vendorsProvider.getCandidates
    });

    window.__palette_providers = {
        register: register,
        detectPrefix: detectPrefix,
        getProvider: getProvider,
        filterEntries: filterEntries,
        setOnDataReady: setOnDataReady,
        _all: providers
    };
})();
