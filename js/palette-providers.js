/* Palette Providers — prefix-driven dropdown candidate suppliers.
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
                { value: 'mythic', label: 'Mythic', sublabel: 'm' },
                { value: 'rare', label: 'Rare', sublabel: 'r' },
                { value: 'uncommon', label: 'Uncommon', sublabel: 'u' },
                { value: 'common', label: 'Common', sublabel: 'c' },
                { value: 'special', label: 'Special', sublabel: 's' },
                { value: 'token', label: 'Token', sublabel: 't' },
                { value: 'oversize', label: 'Oversize', sublabel: 'o' }
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
                { value: 'foil', label: 'Foil' },
                { value: 'nonfoil', label: 'Non-foil' },
                { value: 'etched', label: 'Etched' }
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

    window.__palette_providers = {
        register: register,
        detectPrefix: detectPrefix,
        getProvider: getProvider,
        filterEntries: filterEntries,
        _all: providers
    };
})();
