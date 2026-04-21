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

    window.__palette_providers = {
        register: register,
        detectPrefix: detectPrefix,
        getProvider: getProvider,
        filterEntries: filterEntries,
        _all: providers
    };
})();
