// What the desktop and mobile offline renderers share: store entries read as
// per-condition prices, store names, and the notices above the results.
(function (root) {
    'use strict';

    var CONDITIONS = ['NM', 'SP', 'MP', 'HP', 'PO'];
    // Mirror of Country2flag (utils.go:23).
    var FLAGS = {EU: '\u{1F1EA}\u{1F1FA}', JP: '\u{1F1EF}\u{1F1F5}'};
    // Static index pairing rules, mirroring the collapseIndex calls (search.go:613-614).
    var INDEX_PAIRS = [
        {low: 'TCGLow', high: 'TCGMarket', label: 'TCG (Low / Market)'},
        {low: 'MKMLow', high: 'MKMTrend', label: 'CM (Low / Trend)'}
    ];
    // Reference stores approximating the online ratio (online shows scraper-provided PriceRatio).
    var REF_STORES = ['CK', 'TCGPlayer', 'TCGLow', 'TCGMarket'];

    function money(v) {
        return Number(v).toFixed(2);
    }

    // keyruneClasses mirrors keyruneForCardSet's rarity/foil mapping (utils.go:110-152).
    function keyruneClasses(card) {
        var rarity = card.r || '';
        if (rarity === 'special' || card.e) {
            rarity = 'timeshifted';
        } else if (rarity === 'token' || rarity === 'oversize') {
            rarity = 'common';
        }
        var out = '';
        if (rarity && rarity !== 'common' && !card.f) {
            out += ' ss-' + rarity;
        }
        if (card.f) {
            out += ' ss-foil ss-grad';
        }
        return out;
    }

    // finishPrice picks the finish-level price matching the card flags.
    function finishPrice(entry, card) {
        if (card.s && entry.sealed > 0) return entry.sealed;
        if (card.e && entry.etched > 0) return entry.etched;
        if (card.f && entry.foil > 0) return entry.foil;
        return entry.regular > 0 ? entry.regular : 0;
    }

    function finishQty(entry, card) {
        if (card.s && entry.qtySealed > 0) return entry.qtySealed;
        if (card.e && entry.qtyEtched > 0) return entry.qtyEtched;
        if (card.f && entry.qtyFoil > 0) return entry.qtyFoil;
        return entry.qty > 0 ? entry.qty : 0;
    }

    // condTag maps a base condition to this finish's payload tag.
    function condTag(cond, card, conds) {
        if (card.e && conds && (cond + '_etched') in conds) return cond + '_etched';
        if (card.f && conds && (cond + '_foil') in conds) return cond + '_foil';
        return cond;
    }

    // condPrices explodes one store entry into {NM: {price, qty}, ...}.
    function condPrices(entry, card) {
        var out = {};
        var conds = entry.conditions;
        if (conds) {
            for (var i = 0; i < CONDITIONS.length; i++) {
                var tag = condTag(CONDITIONS[i], card, conds);
                if (conds[tag] > 0) {
                    out[CONDITIONS[i]] = {
                        price: conds[tag],
                        qty: (entry.quantities && entry.quantities[tag]) || 0
                    };
                }
            }
            if (Object.keys(out).length > 0) {
                return out;
            }
        }
        var price = finishPrice(entry, card);
        if (price > 0) {
            var cond = entry.cond || 'NM';
            out[cond.split('_')[0]] = {price: price, qty: finishQty(entry, card)};
        }
        return out;
    }

    function storeName(ctx, short) {
        var s = ctx.stores[short];
        if (!s) return short;
        var flag = s.c && FLAGS[s.c] ? ' ' + FLAGS[s.c] : '';
        return s.n + flag;
    }

    function isIndex(ctx, short) {
        var s = ctx.stores[short];
        return !!(s && s.i);
    }

    function rowComparator(ctx) {
        if (ctx.byStore) {
            return function (a, b) {
                return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1;
            };
        }
        return function (a, b) {
            if (a.price !== b.price) return a.price - b.price;
            return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1;
        };
    }

    // refRetail finds the best CK-or-TCG retail for the ratio.
    function refRetail(res, cond) {
        var best = 0;
        for (var i = 0; i < REF_STORES.length; i++) {
            var entry = res.retail[REF_STORES[i]];
            if (!entry) continue;
            var per = condPrices(entry, res.card);
            var p = per[cond] ? per[cond].price : finishPrice(entry, res.card);
            if (p > 0 && (best === 0 || p < best)) {
                best = p;
            }
        }
        return best;
    }

    function noticesHTML(exec, ctx) {
        var html = '';
        if (exec.unsupported && exec.unsupported.length > 0) {
            html += '<div class="offline-notice offline-notice-warn">Not available offline: ' +
                exec.unsupported.map(escapeHtml).join(', ') + '</div>';
        }
        (exec.missingSets || []).forEach(function (code) {
            var set = ctx.sets[code];
            html += '<div class="offline-notice offline-notice-missing">' +
                escapeHtml(set && set.n ? set.n : code) + ' is not synced offline. ' +
                '<a href="/search?settings=offline">Choose synced editions in Settings</a> (requires connectivity).' +
                '</div>';
        });
        if (exec.truncated) {
            html += '<div class="offline-notice">Too many matches, showing a truncated list.</div>';
        }
        if (exec.results.length === 0 && (exec.missingSets || []).length === 0) {
            html += '<div class="offline-empty"><em>No results found in offline data</em></div>';
        }
        return html;
    }

    root.OfflineRenderShared = {
        CONDITIONS: CONDITIONS,
        INDEX_PAIRS: INDEX_PAIRS,
        money: money,
        keyruneClasses: keyruneClasses,
        finishPrice: finishPrice,
        condPrices: condPrices,
        storeName: storeName,
        isIndex: isIndex,
        rowComparator: rowComparator,
        refRetail: refRetail,
        noticesHTML: noticesHTML
    };
})(typeof self !== 'undefined' ? self : globalThis);
