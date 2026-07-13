// Mobile offline result renderer: emits .m-card markup mirroring search-mobile.css.
(function (root) {
    'use strict';

    var CONDITIONS = ['NM', 'SP', 'MP', 'HP', 'PO'];
    var FLAGS = {EU: '\u{1F1EA}\u{1F1FA}', JP: '\u{1F1EF}\u{1F1F5}'};
    var INDEX_PAIRS = [
        {low: 'TCGLow', high: 'TCGMarket', label: 'TCG (Low / Market)'},
        {low: 'MKMLow', high: 'MKMTrend', label: 'CM (Low / Trend)'}
    ];
    var REF_STORES = ['CK', 'TCGPlayer', 'TCGLow', 'TCGMarket'];

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

    function money(v) { return Number(v).toFixed(2); }

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

    function condTag(cond, card, conds) {
        if (card.e && conds && (cond + '_etched') in conds) return cond + '_etched';
        if (card.f && conds && (cond + '_foil') in conds) return cond + '_foil';
        return cond;
    }

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
            if (Object.keys(out).length > 0) return out;
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

    function refRetail(res, cond) {
        var best = 0;
        for (var i = 0; i < REF_STORES.length; i++) {
            var entry = res.retail[REF_STORES[i]];
            if (!entry) continue;
            var per = condPrices(entry, res.card);
            var p = per[cond] ? per[cond].price : finishPrice(entry, res.card);
            if (p > 0 && (best === 0 || p < best)) best = p;
        }
        return best;
    }

    function flatRow(name, price, qty, extra) {
        return '<div class="m-vendor-row m-vendor-flat' + (extra || '') + '">' +
            '<span class="m-vendor-name">' + esc(name) + '</span>' +
            '<span class="m-vendor-right">' +
            '<span class="m-vendor-price">' + (price > 0 ? '$ ' + money(price) : 'n/a') + '</span>' +
            '<span class="m-vendor-qty">' + (qty > 0 ? qty : '') + '</span>' +
            '</span></div>';
    }

    function noOffersRow() {
        return '<div class="m-vendor-row m-vendor-flat">' +
            '<span class="m-vendor-name dim">No offers</span>' +
            '<span class="m-vendor-right"><span class="m-vendor-price">n/a</span>' +
            '<span class="m-vendor-qty"></span></span></div>';
    }

    function headerHTML(res) {
        var card = res.card;
        var imgURL = '/api/offline/images/' + encodeURIComponent(res.uuid) + '.webp';
        var icon = res._setKey
            ? '<i class="ss ss-' + esc(res._setKey) + ' ss-fw"></i>'
            : '<span>' + esc(card.set) + '</span>';
        var finish = '';
        if (card.e) finish = '<span class="m-badge etched">Etched</span>';
        else if (card.f) finish = '<span class="m-badge foil">Foil</span>';
        var num = card.num ? ' · #' + esc(card.num) : '';
        return '<div class="m-card-header"' +
            ' data-card-id="' + esc(res.uuid) + '"' +
            ' data-card-name="' + esc(card.n) + '"' +
            ' data-set-code="' + esc(card.set) + '"' +
            ' data-image-url="' + esc(imgURL) + '">' +
            '<div class="m-card-icon">' + icon + '</div>' +
            '<div class="m-card-info">' +
            '<span class="m-card-name">' + esc(card.n) + '</span>' +
            '<span class="m-card-set">' + esc(card.set) + num + '</span>' +
            '</div>' +
            '<div class="m-card-badges">' + finish + '</div>' +
            '</div>';
    }

    // condGroupsForSellers returns {indexRows, groups, hasAny} for the sellers side.
    function condGroupsForSellers(res, ctx) {
        var card = res.card;
        var shorts = Object.keys(res.retail).filter(function (s) {
            return ctx.hiddenSellers.indexOf(s) === -1;
        });
        var indexRows = [];
        var consumed = {};
        var idxShorts = shorts.filter(function (s) { return isIndex(ctx, s); });
        INDEX_PAIRS.forEach(function (pair) {
            if (idxShorts.indexOf(pair.low) !== -1 && idxShorts.indexOf(pair.high) !== -1) {
                indexRows.push({name: pair.label + ' (Low)', price: finishPrice(res.retail[pair.low], card)});
                indexRows.push({name: pair.label + ' (Market)', price: finishPrice(res.retail[pair.high], card)});
                consumed[pair.low] = true;
                consumed[pair.high] = true;
            }
        });
        idxShorts.forEach(function (s) {
            if (consumed[s]) return;
            indexRows.push({name: storeName(ctx, s), price: finishPrice(res.retail[s], card)});
        });
        indexRows.sort(function (a, b) {
            return a.name.toLowerCase() < b.name.toLowerCase() ? -1 : 1;
        });
        var groups = {};
        shorts.forEach(function (s) {
            if (isIndex(ctx, s)) return;
            var per = condPrices(res.retail[s], card);
            for (var cond in per) {
                (groups[cond] = groups[cond] || []).push({
                    name: storeName(ctx, s), price: per[cond].price, qty: per[cond].qty
                });
            }
        });
        CONDITIONS.forEach(function (cond) {
            if (groups[cond]) groups[cond].sort(rowComparator(ctx));
        });
        var hasAny = indexRows.length > 0 || Object.keys(groups).length > 0;
        return {indexRows: indexRows, groups: groups, hasAny: hasAny};
    }

    function condGroupsForBuyers(res, ctx) {
        var card = res.card;
        var shorts = Object.keys(res.buylist).filter(function (s) {
            return ctx.hiddenVendors.indexOf(s) === -1;
        });
        var indexRows = [];
        var idxShorts = shorts.filter(function (s) { return isIndex(ctx, s); });
        idxShorts.forEach(function (s) {
            var entry = res.buylist[s];
            if (s === 'SYP') {
                indexRows.push({name: storeName(ctx, s), syp: true, qty: entry.qty || 0});
            } else {
                indexRows.push({name: storeName(ctx, s), price: finishPrice(entry, card)});
            }
        });
        var groups = {};
        shorts.forEach(function (s) {
            if (isIndex(ctx, s)) return;
            var per = condPrices(res.buylist[s], card);
            for (var cond in per) {
                (groups[cond] = groups[cond] || []).push({
                    name: storeName(ctx, s), price: per[cond].price, qty: per[cond].qty
                });
            }
        });
        CONDITIONS.forEach(function (cond) {
            if (!groups[cond]) return;
            groups[cond].sort(rowComparator(ctx));
            if (!ctx.byStore) groups[cond].reverse();
        });
        var hasAny = indexRows.length > 0 || Object.keys(groups).length > 0;
        return {indexRows: indexRows, groups: groups, hasAny: hasAny};
    }

    function activeConds(sellersData, buyersData) {
        var seen = {};
        var order = [];
        function add(c) { if (!seen[c]) { seen[c] = true; order.push(c); } }
        CONDITIONS.forEach(function (c) {
            if (sellersData.groups[c] || buyersData.groups[c]) add(c);
        });
        var hasIndex = sellersData.indexRows.length > 0 || buyersData.indexRows.length > 0;
        return {conds: order, hasIndex: hasIndex};
    }

    function condPillsHTML(uuid, conds, hasIndex, isSealed) {
        if (isSealed) return '';
        if (conds.length === 0 && !hasIndex) return '';
        var left = '';
        var first = true;
        conds.forEach(function (c) {
            left += '<button class="m-cond-pill' + (first ? ' active' : '') + '" data-cond="' + esc(c) + '" data-card="' + esc(uuid) + '">' + esc(c) + '</button>';
            first = false;
        });
        var right = hasIndex
            ? '<span class="m-cond-pills-right"><button class="m-cond-pill" data-cond="INDEX" data-card="' + esc(uuid) + '">Index</button></span>'
            : '';
        return '<div class="m-cond-pills" data-card="' + esc(uuid) + '">' +
            '<span class="m-cond-pills-left">' + left + '</span>' + right + '</div>';
    }

    function tabsHTML(uuid, hasSellers, hasBuyers) {
        var html = '<div class="m-tabs" data-card="' + esc(uuid) + '">';
        if (hasSellers) html += '<button class="m-tab active" data-target="sellers-' + esc(uuid) + '">Sellers</button>';
        if (hasBuyers) html += '<button class="m-tab' + (hasSellers ? '' : ' active') + '" data-target="buyers-' + esc(uuid) + '">Buyers</button>';
        html += '</div>';
        return html;
    }

    function sellersPanel(uuid, data, ac, isSealed) {
        var html = '<div class="m-tab-panel active" id="sellers-' + esc(uuid) + '">';
        if (data.indexRows.length > 0) {
            html += '<div class="m-cond-group" data-cond="INDEX" data-card="' + esc(uuid) + '">';
            data.indexRows.forEach(function (r) {
                html += flatRow(r.name, r.price, 0);
            });
            html += '</div>';
        }
        if (!data.hasAny || (data.indexRows.length === 0 && Object.keys(data.groups).length === 0)) {
            html += noOffersRow();
        }
        CONDITIONS.forEach(function (cond) {
            var rows = data.groups[cond];
            if (!rows) return;
            var isActive = ac.conds.length > 0 && ac.conds[0] === cond;
            html += '<div class="m-cond-group' + (isActive ? ' active' : '') + '" data-cond="' + esc(cond) + '" data-card="' + esc(uuid) + '">';
            if (isSealed) {
                html += '<div class="m-cond-label">Purchase from</div>';
            }
            rows.forEach(function (r, i) {
                html += '<div class="m-vendor-row m-vendor-flat' + (i === 0 ? ' m-best-price' : '') + '">' +
                    '<span class="m-vendor-name">' + esc(r.name) + (i === 0 ? '<span class="m-best-badge">Best</span>' : '') + '</span>' +
                    '<span class="m-vendor-right">' +
                    '<span class="m-vendor-price">' + (r.price > 0 ? '$ ' + money(r.price) : 'n/a') + '</span>' +
                    '<span class="m-vendor-qty">' + (r.qty > 0 ? r.qty : '') + '</span>' +
                    '</span></div>';
            });
            html += '</div>';
        });
        html += '</div>';
        return html;
    }

    function buyersPanel(uuid, data, ac, res, isSealed) {
        var html = '<div class="m-tab-panel" id="buyers-' + esc(uuid) + '">';
        if (data.indexRows.length > 0) {
            html += '<div class="m-cond-group" data-cond="INDEX" data-card="' + esc(uuid) + '">';
            data.indexRows.forEach(function (r) {
                if (r.syp) {
                    html += '<div class="m-vendor-row m-vendor-flat">' +
                        '<span class="m-vendor-name">' + esc(r.name) + '</span>' +
                        '<span class="m-vendor-right">' +
                        '<span class="m-vendor-price"># ' + esc(String(r.qty)) + '</span>' +
                        '<span class="m-vendor-qty"></span>' +
                        '</span></div>';
                } else {
                    html += flatRow(r.name, r.price, 0);
                }
            });
            html += '</div>';
        }
        if (!data.hasAny || (data.indexRows.length === 0 && Object.keys(data.groups).length === 0)) {
            html += noOffersRow();
        }
        CONDITIONS.forEach(function (cond) {
            var rows = data.groups[cond];
            if (!rows) return;
            var isActive = ac.conds.length > 0 && ac.conds[0] === cond;
            var ref = refRetail(res, cond);
            html += '<div class="m-cond-group' + (isActive ? ' active' : '') + '" data-cond="' + esc(cond) + '" data-card="' + esc(uuid) + '">';
            if (isSealed) {
                html += '<div class="m-cond-label">Sell to</div>';
            }
            rows.forEach(function (r, i) {
                var ratio = (cond === 'NM' && ref > 0) ? (r.price / ref) * 100 : 0;
                var title = ratio > 0 ? ' title="Ratio: ' + ratio.toFixed(2) + '%"' : '';
                html += '<div class="m-vendor-row m-vendor-flat' + (i === 0 ? ' m-best-price' : '') + '"' + title + '>' +
                    '<span class="m-vendor-name">' + esc(r.name) + (i === 0 ? '<span class="m-best-badge">Best</span>' : '') + '</span>' +
                    '<span class="m-vendor-right">' +
                    '<span class="m-vendor-price">' + (r.price > 0 ? '$ ' + money(r.price) : 'n/a') + '</span>' +
                    '<span class="m-vendor-qty">' + (cond === 'NM' && r.qty > 0 ? r.qty : '') + '</span>' +
                    '</span></div>';
            });
            html += '</div>';
        });
        html += '</div>';
        return html;
    }

    function cardHTML(res, ctx) {
        var card = res.card;
        var set = ctx.sets[card.set] || {};
        res._setKey = set.k || '';
        var imgURL = '/api/offline/images/' + encodeURIComponent(res.uuid) + '.webp';
        var sData = condGroupsForSellers(res, ctx);
        var bData = condGroupsForBuyers(res, ctx);
        var ac = activeConds(sData, bData);
        var html = '<div class="m-card">';
        html += headerHTML(res);
        html += condPillsHTML(res.uuid, ac.conds, ac.hasIndex, !!card.s);
        html += tabsHTML(res.uuid, sData.hasAny, bData.hasAny);
        html += '<img class="m-card-img-landscape" src="' + esc(imgURL) + '" loading="lazy" alt="' + esc(card.n) + '">';
        html += sellersPanel(res.uuid, sData, ac, !!card.s);
        html += buyersPanel(res.uuid, bData, ac, res, !!card.s);
        html += '</div>';
        return html;
    }

    function noticesHTML(exec, ctx) {
        var html = '';
        if (exec.unsupported && exec.unsupported.length > 0) {
            html += '<div class="offline-notice offline-notice-warn">Not available offline: ' +
                exec.unsupported.map(esc).join(', ') + '</div>';
        }
        (exec.missingSets || []).forEach(function (code) {
            var set = ctx.sets[code];
            html += '<div class="offline-notice offline-notice-missing">' +
                esc(set && set.n ? set.n : code) + ' is not synced offline. ' +
                '<a href="/search?settings=1">Choose synced editions in Settings</a> (requires connectivity).' +
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

    function buildHTML(results, ctx) {
        var html = '';
        for (var i = 0; i < results.length; i++) {
            html += cardHTML(results[i], ctx);
        }
        return html;
    }

    function render(container, exec, ctx) {
        container.innerHTML = noticesHTML(exec, ctx) + buildHTML(exec.results, ctx);
    }

    root.OfflineRenderMobile = {render: render, buildHTML: buildHTML, noticesHTML: noticesHTML, condPrices: condPrices, refRetail: refRetail};
})(typeof self !== 'undefined' ? self : globalThis);
