// Mobile offline result renderer: emits .m-card markup mirroring search-mobile.css.
(function (root) {
    'use strict';

    var S = root.OfflineRenderShared;
    var CONDITIONS = S.CONDITIONS, INDEX_PAIRS = S.INDEX_PAIRS;
    var money = S.money, keyruneClasses = S.keyruneClasses, finishPrice = S.finishPrice,
        condPrices = S.condPrices, storeName = S.storeName, isIndex = S.isIndex,
        rowComparator = S.rowComparator, refRetail = S.refRetail, noticesHTML = S.noticesHTML;

    function flatRow(name, price, qty, extra) {
        return '<div class="m-vendor-row m-vendor-flat' + (extra || '') + '">' +
            '<span class="m-vendor-name">' + escapeHtml(name) + '</span>' +
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
        var imgURL = res.i ? '/api/offline/images/' + encodeURIComponent(res.i) + '.webp' : '';
        var icon = res._setKey
            ? '<i class="ss ss-' + escapeHtml(res._setKey) + keyruneClasses(card) + ' ss-fw"></i>'
            : '<span>' + escapeHtml(card.set) + '</span>';
        var finish = '';
        if (card.e) finish = '<span class="m-badge etched">Etched</span>';
        else if (card.f) finish = '<span class="m-badge foil">Foil</span>';
        var num = card.num ? ' · #' + escapeHtml(card.num) : '';
        return '<div class="m-card-header"' +
            ' data-card-id="' + escapeHtml(res.uuid) + '"' +
            ' data-card-name="' + escapeHtml(card.n) + '"' +
            ' data-set-code="' + escapeHtml(card.set) + '"' +
            ' data-image-url="' + escapeHtml(imgURL) + '">' +
            '<div class="m-card-icon">' + icon + '</div>' +
            '<div class="m-card-info">' +
            '<span class="m-card-name">' + escapeHtml(card.n) + '</span>' +
            '<span class="m-card-set">' + escapeHtml(card.set) + num + '</span>' +
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
            left += '<button class="m-cond-pill' + (first ? ' active' : '') + '" data-cond="' + escapeHtml(c) + '" data-card="' + escapeHtml(uuid) + '">' + escapeHtml(c) + '</button>';
            first = false;
        });
        var right = hasIndex
            ? '<span class="m-cond-pills-right"><button class="m-cond-pill' + (conds.length === 0 ? ' active' : '') + '" data-cond="INDEX" data-card="' + escapeHtml(uuid) + '">Index</button></span>'
            : '';
        return '<div class="m-cond-pills" data-card="' + escapeHtml(uuid) + '">' +
            '<span class="m-cond-pills-left">' + left + '</span>' + right + '</div>';
    }

    function tabsHTML(uuid, hasSellers, hasBuyers) {
        var html = '<div class="m-tabs" data-card="' + escapeHtml(uuid) + '">';
        if (hasSellers) html += '<button class="m-tab active" data-target="sellers-' + escapeHtml(uuid) + '">Sellers</button>';
        if (hasBuyers) html += '<button class="m-tab' + (hasSellers ? '' : ' active') + '" data-target="buyers-' + escapeHtml(uuid) + '">Buyers</button>';
        html += '</div>';
        return html;
    }

    function sellersPanel(uuid, data, ac, isSealed) {
        var html = '<div class="m-tab-panel active" id="sellers-' + escapeHtml(uuid) + '">';
        if (data.indexRows.length > 0) {
            var idxActive = Object.keys(data.groups).length === 0 ? ' active' : '';
            html += '<div class="m-cond-group' + idxActive + '" data-cond="INDEX" data-card="' + escapeHtml(uuid) + '">';
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
            html += '<div class="m-cond-group' + (isActive ? ' active' : '') + '" data-cond="' + escapeHtml(cond) + '" data-card="' + escapeHtml(uuid) + '">';
            if (isSealed) {
                html += '<div class="m-cond-label">Purchase from</div>';
            }
            rows.forEach(function (r, i) {
                html += '<div class="m-vendor-row m-vendor-flat' + (i === 0 ? ' m-best-price' : '') + '">' +
                    '<span class="m-vendor-name">' + escapeHtml(r.name) + (i === 0 ? '<span class="m-best-badge">Best</span>' : '') + '</span>' +
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
        var html = '<div class="m-tab-panel" id="buyers-' + escapeHtml(uuid) + '">';
        if (data.indexRows.length > 0) {
            var idxActive = Object.keys(data.groups).length === 0 ? ' active' : '';
            html += '<div class="m-cond-group' + idxActive + '" data-cond="INDEX" data-card="' + escapeHtml(uuid) + '">';
            data.indexRows.forEach(function (r) {
                if (r.syp) {
                    html += '<div class="m-vendor-row m-vendor-flat">' +
                        '<span class="m-vendor-name">' + escapeHtml(r.name) + '</span>' +
                        '<span class="m-vendor-right">' +
                        '<span class="m-vendor-price"># ' + escapeHtml(String(r.qty)) + '</span>' +
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
            html += '<div class="m-cond-group' + (isActive ? ' active' : '') + '" data-cond="' + escapeHtml(cond) + '" data-card="' + escapeHtml(uuid) + '">';
            if (isSealed) {
                html += '<div class="m-cond-label">Sell to</div>';
            }
            rows.forEach(function (r, i) {
                var ratio = (cond === 'NM' && ref > 0) ? (r.price / ref) * 100 : 0;
                var title = ratio > 0 ? ' title="Ratio: ' + ratio.toFixed(2) + '%"' : '';
                html += '<div class="m-vendor-row m-vendor-flat' + (i === 0 ? ' m-best-price' : '') + '"' + title + '>' +
                    '<span class="m-vendor-name">' + escapeHtml(r.name) + (i === 0 ? '<span class="m-best-badge">Best</span>' : '') + '</span>' +
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
        var imgURL = res.i ? '/api/offline/images/' + encodeURIComponent(res.i) + '.webp' : '';
        var sData = condGroupsForSellers(res, ctx);
        var bData = condGroupsForBuyers(res, ctx);
        var ac = activeConds(sData, bData);
        var html = '<div class="m-card">';
        html += headerHTML(res);
        html += condPillsHTML(res.uuid, ac.conds, ac.hasIndex, !!card.s);
        html += tabsHTML(res.uuid, sData.hasAny, bData.hasAny);
        if (imgURL) {
            html += '<img class="m-card-img-landscape" src="' + escapeHtml(imgURL) + '" loading="lazy" alt="' + escapeHtml(card.n) + '">';
        }
        html += sellersPanel(res.uuid, sData, ac, !!card.s);
        html += buyersPanel(res.uuid, bData, ac, res, !!card.s);
        html += '</div>';
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

    root.OfflineRenderMobile = {render: render, buildHTML: buildHTML, noticesHTML: noticesHTML, condPrices: condPrices, refRetail: refRetail, keyruneClasses: keyruneClasses};
})(typeof self !== 'undefined' ? self : globalThis);
