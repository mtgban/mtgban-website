// Offline result renderer mirroring the markup of templates/search.html and
// its columns (templates/partials/search-columns.html).
(function (root) {
    'use strict';

    var S = root.OfflineRenderShared;
    var CONDITIONS = S.CONDITIONS, INDEX_PAIRS = S.INDEX_PAIRS;
    var money = S.money, keyruneClasses = S.keyruneClasses, markAttr = S.markAttr, finishPrice = S.finishPrice,
        condPrices = S.condPrices, slabPrices = S.slabPrices, storeName = S.storeName, isIndex = S.isIndex,
        rowComparator = S.rowComparator, refRetail = S.refRetail, noticesHTML = S.noticesHTML;

    function priceSpan(price) {
        if (price > 0) {
            return '<span class="price"><span class="cur">$</span><span class="amt">' + money(price) + '</span></span>';
        }
        return '<span class="price">n/a</span>';
    }

    // sellerRow mirrors result-sellers' URL-less branch, a slab's name beside
    // its store.
    function sellerRow(name, price, qty, cond, slab) {
        var slabName = slab ? '<span class="slab-name" title="' + escapeHtml(slab) + '">' + escapeHtml(slab) + '</span>' : '';
        return '<div class="price-row' + (cond ? ' cond-' + cond : '') + '">' +
            '<span class="store-cell"><a class="store-name dim">' + escapeHtml(name) + '</a>' + slabName + '</span>' +
            '<span class="price-right">' +
            priceSpan(price) +
            '<span class="qty">' + (qty > 0 ? qty : '') + '</span>' +
            '</span>' +
            '</div>';
    }

    // indexRow mirrors result-sellers' collapsed low/high reference row.
    function indexRow(label, low, high) {
        return '<div class="price-row">' +
            '<span class="store-cell"><a class="store-name dim">' + escapeHtml(label) + '</a></span>' +
            '<span class="price-right has-secondary">' +
            priceSpan(low) +
            '<span class="secondary"><span class="cur">$</span><span class="amt">' + money(high) + '</span></span>' +
            '</span>' +
            '</div>';
    }

    // sypBuyerRow mirrors result-buyers' row for SYP, priced as a count.
    function sypBuyerRow(name, qty) {
        return '<div class="price-row">' +
            '<span class="store-cell"><a class="store-name dim">' + escapeHtml(name) + '</a></span>' +
            '<span class="price-right has-buylist-extra">' +
            '<span class="price"><span class="cur">#</span><span class="amt">' + qty + '</span></span>' +
            '<span class="buylist-extra" data-ratio="" data-credit="" data-marketcredit=""></span>' +
            '<span class="qty"></span>' +
            '</span>' +
            '</div>';
    }

    // Visible secondary cell text, mirroring renderCell (js/buylist-extra.js).
    // Credit modes have no offline data so they render blank like empty online cells.
    function buylistExtraText(ctx, ratio, isNM) {
        var mode = ctx.buylistSecondary || '';
        if (mode === 'creditPrice' || mode === 'marketCredit') return '';
        return (ratio > 0 && isNM) ? ratio.toFixed(2) + ' %' : '';
    }

    // buyerRow mirrors a result-buyers row.
    function buyerRow(name, price, qty, ratio, isNM, extra) {
        var title = (ratio > 0 && isNM) ? ' title="Ratio: ' + ratio.toFixed(2) + '%"' : '';
        return '<div class="price-row"' + title + '>' +
            '<span class="store-cell"><a class="store-name dim">' + escapeHtml(name) + '</a></span>' +
            '<span class="price-right has-buylist-extra">' +
            priceSpan(price) +
            '<span class="buylist-extra"' +
            ' data-ratio="' + ((ratio > 0 && isNM) ? ratio.toFixed(2) : '') + '"' +
            ' data-credit="" data-marketcredit="">' + escapeHtml(extra || '') + '</span>' +
            '<span class="qty">' + ((isNM && qty > 0) ? qty : '') + '</span>' +
            '</span>' +
            '</div>';
    }

    // Only the sellers carry their condition: search-rows.css hides Poor by it.
    function condHeader(card, cond, selling) {
        var classes = 'price-cond-header' + (selling ? '' : ' cond-' + cond);
        if (card.s) {
            return '<div class="' + classes + '">' + (selling ? 'Sell to' : 'Purchase from') + '</div>';
        }
        return '<div class="' + classes + '">Condition: ' + cond + '</div>';
    }

    // column wraps a side's rows as templates/partials/search-columns.html
    // does.
    function column(title, rows, before) {
        return '<div class="result-col">' +
            '<div class="result-col-header">' + title + '</div>' +
            (rows === '' ? '<div class="no-offers"><i>No offers</i></div>' : '') +
            (before || '') +
            '<div class="rows-main">' + rows + '</div>' +
            '</div>';
    }

    // sellers is a card's Sellers column, whether it has any row, and its best
    // price: the first in the best condition there is.
    function sellers(res, ctx) {
        var card = res.card;
        var shorts = Object.keys(res.retail || {}).filter(function (s) {
            return ctx.hiddenSellers.indexOf(s) === -1;
        });

        // Index reference rows come first, pairing known low/high couples.
        var idxRows = [];
        var consumed = {};
        var idxShorts = shorts.filter(function (s) { return isIndex(ctx, s); });
        INDEX_PAIRS.forEach(function (pair) {
            if (idxShorts.indexOf(pair.low) !== -1 && idxShorts.indexOf(pair.high) !== -1) {
                idxRows.push({
                    label: pair.label,
                    html: indexRow(pair.label,
                        finishPrice(res.retail[pair.low], card),
                        finishPrice(res.retail[pair.high], card))
                });
                consumed[pair.low] = true;
                consumed[pair.high] = true;
            }
        });
        idxShorts.forEach(function (s) {
            if (consumed[s]) return;
            var label = storeName(ctx, s);
            idxRows.push({label: label, html: sellerRow(label, finishPrice(res.retail[s], card), 0)});
        });
        // Alphabetical like the online collapse pass (rebuildIndexRows).
        idxRows.sort(function (a, b) {
            return a.label.toLowerCase() < b.label.toLowerCase() ? -1 : 1;
        });
        var rowsMain = idxRows.map(function (r) { return r.html; }).join('');
        var best = 0;

        // Condition-grouped regular store rows.
        var groups = {};
        shorts.forEach(function (s) {
            if (isIndex(ctx, s)) return;
            var per = condPrices(res.retail[s], card);
            for (var cond in per) {
                (groups[cond] = groups[cond] || []).push({
                    name: storeName(ctx, s),
                    price: per[cond].price,
                    qty: per[cond].qty
                });
            }
            slabPrices(res.retail[s]).forEach(function (slab) {
                (groups[slab.cond] = groups[slab.cond] || []).push({
                    name: storeName(ctx, s),
                    price: slab.price,
                    qty: slab.qty,
                    slab: slab.slab
                });
            });
        });
        CONDITIONS.forEach(function (cond) {
            var rows = groups[cond];
            if (!rows) return;
            rows.sort(rowComparator(ctx));
            best = best || rows[0].price;
            rowsMain += condHeader(card, cond, false);
            rows.forEach(function (r) {
                rowsMain += sellerRow(r.name, r.price, r.qty, cond, r.slab);
            });
        });

        return {html: column('Sellers', rowsMain, '<div class="rows-index"></div>'), any: rowsMain !== '', best: best};
    }

    // buyers is the same for a card's Buyers column.
    function buyers(res, ctx) {
        var card = res.card;
        var shorts = Object.keys(res.buylist || {}).filter(function (s) {
            return ctx.hiddenVendors.indexOf(s) === -1;
        });

        // Index (MetadataOnly) vendor rows come before condition headers,
        // mirroring result-buyers' INDEX group.
        var indexHtml = '';
        var indexShorts = shorts.filter(function (s) { return isIndex(ctx, s); });
        indexShorts.forEach(function (s) {
            var name = storeName(ctx, s);
            var entry = res.buylist[s];
            if (s === 'SYP') {
                indexHtml += sypBuyerRow(name, entry.qty || 0);
            } else {
                indexHtml += buyerRow(name, finishPrice(entry, card), 0, 0, false, '');
            }
        });

        var groups = {};
        shorts.forEach(function (s) {
            if (isIndex(ctx, s)) return;
            var per = condPrices(res.buylist[s], card);
            for (var cond in per) {
                (groups[cond] = groups[cond] || []).push({
                    name: storeName(ctx, s),
                    price: per[cond].price,
                    qty: per[cond].qty
                });
            }
        });

        var rowsMain = indexHtml;
        var best = 0;
        CONDITIONS.forEach(function (cond) {
            var rows = groups[cond];
            if (!rows) return;
            rows.sort(rowComparator(ctx));
            // Buyers default to highest offer first.
            if (!ctx.byStore) rows.reverse();
            best = best || rows[0].price;
            rowsMain += condHeader(card, cond, true);
            var ref = refRetail(res, cond);
            rows.forEach(function (r) {
                var ratio = ref > 0 ? (r.price / ref) * 100 : 0;
                rowsMain += buyerRow(r.name, r.price, r.qty, ratio, cond === 'NM', buylistExtraText(ctx, ratio, cond === 'NM'));
            });
        });

        return {html: column('Buyers', rowsMain), any: rowsMain !== '', best: best};
    }

    // titleLine mirrors editionTitle (utils.go) from catalog fields.
    function titleLine(card, set) {
        var finish = card.e ? ' Etched' : card.f ? ' Foil' : '';
        var rarity = card.r ? card.r.charAt(0).toUpperCase() + card.r.slice(1) : '';
        var extra = card.s ? '' : ' #' + (card.num || '');
        return (set.n || card.set) + ' -' + finish + ' ' + rarity + extra;
    }

    function headerHTML(res, ctx, i) {
        var card = res.card;
        var set = ctx.sets[card.set] || {};
        var imgURL = res.i ? '/api/offline/images/' + encodeURIComponent(res.i) + '.webp' : '';

        var icon;
        if (set.k) {
            icon = '<i class="ss ss-' + escapeHtml(set.k) + keyruneClasses(card) + ' ss-2x ss-fw result-set-icon"' + markAttr(set) + '></i>';
        } else {
            icon = '<span>' + escapeHtml(card.set) + '</span>';
        }

        var badge = '';
        if (card.e) {
            badge = '<span class="result-badge etched">Etched</span>';
        } else if (card.f) {
            badge = '<span class="result-badge foil">Foil</span>';
        }

        // Sealed's mode rides on the shell's own links, and the Graded page's
        // mark its exits lead back by.
        var mode = card.s ? '?sealed=1&q=' : '?q=';
        var mark = ctx.graded ? '&graded=1' : '';
        var setQuery = mode + encodeURIComponent('s:' + card.set) + mark;
        var nameQuery = mode + encodeURIComponent('"' + card.n + '"') + mark;

        // Products link mirrors search.html's "Found in N products".
        var productsLink = '';
        if (card.p && card.p.length > 0) {
            var n = card.p.length;
            productsLink = ' - <a href="/sealed?q=container:' + encodeURIComponent(res.uuid) + '">' +
                'Found in ' + n + ' product' + (n > 1 ? 's' : '') + '</a>';
        }

        return '<div class="result-header-cover"></div>' +
            '<div class="result-header' + (i === 0 ? ' result-first' : '') + '"' +
            ' data-card-id="' + escapeHtml(res.uuid) + '"' +
            ' data-card-name="' + escapeHtml(card.n) + '"' +
            ' data-set-code="' + escapeHtml(card.set) + '"' +
            ' data-number="' + escapeHtml(card.num || '') + '"' +
            ' data-image-url="' + escapeHtml(imgURL) + '"' +
            ' data-foil="' + (card.f ? 'true' : 'false') + '"' +
            ' data-etched="' + (card.e ? 'true' : 'false') + '">' +
            '<a class="result-set-link" href="' + setQuery + '">' + icon + '</a>' +
            '<div class="result-card-info">' +
            '<div class="result-card-name-row">' +
            '<a class="result-card-name" href="' + nameQuery + '">' + escapeHtml(card.n) + '</a>' +
            '<div class="result-badges">' + badge + '</div>' +
            '</div>' +
            '<span class="result-set-title"><a href="' + setQuery + '">' + escapeHtml(titleLine(card, set)) + '</a>' + productsLink + '</span>' +
            '</div>' +
            '</div>';
    }

    function bodyHTML(res, ctx, isLast) {
        var card = res.card;
        return '<div class="result-body' + (isLast ? ' result-last-body' : '') + '"' +
            ' data-image-url="' + escapeHtml(res.i ? '/api/offline/images/' + encodeURIComponent(res.i) + '.webp' : '') + '"' +
            ' data-set-code="' + escapeHtml(card.set) + '"' +
            ' data-foil="' + (card.f ? 'true' : 'false') + '"' +
            ' data-etched="' + (card.e ? 'true' : 'false') + '">' +
            sellers(res, ctx).html +
            buyers(res, ctx).html +
            '</div>';
    }

    function buildHTML(results, ctx) {
        var html = '';
        for (var i = 0; i < results.length; i++) {
            html += headerHTML(results[i], ctx, i);
            html += bodyHTML(results[i], ctx, i === results.length - 1);
        }
        return html;
    }

    function render(container, exec, ctx) {
        container.innerHTML = noticesHTML(exec) + buildHTML(exec.results, ctx);
    }

    root.OfflineRender = {
        render: render,
        sellers: sellers,
        buyers: buyers,
        buildHTML: buildHTML,
        noticesHTML: noticesHTML,
        condPrices: condPrices,
        refRetail: refRetail,
        keyruneClasses: keyruneClasses
    };
})(typeof self !== 'undefined' ? self : globalThis);
