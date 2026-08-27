// Offline result renderer mirroring templates/search.html markup.
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

    function esc(s) {
        return String(s == null ? '' : s)
            .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    }

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

    function priceSpan(price) {
        if (price > 0) {
            return '<span class="price"><span class="cur">$</span><span class="amt">' + money(price) + '</span></span>';
        }
        return '<span class="price">n/a</span>';
    }

    // sellerRow mirrors the URL-less seller branch (search.html:1150-1191).
    function sellerRow(name, price, qty) {
        return '<div class="price-row">' +
            '<span class="store-cell"><a class="store-name dim">' + esc(name) + '</a></span>' +
            '<span class="price-right">' +
            priceSpan(price) +
            '<span class="qty">' + (qty > 0 ? qty : '') + '</span>' +
            '</span>' +
            '</div>';
    }

    // indexRow mirrors the collapsed low/high reference row (search.html:1168-1183).
    function indexRow(label, low, high) {
        return '<div class="price-row">' +
            '<span class="store-cell"><a class="store-name dim">' + esc(label) + '</a></span>' +
            '<span class="price-right has-secondary">' +
            priceSpan(low) +
            '<span class="secondary"><span class="cur">$</span><span class="amt">' + money(high) + '</span></span>' +
            '</span>' +
            '</div>';
    }

    // sypBuyerRow mirrors the SYP-specific branch (search.html:1247).
    function sypBuyerRow(name, qty) {
        return '<div class="price-row">' +
            '<span class="store-cell"><a class="store-name dim">' + esc(name) + '</a></span>' +
            '<span class="price-right has-buylist-extra">' +
            '<span class="price"><span class="cur">#</span><span class="amt">' + qty + '</span></span>' +
            '<span class="buylist-extra" data-ratio="" data-credit="" data-marketcredit=""></span>' +
            '<span class="qty"></span>' +
            '</span>' +
            '</div>';
    }

    // Visible secondary cell text, mirroring renderCell (search.html:1316-1338).
    // Credit modes have no offline data so they render blank like empty online cells.
    function buylistExtraText(ctx, ratio, isNM) {
        var mode = ctx.buylistSecondary || '';
        if (mode === 'creditPrice' || mode === 'marketCredit') return '';
        return (ratio > 0 && isNM) ? ratio.toFixed(2) + ' %' : '';
    }

    // buyerRow mirrors the vendor branch (search.html:1216-1262).
    function buyerRow(name, price, qty, ratio, isNM, extra) {
        var title = (ratio > 0 && isNM) ? ' title="Ratio: ' + ratio.toFixed(2) + '%"' : '';
        return '<div class="price-row"' + title + '>' +
            '<span class="store-cell"><a class="store-name dim">' + esc(name) + '</a></span>' +
            '<span class="price-right has-buylist-extra">' +
            priceSpan(price) +
            '<span class="buylist-extra"' +
            ' data-ratio="' + ((ratio > 0 && isNM) ? ratio.toFixed(2) : '') + '"' +
            ' data-credit="" data-marketcredit="">' + esc(extra || '') + '</span>' +
            '<span class="qty">' + ((isNM && qty > 0) ? qty : '') + '</span>' +
            '</span>' +
            '</div>';
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

    function condHeader(card, cond, selling) {
        if (card.s) {
            return '<div class="price-cond-header">' + (selling ? 'Sell to' : 'Purchase from') + '</div>';
        }
        return '<div class="price-cond-header">Condition: ' + cond + '</div>';
    }

    function sellersColumn(res, ctx) {
        var card = res.card;
        var shorts = Object.keys(res.retail).filter(function (s) {
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
        // Alphabetical like the online collapse pass (search.go:674-678).
        idxRows.sort(function (a, b) {
            return a.label.toLowerCase() < b.label.toLowerCase() ? -1 : 1;
        });
        var rowsMain = idxRows.map(function (r) { return r.html; }).join('');

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
        });
        CONDITIONS.forEach(function (cond) {
            var rows = groups[cond];
            if (!rows) return;
            rows.sort(rowComparator(ctx));
            rowsMain += condHeader(card, cond, false);
            rows.forEach(function (r) {
                rowsMain += sellerRow(r.name, r.price, r.qty);
            });
        });

        var html = '<div class="result-col">' +
            '<div class="result-col-header">Sellers</div>';
        if (rowsMain === '') {
            html += '<div class="no-offers"><i>No offers</i></div>';
        }
        html += '<div class="rows-index"></div>' +
            '<div class="rows-main">' + rowsMain + '</div>' +
            '</div>';
        return html;
    }

    function buyersColumn(res, ctx) {
        var card = res.card;
        var shorts = Object.keys(res.buylist).filter(function (s) {
            return ctx.hiddenVendors.indexOf(s) === -1;
        });

        // Index (MetadataOnly) vendor rows come before condition headers,
        // mirroring the INDEX group in search.go:1088 / search.html:1210-1213.
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
        CONDITIONS.forEach(function (cond) {
            var rows = groups[cond];
            if (!rows) return;
            rows.sort(rowComparator(ctx));
            // Buyers default to highest offer first.
            if (!ctx.byStore) rows.reverse();
            rowsMain += condHeader(card, cond, true);
            var ref = refRetail(res, cond);
            rows.forEach(function (r) {
                var ratio = ref > 0 ? (r.price / ref) * 100 : 0;
                rowsMain += buyerRow(r.name, r.price, r.qty, ratio, cond === 'NM', buylistExtraText(ctx, ratio, cond === 'NM'));
            });
        });

        var html = '<div class="result-col">' +
            '<div class="result-col-header">Buyers</div>';
        if (rowsMain === '') {
            html += '<div class="no-offers"><i>No offers</i></div>';
        }
        html += '<div class="rows-main">' + rowsMain + '</div>' +
            '</div>';
        return html;
    }

    // titleLine mirrors editionTitle (utils.go:170-209) from catalog fields.
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
            icon = '<i class="ss ss-' + esc(set.k) + keyruneClasses(card) + ' ss-2x ss-fw result-set-icon"></i>';
        } else {
            icon = '<span>' + esc(card.set) + '</span>';
        }

        var badge = '';
        if (card.e) {
            badge = '<span class="result-badge etched">Etched</span>';
        } else if (card.f) {
            badge = '<span class="result-badge foil">Foil</span>';
        }

        var setQuery = '?q=' + encodeURIComponent('s:' + card.set);
        var nameQuery = '?q=' + encodeURIComponent('"' + card.n + '"');

        // Products link mirrors search.html:991-993.
        var productsLink = '';
        if (card.p && card.p.length > 0) {
            var n = card.p.length;
            productsLink = ' - <a href="/sealed?q=container:' + encodeURIComponent(res.uuid) + '">' +
                'Found in ' + n + ' product' + (n > 1 ? 's' : '') + '</a>';
        }

        return '<div class="result-header-cover" style="z-index: ' + i + '"></div>' +
            '<div class="result-header' + (i === 0 ? ' result-first' : '') + '"' +
            ' style="z-index: ' + (i + 100) + '"' +
            ' data-card-id="' + esc(res.uuid) + '"' +
            ' data-card-name="' + esc(card.n) + '"' +
            ' data-set-code="' + esc(card.set) + '"' +
            ' data-number="' + esc(card.num || '') + '"' +
            ' data-image-url="' + esc(imgURL) + '"' +
            ' data-foil="' + (card.f ? 'true' : 'false') + '"' +
            ' data-etched="' + (card.e ? 'true' : 'false') + '">' +
            '<a class="result-set-link" href="' + setQuery + '">' + icon + '</a>' +
            '<div class="result-card-info">' +
            '<div class="result-card-name-row">' +
            '<a class="result-card-name" href="' + nameQuery + '" title="' + esc(card.n) + '">' + esc(card.n) + '</a>' +
            '<div class="result-badges">' + badge + '</div>' +
            '</div>' +
            '<span class="result-set-title"><a href="' + setQuery + '">' + esc(titleLine(card, set)) + '</a>' + productsLink + '</span>' +
            '</div>' +
            '</div>';
    }

    function bodyHTML(res, ctx, isLast) {
        var card = res.card;
        return '<div class="result-body' + (isLast ? ' result-last-body' : '') + '"' +
            ' data-image-url="' + esc(res.i ? '/api/offline/images/' + encodeURIComponent(res.i) + '.webp' : '') + '"' +
            ' data-set-code="' + esc(card.set) + '"' +
            ' data-foil="' + (card.f ? 'true' : 'false') + '"' +
            ' data-etched="' + (card.e ? 'true' : 'false') + '">' +
            sellersColumn(res, ctx) +
            buyersColumn(res, ctx) +
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

    function render(container, exec, ctx) {
        container.innerHTML = noticesHTML(exec, ctx) + buildHTML(exec.results, ctx);
    }

    root.OfflineRender = {
        render: render,
        buildHTML: buildHTML,
        noticesHTML: noticesHTML,
        condPrices: condPrices,
        refRetail: refRetail,
        keyruneClasses: keyruneClasses
    };
})(typeof self !== 'undefined' ? self : globalThis);
