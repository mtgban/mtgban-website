// The phone's offline cards, in the markup of templates/mobile/search.html's
// Cards: the lists are the desktop page's columns (offline-render.js), and the
// edge buttons and list headings come from the page's own templates.
(function (root) {
    'use strict';

    var S = root.OfflineRenderShared;
    var money = S.money, keyruneClasses = S.keyruneClasses, markAttr = S.markAttr;

    // The markup offline.html's m-offline-parts holds for an edge's price.
    var EDGE_PRICE = '<span class="m-edge-price">{price}</span>';

    function imageURL(res) {
        return res.i ? '/api/offline/images/' + encodeURIComponent(res.i) + '.webp' : '';
    }

    function headerHTML(res, ctx) {
        var card = res.card;
        var set = ctx.sets[card.set] || {};
        var icon = set.k
            ? '<i class="ss ss-' + escapeHtml(set.k) + keyruneClasses(card) + ' ss-fw"' + markAttr(set) + '></i>'
            : '<span>' + escapeHtml(card.set) + '</span>';
        var finish = '';
        if (card.e) finish = '<span class="m-badge etched">Etched</span>';
        else if (card.f) finish = '<span class="m-badge foil">Foil</span>';
        var nameQuery = '?' + (card.s ? 'sealed=1&' : '') + 'q=' + encodeURIComponent('"' + card.n + '"');
        return '<div class="m-card-header"' +
            ' data-card-id="' + escapeHtml(res.uuid) + '"' +
            ' data-card-name="' + escapeHtml(card.n) + '"' +
            ' data-set-code="' + escapeHtml(card.set) + '"' +
            ' data-number="' + escapeHtml(card.num || '') + '"' +
            ' data-image-url="' + escapeHtml(imageURL(res)) + '">' +
            '<div class="m-card-icon">' + icon + '</div>' +
            '<div class="m-card-info">' +
            '<span class="m-card-title">' +
            '<a class="m-card-name' + (card.n.length > 19 ? ' m-card-name-long' : '') + '" href="' + escapeHtml(nameQuery) + '">' + escapeHtml(card.n) + '</a>' +
            '</span>' +
            '<span class="m-card-setline">' +
            '<span class="m-card-set">' + escapeHtml(card.set) + (card.num ? ' · #' + escapeHtml(card.num) : '') + '</span>' +
            finish +
            '</span>' +
            '</div>' +
            '</div>';
    }

    function edge(part, side) {
        if (side.best > 0) return part.replace('{price}', '$ ' + money(side.best));
        return part.replace(EDGE_PRICE, '');
    }

    function pane(name, title, uuid, head, side) {
        return '<div class="m-tab-panel active" id="' + name + '-' + escapeHtml(uuid) + '" role="region" aria-label="' + title + '">' +
            head + side.html + '</div>';
    }

    // The card back shows where the sync holds no picture, as it does for one
    // that fails to load (card-art-fallback.js).
    function pictureHTML(res, ctx, back, i) {
        var card = res.card;
        var set = ctx.sets[card.set] || {};
        var src = imageURL(res) || back;
        if (!src) return '';
        return '<img class="m-card-img-landscape" data-set="' + escapeHtml(card.set) + '" data-date="' + escapeHtml(set.d || '') + '"' +
            (card.s ? ' data-sealed' : '') +
            ' src="' + escapeHtml(src) + '" loading="' + (i < 2 ? 'eager' : 'lazy') + '" alt="' + escapeHtml(card.n) + '">';
    }

    function cardHTML(res, ctx, parts, i) {
        var sellers = root.OfflineRender.sellers(res, ctx);
        var buyers = root.OfflineRender.buyers(res, ctx);
        var html = '<div class="m-card">' + headerHTML(res, ctx);
        if (sellers.any) html += edge(parts['edge-sellers'], sellers);
        if (buyers.any) html += edge(parts['edge-buyers'], buyers);
        html += '<div class="m-card-tools"></div>' + pictureHTML(res, ctx, parts.back, i);
        if (sellers.any) html += pane('sellers', 'Sellers', res.uuid, parts['head-sellers'], sellers);
        if (buyers.any) html += pane('buyers', 'Buyers', res.uuid, parts['head-buyers'], buyers);
        if (!sellers.any && !buyers.any) html += '<div class="no-offers"><i>No offers</i></div>';
        return html + '</div>';
    }

    // parts is the edge buttons' and list headings' markup by data-part, and
    // the game's card back.
    function buildHTML(results, ctx, parts) {
        return results.map(function (res, i) { return cardHTML(res, ctx, parts, i); }).join('');
    }

    function render(container, exec, ctx, parts) {
        container.innerHTML = buildHTML(exec.results, ctx, parts);
    }

    root.OfflineRenderMobile = {render: render, buildHTML: buildHTML};
})(typeof self !== 'undefined' ? self : globalThis);
