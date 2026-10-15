// Reads a search result row into the object favorites and the backpack store:
// the card identity from the header data attributes and, when the
// row panels are open, its best prices.
window.CardRow = (function () {
    "use strict";

    function read(btn) {
        // Walk to the row container by class. Both button and row carry data-card-id,
        // so a [data-card-id] selector would match the button itself first.
        var row = btn.closest('.m-card-header, .result-header');
        if (!row) {
            // A fav button can sit outside the header (e.g. the mobile actions
            // menu is a sibling of the header), so fall back to the card container.
            var card = btn.closest('.m-card');
            if (card) row = card.querySelector('.m-card-header');
        }
        if (!row) return null;

        var cardId = row.getAttribute('data-card-id') || btn.getAttribute('data-card-id');
        if (!cardId) return null;

        var name = row.getAttribute('data-card-name') || '';
        var setCode = row.getAttribute('data-set-code') || '';
        var edition = row.getAttribute('data-edition') || '';
        var number = row.getAttribute('data-number') || '';
        var imageUrl = row.getAttribute('data-image-url') || '';
        var finishTag = row.getAttribute('data-finish-tag') || '';
        var finishClass = row.getAttribute('data-finish-class') || '';
        var treatmentsAttr = row.getAttribute('data-treatments') || '';
        var treatments = treatmentsAttr ? treatmentsAttr.split(',').filter(function(t) { return t.length > 0; }) : [];

        var isFoil = finishClass === 'foil' || finishClass === 'altfoil';
        var isEtched = finishClass === 'etched';
        var hasContentWarning = row.getAttribute('data-has-warning') === 'true';

        // Locate the surrounding card container to find best-price rows.
        // Mobile: .m-card. Desktop: each card's results sit between .result-header rows; the .result-body follows.
        var cardContainer = row.closest('.m-card') || row.parentNode;

        var sellPrice = null;
        var sellVendor = '';
        var sellersPanel = cardContainer.querySelector('[id^="sellers-"]');
        if (sellersPanel) {
            var bestSell = sellersPanel.querySelector('.m-best-price');
            if (bestSell) {
                var sp = bestSell.querySelector('.m-vendor-price');
                if (sp) {
                    var psp = parseFloat(sp.textContent.trim().replace('$', '').trim());
                    if (!isNaN(psp)) sellPrice = psp;
                }
                var sn = bestSell.querySelector('.m-vendor-name');
                if (sn) sellVendor = sn.textContent.replace('Best', '').trim();
            }
        }

        var buyPrice = null;
        var buyVendor = '';
        var buyersPanel = cardContainer.querySelector('[id^="buyers-"]');
        if (buyersPanel) {
            var bestBuy = buyersPanel.querySelector('.m-best-price');
            if (bestBuy) {
                var bp = bestBuy.querySelector('.m-vendor-price');
                if (bp) {
                    var pbp = parseFloat(bp.textContent.trim().replace('$', '').trim());
                    if (!isNaN(pbp)) buyPrice = pbp;
                }
                var bn = bestBuy.querySelector('.m-vendor-name');
                if (bn) buyVendor = bn.textContent.replace('Best', '').trim();
            }
        }

        var query = name;
        if (setCode) query += ' s:' + setCode;
        if (number) query += ' cns:' + number;
        if (isEtched) query += ' f:etched';
        else if (isFoil) query += ' f:foil';

        return {
            id: cardId,
            name: name,
            set: setCode,
            edition: edition,
            number: number,
            foil: isFoil,
            etched: isEtched,
            finishTag: finishTag,
            finishClass: finishClass,
            treatments: treatments,
            sellPrice: sellPrice,
            sellVendor: sellVendor,
            buyPrice: buyPrice,
            buyVendor: buyVendor,
            query: query,
            t: Date.now(),
            img: imageUrl,
            cw: hasContentWarning
        };
    }

    return { read: read };
})();
