// Reads a search result row into the object favorites and the backpack store:
// the card identity, from the header data attributes.
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

        var query = queryName(name);
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
            query: query,
            t: Date.now(),
            img: imageUrl,
            cw: hasContentWarning
        };
    }

    // queryName quotes a name the search could read a filter out of, such
    // as "S:P Little Knight"; a quoted name searches the same either way.
    function queryName(name) {
        return /[:<>]/.test(name) ? '"' + name + '"' : name;
    }

    return { read: read, queryName: queryName };
})();
