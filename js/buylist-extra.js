// Fills each buyer row's extra column with what the reader picked in
// SearchBuylistSecondary: the price ratio (the default), the store credit,
// or that credit at the market rate. The row carries all three as data.
(function () {
    'use strict';

    var secondaryValue = getCookie('SearchBuylistSecondary');

    function renderCell(td) {
        td.textContent = '';

        switch (secondaryValue) {
        case 'marketCredit':
            if (td.dataset.marketcredit) {
                td.textContent = '$ ' + td.dataset.marketcredit;
            }
            break;
        case 'creditPrice':
            if (td.dataset.credit) {
                td.textContent = '$ ' + td.dataset.credit;
            }
            break;
        default:
            if (td.dataset.ratio) {
                td.textContent = td.dataset.ratio + ' %';
            }
            break;
        }
    }

    document.querySelectorAll('.buylist-extra[data-ratio]').forEach(renderCell);
})();
