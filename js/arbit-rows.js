// Counts the arbitrage tables' row controls, scoped by each section's data-store.
(function () {
    // A section's store, as the server wrote it, or other.
    function sectionStore(section) {
        var store = section.getAttribute('data-store') || '';
        return /^[A-Za-z0-9_.,+-]{1,40}$/.test(store) ? store : 'other';
    }

    document.addEventListener('change', function (e) {
        var t = e.target;
        if (!t || typeof t.closest !== 'function' || !t.closest('.arb-section')) return;
        if (t.classList && t.classList.contains('arb-row-check')) {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.arbit.row', 'check');
        } else if (t.type === 'checkbox' && t.closest('.arb-section thead')) {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.arbit.row', 'check_all');
        }
    });

    document.addEventListener('click', function (e) {
        var t = e.target;
        if (!t || typeof t.closest !== 'function') return;
        var link = t.closest('.arb-qlink');
        if (link) {
            var section = link.closest('.arb-section');
            if (!section) return;
            var value = link.classList.contains('ref') ? 'buy_reference' : link.classList.contains('sell') ? 'sell' : 'buy';
            if (window.BAN && window.BAN.track) window.BAN.track('ui.arbit.quick_link', value, sectionStore(section));
            return;
        }
        if (t.closest('.arb-contents')) {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.arbit.contents');
        }
    });
})();
