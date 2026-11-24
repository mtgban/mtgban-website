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
        // Arbitrage's Buy/Sell buttons, or a price Global links to its store.
        var link = t.closest('.arb-qlink, .arb-price-link');
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

// The unticked rows, by card, listing and section store, are kept in the
// tab's session for the page's mode and source, so a sort, a filter or a
// refresh, each a page load, leaves them unticked.
(function () {
    var cfg = window.BAN_ARBIT || {};
    var KEY = 'mtgban_arbit_unticked:' + cfg.mode + ':' + cfg.source;

    function rowKey(tr) {
        return [tr.dataset.arbId, tr.dataset.arbListing, tr.closest('.arb-section').dataset.store].join('\t');
    }

    function read() {
        try {
            var keys = JSON.parse(sessionStorage.getItem(KEY) || '[]');
            return Array.isArray(keys) ? keys : [];
        } catch (e) {
            return [];
        }
    }

    // A kept row this page does not show, filtered out, stays kept
    function save(section) {
        var keys = new Set(read());
        section.querySelectorAll('tr[data-arb-id]').forEach(function (tr) {
            if (tr.classList.contains('arb-removed')) keys.add(rowKey(tr));
            else keys.delete(rowKey(tr));
        });
        try {
            if (keys.size) sessionStorage.setItem(KEY, JSON.stringify(Array.from(keys)));
            else sessionStorage.removeItem(KEY);
        } catch (e) {}
    }

    document.addEventListener('change', function (e) {
        var section = e.target && e.target.closest && e.target.closest('.arb-section');
        if (section) save(section);
    });

    // After the page has wired its load lists, which a change rebuilds
    document.addEventListener('DOMContentLoaded', function () {
        var unticked = new Set(read());
        if (!unticked.size) return;
        document.querySelectorAll('.arb-section').forEach(function (section) {
            var any = false;
            var ticked = false;
            section.querySelectorAll('tr[data-arb-id]').forEach(function (tr) {
                var cb = tr.querySelector('.arb-row-check');
                if (cb && unticked.has(rowKey(tr))) {
                    cb.checked = false;
                    tr.classList.add('arb-removed');
                    any = true;
                } else if (cb) {
                    ticked = true;
                }
            });
            if (!any) return;
            var all = section.querySelector('thead input[type="checkbox"]');
            if (all) all.checked = ticked;
            section.dispatchEvent(new Event('change', { bubbles: true }));
        });
    });
})();
