// Counts the search page clicks a mark cannot say: an offer row opened, a chart roster changed.
(function () {
    // classify names what a click does before it happens: 'velocity', 'detail', 'roster_add', 'roster_remove' or ''.
    function classify(target, modal) {
        if (!target || typeof target.closest !== 'function') return '';
        var summary = target.closest('summary');
        if (summary) {
            var link = target.closest('a');
            if (link && link.closest('summary') === summary) return '';
            var row = summary.parentNode;
            if (!row || !row.classList || row.open) return '';
            // The mobile sales row is an offer row too, so it is asked first.
            if (row.classList.contains('sales-velocity')) return 'velocity';
            if (row.classList.contains('m-vendor-row')) return 'detail';
            return '';
        }
        // Inside the chart modal, search-modal.js counts the roster, knowing whether it changed.
        if (modal) return '';
        if (target.closest('a.chart-add-link')) return 'roster_add';
        if (target.closest('a.chart-remove-link')) return 'roster_remove';
        return '';
    }

    document.addEventListener('click', function (e) {
        var what = classify(e && e.target, !!window.BAN_SEARCH_MODAL);
        if (what === 'velocity') {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.row.velocity', 'open');
        } else if (what === 'detail') {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.row.detail', 'open');
        } else if (what === 'roster_add') {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.chart.roster', 'add', 'page');
        } else if (what === 'roster_remove') {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.chart.roster', 'remove', 'page');
        }
    }, true);

    self.SearchTrack = { classify: classify };
})();
