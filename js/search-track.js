// Counts the search page clicks a mark cannot say: the sales row opened, a chart roster changed.
(function () {
    // classify names what a click does before it happens: 'velocity', 'roster_add', 'roster_remove' or ''.
    function classify(target, modal) {
        if (!target || typeof target.closest !== 'function') return '';
        var summary = target.closest('summary');
        if (summary) {
            var link = target.closest('a');
            if (link && link.closest('summary') === summary) return '';
            var row = summary.parentNode;
            if (!row || !row.classList || row.open) return '';
            if (row.classList.contains('sales-velocity')) return 'velocity';
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
        } else if (what === 'roster_add') {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.chart.roster', 'add', 'page');
        } else if (what === 'roster_remove') {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.chart.roster', 'remove', 'page');
        }
    }, true);

    self.SearchTrack = { classify: classify };
})();
