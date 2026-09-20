(function () {
    var COLORS = ['#9ca3af', '#60a5fa', '#2dd4bf', '#fbbf24', '#a78bfa', '#f97316'];
    var NAMES  = ['Promo', 'Standard', 'Modern', 'Legacy', 'Vintage', 'Type 1'];
    var sel    = null;

    function hexRgba(hex, a) {
        var r = parseInt(hex.slice(1, 3), 16);
        var g = parseInt(hex.slice(3, 5), 16);
        var b = parseInt(hex.slice(5, 7), 16);
        return 'rgba(' + r + ',' + g + ',' + b + ',' + a + ')';
    }

    function render() {
        // Pills
        document.querySelectorAll('.info-pill').forEach(function (p) {
            p.classList.toggle('active', parseInt(p.dataset.idx) === sel);
        });

        // Header cells
        document.querySelectorAll('.im-th-tier').forEach(function (th) {
            var c = parseInt(th.dataset.col);
            var on = sel !== null && c === sel;
            th.classList.toggle('active', on);
            th.style.background = on ? hexRgba(COLORS[c], 0.12) : '';
            var nameEl = th.querySelector('.im-th-name');
            if (nameEl) nameEl.style.color = on ? COLORS[c] : '';
        });

        // Value cells
        document.querySelectorAll('.im-td-val').forEach(function (td) {
            var c = parseInt(td.dataset.col);
            var on = sel !== null && c === sel;
            td.style.background = on ? hexRgba(COLORS[c], 0.07) : '';
        });

        // Hint
        var hint = document.getElementById('info-hint');
        if (hint) {
            if (sel !== null) {
                hint.textContent = NAMES[sel] + ' selected \u2014 click the tile again to clear';
                hint.style.color = COLORS[sel];
            } else {
                hint.textContent = 'Select a tier above to highlight its column \u2014 click again to clear';
                hint.style.color = '';
            }
        }
    }

    // Expose globally for onclick handlers
    window.infoPick = function (idx) {
        sel = (sel === idx) ? null : idx;
        render();
    };
})();
