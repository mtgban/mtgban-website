// The Buyers column's switch between the buylist and the recent sales
// (docs/adr/0009-recent-tcgplayer-sales.md). A switch sets every card on the
// page and is remembered in SearchBuyersMode. The search draws no sales, so
// the page fetches every card's pane at once when Sales is first on show.
(function () {
    var MODES = ['buylist', 'sales'];
    // The panes still to draw: never fetched, or a fetch that failed.
    var WAITING = '.sales-pane[data-pending], .sales-pane[data-failed]';
    // The fetch under way, so a second switch waits on it rather than asking again.
    var inflight = null;

    // apply shows mode on every column and switch under root.
    function apply(root, mode) {
        root.querySelectorAll('[data-buyers-mode]').forEach(function (col) {
            col.setAttribute('data-buyers-mode', mode);
        });
        root.querySelectorAll('[data-buyers-set]').forEach(function (btn) {
            var on = btn.getAttribute('data-buyers-set') === mode;
            btn.classList.toggle('on', on);
            btn.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
    }

    // pendingIDs is the cards whose Sales pane is still to fetch, once each.
    function pendingIDs(root) {
        var seen = {};
        var ids = [];
        root.querySelectorAll(WAITING).forEach(function (pane) {
            var id = pane.getAttribute('data-card');
            if (id && !seen[id]) {
                seen[id] = true;
                ids.push(id);
            }
        });
        return ids;
    }

    // fill puts each card's pane from panes into the page.
    function fill(root, panes) {
        root.querySelectorAll(WAITING).forEach(function (pane) {
            var html = panes[pane.getAttribute('data-card')];
            if (html === undefined) return;
            pane.innerHTML = html;
            pane.removeAttribute('data-pending');
            pane.removeAttribute('data-failed');
        });
    }

    // failed tells each pane still waiting that its sales did not load, no
    // longer loading; the next switch to Sales asks again.
    function failed(root) {
        root.querySelectorAll(WAITING).forEach(function (pane) {
            pane.textContent = 'Recent sales could not be loaded.';
            pane.removeAttribute('data-pending');
            pane.setAttribute('data-failed', '');
        });
    }

    // load fetches the panes the page has not drawn yet.
    function load(root, fetchFn) {
        if (inflight) return inflight;
        var ids = pendingIDs(root);
        if (!ids.length) return Promise.resolve();
        inflight = fetchFn('/data/sales/' + ids.map(encodeURIComponent).join(','), { credentials: 'same-origin' })
            .then(function (resp) {
                if (!resp.ok) throw new Error('status ' + resp.status);
                return resp.json();
            })
            .then(function (panes) {
                fill(root, panes);
            })
            .catch(function () {
                failed(root);
            })
            .then(function () {
                inflight = null;
            });
        return inflight;
    }

    function choose(root, mode, fetchFn) {
        if (MODES.indexOf(mode) < 0) return Promise.resolve();
        apply(root, mode);
        if (typeof setCookie === 'function') setCookie('SearchBuyersMode', mode, 1000);
        return mode === 'sales' ? load(root, fetchFn) : Promise.resolve();
    }

    // start fills the panes of a page that opens in Sales.
    function start(root, fetchFn) {
        if (!root.querySelector('[data-buyers-mode="sales"]')) return Promise.resolve();
        return load(root, fetchFn);
    }

    function onClick(e) {
        var btn = e.target && e.target.closest ? e.target.closest('[data-buyers-set]') : null;
        if (!btn) return;
        e.preventDefault();
        choose(document, btn.getAttribute('data-buyers-set'), window.fetch.bind(window));
    }

    if (typeof document !== 'undefined') {
        document.addEventListener('click', onClick);
        if (document.querySelector) start(document, window.fetch.bind(window));
    }

    self.SearchBuyers = { apply: apply, pendingIDs: pendingIDs, fill: fill, load: load, choose: choose, start: start };
})();
