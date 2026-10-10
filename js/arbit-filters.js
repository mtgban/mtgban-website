// The arbitrage pages' filter bar and sort links. arbit.html sets
// window.BAN_ARBIT to the source, the filter state as a query, and the
// cookie the page saves the reader's filters in.
(function () {
    var cfg = window.BAN_ARBIT || {};

    // sortURL is the page sorted by sort, filters kept, at the table named.
    function sortURL(sort, name) {
        var q = 'source=' + encodeURIComponent(cfg.source || '');
        if (cfg.query) q += '&' + cfg.query;
        return '?' + q + '&sort=' + encodeURIComponent(sort) + '#' + name;
    }

    // What the page would read the same without posts nothing: an empty
    // field is a limit left to the page's default, and a picker with every
    // box ticked keeps the whole list.
    function dropEmpty(form) {
        form.querySelectorAll('input[type=number]').forEach(function (input) {
            if (input.value === '') input.disabled = true;
        });
        form.querySelectorAll('[data-pick]').forEach(function (group) {
            var boxes = group.querySelectorAll('input[type=checkbox]');
            var all = Array.prototype.every.call(boxes, function (box) { return box.checked; });
            if (!all) return;
            group.querySelectorAll('input').forEach(function (input) { input.disabled = true; });
        });
    }

    // Back from the results restores the form as it was submitted, the
    // dropped inputs still disabled.
    function restore(form) {
        form.querySelectorAll('input').forEach(function (input) {
            input.disabled = false;
        });
    }

    // Keep a state as the reader's own, with when it was applied. Only what
    // the reader does on the page saves: following a link never does.
    function save(query) {
        if (!cfg.cookie) return;
        var value = query + (query ? '&' : '') + 't=' + Date.now();
        writeCookie(cfg.cookie, encodeURIComponent(value), 1000, '/');
    }

    // The form as the query it submits, less the source, which a saved
    // state applies to every source.
    function formQuery(form) {
        var params = new URLSearchParams(new FormData(form));
        params.delete('source');
        return params.toString();
    }

    // A sort click saves the sort over what the reader saved, not over the
    // page: one opened from someone else's link keeps its filters to itself.
    function savedWithSort(sort) {
        var saved = new URLSearchParams(cfg.cookie ? getCookie(cfg.cookie) : '');
        saved.delete('t');
        saved.set('f', '1');
        saved.set('sort', sort);
        return saved.toString();
    }

    window.sortBy = function (sort, name) {
        save(savedWithSort(sort));
        window.location.href = sortURL(sort, name);
    };

    // Open or close the bar, and remember it for every arbitrage page, which
    // the server reads to render it the same way next time.
    function setOpen(toggle, panel, open) {
        panel.hidden = !open;
        toggle.setAttribute('aria-expanded', open ? 'true' : 'false');
        writeCookie('ArbitFiltersOpen', open ? '1' : '', 1000, '/');
    }

    var toggle = document.getElementById('arbFilterToggle');
    var panel = document.getElementById('arbFilterPanel');
    if (toggle && panel) {
        toggle.addEventListener('click', function () { setOpen(toggle, panel, panel.hidden); });
    }

    var form = document.getElementById('arbFilters');
    if (form) {
        form.addEventListener('submit', function () {
            dropEmpty(form);
            save(formQuery(form));
        });
        window.addEventListener('pageshow', function () { restore(form); });
    }

    // Saved as a state of its own rather than deleted, so a reset is the
    // latest thing the reader applied
    var reset = document.getElementById('arbFilterReset');
    if (reset) {
        reset.addEventListener('click', function () { save('f=1'); });
    }

    window.ArbitFilters = { sortURL: sortURL, dropEmpty: dropEmpty, restore: restore, setOpen: setOpen, save: save, formQuery: formQuery };
})();
