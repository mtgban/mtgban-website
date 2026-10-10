// The arbitrage pages' filter bar and sort links. arbit.html sets
// window.BAN_ARBIT to the source and the filter state as a query.
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

    window.sortBy = function (sort, name) {
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
        form.addEventListener('submit', function () { dropEmpty(form); });
        window.addEventListener('pageshow', function () { restore(form); });
    }

    window.ArbitFilters = { sortURL: sortURL, dropEmpty: dropEmpty, restore: restore, setOpen: setOpen };
})();
