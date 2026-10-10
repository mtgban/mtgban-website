// The arbitrage pages' filter bar and sort links. arbit.html sets
// window.BAN_ARBIT to the source, the filter state as a query, the cookie
// the page saves the reader's filters in, and when the saved state it was
// drawn from was applied.
(function () {
    var cfg = window.BAN_ARBIT || {};

    // The saved filters, also kept where user-state.js syncs them to the
    // reader's other devices, one state per page group
    var STORE_KEY = 'mtgban_arbit_filters';
    var GROUPS = { arbit: 'ArbitFilters', global: 'GlobalFilters' };

    function groupOf(cookie) {
        return cookie === GROUPS.global ? 'global' : 'arbit';
    }

    function readSaved() {
        try {
            var o = JSON.parse(localStorage.getItem(STORE_KEY) || '{}');
            return o && typeof o === 'object' && !Array.isArray(o) ? o : {};
        } catch (e) {
            return {};
        }
    }

    function writeSaved(cookie, query, t) {
        writeCookie(cookie, encodeURIComponent(query + (query ? '&' : '') + 't=' + t), 1000, '/');
    }

    // When a saved cookie's state was applied, 0 for none.
    function cookieTime(cookie) {
        var t = Number(new URLSearchParams(getCookie(cookie)).get('t'));
        return isFinite(t) ? t : 0;
    }

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
        var t = Date.now();
        writeSaved(cfg.cookie, query, t);
        try {
            var saved = readSaved();
            saved[groupOf(cfg.cookie)] = { q: query, t: t };
            localStorage.setItem(STORE_KEY, JSON.stringify(saved));
        } catch (e) {}
    }

    // Bring each cookie and the synced copy to whichever was applied later:
    // a cookie to filters applied on another device, and the synced copy to
    // a cookie it never held (saved signed out, or before syncing, or under
    // an older copy a sync wrote back). Then show the newer filters where
    // this page was drawn from older ones and no link of its own says
    // otherwise. Runs on load, and from user-state.js after a sync.
    function refresh() {
        var saved = readSaved();
        var adopted = false;
        Object.keys(GROUPS).forEach(function (g) {
            var entry = saved[g];
            var cookieAt = cookieTime(GROUPS[g]);
            if (entry && typeof entry.q === 'string' && entry.t > cookieAt) {
                writeSaved(GROUPS[g], entry.q, entry.t);
            } else if (cookieAt > ((entry && entry.t) || 0)) {
                var q = new URLSearchParams(getCookie(GROUPS[g]));
                q.delete('t');
                saved[g] = { q: q.toString(), t: cookieAt };
                adopted = true;
            }
        });
        if (adopted) {
            try { localStorage.setItem(STORE_KEY, JSON.stringify(saved)); } catch (e) {}
        }

        var mine = cfg.cookie ? saved[groupOf(cfg.cookie)] : null;
        var marked = new URLSearchParams(window.location.search).has('f');
        if (marked || !mine || !(mine.t > (cfg.savedAt || 0))) return;
        // Once per state, should the cookie not have taken
        try {
            if (sessionStorage.getItem('mtgban_arbit_reloaded') === String(mine.t)) return;
            sessionStorage.setItem('mtgban_arbit_reloaded', String(mine.t));
        } catch (e) {
            return;
        }
        window.location.reload();
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

    window.ArbitFilters = { sortURL: sortURL, dropEmpty: dropEmpty, restore: restore, setOpen: setOpen, save: save, formQuery: formQuery, refresh: refresh };
    refresh();
})();
