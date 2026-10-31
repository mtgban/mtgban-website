// The newspaper's filter and sort choices, saved for each report on its
// own. A link naming only the report (the contents, the report tabs) opens
// it with the reader's last choices for it.
(function () {
    // Kept where user-state.js syncs it to the reader's other devices, one
    // state per report
    var STORE_KEY = 'mtgban_news_filters';

    var form = document.getElementById('newsFilters');
    var report = form && form.elements.page ? form.elements.page.value : '';

    function readSaved() {
        try {
            var o = JSON.parse(localStorage.getItem(STORE_KEY) || '{}');
            return o && typeof o === 'object' && !Array.isArray(o) ? o : {};
        } catch (e) {
            return {};
        }
    }

    // When a state is saved, on the server's clock once a sync has read it
    function now() {
        return window.UserState ? window.UserState.now() : Date.now();
    }

    // The choices a query holds: all of it but the report and the page of
    // results, an empty one left to the report's default.
    function choices(params) {
        var out = new URLSearchParams();
        params.forEach(function (v, k) {
            if (k === 'page' || k === 'index' || v === '') return;
            out.append(k, v);
        });
        return out.toString();
    }

    // Keep the reader's choices for this report. Only what the reader does
    // on the page saves: following a link never does.
    function save(query) {
        if (!report) return;
        try {
            var saved = readSaved();
            saved[report] = { q: query, t: now() };
            localStorage.setItem(STORE_KEY, JSON.stringify(saved));
        } catch (e) {}
    }

    // Open the report with its saved choices where the link named none.
    // Runs on load, and from user-state.js after a sync.
    function refresh() {
        if (!report) return;
        var here = new URLSearchParams(window.location.search);
        var bare = true;
        here.forEach(function (v, k) { if (k !== 'page') bare = false; });
        var mine = readSaved()[report];
        if (!bare || !mine || typeof mine.q !== 'string') return;
        var q = choices(new URLSearchParams(mine.q));
        if (!q) return;
        window.location.replace(window.location.pathname + '?page=' + encodeURIComponent(report) + '&' + q);
    }

    if (form) {
        form.addEventListener('submit', function () {
            save(choices(new URLSearchParams(new FormData(form))));
        });
    }
    document.querySelectorAll('#newsTable .sort-links a').forEach(function (a) {
        a.addEventListener('click', function () {
            save(choices(new URLSearchParams(a.search)));
        });
    });

    window.NewsFilters = { choices: choices, save: save, refresh: refresh };
    refresh();
})();
