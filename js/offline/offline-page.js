// What the desktop and mobile offline pages share: the database, the search
// box, the browser history and running a query. Each page's own script draws.
(function (root) {
    'use strict';

    // Mirrors MaxSearchResults (search.go:29); no pagination in v1.
    var PAGE_SIZE = 100;

    function hiddenList(name) {
        return (getCookie(name) || '').split(',').filter(Boolean);
    }

    // start runs a page. hooks names its boxId, formId and resultsId, and how it
    // draws: render(el, page, exec, ctx), with order(results, ctx) first if it
    // sorts. Optional are ready() at page load, cleared() when the box empties,
    // and queryChanged(q) when the query or the singles or sealed mode may have,
    // page load included.
    function start(hooks) {
        var dicts = null;
        var env = null;
        var exec = null;
        var ctx = null;
        var sealedMode = new URLSearchParams(location.search).get('sealed') === '1';
        // Suggestions read the current mode off this shared deps object.
        var searchDeps = null;
        // The latest search. One still running when a newer one starts, or the
        // box empties, is left to finish unseen.
        var latestSearch = 0;
        // The latest draw, as a new sort of the same answer also has to price
        // rows and can be overtaken.
        var latestDraw = 0;
        var lastQuery = '';

        function call(name) {
            if (hooks[name]) hooks[name]();
        }

        function queryChanged(q) {
            if (hooks.queryChanged) hooks.queryChanged(q);
        }

        function urlQuery() {
            return new URLSearchParams(location.search).get('q') || '';
        }

        function resultsEl() {
            return document.getElementById(hooks.resultsId);
        }

        // Compose a shell URL carrying the query and active mode.
        function buildUrl(q) {
            var parts = [];
            if (q) parts.push('q=' + encodeURIComponent(q));
            if (sealedMode) parts.push('sealed=1');
            return parts.length ? '?' + parts.join('&') : location.pathname;
        }

        async function setup() {
            // Warm the shared connection; rejects when IndexedDB is unavailable.
            await OfflineDB.open();
            dicts = await OfflineUtil.loadCatalogDicts();
            var version;
            var cards = null;
            var reads = 0;
            var applied = 0;
            env = {
                normName: OfflineUtil.normName,
                // A slower, older read must not take a newer search back to the
                // catalog it replaced.
                searchState: async function () {
                    var read = ++reads;
                    var state = await OfflineDB.searchState();
                    var loaded = await OfflineDB.catalog(state.catalogVersion);
                    if (read > applied) {
                        applied = read;
                        version = state.catalogVersion;
                        cards = loaded;
                    }
                    return state;
                },
                lookupName: OfflineDB.lookupName,
                allNames: function () { return OfflineDB.allNames(version); },
                getCard: function (uuid) { return cards.byId.get(uuid); },
                allCards: function () { return cards.list; },
                loadSetPayload: OfflineUtil.loadSetPayload
            };
            // In the background, so the first search doesn't wait on it.
            env.searchState().then(function () { return env.allNames(); }).catch(function () {});
            ctx = {
                sets: dicts.sets,
                stores: dicts.stores,
                hiddenSellers: hiddenList('SearchSellersList'),
                hiddenVendors: hiddenList('SearchVendorsList'),
                byStore: getCookie('SearchListingPriority') === 'stores',
                buylistSecondary: getCookie('SearchBuylistSecondary') || ''
            };
        }

        // What this page shows of an answer, read when it is priced.
        function view() {
            return {
                size: PAGE_SIZE,
                order: hooks.order && function (results) { hooks.order(results, ctx); },
                allPrices: hooks.needsAllPrices
            };
        }

        function draw() {
            var page = Object.assign({}, exec, {results: exec.page});
            hooks.render(resultsEl(), page, exec, ctx);
        }

        async function redraw() {
            var turn = ++latestDraw;
            var shown = exec;
            var complete = await OfflineQuery.showPage(shown, env, view());
            if (turn !== latestDraw || shown !== exec) return;
            // A set that could not be opened changes the answer itself
            if (complete) draw();
            else runQuery(lastQuery).catch(showErrorNotice);
        }

        async function runQuery(q) {
            var search = ++latestSearch;
            latestDraw++;
            lastQuery = q;
            if (!q) {
                exec = null;
                resultsEl().innerHTML = '';
                call('cleared');
                return;
            }
            var parsed = OfflineQuery.parse(q, dicts.finishes, dicts.rarities, dicts.sets);
            parsed.sealed = sealedMode;
            var answer;
            try {
                answer = await OfflineQuery.execute(parsed, env, view());
            } catch (err) {
                if (search === latestSearch) throw err;
                return;
            }
            if (search !== latestSearch) return;
            latestDraw++;
            exec = answer;
            draw();
        }

        function showErrorNotice(err) {
            resultsEl().innerHTML =
                '<div class="offline-notice offline-notice-warn">Offline data is not ready. Enable offline mode in Settings and let a sync finish.</div>';
            console.error('offline shell setup failed', err);
        }

        document.addEventListener('DOMContentLoaded', function () {
            call('ready');
            queryChanged(urlQuery());
            var box = document.getElementById(hooks.boxId);
            var form = document.getElementById(hooks.formId);

            window.addEventListener('popstate', function () {
                var q = urlQuery();
                sealedMode = new URLSearchParams(location.search).get('sealed') === '1';
                queryChanged(q);
                if (searchDeps) searchDeps.sealed = sealedMode;
                if (box) box.value = q;
                runQuery(q).catch(showErrorNotice);
            });

            setup().then(function () {
                searchDeps = {
                    normName: OfflineUtil.normName,
                    allNames: OfflineDB.allNames,
                    getCard: OfflineDB.getCard,
                    sets: dicts.sets,
                    sealed: sealedMode
                };
                OfflineSearch.mount({
                    input: box,
                    form: form,
                    deps: searchDeps,
                    onSubmit: function (q) {
                        history.pushState(null, '', buildUrl(q));
                        queryChanged(q);
                        runQuery(q).catch(showErrorNotice);
                    }
                });
                var q = urlQuery();
                if (box) box.value = q;
                return runQuery(q);
            }).catch(showErrorNotice);
        });

        return {
            sealed: function () { return sealedMode; },
            // Draw the last answer again, as a new sort asks.
            repaint: function () {
                if (exec) redraw().catch(showErrorNotice);
            }
        };
    }

    root.OfflinePage = {start: start};
})(typeof self !== 'undefined' ? self : globalThis);
