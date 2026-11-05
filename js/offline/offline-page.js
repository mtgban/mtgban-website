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
            env = {
                normName: OfflineUtil.normName,
                lastSync: function () { return OfflineDB.getMeta('lastSync'); },
                lookupName: OfflineDB.lookupName,
                allNames: OfflineDB.allNames,
                getCard: OfflineDB.getCard,
                hasSet: OfflineDB.hasSet,
                allCards: function () { return OfflineDB.getAllRows('cards'); },
                loadSetPayload: OfflineUtil.loadSetPayload
            };
            ctx = {
                sets: dicts.sets,
                stores: dicts.stores,
                hiddenSellers: hiddenList('SearchSellersList'),
                hiddenVendors: hiddenList('SearchVendorsList'),
                byStore: getCookie('SearchListingPriority') === 'stores',
                buylistSecondary: getCookie('SearchBuylistSecondary') || ''
            };
        }

        function paint() {
            if (hooks.order) hooks.order(exec.results, ctx);
            var page = Object.assign({}, exec, {results: exec.results.slice(0, PAGE_SIZE)});
            hooks.render(resultsEl(), page, exec, ctx);
        }

        async function runQuery(q) {
            var search = ++latestSearch;
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
                answer = await OfflineQuery.execute(parsed, env);
            } catch (err) {
                if (search === latestSearch) throw err;
                return;
            }
            if (search !== latestSearch) return;
            exec = answer;
            paint();
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
            // Draw the last answer again, as a new sort asks; false without one.
            repaint: function () {
                if (!exec) return false;
                paint();
                return true;
            }
        };
    }

    root.OfflinePage = {start: start};
})(typeof self !== 'undefined' ? self : globalThis);
