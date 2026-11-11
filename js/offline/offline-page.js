// What the desktop and mobile offline pages share: the database, the search
// box, the browser history and running a query. Each page's own script draws.
(function (root) {
    'use strict';

    // Mirrors MaxSearchResults (search.go:29); no pagination in v1.
    var PAGE_SIZE = 100;
    // What a keystroke prices and draws, a screen and some to spare. The pause
    // fills in the rest of the page.
    var TYPING_ROWS = 10;
    // How long the box stays still before the answer settles.
    var PAUSE_MS = 350;

    function hiddenList(name) {
        return (getCookie(name) || '').split(',').filter(Boolean);
    }

    // start runs a page. hooks names its surface, boxId, formId and resultsId, and
    // how it draws: render(el, page, exec, ctx), with order(results, ctx, typing)
    // first if it sorts. page.typing says an answer is still being typed. Optional
    // are ready() at page load, cleared() when the box empties, queryChanged(q) when
    // the query or the singles or sealed mode may have, page load included, move(step)
    // for an arrow key, and closeKeyboard to give up the box on Enter.
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
        // Whether the box is ahead of the last answer that settled.
        var typing = false;
        var pauseTimer = null;
        // The top of what is on screen, null until something is.
        var shownTop = null;
        // The rows on screen, in order, whether they settled, and their notices.
        var shown = null;

        function live() {
            return root.OfflineLive.on(hooks.surface);
        }

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

        // A sync, here or in another tab, can bring new sets and stores.
        async function readDicts() {
            dicts = await OfflineUtil.loadCatalogDicts();
            if (ctx) {
                ctx.sets = dicts.sets;
                ctx.stores = dicts.stores;
            }
            if (searchDeps) searchDeps.sets = dicts.sets;
        }

        async function setup() {
            // Warm the shared connection; rejects when IndexedDB is unavailable.
            await OfflineDB.open();
            await readDicts();
            var version;
            var cards = null;
            var reads = 0;
            var applied = 0;
            var sync;
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
                        var synced = sync !== undefined && sync !== state.lastSync;
                        sync = state.lastSync;
                        if (synced) await readDicts();
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

        // What this page shows of an answer, read when it is priced. stale says
        // nobody is waiting for it any more.
        function view(draft, stale) {
            return {
                size: draft ? TYPING_ROWS : PAGE_SIZE,
                order: hooks.order && function (results) { hooks.order(results, ctx, draft); },
                bestMatch: !draft && live(),
                allPrices: draft ? null : hooks.needsAllPrices,
                stale: stale
            };
        }

        // A new answer starts from the top, however far down the last one was read.
        function followTop(answer) {
            var top = answer.results.length + ':' +
                answer.results.slice(0, TYPING_ROWS).map(function (row) { return row.uuid; }).join();
            if (live() && shownTop !== null && top !== shownTop) window.scrollTo(0, 0);
            shownTop = top;
        }

        function notices(answer) {
            return (answer.unsupported || []).join('\n') + (answer.truncated ? '+' : '');
        }

        // unchanged says an answer would only draw what is on screen again. A
        // draft with the same rows keeps them in the order shown, which a settled
        // one has to match row for row.
        function unchanged(answer, draft) {
            if (!shown || shown.ids.length !== answer.results.length) return false;
            if (draft) {
                var have = new Set(shown.ids);
                return answer.results.every(function (row) { return have.has(row.uuid); });
            }
            return shown.settled && shown.notices === notices(answer) &&
                answer.results.every(function (row, i) { return row.uuid === shown.ids[i]; });
        }

        function draw(draft) {
            shown = {
                ids: exec.results.map(function (row) { return row.uuid; }),
                settled: !draft,
                notices: notices(exec)
            };
            var page = Object.assign({}, exec, {
                results: exec.page,
                typing: draft,
                pageRows: Math.min(exec.results.length, PAGE_SIZE)
            });
            hooks.render(resultsEl(), page, exec, ctx);
            followTop(exec);
        }

        async function redraw() {
            var turn = ++latestDraw;
            var answer = exec;
            var complete = await OfflineQuery.showPage(answer, env, view(false));
            if (turn !== latestDraw || answer !== exec) return;
            // A set that could not be opened changes the answer itself
            if (complete) draw(false);
            else runQuery(lastQuery).catch(showErrorNotice);
        }

        function read(q, draft) {
            var parsed = OfflineQuery.parse(q, dicts.finishes, dicts.rarities, dicts.sets, {draft: draft});
            parsed.sealed = sealedMode;
            return parsed;
        }

        // keep leaves the screen alone when the answer would not change it, as
        // typing asks; anything else draws, as new prices or a new sort may.
        async function runQuery(q, keep) {
            var search = ++latestSearch;
            var draft = typing;
            latestDraw++;
            lastQuery = q;
            if (!q) {
                exec = null;
                shownTop = null;
                shown = null;
                resultsEl().innerHTML = '';
                call('cleared');
                return;
            }
            var parsed = read(q, draft);
            // What is on screen stays up until there is something better to show
            if (draft && !OfflineQuery.answerable(parsed, env)) return;
            var answer;
            try {
                answer = await OfflineQuery.execute(parsed, env, view(draft, function () {
                    return search !== latestSearch;
                }));
            } catch (err) {
                if (search === latestSearch) throw err;
                return;
            }
            if (search !== latestSearch) return;
            latestDraw++;
            if (draft && !answer.results.length) return;
            if (keep && unchanged(answer, draft)) return;
            exec = answer;
            draw(draft);
        }

        // settle gives the exact answer to q: read as finished, in best-match
        // order, the whole page. Back lands here rather than on a half-typed query.
        function settle(q, keep) {
            clearTimeout(pauseTimer);
            typing = false;
            history.replaceState(null, '', buildUrl(q));
            queryChanged(q);
            return runQuery(q, keep);
        }

        // The URL waits for the pause: Safari throws on over 100 history changes
        // in 30 seconds.
        function typed(value) {
            var q = value.trim();
            clearTimeout(pauseTimer);
            if (!q) {
                settle(q).catch(showErrorNotice);
                return;
            }
            if (!typing) {
                typing = true;
                history.pushState(null, '', buildUrl(q));
            }
            queryChanged(q);
            pauseTimer = setTimeout(function () {
                // A letter or two can't be said to find nothing; Enter still asks
                if (OfflineQuery.answerable(read(value, true), env)) settle(q, true).catch(showErrorNotice);
                else history.replaceState(null, '', buildUrl(q));
            }, PAUSE_MS);
            runQuery(value, true).catch(showErrorNotice);
        }

        function showErrorNotice(err) {
            shown = null;
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
                clearTimeout(pauseTimer);
                typing = false;
                sealedMode = new URLSearchParams(location.search).get('sealed') === '1';
                queryChanged(q);
                if (searchDeps) searchDeps.sealed = sealedMode;
                if (box) box.value = q;
                runQuery(q).catch(showErrorNotice);
            });

            // A sync brings new prices, so a settled answer is read again
            document.addEventListener('offline:synced', function () {
                if (exec && !typing) runQuery(lastQuery).catch(showErrorNotice);
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
                    live: live,
                    onType: typed,
                    onArrow: function (step) {
                        var ready = typing ? settle(lastQuery.trim(), true) : Promise.resolve();
                        ready.then(function () {
                            if (hooks.move) hooks.move(step);
                        }).catch(showErrorNotice);
                    },
                    onSubmit: function (q) {
                        if (live() && hooks.closeKeyboard) box.blur();
                        if (typing) {
                            settle(q, true).catch(showErrorNotice);
                            return;
                        }
                        // Live, Enter on what has already settled has nothing to add
                        if (live() && q === lastQuery) return;
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
            // Draw the last answer again, as a new sort asks, which also ends typing.
            repaint: function () {
                if (typing) settle(lastQuery.trim()).catch(showErrorNotice);
                else if (exec) redraw().catch(showErrorNotice);
            }
        };
    }

    root.OfflinePage = {start: start};
})(typeof self !== 'undefined' ? self : globalThis);
