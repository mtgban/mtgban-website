// The desktop offline page: the result count, the sort pills and the sidebar
// image, on top of offline-page.js.
(function (root) {
    'use strict';

    var PLACEHOLDER = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

    var sortMode = getCookie('SearchDefaultSort') || 'chrono';
    var reverse = false;
    if (sortMode === 'hybrid') sortMode = 'alpha';
    // The result the arrow keys are on, and the first one starts out showing.
    var cursor = 0;
    // The header stuck on top after the last move, -1 until there is one.
    var movedTo = -1;

    function paintCount(n, shown) {
        document.getElementById('offline-count').textContent =
            n + ' result' + (n === 1 ? '' : 's') + ' found' + (n > shown ? ' (' + shown + ' shown)' : '');
    }

    function paintPills() {
        document.querySelectorAll('.search-sort-pill').forEach(function (b) {
            b.classList.toggle('active', b.getAttribute('data-sort') === sortMode);
            b.classList.toggle('reversed', b.getAttribute('data-sort') === sortMode && reverse);
        });
    }

    // The renderers emit exactly one shape, /api/offline/images/<key>.webp for
    // singles or .jpg for sealed, or an empty string. Anything else is
    // rejected rather than assigned: the
    // value is read back out of the DOM, so checking it here does not depend on
    // the renderers' escaping staying correct as they change.
    var IMAGE_URL = /^\/api\/offline\/images\/[A-Za-z0-9._%-]+\.(webp|jpg)$/;

    function safeImageURL(url) {
        return (url && IMAGE_URL.test(url)) ? url : PLACEHOLDER;
    }

    function showImage(url, isFoil, isEtched, setCode) {
        // Through setCardArtSource (card-art-fallback.js), which re-arms the
        // card-back fallback for each card: an entry the sync never cached
        // answers 404 and shows the back, which sw.js precaches, not a hole.
        setCardArtSource(document.getElementById('cardImage'), safeImageURL(url));
        var wrapper = document.getElementById('cardImageWrapper');
        if (wrapper) {
            var ok = IMAGE_URL.test(url || '');
            wrapper.setAttribute('data-foil', (ok && isFoil) ? 'true' : 'false');
            wrapper.setAttribute('data-etched', (ok && isEtched) ? 'true' : 'false');
            wrapper.setAttribute('data-set', setCode || '');
            wrapper.toggleAttribute('data-sealed', page.sealed());
        }
    }

    function needsAllPrices() {
        return sortMode === 'retail' || sortMode === 'buylist';
    }

    function showRowImage(row) {
        showImage(row.getAttribute('data-image-url'), row.getAttribute('data-foil') === 'true',
            row.getAttribute('data-etched') === 'true', row.getAttribute('data-set-code'));
    }

    // Lands a result's header where it sticks. A stuck header can't say where it
    // belongs, but the body above it can.
    function scrollToHeader(headers, i) {
        if (i === 0) {
            window.scrollTo(0, 0);
            return;
        }
        var above = headers[i - 1].nextElementSibling.getBoundingClientRect().bottom;
        window.scrollBy(0, above - parseFloat(getComputedStyle(headers[i]).top));
    }

    function resultHeaders() {
        return document.getElementById('offline-results').querySelectorAll('.result-header');
    }

    // Moves to result i; mark draws the arrow keys' cursor on it.
    function goTo(headers, i, mark) {
        headers[cursor].classList.remove('offline-cursor');
        cursor = i;
        if (mark) headers[cursor].classList.add('offline-cursor');
        scrollToHeader(headers, cursor);
        movedTo = stuckIndex(headers);
        showRowImage(headers[cursor]);
    }

    function moveCursor(step) {
        var headers = resultHeaders();
        var next = cursor + step;
        if (next < 0 || next >= headers.length) return;
        goTo(headers, next, true);
    }

    // The last result whose header has reached where it sticks.
    function stuckIndex(headers) {
        for (var i = headers.length - 1; i > 0; i--) {
            var top = parseFloat(getComputedStyle(headers[i]).top);
            if (headers[i].getBoundingClientRect().top <= top + 2) return i;
        }
        return 0;
    }

    // PgDn and PgUp step a result from the one on top, or from the last one
    // moved to while nothing has scrolled since, which the results at the
    // bottom need as their headers never reach the top.
    function pageStep(down) {
        var headers = resultHeaders();
        if (headers.length === 0) return;
        var at = stuckIndex(headers);
        if (at === movedTo) at = cursor;
        goTo(headers, down ? Math.min(at + 1, headers.length - 1) : Math.max(at - 1, 0), false);
    }

    // From the box too, as search-result-nav.js does on the search page, once
    // what is being typed has settled, as the arrow keys do.
    function pageKey(e) {
        if (e.key !== 'PageDown' && e.key !== 'PageUp') return;
        if (resultHeaders().length === 0) return;
        e.preventDefault();
        var down = e.key === 'PageDown';
        if (!e.repeat && root.BAN && root.BAN.track) root.BAN.track('ui.search.key', down ? 'result_page_down' : 'result_page_up');
        page.afterTyping(function () { pageStep(down); });
    }

    // Tab outside a text field takes the search box and Escape gives it up,
    // as search-result-nav.js does on the search page.
    function boxKey(e) {
        var box = document.getElementById('nav-searchbox');
        if (!box) return;
        if (e.key === 'Tab') {
            var tag = e.target.tagName;
            if (tag === 'INPUT' || tag === 'TEXTAREA') return;
            e.preventDefault();
            if (root.BAN && root.BAN.track) root.BAN.track('ui.search.key', 'tab_to_search');
            box.focus();
            box.setSelectionRange(0, box.value.length);
        } else if (e.key === 'Escape' && document.activeElement === box) {
            box.blur();
        }
    }

    // The navbar's Search and Sealed links keep the current query.
    function paintNavLinks(q) {
        document.querySelectorAll('.offline-mode-btn').forEach(function (a) {
            var url = new URL(a.href);
            if (q) url.searchParams.set('q', q);
            else url.searchParams.delete('q');
            a.setAttribute('href', url.pathname + url.search);
        });
    }

    var page = root.OfflinePage.start({
        surface: 'desktop',
        boxId: 'nav-searchbox',
        formId: 'nav-searchform',
        resultsId: 'offline-results',
        queryChanged: paintNavLinks,
        move: moveCursor,
        ready: function () {
            document.addEventListener('keydown', function (e) {
                boxKey(e);
                pageKey(e);
            });

            // Sidebar image follows the hovered result, like search.html.
            document.getElementById('offline-results').addEventListener('mouseover', function (e) {
                var row = e.target.closest('[data-image-url]');
                if (row) showRowImage(row);
            });

            document.querySelectorAll('.search-sort-pill').forEach(function (b) {
                b.addEventListener('click', function () {
                    var mode = b.getAttribute('data-sort');
                    reverse = (mode === sortMode) ? !reverse : false;
                    sortMode = mode;
                    page.repaint();
                });
            });
        },
        // A price sort needs every row priced, so it waits for the pause.
        order: function (results, ctx, typing) {
            if (typing && needsAllPrices()) OfflineQuery.sortResults(results, 'chrono', false, ctx.sets);
            else OfflineQuery.sortResults(results, sortMode, reverse, ctx.sets);
        },
        needsAllPrices: needsAllPrices,
        render: function (el, shown, exec, ctx) {
            OfflineRender.render(el, shown, ctx);
            paintCount(exec.results.length, shown.pageRows);
            paintPills();
            cursor = 0;
            movedTo = -1;
            var first = el.querySelector('.result-header');
            if (first && !shown.typing) showRowImage(first);
        },
        recount: paintCount,
        cleared: function () {
            document.getElementById('offline-count').textContent = '';
        }
    });
})(typeof self !== 'undefined' ? self : globalThis);
