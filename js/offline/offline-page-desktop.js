// The desktop offline page: the result count, the sort pills and the sidebar
// image, on top of offline-page.js.
(function (root) {
    'use strict';

    var PLACEHOLDER = 'data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7';

    var sortMode = getCookie('SearchDefaultSort') || 'chrono';
    var reverse = false;
    if (sortMode === 'hybrid') sortMode = 'alpha';

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

    var page = root.OfflinePage.start({
        boxId: 'nav-searchbox',
        formId: 'nav-searchform',
        resultsId: 'offline-results',
        ready: function () {
            // Sidebar image follows the hovered result, like search.html.
            document.getElementById('offline-results').addEventListener('mouseover', function (e) {
                var row = e.target.closest('[data-image-url]');
                if (row) {
                    showImage(row.getAttribute('data-image-url'), row.getAttribute('data-foil') === 'true',
                        row.getAttribute('data-etched') === 'true', row.getAttribute('data-set-code'));
                }
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
        order: function (results, ctx) {
            OfflineQuery.sortResults(results, sortMode, reverse, ctx.sets);
        },
        needsAllPrices: function () {
            return sortMode === 'retail' || sortMode === 'buylist';
        },
        render: function (el, shown, exec, ctx) {
            OfflineRender.render(el, shown, ctx);
            paintCount(exec.results.length, shown.results.length);
            paintPills();
            var first = el.querySelector('.result-header');
            if (first) {
                showImage(first.getAttribute('data-image-url'), first.getAttribute('data-foil') === 'true',
                    first.getAttribute('data-etched') === 'true', first.getAttribute('data-set-code'));
            }
        },
        cleared: function () {
            document.getElementById('offline-count').textContent = '';
        }
    });
})(typeof self !== 'undefined' ? self : globalThis);
