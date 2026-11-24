// The mobile offline page: the singles and sealed pills and the Cards deck, on
// top of offline-page.js.
(function (root) {
    'use strict';

    var parts = null;

    function singlesUrl(q) {
        return q ? '/offline?q=' + encodeURIComponent(q) : '/offline';
    }

    function paintModePills(q) {
        var s = document.getElementById('offline-pill-singles');
        var p = document.getElementById('offline-pill-sealed');
        if (!s || !p) return;
        var sealed = page.sealed();
        s.href = singlesUrl(q);
        p.href = '/offline?sealed=1' + (q ? '&q=' + encodeURIComponent(q) : '');
        s.classList.toggle('active', !sealed);
        p.classList.toggle('active', sealed);
    }

    function readParts() {
        parts = {back: root.cardBackForGame ? root.cardBackForGame() : ''};
        document.getElementById('m-offline-parts').content.querySelectorAll('[data-part]').forEach(function (el) {
            parts[el.getAttribute('data-part')] = el.innerHTML.trim();
        });
    }

    function paintCount(n, shown) {
        document.getElementById('m-offline-count').textContent =
            n ? n + ' result' + (n === 1 ? '' : 's') + (n > shown ? ' (' + shown + ' shown)' : '') : '';
        document.getElementById('m-offline-end').textContent =
            n > shown ? 'The first ' + shown + ' of ' + n + ' results' : n ? 'End of results' : '';
    }

    var page = root.OfflinePage.start({
        surface: 'mobile',
        closeKeyboard: true,
        // The box at the foot, and the navbar's on a landscape phone
        boxes: [['searchbox', 'searchform'], ['navsearchbox', 'navsearchform']],
        resultsId: 'm-offline-results',
        queryChanged: paintModePills,
        ready: readParts,
        render: function (el, shown, exec, ctx) {
            document.getElementById('m-offline-notices').innerHTML = OfflineRenderShared.noticesHTML(exec);
            OfflineRenderMobile.render(el, shown, ctx, parts);
            paintCount(exec.results.length, shown.pageRows);
            SearchCards.refresh();
        },
        recount: paintCount,
        toTop: function () { SearchCards.toTop(); },
        cleared: function () {
            document.getElementById('m-offline-notices').innerHTML = '';
            paintCount(0, 0);
        }
    });
})(typeof self !== 'undefined' ? self : globalThis);
