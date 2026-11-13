// The mobile offline page: the singles and sealed pills and each card's tabs,
// on top of offline-page.js.
(function (root) {
    'use strict';

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

    // Wire tab/pill interactions on freshly rendered .m-card nodes; scoped to
    // the results container so listeners never attach outside it.
    function wireCardInteractions(results) {
        results.querySelectorAll('.m-tab').forEach(function (tab) {
            tab.addEventListener('click', function () {
                if (window.BAN && window.BAN.track) window.BAN.track('ui.offline.page', 'tab');
                var card = this.closest('.m-card');
                card.querySelectorAll('.m-tab').forEach(function (t) { t.classList.remove('active'); });
                card.querySelectorAll('.m-tab-panel').forEach(function (p) { p.classList.remove('active'); });
                this.classList.add('active');
                var target = document.getElementById(this.getAttribute('data-target'));
                if (target) target.classList.add('active');
            });
        });
        results.querySelectorAll('.m-cond-pill').forEach(function (pill) {
            pill.addEventListener('click', function () {
                var cond = this.getAttribute('data-cond');
                var card = this.closest('.m-card');
                if (!card) return;
                if (window.BAN && window.BAN.track) window.BAN.track('ui.offline.page', 'condition');
                this.closest('.m-cond-pills').querySelectorAll('.m-cond-pill').forEach(function (p) { p.classList.remove('active'); });
                this.classList.add('active');
                card.querySelectorAll('.m-cond-group').forEach(function (g) {
                    g.classList.toggle('active', g.getAttribute('data-cond') === cond);
                });
            });
        });
    }

    var page = root.OfflinePage.start({
        surface: 'mobile',
        closeKeyboard: true,
        boxId: 'navsearchbox',
        formId: 'navsearchform',
        resultsId: 'm-offline-results',
        queryChanged: paintModePills,
        render: function (el, shown, exec, ctx) {
            OfflineRenderMobile.render(el, shown, ctx);
            wireCardInteractions(el);
        }
    });
})(typeof self !== 'undefined' ? self : globalThis);
