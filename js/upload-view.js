// The Optimizer's card view: a store's rows drawn as card images. The
// toolbar's button sets every store and is kept per browser; a store's own
// button sets that store alone, for this page. A phone starts on it.
var UPLOAD_VIEW_STORE = 'mtgban_upload_view';

(function () {
    var panel = document.getElementById('panel-optimizer');
    if (!panel) return;
    var all = document.querySelector('.res-view-btn');
    var stores = panel.querySelectorAll('.opt-store');

    function press(btn, cards) {
        if (!btn) return;
        btn.setAttribute('aria-pressed', cards ? 'true' : 'false');
        btn.classList.toggle('on', cards);
    }

    function show(store, cards) {
        store.classList.toggle('opt-cards', cards);
        press(store.querySelector('.opt-view-btn'), cards);
    }

    // The toolbar's button reads on only while every store shows cards
    function showAll() {
        press(all, stores.length > 0 && !panel.querySelector('.opt-store:not(.opt-cards)'));
    }

    var saved = '';
    try { saved = localStorage.getItem(UPLOAD_VIEW_STORE) || ''; } catch (e) {}
    // With nothing chosen a phone gets cards: a store's table is wider than it
    var start = saved ? saved === 'cards' : window.matchMedia('(max-width: 560px)').matches;
    stores.forEach(function (store) { show(store, start); });
    showAll();

    if (all) {
        all.addEventListener('click', function () {
            var cards = !all.classList.contains('on');
            stores.forEach(function (store) { show(store, cards); });
            showAll();
            try { localStorage.setItem(UPLOAD_VIEW_STORE, cards ? 'cards' : 'rows'); } catch (e) {}
        });
    }
    panel.addEventListener('click', function (e) {
        var btn = e.target.closest('.opt-view-btn');
        if (!btn) return;
        var store = btn.closest('.opt-store');
        show(store, !store.classList.contains('opt-cards'));
        showAll();
    });
})();
