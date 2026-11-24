// The Cards search layout on phones (docs/adr/0010-mobile-card-view.md).
// Scrolling is the browser's own snapping; this only does what CSS cannot:
// keeps the search from zooming, puts cards back on their picture after a
// rotation, returns to the card the reader left, opens a list from its edge
// button, slides the search bar away while a list is in, jumps to a card
// from the scrubber, fetches the sales when a card first shows them, and
// counts the lists read.
(function () {
    'use strict';

    // iOS pinch-zooms whatever touch-action says, unless its gesture events
    // are cancelled; the price chart's own pinch is left alone.
    function noZoom(e) {
        if (!(e.target && e.target.closest && e.target.closest('.m-chart-drawer'))) e.preventDefault();
    }
    if (document.querySelector('.m-layout-cards, .m-landing')) {
        document.addEventListener('gesturestart', noZoom);
        document.addEventListener('gesturechange', noZoom);
    }

    // The stylesheet fans the search box's top corners out into the
    // suggestions above it, and needs where the box sits in its bar.
    var wrap = document.querySelector('.m-landing .m-search-wrap, .m-layout-cards .m-search-wrap');
    var box = wrap && wrap.querySelector('form');
    function fan() {
        wrap.style.setProperty('--box-l', box.offsetLeft + 'px');
        wrap.style.setProperty('--box-r', (wrap.clientWidth - box.offsetLeft - box.offsetWidth) + 'px');
    }
    if (box) {
        fan();
        window.addEventListener('resize', fan);
    }

    var deck = document.querySelector('.m-layout-cards .m-results');
    if (!deck) return;
    var page = deck.closest('.m-page');

    var portrait = window.matchMedia('(orientation: portrait)');
    var reduced = window.matchMedia('(prefers-reduced-motion: reduce)');

    // panes lists a card's columns left to right: its sellers, its picture,
    // then its buyers and sales in the page's order, whichever it has.
    function panes(card) {
        var out = [];
        if (card.querySelector(':scope > [id^="sellers"]')) out.push('sellers');
        out.push('picture');
        card.querySelectorAll(':scope > .m-tab-panel:not([id^="sellers"])').forEach(function (p) {
            out.push(p.id.split('-')[0]);
        });
        return out;
    }

    // The first time any card shows its sales, every card's are fetched.
    function showSales(pane) {
        if (pane === 'sales' && window.SearchBuyers) SearchBuyers.show(document, window.fetch.bind(window));
    }

    function paneAt(card) {
        var list = panes(card);
        var i = Math.round(card.scrollLeft / Math.max(card.clientWidth, 1));
        return list[Math.min(Math.max(i, 0), list.length - 1)];
    }

    // slide moves a card to a pane in 180 ms, quicker than the browser's
    // smooth scroll; the snap waits until it lands.
    function slide(card, to) {
        var from = card.scrollLeft, t0 = null;
        card.style.scrollSnapType = 'none';
        function step(t) {
            if (t0 === null) t0 = t;
            var k = Math.min((t - t0) / 180, 1);
            card.scrollLeft = from + (to - from) * (1 - Math.pow(1 - k, 3));
            if (k < 1) requestAnimationFrame(step);
            else card.style.scrollSnapType = '';
        }
        requestAnimationFrame(step);
    }

    function show(card, pane, smooth) {
        var i = panes(card).indexOf(pane);
        if (i < 0) return;
        if (smooth && !reduced.matches) slide(card, i * card.clientWidth);
        else card.scrollTo({ left: i * card.clientWidth, behavior: 'auto' });
    }

    function cards() {
        return deck.querySelectorAll(':scope > .m-card');
    }

    function centreAll() {
        cards().forEach(function (card) { show(card, 'picture', false); });
    }

    // Each card opens on its picture again after the layout changes size.
    var width = window.innerWidth;
    window.addEventListener('resize', function () {
        if (window.innerWidth === width) return;
        width = window.innerWidth;
        centreAll();
    });
    portrait.addEventListener('change', centreAll);

    // pitch is a card's height, a whole pixel (the stylesheet rounds it
    // down), so every card starts on a pixel and lands exactly in place.
    function pitch() {
        var c = deck.querySelector(':scope > .m-card');
        return Math.max(c ? c.offsetHeight : deck.clientHeight, 1);
    }

    // Remember the card in this history entry, and return to it.
    function current() {
        return Math.round(deck.scrollTop / pitch());
    }

    function remember() {
        var state = Object.assign({}, history.state || {}, { cardsIndex: current() });
        try { history.replaceState(state, ''); } catch (e) {}
    }

    function restore() {
        var i = history.state && history.state.cardsIndex;
        if (i > 0 && portrait.matches && current() !== i) deck.scrollTop = i * pitch();
    }
    restore();
    // Again once the page has loaded, should the browser have moved the deck
    // after the first try, and when it comes back from the back/forward cache.
    window.addEventListener('load', restore);
    window.addEventListener('pageshow', function (e) { if (e.persisted) restore(); });
    // The card in view as the page is left, even mid-swipe.
    window.addEventListener('pagehide', remember);

    // Settled scrolls: the card the reader is on, and the list a swipe
    // opened. Debounced scroll, since not every Safari sends scrollend.
    var timers = new WeakMap();
    var shown = new WeakMap();
    var tapped = new WeakSet();

    // The search bar slides down as a swipe heads away from the picture and
    // back up as one comes onto it, once it has moved STEP pixels that way,
    // so a finger's small reversals and the snap's settling don't flip it
    // back and forth. Between two lists it stays down, and on the picture it
    // always shows.
    var STEP = 24;
    var turns = new WeakMap();

    // offset is how far the card sits from its picture, leaving out the
    // bounce past either end, which would read as turning back.
    function offset(card) {
        var x = Math.min(Math.max(card.scrollLeft, 0), card.scrollWidth - card.clientWidth);
        return Math.abs(x - panes(card).indexOf('picture') * card.clientWidth);
    }

    function tuck(card) {
        if (!card) return;
        var off = offset(card);
        var hidden = page.classList.contains('m-list-open');
        var turn = turns.has(card) ? turns.get(card) : 0;
        if (off <= 1) {
            hidden = false;
            turn = 0;
        } else if (hidden) {
            if (off > turn) turn = off;
            else if (Math.min(turn, card.clientWidth) - off > STEP) { hidden = false; turn = off; }
        } else {
            if (off < turn) turn = off;
            else if (off - turn > STEP) { hidden = true; turn = off; }
        }
        turns.set(card, turn);
        page.classList.toggle('m-list-open', hidden);
        if (hidden) pager(false);
    }

    // A card the deck lands on sets the bar by where it rests.
    function land(card) {
        if (!card) return;
        var off = offset(card);
        turns.set(card, off);
        page.classList.toggle('m-list-open', off > 1);
    }

    function settled(el) {
        if (el === deck) {
            land(cards()[current()]);
            remember();
            return;
        }
        // A swipe that ends back where it began still sets the bar by where
        // the card rests.
        if (el === cards()[current()]) land(el);
        var pane = paneAt(el);
        if (pane === shown.get(el)) return;
        shown.set(el, pane);
        showSales(pane);
        if (tapped.has(el)) {
            tapped.delete(el);
            return;
        }
        if (pane !== 'picture' && window.BAN && BAN.track) BAN.track('ui.cards.pane', pane, 'swipe');
    }

    // The scrubber on the right edge: its thumb follows the card in view, and
    // a tap or a drag along it puts the deck on that card at once.
    var scrub = page.querySelector('.m-scrub');
    var thumb = scrub && scrub.querySelector('.m-scrub-thumb');
    // The track is as long as its cards, up to the deck's height.
    if (scrub) scrub.style.setProperty('--n', cards().length);

    // The thumb follows the deck's scroll as it moves, not the card it will
    // settle on, so it glides along with a swipe.
    function place() {
        if (!thumb) return;
        var n = cards().length;
        var f = n > 1 ? deck.scrollTop / pitch() / (n - 1) : 0;
        thumb.style.setProperty('--f', Math.min(Math.max(f, 0), 1));
    }

    // printing names a card by its set and collector number, "TRC #499".
    function printing(card) {
        var head = card && card.querySelector('.m-card-header');
        if (!head) return '';
        var set = head.getAttribute('data-set-code') || '';
        var number = head.getAttribute('data-number') || '';
        return number ? set + ' #' + number : set;
    }

    function jump(e) {
        var n = cards().length;
        var r = scrub.getBoundingClientRect();
        var f = Math.min(Math.max((e.clientY - r.top) / Math.max(r.height, 1), 0), 1);
        var i = Math.round(f * (n - 1));
        if (i !== current()) deck.scrollTop = i * pitch();
        thumb.setAttribute('data-n', printing(cards()[i]) || (i + 1) + ' / ' + n);
        place();
    }

    function release() {
        if (!scrub.classList.contains('m-scrubbing')) return;
        scrub.classList.remove('m-scrubbing');
        if (window.BAN && BAN.track) BAN.track('ui.cards.scrub');
    }

    if (scrub) {
        scrub.addEventListener('pointerdown', function (e) {
            e.preventDefault();
            try { scrub.setPointerCapture(e.pointerId); } catch (err) {}
            scrub.classList.add('m-scrubbing');
            jump(e);
        });
        scrub.addEventListener('pointermove', function (e) {
            if (scrub.classList.contains('m-scrubbing')) jump(e);
        });
        scrub.addEventListener('pointerup', release);
        scrub.addEventListener('pointercancel', release);
        place();
    }

    // The end drawer, the pager or where the results end: the last card
    // cannot scroll on, so a swipe up on it raises the drawer, and a swipe
    // down anywhere lowers it again. While it is up the script owns every
    // swipe, since nothing under it scrolls: a sideways one folds the drawer
    // and moves the card one list over.
    var drawer = page.querySelector('.m-results-end');
    var SWIPE = 40;
    var startX = null, startY = null;

    function held(e) {
        if (e.cancelable) e.preventDefault();
        if (startX === null) return;
        var dx = e.touches[0].clientX - startX;
        var dy = e.touches[0].clientY - startY;
        if (Math.abs(dx) <= SWIPE || Math.abs(dx) <= Math.abs(dy)) return;
        startX = startY = null;
        pager(false);
        var card = cards()[current()];
        if (!card) return;
        var list = panes(card);
        var j = list.indexOf(paneAt(card)) + (dx < 0 ? 1 : -1);
        if (j >= 0 && j < list.length) show(card, list[j], true);
    }

    function pager(open) {
        if (page.classList.contains('m-pager-open') === open) return;
        page.classList.toggle('m-pager-open', open);
        if (open) page.addEventListener('touchmove', held, { passive: false });
        else page.removeEventListener('touchmove', held, { passive: false });
    }

    function onLast() {
        var n = cards().length;
        return n > 0 && current() >= n - 1 && portrait.matches;
    }

    if (drawer) {
        page.addEventListener('touchstart', function (e) {
            var one = e.touches.length === 1;
            startX = one ? e.touches[0].clientX : null;
            startY = one ? e.touches[0].clientY : null;
        }, { passive: true });
        page.addEventListener('touchmove', function (e) {
            if (startY === null) return;
            var dx = e.touches[0].clientX - startX;
            var dy = e.touches[0].clientY - startY;
            var open = page.classList.contains('m-pager-open');
            if (Math.abs(dx) > Math.abs(dy)) return;
            if (!open && dy < -SWIPE && onLast() && !page.classList.contains('m-list-open')) {
                pager(true);
                startX = startY = null;
            } else if (open && dy > SWIPE) {
                pager(false);
                startX = startY = null;
            }
        }, { passive: true });
        page.addEventListener('touchend', function () { startX = startY = null; }, { passive: true });
    }

    document.addEventListener('scroll', function (e) {
        var el = e.target;
        if (el !== deck && !(el.classList && el.classList.contains('m-card') && el.parentNode === deck)) return;
        if (el === deck) place();
        if (window.closeActionsMenus) window.closeActionsMenus();
        if (el !== deck && el === cards()[current()]) tuck(el);
        clearTimeout(timers.get(el));
        timers.set(el, setTimeout(function () { settled(el); }, 150));
    }, { capture: true, passive: true });

    // An edge button moves its card to its list.
    deck.addEventListener('click', function (e) {
        var btn = e.target.closest('[data-pane]');
        if (!btn || !deck.contains(btn)) return;
        var card = btn.closest('.m-card');
        var pane = btn.getAttribute('data-pane').split('-')[0];
        if (paneAt(card) === pane) return;
        tapped.add(card);
        show(card, pane, true);
    });

    cards().forEach(function (card) { shown.set(card, 'picture'); });
})();
