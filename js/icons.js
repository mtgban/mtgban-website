// Paints the server-rendered <i data-lucide> placeholders once lucide has
// loaded. Icons inside result cards wait for the card to scroll near:
// a phone results page carries hundreds, and painting them all at once
// was the longest task on the page.
(function () {
    function paint(root) {
        if (!window.lucide || !window.lucide.createIcons) return;
        if (root) window.lucide.createIcons({ root: root });
        else window.lucide.createIcons();
    }
    window.paintIcons = paint;

    function paintCard(card) {
        card.querySelectorAll('i[data-lucide-lazy]').forEach(function (i) {
            i.setAttribute('data-lucide', i.getAttribute('data-lucide-lazy'));
            i.removeAttribute('data-lucide-lazy');
        });
        paint(card);
    }

    document.addEventListener('DOMContentLoaded', function () {
        var cards = document.querySelectorAll('.m-card');
        if (!cards.length) { paint(); return; }
        // Park the card icons so the document-wide pass skips them.
        document.querySelectorAll('i[data-lucide]').forEach(function (i) {
            if (!i.closest('.m-card')) return;
            i.setAttribute('data-lucide-lazy', i.getAttribute('data-lucide'));
            i.removeAttribute('data-lucide');
        });
        paint();
        if (typeof IntersectionObserver === 'undefined') {
            cards.forEach(paintCard);
            return;
        }
        var io = new IntersectionObserver(function (entries) {
            entries.forEach(function (e) {
                if (!e.isIntersecting) return;
                io.unobserve(e.target);
                paintCard(e.target);
            });
        }, { rootMargin: window.innerHeight + 'px 0px' });
        cards.forEach(function (c) { io.observe(c); });
    });
})();
