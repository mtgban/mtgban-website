// The fold button in a store's header on the upload optimizer and the arbit
// page hides that store's cards and leaves the header in place to show them
// again. The button sits inside the [data-fold] element it folds.
document.addEventListener('click', function (e) {
    var btn = e.target.closest && e.target.closest('.section-fold');
    if (!btn) return;
    var section = btn.closest('[data-fold]');
    if (!section) return;
    var folded = section.classList.toggle('folded');
    btn.setAttribute('aria-expanded', String(!folded));
    btn.title = folded ? 'Show these cards' : 'Hide these cards';
});
