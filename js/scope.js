/*
 * The pinned-filter bar: the second search field, for what does not change
 * from one search to the next. Enhances markup the navbar (desktop) or the
 * search page (mobile) already rendered, under the same ids on both.
 *
 * The row is bound to the search form by id rather than by nesting, so
 * typing in either bar and pressing Enter sends both fields; everything
 * here is only about opening, closing, running and clearing it without
 * losing the rest of the url.
 */
(function() {
    var btn = document.getElementById('nav-pin-btn');
    var row = document.getElementById('nav-scope');
    var box = document.getElementById('nav-scopebox');
    var clear = document.getElementById('nav-scope-clear');
    var go = document.getElementById('nav-scope-go');
    var field = document.getElementById('nav-scopefield');
    if (!btn || !row || !box) return;

    var chips = row.querySelectorAll('.nav2-scope-chip');

    // The visible bar is not part of the search form - two text fields and
    // no submit button would cost the main bar its Enter - so what is typed
    // here is mirrored into the hidden field that is.
    // The red state is the server's verdict on the scope that is actually
    // applied, so it only ever spoke for the text that produced it. Once the
    // box says something else the verdict is about a string that is no longer
    // there, and the warning has to stand down - typing the ignored one back
    // brings it round again, and the next search has the last word either way.
    //
    // Nothing here decides for itself whether a filter is real: the syntax is
    // the search parser's, and a second opinion written in js would only be
    // wrong somewhere the first one is right.
    var ignoredValue = box.classList.contains('is-ignored') ? box.value.trim() : null;
    var ignoredTitle = box.title;

    function markState() {
        // The icon fills while the bar holds something. This one needs no
        // parser: whether the bar is empty is a question the box can answer
        // for itself, so it answers per keystroke rather than per search.
        btn.classList.toggle('is-active', box.value.trim() !== '');

        var on = ignoredValue !== null && box.value.trim() === ignoredValue;
        box.classList.toggle('is-ignored', on);
        if (on) {
            box.title = ignoredTitle;
        } else {
            box.removeAttribute('title');
        }
    }

    function write(value) {
        box.value = value;
        if (field) field.value = value.trim();
        markState();
    }

    box.addEventListener('input', function() { write(box.value); });
    write(box.value);

    // A suggestion picked from the list writes the box without an input
    // event, so the field is read again from it when the form goes.
    var form = document.getElementById('nav-searchform') || document.getElementById('searchform');
    if (form && field) {
        form.addEventListener('submit', function() { field.value = box.value.trim(); });
    }

    /* The pinned field accepts the same filter vocabulary as the primary
       search. Reuse the shared autocomplete so values like f: or s: get the
       same provider candidates, while the form keeps both fields on submit. */
    if (typeof autocomplete === 'function' && !box._scopeAutocompleteBound) {
        if (form) {
            box._scopeAutocompleteBound = true;
            autocomplete(form, box, location.pathname.indexOf('/sealed') === 0 ? 'true' : 'false');
        }
    }

    function isOpen() { return document.body.classList.contains('has-scope'); }

    function setOpen(open) {
        document.body.classList.toggle('has-scope', open);
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
    }

    // Reload with a different scope rather than submitting the form: the
    // sort, the page and everything else the reader already chose live in
    // the url, and a GET form would drop all of it on the floor.
    function apply(value) {
        var url = new URL(window.location.href);
        url.searchParams.set('scope', value);
        window.location.assign(url.toString());
    }

    // A plain toggle. It used to refuse to close over a filter, on the
    // grounds that a filter nobody can see is one nobody can undo - but a
    // button that stops answering is worse than the thing it guarded, and
    // what it guarded is covered anyway: the chip stays lit and names the
    // filter, and a search the filter empties says so in the page itself,
    // with a link that drops it.
    btn.addEventListener('click', function() {
        var open = !isOpen();
        setOpen(open);
        if (open) {
            box.focus();
            box.setSelectionRange(0, box.value.length);
        }
    });

    // CLEAR empties the bar, closes it, and reloads so the active search is
    // immediately rerun without the pinned filters. Keeping the reload here
    // also makes the visible state, hidden form field, and server-side result
    // agree in one action.
    if (clear) {
        clear.addEventListener('click', function() {
            write('');
            setOpen(false);
            apply('');
        });
    }

    // GO is the Enter below, as something to click. The box is bound to the
    // search form by id rather than by nesting, so nothing on screen says a
    // keypress is what runs it - and on a phone there is no Enter in view at
    // all until the keyboard is up.
    if (go) {
        go.addEventListener('click', function() {
            apply(box.value.trim());
        });
    }

    // A shortcut writes itself into the bar, and that is all it does: CLEAR
    // is what empties it, and GO or Enter is what runs the search, so a
    // click meant as the first half of typing something else costs nothing.
    for (var i = 0; i < chips.length; i++) {
        chips[i].addEventListener('click', function() {
            write(this.getAttribute('data-scope'));
            box.focus();
            box.setSelectionRange(box.value.length, box.value.length);
        });
    }

    box.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            // A highlighted suggestion is the autocomplete's to take: this
            // Enter picks it, and the next one runs the search.
            var list = document.getElementById(box.id + 'autocomplete-list');
            if (list && list.querySelector('.autocomplete-active')) return;
            apply(box.value.trim());
        } else if (e.key === 'Escape') {
            // Dismiss, in the usual sense: put the row away and leave what
            // is in it alone. Emptying it is what CLEAR is for.
            e.preventDefault();
            setOpen(false);
            btn.focus();
        }
    });
})();
