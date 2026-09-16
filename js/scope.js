/*
 * The pinned-filter bar: the second search field, for what does not change
 * from one search to the next. Enhances markup the navbar (desktop) or the
 * search page (mobile) already rendered, under the same ids on both.
 *
 * The row is bound to the search form by id rather than by nesting, so
 * typing in either bar and pressing Enter sends both fields; everything
 * here is only about opening, closing and clearing it without losing the
 * rest of the url.
 */
(function() {
    var btn = document.getElementById('nav-pin-btn');
    var row = document.getElementById('nav-scope');
    var box = document.getElementById('nav-scopebox');
    var clear = document.getElementById('nav-scope-clear');
    var field = document.getElementById('nav-scopefield');
    if (!btn || !row || !box) return;

    // The visible bar is not part of the search form - two text fields and
    // no submit button would cost the main bar its Enter - so what is typed
    // here is mirrored into the hidden field that is.
    if (field) {
        box.addEventListener('input', function() { field.value = box.value.trim(); });
    }

    function isOpen() { return document.body.classList.contains('has-scope'); }

    function setOpen(open) {
        document.body.classList.toggle('has-scope', open);
        btn.setAttribute('aria-expanded', open ? 'true' : 'false');
        // Remembered server-side, so the next page draws the row the way it
        // was left instead of reopening it under the reader.
        setCookie('SearchScopeOpen', open ? '1' : '0', 3650);
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

    // The x empties the bar and leaves it open, cursor waiting. Emptying it
    // is an edit like any other and takes effect on the next search, so it
    // neither reloads the page nor puts the row away - a clear meant as the
    // first half of typing something else should not cost a round trip.
    //
    // Setting .value in script fires no input event, so the hidden field the
    // form actually submits is cleared by hand here.
    if (clear) {
        clear.addEventListener('click', function() {
            box.value = '';
            if (field) field.value = '';
            box.focus();
        });
    }

    box.addEventListener('keydown', function(e) {
        if (e.key === 'Enter') {
            e.preventDefault();
            apply(box.value.trim());
        } else if (e.key === 'Escape') {
            // Dismiss, in the usual sense: put the row away and leave what
            // is in it alone. Emptying it is what the x is for.
            e.preventDefault();
            setOpen(false);
            btn.focus();
        }
    });
})();
