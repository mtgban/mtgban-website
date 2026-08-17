// The store picker is a bare <select> sitting inside a padded pill next to its
// "Buying from" / "Selling to" label. Only the select's own text was clickable,
// so clicking the label or the padding around it did nothing. Widen the hit area
// to the whole pill.
//
// showPicker() is what actually pops the menu open; it needs transient user
// activation, which a click handler provides. Where it is unavailable (or
// refuses) fall back to focusing the select, which at least lets the keyboard
// open it.
document.addEventListener('click', function (event) {
    var target = event.target;
    if (!target || typeof target.closest !== 'function') {
        return;
    }

    var wrapper = target.closest('.arb-current-store');
    if (!wrapper) {
        return;
    }

    var select = wrapper.querySelector('.arb-store-select');
    // Clicks on the select itself already open it natively; calling showPicker()
    // on top of that would toggle the menu straight back shut.
    if (!select || select === target || select.contains(target)) {
        return;
    }

    if (typeof select.showPicker === 'function') {
        try {
            select.showPicker();
            return;
        } catch (err) {
            // Not allowed in this context - fall through to focusing instead.
        }
    }

    select.focus();
});

// Picking a store navigates to the option's value, so the value decides where
// the visitor lands. Resolving it against the current page and comparing the
// origin is what the browser itself would do, so nothing can look local and
// resolve elsewhere: a browser strips a tab, newline or carriage return before
// it parses, which is how "/\t/evil.com" reads as "//evil.com" and leaves.
//
// The store that is already active carries an empty value, and an empty value
// resolves to this very page, so it needs saying that it goes nowhere.
function goToStore(value) {
    if (!value) {
        return;
    }

    var url;
    try {
        url = new URL(value, window.location.href);
    } catch (err) {
        return;
    }

    if (url.origin !== window.location.origin) {
        return;
    }

    window.location.href = url.href;
}
