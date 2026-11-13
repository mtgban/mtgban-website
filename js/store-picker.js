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
    // A control of its own in the pill, as the preset's pin, keeps its click
    if (target.closest('button')) {
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

// What each arbitrage page's store picker picks
var STORE_PICKS = { arbit: 'buying', reverse: 'selling', global: 'index' };

// A store picked, or a section jumped to; the selects' own onchange navigates.
document.addEventListener('change', function (event) {
    var select = event.target;
    if (!select || typeof select.getAttribute !== 'function' || !select.value) {
        return;
    }
    var pick = select.getAttribute('data-pick');
    if (pick === 'jump') {
        if (window.BAN && window.BAN.track) window.BAN.track('ui.arbit.jump');
        return;
    }
    if (pick !== 'store') {
        return;
    }
    var mode = window.BAN_ARBIT ? window.BAN_ARBIT.mode : '';
    var value = Object.prototype.hasOwnProperty.call(STORE_PICKS, mode) ? STORE_PICKS[mode] : '';
    if (value && window.BAN && window.BAN.track) window.BAN.track('ui.arbit.store_select', value);
    var presets = window.ArbitPresets;
    if (presets && typeof presets.pinnedStore === 'function' && presets.pinnedStore(select.value)) {
        if (window.BAN && window.BAN.track) window.BAN.track('ui.arbit.pin_auto');
    }
});
