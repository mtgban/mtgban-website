const PRINTINGS_THRESHOLD = 6;
// The panel needs at least this many editions to hold: a "+1"
// button would open a whole panel to show one symbol.
const PRINTINGS_MIN_OVERFLOW = 2;

// The two ways out of the overflow panel that are not the
// button itself. Both hooked up once: collapsePrintings runs
// on every hover - the sidebar rebuilds its printings per
// result the pointer crosses - so a listener registered
// inside it would stack one per hover, each closing over a
// dropdown that had already been removed.
document.addEventListener('click', function(e) {
    const container = document.getElementById('printings');
    if (!container || container.contains(e.target)) return;
    closePrintings(container);
});
// Escape belongs to the panel, not to the input: it has to
// answer with the caret on a symbol inside the panel, or on
// the button, and not only where it was left on opening.
// Whether it hands focus back is a separate question - the
// key still reaches here from the main search box, and a
// panel closing out of the corner of the eye is no reason to
// pull the caret out of what is being typed.
document.addEventListener('keydown', function(e) {
    if (e.key !== 'Escape') return;
    const container = document.getElementById('printings');
    if (!container) return;
    closePrintings(container, container.contains(document.activeElement));
});

// Closing empties the filter with the panel, so every way out
// leaves the same thing behind: the next open starts on the
// whole list rather than dropping the caret into a stale query
// half the symbols are still hidden by.
function closePrintings(container, refocus) {
    const dropdown = container.querySelector('.sidebar-printings-dropdown.open');
    if (!dropdown) return;
    dropdown.classList.remove('open');
    const filter = dropdown.querySelector('.sidebar-printings-filter');
    if (filter) filter.value = '';
    dropdown.querySelectorAll('a.printing-symbol').forEach(a => { a.style.display = ''; });
    const trigger = container.querySelector('.sidebar-printings-more');
    if (!trigger) return;
    setTriggerState(trigger, false);
    if (refocus) trigger.focus();
}

// Available In collapses to its title bar when the column runs
// short, and presses open over the Export box. The attribute
// is what a press leaves behind: absent means "whatever the
// column's height calls for", which is what a fresh card and
// a click-away both go back to.
// Whether the title is a control at all is the stylesheet's
// call, not this script's: it becomes one only where the
// column is too short to show the list outright, and the
// caret is the rule that says so. Reading it back keeps the
// two from disagreeing - and stops a stray press collapsing
// a list on a tall window, where there would be no caret
// left to press to bring it back.
function productsIsCollapsible() {
    const caret = document.querySelector('.sidebar-products-caret');
    return !!caret && getComputedStyle(caret).display !== 'none';
}

function productsListOpen() {
    const list = document.getElementById('products');
    return !!list && getComputedStyle(list).display !== 'none';
}

// What a reader can see, not what was last pressed: with no
// attribute the stylesheet decides, so the list's own display
// is the only honest answer either way.
function syncProductsToggle() {
    const toggle = document.getElementById('productsToggle');
    if (!toggle) return;
    toggle.setAttribute('aria-expanded', productsListOpen() ? 'true' : 'false');
}

function setProductsExpanded(state) {
    const card = document.getElementById('productsCard');
    if (!card) return;
    if (state === null) {
        card.removeAttribute('data-expanded');
    } else {
        card.setAttribute('data-expanded', state ? 'true' : 'false');
    }
    syncProductsToggle();
}

// A resize moves the column's height across the threshold
// without anyone pressing anything, so the label has to be
// re-read rather than remembered.
window.addEventListener('resize', function() {
    setTimeout(syncProductsToggle, 0);
});
window.addEventListener('load', syncProductsToggle);

document.addEventListener('click', function(e) {
    const card = document.getElementById('productsCard');
    if (!card) return;
    const toggle = document.getElementById('productsToggle');
    if (toggle && toggle.contains(e.target)) {
        if (productsIsCollapsible()) setProductsExpanded(!productsListOpen());
        return;
    }
    // Clicked away. Only worth acting on while it is holding
    // a state of its own - otherwise every click on the page
    // would be writing the same attribute back.
    if (card.hasAttribute('data-expanded') && !card.contains(e.target)) {
        setProductsExpanded(null);
    }
});

document.addEventListener('keydown', function(e) {
    if (e.key !== 'Escape') return;
    const card = document.getElementById('productsCard');
    if (card && card.hasAttribute('data-expanded')) setProductsExpanded(null);
});

// What the panel is comfortable at, and the least it can be
// and still read as a list rather than a sliver.
// Placed against the viewport, because position: fixed leaves
// the panel with no offsets of its own. Where it goes is
// arithmetic and lives in js/printings-panel.js, where it can
// be tested; this is the DOM half. Measured at open time and
// again on resize: the row it hangs from moves with every
// hovered result, and the room under it moves with the window.
function positionPrintings(container, dropdown) {
    const at = self.PrintingsPanel.placement(
        container.getBoundingClientRect(), window.innerHeight);
    dropdown.style.left = at.left + 'px';
    dropdown.style.width = at.width + 'px';
    dropdown.style.top = at.top + 'px';
    dropdown.style.maxHeight = at.maxHeight + 'px';
}

// Deferred: a resize moves the card too (its cap is in vh), so
// the row this hangs from is still where it was when the event
// fires. Reading it a task later reads where it ended up.
window.addEventListener('resize', function() {
    setTimeout(function() {
        const container = document.getElementById('printings');
        if (!container) return;
        const dropdown = container.querySelector('.sidebar-printings-dropdown.open');
        if (dropdown) positionPrintings(container, dropdown);
    }, 0);
});

// The label says what pressing the button will do, so it has
// to turn over with the panel: left alone, an open panel goes
// on offering to show what is already on screen.
function setTriggerState(trigger, open) {
    trigger.setAttribute('aria-expanded', open ? 'true' : 'false');
    trigger.setAttribute('aria-label',
        (open ? 'Hide ' : 'Show ') + trigger.dataset.count + ' more editions');
}

function collapsePrintings() {
    const container = document.getElementById('printings');
    if (!container) return;

    // A rebuild starts from the markup as it was served, so
    // the note goes back on the row before we decide again
    // whether there is a panel for it to move into. Taken out
    // first: on a rebuild with the panel still open it is a
    // child of that panel, and would go in the bin with it.
    const oldNote = container.querySelector('.sidebar-printings-note');
    if (oldNote) container.appendChild(oldNote);


    // Clean up previous collapse elements
    const oldDropdown = container.querySelector('.sidebar-printings-dropdown');
    if (oldDropdown) oldDropdown.remove();
    const oldTrigger = container.querySelector('.sidebar-printings-more');
    if (oldTrigger) oldTrigger.remove();
    // Unhide any previously hidden links (from prior hover)
    container.querySelectorAll('a.sidebar-printings-hidden').forEach(a => a.classList.remove('sidebar-printings-hidden'));

    const links = Array.from(container.querySelectorAll('a.printing-symbol'));
    if (links.length < PRINTINGS_THRESHOLD + PRINTINGS_MIN_OVERFLOW) return;

    const overflow = links.slice(PRINTINGS_THRESHOLD);
    overflow.forEach(a => a.classList.add('sidebar-printings-hidden'));

    // The panel: the filter on top, the overflow icons under it.
    const dropdown = document.createElement('div');
    dropdown.className = 'sidebar-printings-dropdown';
    // Only ever one panel on the page - the teardown above
    // drops the last one - so the id the button points at
    // stays unique.
    dropdown.id = 'printings-overflow';

    const filter = document.createElement('input');
    filter.type = 'text';
    filter.className = 'sidebar-printings-filter';
    filter.placeholder = 'Filter editions';
    filter.setAttribute('aria-label', 'Filter editions');
    filter.autocomplete = 'off';
    dropdown.appendChild(filter);

    const list = document.createElement('div');
    list.className = 'sidebar-printings-list';
    overflow.forEach(a => {
        const clone = a.cloneNode(true);
        clone.classList.remove('sidebar-printings-hidden');
        list.appendChild(clone);
    });
    dropdown.appendChild(list);

    // The truncation note reads as a footnote to the list it
    // is about, so it travels with it into the panel rather
    // than sitting under the six symbols on the row outside.
    // Moved, not cloned: leaving a copy behind would say
    // there is more to see next to the very row that is not
    // showing it.
    const note = container.querySelector('.sidebar-printings-note');
    if (note) dropdown.appendChild(note);

    // The count is a button that stays the size it reads, so
    // opening the panel does not shove the symbols beside it
    // along the row the way a growing input did.
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.className = 'sidebar-printings-more';
    trigger.textContent = '+' + overflow.length;
    trigger.dataset.count = overflow.length;
    trigger.setAttribute('aria-controls', dropdown.id);
    setTriggerState(trigger, false);
    trigger.addEventListener('click', function() {
        if (dropdown.classList.contains('open')) {
            closePrintings(container);
            return;
        }
        positionPrintings(container, dropdown);
        dropdown.classList.add('open');
        setTriggerState(trigger, true);
        // The filter is the reason the panel opened: take the
        // caret there so a set can be typed without reaching
        // for it. preventScroll because the panel hangs below
        // this row over the boxes underneath: any scrollable
        // ancestor would otherwise "reveal" it by scrolling
        // the column, dragging the card off the top.
        filter.focus({ preventScroll: true });
    });

    filter.addEventListener('input', function() {
        const q = this.value.trim().toLowerCase();
        list.querySelectorAll('a.printing-symbol').forEach(function(a) {
            const title = (a.getAttribute('title') || a.getAttribute('data-ban-title') || '').toLowerCase();
            const href = (a.getAttribute('href') || '').toLowerCase();
            const matches = !q || title.indexOf(q) !== -1 || href.indexOf(q) !== -1;
            a.style.display = matches ? '' : 'none';
        });
    });

    container.appendChild(trigger);
    container.appendChild(dropdown);
}

// The sidebar follows the result under the pointer via mouseenter.
// Pressing a modifier (Cmd/Ctrl) makes the browser re-hit-test
// under the still cursor and fire a phantom `mouseenter` — and
// with the stacked sticky headers that resolves to the pinned
// first card, snapping the panel to the wrong result. Chrome
// fires it with no preceding mousemove; Firefox re-emits a
// same-position mousemove first. Guard against both: require a
// recent *real* (position-changing) move or scroll, and ignore
// any hover glued to a keystroke (the phantom's actual cause).
var __lastMove = 0, __mx = null, __my = null, __lastKey = 0;
// Set while the scroll handler calls a row's handler after
// hit-testing the pointer itself: that update is trusted by
// construction and must not be filtered as a phantom.
var __hoverTrusted = false;
document.addEventListener('mousemove', function(e) {
    if (e.clientX !== __mx || e.clientY !== __my) {
        __mx = e.clientX; __my = e.clientY; __lastMove = performance.now();
    }
}, true);
['wheel', 'scroll'].forEach(function(ev) {
    document.addEventListener(ev, function() { __lastMove = performance.now(); }, true);
});
['keydown', 'keyup'].forEach(function(ev) {
    document.addEventListener(ev, function() { __lastKey = performance.now(); }, true);
});
function hoverSidebar() {
    var now = performance.now();
    if (!__hoverTrusted && (now - __lastMove > 100 || now - __lastKey < 120)) return;
    updateSidebar.apply(null, arguments);
}

// The set value tables render inline in the pinned printings
// slot while the column is tall enough; only when inline
// tables would squeeze the scrolling products list below a
// useful height are they stashed behind the hover trigger.
// Measured by un-stashing and reading the body's flex
// leftover, so it tracks the actual image and table heights.
// The threshold and the rule live in js/printings-panel.js.
function updateSetValueMode() {
    var printings = document.getElementById('printings');
    if (!printings) return;
    printings.classList.remove('setvalue-stashed');
    if (!printings.querySelector('.sidebar-setvalue')) return;
    var sidebar = printings.closest('.search-sidebar');
    var body = sidebar ? sidebar.querySelector('.sidebar-body') : null;
    if (body && self.PrintingsPanel.shouldStashSetValue(body.clientHeight)) {
        printings.classList.add('setvalue-stashed');
    }
}

function updateSidebar(src, printings, products, isFoil, isEtched, setCode, hasWarning, productsCount, releaseDate, cardName) {
    var img = document.getElementById('cardImage');
    var sidebarCardKey = [src || '', isFoil ? 'foil' : '', isEtched ? 'etched' : '', setCode || '', cardName || ''].join('\u001f');
    if (img && img.__sidebarCardKey === sidebarCardKey) return;
    if (img) img.__sidebarCardKey = sidebarCardKey;
    // The sidebar image is reused across hover targets; let a
    // newly assigned source trigger the fallback independently.
    window.setCardArtSource(img, src);
    // The image height feeds the space measurement but only
    // settles on load; resizes move the 52vh cap too.
    if (!img.__setValueHooked) {
        img.__setValueHooked = true;
        img.addEventListener('load', function() {
            updateSetValueMode();
        });
        window.addEventListener('resize', updateSetValueMode);
    }
    var wrapper = document.getElementById('cardImageWrapper');
    if (wrapper) {
        wrapper.setAttribute('data-foil', isFoil ? 'true' : 'false');
        wrapper.setAttribute('data-etched', isEtched ? 'true' : 'false');
        wrapper.setAttribute('data-set', setCode);
        wrapper.setAttribute('data-date', releaseDate || '');
        wrapper.setAttribute('data-name', cardName || '');
        if (hasWarning) {
            wrapper.classList.add('content-warning');
        } else {
            wrapper.classList.remove('content-warning');
        }
    }
    document.getElementById('printings').innerHTML = printings;
    collapsePrintings();
    updateSetValueMode();

    // A different card, so whatever the last one was pressed
    // into does not carry over to a list it was not about.
    setProductsExpanded(null);

    let productDiv = document.getElementById('products');
    if (productDiv) {
        if (products === "") {
            products = "n/a"
        }
        productDiv.innerHTML = products;
    }
    let productCountSpan = document.getElementById('productsCount');
    if (productCountSpan) {
        productCountSpan.textContent = productsCount > 0 ? productsCount : '';
    }
}
