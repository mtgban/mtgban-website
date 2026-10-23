document.querySelectorAll('.opt-table').forEach(function(t) {
    var sorter = new Tablesort(t);
    t.addEventListener('beforeSort', function() {
        sorter.options.descending = sorter.current.getAttribute('data-sort-descending') === 'true';
    });
});

// optTableOut takes the card art down when the pointer leaves a table's
// rows, out of the table or up into the store header pinned in its head.
function optTableOut(table, event) {
    var to = event.relatedTarget;
    var rows = table.tBodies[0];
    if (to && rows && rows.contains(to)) return;
    window.setCardArtSource(document.getElementById('hoverImage'), window.cardArtPlaceholder);
    var hw = document.getElementById('hoverWrap');
    hw.setAttribute('data-foil', 'false');
    hw.setAttribute('data-etched', 'false');
}

function toggleOptRow(checkbox) {
    var row = checkbox.closest('tr');
    if (!row) return;
    if (checkbox.checked) {
        row.classList.remove('opt-removed');
    } else {
        row.classList.add('opt-removed');
    }
}

function toggleAllOptRows(masterCheckbox) {
    var table = masterCheckbox.closest('table');
    if (!table) return;
    table.querySelectorAll('.opt-row-check').forEach(function(cb) {
        cb.checked = masterCheckbox.checked;
        toggleOptRow(cb);
    });
}

// updateOptTotals recounts a store's cards, copies and total from the rows
// still ticked, in its header and in its entry in the list above the stores.
function updateOptTotals(section) {
    var cards = 0;
    var qty = 0;
    var total = 0;
    section.querySelectorAll('tr[data-load-idx]').forEach(function(tr) {
        if (tr.classList.contains('opt-removed')) return;
        var q = parseInt(tr.dataset.loadQty, 10) || 1;
        cards++;
        qty += q;
        total += (parseFloat(tr.dataset.optPrice) || 0) * q;
    });
    // As the template's plural writes it
    var stats = cards + (cards === 1 ? ' card' : ' cards') + (qty !== cards ? ' (' + qty + ' total)' : '');
    var sum = '$ ' + total.toFixed(2);

    var places = [[section.querySelector('.opt-count'), section.querySelector('.opt-total')]];
    document.querySelectorAll('.opt-toc-item').forEach(function(item) {
        if (item.getAttribute('href') === '#' + section.id) {
            places.push([item.querySelector('.toc-stats'), item.querySelector('.toc-total')]);
        }
    });
    places.forEach(function(p) {
        if (p[0]) p[0].textContent = stats;
        if (p[1]) p[1].textContent = sum;
    });
}

// After the row's own handler has marked it, as wireLoadLists does
document.addEventListener('change', function(e) {
    var section = e.target.closest && e.target.closest('.opt-store');
    if (section) {
        updateOptTotals(section);
    }
});

wireLoadLists({section: '.opt-store', removed: 'opt-removed'});
