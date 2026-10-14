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

wireLoadLists({section: '.opt-store', removed: 'opt-removed'});
