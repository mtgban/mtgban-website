document.querySelectorAll('.opt-table').forEach(function(t) {
    var sorter = new Tablesort(t);
    t.addEventListener('beforeSort', function() {
        sorter.options.descending = sorter.current.getAttribute('data-sort-descending') === 'true';
    });
});

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
