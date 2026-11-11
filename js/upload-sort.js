// Sorts a results or optimizer table by the column whose header was clicked.
// The rows move on the page itself: the exports read them back off the page
// in the order they stand (upload-exports.js), so a CSV follows the order
// shown.

// What a cell sorts by: its data-sort, else its text. A cell with nothing
// to sort by goes last whichever way the column is sorted.
function uresSortKey(cell, numeric) {
    if (!cell) return null;
    var raw = cell.hasAttribute('data-sort') ? cell.getAttribute('data-sort') : cell.textContent;
    raw = (raw || '').trim();
    if (raw === '') return null;
    if (!numeric) return raw.toLowerCase();
    var n = parseFloat(raw.replace(/[^0-9.+-]/g, ''));
    return isNaN(n) ? null : n;
}

// The rows in the column's order: missing values last either way, ties in
// the order they had.
function uresSortedRows(rows, col, numeric, descending) {
    var keyed = rows.map(function(row, i) {
        return {row: row, key: uresSortKey(row.cells[col], numeric), index: i};
    });
    keyed.sort(function(a, b) {
        if (a.key === null || b.key === null) {
            if (a.key === b.key) return a.index - b.index;
            return a.key === null ? 1 : -1;
        }
        var c = numeric ? a.key - b.key : a.key.localeCompare(b.key, undefined, {numeric: true});
        if (descending) c = -c;
        return c || a.index - b.index;
    });
    return keyed.map(function(k) { return k.row; });
}

// Sorts the header's table by its column. The first click goes the way the
// header asks (data-sort-descending, bare or "true"), each one after turns
// it round. A row marked data-sort-method="none", the totals, keeps the end
// of the table.
function uresSortBy(th) {
    var table = th.closest('table');
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var numeric = th.getAttribute('data-sort-method') === 'number';
    var was = th.getAttribute('aria-sort');
    var first = th.getAttribute('data-sort-descending');
    var descending = was ? was === 'ascending' : first !== null && first !== 'false';

    var entries = [], rest = [];
    Array.prototype.forEach.call(tbody.rows, function(row) {
        (row.getAttribute('data-sort-method') === 'none' ? rest : entries).push(row);
    });
    uresSortedRows(entries, th.cellIndex, numeric, descending).concat(rest).forEach(function(row) {
        tbody.appendChild(row);
    });

    // The header's own row: an optimizer table heads it with its store
    Array.prototype.forEach.call(th.parentNode.cells, function(cell) {
        cell.removeAttribute('aria-sort');
    });
    th.setAttribute('aria-sort', descending ? 'descending' : 'ascending');

    // The optimizer's load lists follow the rows (load-lists.js)
    table.dispatchEvent(new Event('rowsmoved', {bubbles: true}));
}

document.addEventListener('DOMContentLoaded', function() {
    document.querySelectorAll('.ures-table thead th, .opt-table thead th').forEach(function(th) {
        if (th.getAttribute('data-sort-method') === 'none') return;
        th.setAttribute('tabindex', '0');
        th.addEventListener('click', function() { uresSortBy(th); });
        th.addEventListener('keydown', function(e) {
            if (e.key !== 'Enter' && e.key !== ' ') return;
            e.preventDefault();
            uresSortBy(th);
        });
    });
});
