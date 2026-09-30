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

// Collect active (non-removed) rows from the optimizer table
function getActiveOptRows(section) {
    var rows = [];
    section.querySelectorAll('tr[data-opt-id]:not(.opt-removed)').forEach(function(row) {
        rows.push({
            id: row.dataset.optId,
            qty: row.dataset.optQty || '1',
            cond: row.dataset.optCond || '',
            name: row.dataset.optName || '',
            ckid: row.dataset.optCkid || ''
        });
    });
    return rows;
}

// Rebuild form inputs/values from active rows before submission
function filterOptForm(form) {
    var section = form.closest('.opt-store');
    if (!section) return;
    var active = getActiveOptRows(section);
    var allRows = section.querySelectorAll('tr[data-opt-id]');
    // If nothing was removed, skip
    if (active.length === allRows.length) return;

    // For forms with a "json" input (CK buylist), rebuild the JSON
    var jsonInput = form.querySelector('input[name="json"]');
    if (jsonInput) {
        var contents = active.map(function(r) {
            return '{"id":' + r.ckid + ',"qty":' + r.qty + '}';
        });
        jsonInput.value = '{"contents":[' + contents.join(',') + ',{}]}';
        return;
    }

    // For forms with a "c" input (CK deckbuilder, TCG massentry), rebuild
    var cInput = form.querySelector('input[name="c"]');
    if (cInput) {
        var val = active.map(function(r) { return r.qty + ' ' + r.name + '||'; }).join('');
        cInput.value = val;
        return;
    }

    // For per-entry forms (hashes), disable removed inputs
    var removed = {};
    section.querySelectorAll('tr.opt-removed').forEach(function(row) {
        if (row.dataset.optId) removed[row.dataset.optId] = true;
    });
    var inputs = form.querySelectorAll('input[type="hidden"]');
    var skip = false;
    for (var i = 0; i < inputs.length; i++) {
        var inp = inputs[i];
        if (inp.name && inp.name.match(/hashes$/)) {
            skip = removed[inp.value] || false;
        }
        if (skip) inp.disabled = true;
    }
}

// Intercept clicks on optimizer action buttons
document.addEventListener('click', function(e) {
    var btn = e.target.closest('.opt-btn');
    if (!btn) return;
    var form = btn.closest('form');
    if (form) filterOptForm(form);
}, true);
