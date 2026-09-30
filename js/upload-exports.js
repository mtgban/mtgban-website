var resExportFields = ["res_download", "res_estimate", "res_deckbox", "res_tcgplayer_csv"];

// The exportable result rows for a category: 'singles', 'sealed', or 'all'
// (both actionable blocks, never the Not Found block).
function exportRows(category) {
    var views = document.querySelector('.ures-views');
    var sel = '.ures-table tr[data-hash]';
    if (!views) {
        // Single-section upload (no sub-tabs): the one rendered table.
        return document.querySelectorAll('#panel-results ' + sel);
    }
    if (category === 'singles') return views.querySelectorAll('.ures-block-singles ' + sel);
    if (category === 'sealed') return views.querySelectorAll('.ures-block-sealed ' + sel);
    return views.querySelectorAll('.ures-block-singles ' + sel + ', .ures-block-sealed ' + sel);
}

function ensureHashesLoaded(category) {
    var form = document.getElementById("upload_form");

    // Always rebuild from current row state so removed/picked rows take effect.
    form.querySelectorAll('input[name="rows"], input[name="hashes"], input[name="hashesQtys"], input[name="hashesCond"], input[name="hashesPrice"], input[name="hashesNotes"]').forEach(function(el) {
        el.remove();
    });

    form.removeAttribute("enctype");

    // One field for the whole list, not five values a row: the form parser
    // counts values and stops at 10,000, handing the server an empty form
    // rather than a short one. Five a row capped an export at 2,000 rows,
    // which a few opened precons pass without trying.
    var lines = [];
    exportRows(category || 'all').forEach(function(row) {
        if (!row.dataset.hash) return;
        if (row.classList.contains('ures-removed-row')) return;
        lines.push(['hash','qtys','cond','price','notes','from','fromqty'].map(function(key) {
            // Tabs and newlines are the separators, and no field this
            // carries is allowed to hold one.
            return (row.dataset[key] || '').replace(/[\t\r\n]+/g, ' ');
        }).join('\t'));
    });

    var input = document.createElement("input");
    input.type = "hidden";
    input.name = "rows";
    input.value = lines.join('\n');
    form.appendChild(input);
}

// Active result view: 'all' | 'singles' | 'sealed' | 'notfound'. Falls back
// to the panel's data-result-view for single-section (untabbed) uploads.
function currentExportView() {
    var views = document.querySelector('.ures-views');
    if (views) return views.getAttribute('data-ures-view');
    var panel = document.getElementById('panel-results');
    return panel ? panel.getAttribute('data-result-view') : 'singles';
}

function runExport(field, category, newWindow) {
    ensureHashesLoaded(category);
    resExportFields.forEach(function(id) {
        document.getElementById(id).value = "";
    });
    document.getElementById("res_" + field).value = "true";
    var scope = document.getElementById("res_csvscope");
    if (scope) {
        scope.value = (field === 'download' && (category === 'singles' || category === 'sealed')) ? category : "";
    }
    var form = document.getElementById("upload_form");
    form.target = newWindow ? '_blank' : '';
    form.submit();
}

// Re-posts the rows on the page with the sealed ones opened. The list is
// read off the page here rather than shipped with it, so a reader who never
// asks carries none of it - and the export fields are cleared, since this
// wants the results page back rather than a file.
function runUnpack() {
    ensureHashesLoaded('all');
    resExportFields.forEach(function(id) {
        document.getElementById(id).value = "";
    });
    var scope = document.getElementById("res_csvscope");
    if (scope) {
        scope.value = "";
    }
    document.getElementById("res_unpack").value = "true";
    var form = document.getElementById("upload_form");
    form.target = '';
    form.submit();
}

// Prices the list the other way round. Only the mode field changes: the
// rows come off the page like every other action here, so nothing has to
// be uploaded again, and the handler still refuses buylist to anyone
// without the grant however this field arrives.
function switchUploadMode() {
    ensureHashesLoaded('all');
    resExportFields.forEach(function(id) {
        document.getElementById(id).value = "";
    });
    var scope = document.getElementById("res_csvscope");
    if (scope) {
        scope.value = "";
    }
    var mode = document.getElementById("res_mode");
    mode.value = mode.value === "true" ? "false" : "true";
    var form = document.getElementById("upload_form");
    form.target = '';
    form.submit();
}

function submitExport(field, newWindow) {
    var view = currentExportView();
    if (view === 'notfound') return; // Not Found is not exportable

    // Get CSV on the All tab splits into two narrow files (singles + sealed)
    // because the categories use disjoint store columns. Everything else
    // exports the active view in one file (All = both combined).
    if (field === 'download' && view === 'all') {
        runExport(field, 'singles', newWindow);
        setTimeout(function() { runExport(field, 'sealed', newWindow); }, 900);
        return;
    }
    runExport(field, view, newWindow);
}

// Hide the singles-only exporters on the Sealed tab, and all of them on
// Not Found.
function updateExportButtons(view) {
    document.querySelectorAll('.res-export-btn').forEach(function(btn) {
        var singlesOnly = btn.hasAttribute('data-singles-only');
        var show = true;
        if (view === 'notfound') show = false;
        else if (view === 'sealed' && singlesOnly) show = false;
        btn.style.display = show ? '' : 'none';
    });
}

// Re-process results with current settings (called by settings save)
window.reprocessUploadResults = function() {
    ensureHashesLoaded('all');
    syncUploadOptionsFromSettings();
    resExportFields.forEach(function(id) {
        document.getElementById(id).value = "";
    });
    // Flag this as a reload so the page keeps the current view
    try { sessionStorage.setItem('uploadReload', '1'); } catch (e) {}
    document.getElementById("upload_form").submit();
};

document.addEventListener('DOMContentLoaded', function() {
    updateExportButtons(currentExportView());
});
