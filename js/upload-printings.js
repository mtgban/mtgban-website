var fixedRows = {};
var removedRows = {};
var activePicker = null;

function updateReloadBar() {
    var fixedCount = Object.keys(fixedRows).length;
    var removedCount = Object.keys(removedRows).length;
    var total = fixedCount + removedCount;
    document.getElementById('reload-fixed-count').textContent = fixedCount;
    document.getElementById('reload-removed-count').textContent = removedCount;
    document.getElementById('reload-fixed-wrap').style.display = fixedCount > 0 ? '' : 'none';
    document.getElementById('reload-removed-wrap').style.display = removedCount > 0 ? '' : 'none';
    document.getElementById('reload-bar').style.display = total > 0 ? 'flex' : 'none';
}

function rowOriginId(row) {
    if (!row.dataset.origHash) row.dataset.origHash = row.dataset.hash;
    return row.dataset.origHash;
}

function toggleRemoveRow(btn) {
    var row = btn.closest('tr');
    if (!row || !row.dataset.hash) return;
    var rowId = rowOriginId(row);
    if (row.classList.contains('ures-removed-row')) {
        row.classList.remove('ures-removed-row');
        delete removedRows[rowId];
    } else {
        row.classList.add('ures-removed-row');
        removedRows[rowId] = true;
    }
    updateReloadBar();
}

function updateRowHash(btn, newHash) {
    var form = document.getElementById("upload_form");
    var oldHash = btn.dataset.hash;

    ensureHashesLoaded();

    // Swap the hash on the row, which is where the form is rebuilt from
    // when it is submitted - there is no per-row input left to edit.
    btn.dataset.hash = newHash;
    btn.closest('tr').dataset.hash = newHash;

    // Mark the row as fixed
    btn.closest('tr').classList.add('ures-fixed-row');
    btn.closest('tr').classList.remove('ures-alias-row');

    // Track the fix - only count each original row once
    var rowId = btn.closest('tr').dataset.origHash || oldHash;
    if (!btn.closest('tr').dataset.origHash) {
        btn.closest('tr').dataset.origHash = oldHash;
    }
    fixedRows[rowId] = true;
    updateReloadBar();
}

// Metadata from Go template - maps UUID to {image, edition, number}
var cardMeta = window.BAN_UPLOAD_PRINTINGS.cards;

function openPrintingPicker(btn) {
    activePicker = btn;
    var currentHash = btn.dataset.hash;
    var aliases = btn.dataset.aliases.split(",").filter(Boolean);
    var grid = document.getElementById("printing-picker-grid");
    grid.innerHTML = "";

    aliases.forEach(function(uuid) {
        var meta = cardMeta[uuid];
        if (!meta) return;
        var card = document.createElement("div");
        card.className = "printing-picker-card" + (uuid === currentHash ? " selected" : "");
        var cardImg = document.createElement("img");
        cardImg.src = meta.image;
        cardImg.loading = "lazy";
        card.appendChild(cardImg);
        var metaDiv = document.createElement("div");
        metaDiv.className = "pp-meta";
        metaDiv.textContent = meta.edition;
        card.appendChild(metaDiv);
        var setDiv = document.createElement("div");
        setDiv.className = "pp-set";
        setDiv.textContent = "#" + meta.number;
        card.appendChild(setDiv);
        card.addEventListener("click", function() {
            updateRowHash(activePicker, uuid);
            // Update thumbnail and set info in the row
            var row = activePicker.closest('tr');
            var img = row.querySelector('.ures-card-cell img');
            var setSpan = row.querySelector('.ures-card-set');
            if (img) window.setCardArtSource(img, meta.image);
            if (setSpan) setSpan.textContent = meta.edition + ' \u00B7 #' + meta.number;
            closePrintingPicker();
        });
        grid.appendChild(card);
    });

    document.getElementById("printing-overlay").classList.add("open");
}

function closePrintingPicker() {
    document.getElementById("printing-overlay").classList.remove("open");
    activePicker = null;
}

document.addEventListener("keydown", function(e) {
    if (e.key === "Escape") closePrintingPicker();
});
