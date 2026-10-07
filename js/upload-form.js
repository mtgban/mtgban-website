function enabledButtons() {
    const fields = [
        'submit_default', 'submit_download', 'submit_estimate', 'submit_deckbox', 'submit_tcgplayer_csv'
    ];

    fields.forEach(element => {
        var btn = document.getElementById(element);
        if (btn) {
            btn.disabled = false;
        }
    });
}

// Bulk select / clear for the currently visible store box only
// (the active Singles or Sealed tab, in the current Retail/
// Buylist mode). The other tab's box carries .upload-store-hidden,
// so :not(.upload-store-hidden) targets just the visible one and
// leaves the hidden tab's selections untouched.
// dispatchFormChange tells upload-presets.js something changed, since the
// callers below set state directly and never fire a native change event.
// storesChanged marks a change that came from the store grids themselves
// (Select all / Clear / only / exclude), so upload-presets.js knows to
// persist it; a plain tab switch does not, so it stays just a re-render.
function dispatchFormChange(storesChanged) {
    var form = document.getElementById('upload_form');
    if (!form) return;
    if (storesChanged) {
        form.dispatchEvent(new CustomEvent('change', { bubbles: true, detail: { stores: true } }));
    } else {
        form.dispatchEvent(new Event('change', { bubbles: true }));
    }
}

window.setVisibleStores = function(checked) {
    var box = document.querySelector('.upload-store-grid:not(.upload-store-hidden)');
    if (!box) return;
    box.querySelectorAll('input[type="checkbox"]').forEach(function(cb) {
        if (!cb.disabled) cb.checked = checked;
    });
    dispatchFormChange(true);
};

// "only" affordance on each store: check this store, uncheck the
// rest — scoped to the store's own grid box so the other tab's
// stores (e.g. sealed while on singles) are left untouched.
//
// After firing "only", the same control flips to "exclude" while
// the pointer stays on the row: clicking it then selects every
// OTHER store (this one off). Leaving the row resets it back to
// "only" for next time. Checkboxes are rebuilt by reloadSelect,
// so use click delegation.
document.addEventListener('click', function(e) {
    var only = e.target.closest('.upload-store-only');
    if (!only) return;
    // Inside a <label>, so stop the default checkbox toggle.
    e.preventDefault();
    e.stopPropagation();
    var item = only.closest('.upload-store-item');
    var box = only.closest('.upload-store-grid');
    if (!item || !box) return;
    var target = item.querySelector('input[type="checkbox"]');
    if (!target || target.disabled) return;

    var isExclude = only.dataset.mode === 'exclude';
    box.querySelectorAll('input[type="checkbox"]').forEach(function(cb) {
        if (cb.disabled) return;
        // only: this on, rest off.  exclude: this off, rest on.
        cb.checked = isExclude ? (cb !== target) : (cb === target);
    });

    function toOnly() {
        only.textContent = 'only';
        only.dataset.mode = 'only';
        only.title = 'Select only this store';
    }
    function toExclude() {
        only.textContent = 'exclude';
        only.dataset.mode = 'exclude';
        only.title = 'Select every other store';
    }
    // Flip the affordance to the inverse action for the next click.
    if (isExclude) { toOnly(); } else { toExclude(); }
    dispatchFormChange(true);

    // Reset to plain "only" once the pointer leaves the row. Guard
    // against binding more than one pending reset during ping-pong.
    if (!item.dataset.resetBound) {
        item.dataset.resetBound = '1';
        item.addEventListener('mouseleave', function () {
            toOnly();
            delete item.dataset.resetBound;
        }, { once: true });
    }
});

// Re-ticks a store grid from its persisted cookie after reloadSelect rebuilds
// it from the page-load snapshot (window.BAN_UPLOAD_FORM), which otherwise
// shows stale ticks once a preset or a prior mode switch changed the cookie.
// An empty or missing cookie means defaults, so the server-rendered ticks
// are left alone.
function retickFromCookie(boxId, cookieName) {
    if (typeof getCookie !== 'function') return;
    var raw = getCookie(cookieName);
    if (!raw) return;
    var want = raw.split('|').filter(Boolean);
    var box = document.getElementById(boxId);
    if (!box) return;
    box.querySelectorAll('input[type="checkbox"]').forEach(function(cb) {
        if (!cb.disabled) cb.checked = want.indexOf(cb.value) >= 0;
    });
}

window.reloadSelect = function(mode) {
    localStorage.setItem("uploadMode", mode);
    const fields = [
        'submit_download', 'submit_estimate', 'submit_deckbox', 'submit_tcgplayer_csv'
    ];
    var singlesBox = document.getElementById('singlesBox');
    if (singlesBox) {
        if (mode == "buylist") {
            singlesBox.innerHTML = window.BAN_UPLOAD_FORM.vendors;
        } else {
            singlesBox.innerHTML = window.BAN_UPLOAD_FORM.sellers;
        }
        fields.forEach(element => {
            var btn = document.getElementById(element);
            if (btn) { btn.style.display = "inline"; }
        });
        retickFromCookie('singlesBox', mode == "buylist" ? 'enabledVendors' : 'enabledSellers');
    }
    var sealedBox = document.getElementById('sealedBox');
    if (sealedBox) {
        if (mode == "buylist") {
            sealedBox.innerHTML = window.BAN_UPLOAD_FORM.sealedVendors;
        } else {
            sealedBox.innerHTML = window.BAN_UPLOAD_FORM.sealedSellers;
        }
        if (!sealedBox.querySelector('input')) {
            sealedBox.innerHTML = "<span class='upload-mode-hint'>No sealed stores available for this mode.</span>";
        } else {
            retickFromCookie('sealedBox', mode == "buylist" ? 'enabledSealedVendors' : 'enabledSealedSellers');
        }
    }
};

window.selectTab = function(tab) {
    var isSealed = (tab === 'sealed');
    document.getElementById('tab-singles').classList.toggle('active', !isSealed);
    document.getElementById('tab-sealed').classList.toggle('active', isSealed);
    var singlesBox = document.getElementById('singlesBox');
    var sealedBox = document.getElementById('sealedBox');
    var sealedNote = document.getElementById('sealedNote');
    var singlesIndexRow = document.getElementById('singlesIndexRow');
    var sealedIndexRow = document.getElementById('sealedIndexRow');
    if (singlesBox) singlesBox.classList.toggle('upload-store-hidden', isSealed);
    if (sealedBox) sealedBox.classList.toggle('upload-store-hidden', !isSealed);
    if (singlesIndexRow) singlesIndexRow.classList.toggle('upload-store-hidden', isSealed);
    if (sealedIndexRow) sealedIndexRow.classList.toggle('upload-store-hidden', !isSealed);
    if (sealedNote) sealedNote.classList.toggle('upload-store-hidden', !isSealed);
    try { localStorage.setItem('uploadTab', tab); } catch(e) {}
    dispatchFormChange();
};

// A file dropped anywhere on the page is picked up, not just over
// the file drop zone - the reader may still be on the URL or Text
// tab, and pressed() already switches source to 'file' as part of
// handling a selection, so routing every drop through the input
// and that same handler covers the mode switch for free.
(function() {
    var counter = 0;
    var previousSource = null;
    var defaultFileLabel = document.getElementById('fileLabel') ? document.getElementById('fileLabel').innerHTML : '';
    function hasFiles(e) {
        return !!(e.dataTransfer && Array.prototype.indexOf.call(e.dataTransfer.types || [], 'Files') !== -1);
    }
    function activeSourceArea() {
        var ids = ['source-file', 'source-url', 'source-text'];
        for (var i = 0; i < ids.length; i++) {
            var el = document.getElementById(ids[i]);
            if (el && !el.classList.contains('upload-source-hidden')) return el;
        }
        return null;
    }
    function activeSourceType() {
        var btn = document.querySelector('.upload-source-btn.active');
        return btn ? btn.id.replace('src-btn-', '') : null;
    }
    // Browsing via the dialog is already constrained to this list
    // by the input's own accept attribute; a drop bypasses that
    // natively, so it's re-applied here by hand. Server-side
    // rejection remains the real backstop either way.
    function acceptedFile(fileInput, file) {
        var accept = (fileInput.getAttribute('accept') || '').split(',')
            .map(function(s) { return s.trim().toLowerCase(); }).filter(Boolean);
        if (!accept.length) return true;
        var name = (file.name || '').toLowerCase();
        var type = (file.type || '').toLowerCase();
        for (var i = 0; i < accept.length; i++) {
            var a = accept[i];
            if (a.charAt(0) === '.' ? name.slice(-a.length) === a : type === a) return true;
        }
        return false;
    }
    function rejectFile(file) {
        var label = document.getElementById('fileLabel');
        var area = document.getElementById('source-file');
        if (!label) return;
        var message = '"' + file.name + '" is not a CSV, TXT, XLS or XLSX file';
        label.textContent = message;
        if (area) area.classList.add('drag-rejected');
        setTimeout(function() {
            if (label.textContent === message) label.innerHTML = defaultFileLabel;
            if (area) area.classList.remove('drag-rejected');
        }, 2500);
    }
    document.addEventListener('dragenter', function(e) {
        if (!hasFiles(e)) return;
        e.preventDefault();
        // Preview the eventual outcome as soon as a file crosses
        // into the page, rather than highlighting whichever of
        // URL/Text happens to be open right up until the drop
        // itself switches it. Remembered so dragging back out
        // without dropping can put the reader back where they
        // were instead of leaving them stranded on File.
        if (counter === 0) {
            var current = activeSourceType();
            previousSource = current === 'file' ? null : current;
            selectSource('file');
        }
        counter++;
        var area = activeSourceArea();
        if (area) area.classList.add('drag-over');
    });
    document.addEventListener('dragover', function(e) {
        if (hasFiles(e)) e.preventDefault();
    });
    document.addEventListener('dragleave', function(e) {
        if (!hasFiles(e)) return;
        counter--;
        if (counter <= 0) {
            counter = 0;
            var area = activeSourceArea();
            if (area) area.classList.remove('drag-over');
            // The drag left without a drop - back to whichever
            // tab was open before the preview switched it.
            if (previousSource) selectSource(previousSource);
            previousSource = null;
        }
    });
    document.addEventListener('drop', function(e) {
        if (!hasFiles(e)) return;
        e.preventDefault();
        counter = 0;
        previousSource = null;
        var area = activeSourceArea();
        if (area) area.classList.remove('drag-over');

        var fileInput = document.getElementById('file');
        var dropped = e.dataTransfer.files;
        if (!fileInput || !dropped || !dropped.length) return;

        var file = dropped[0];
        if (!acceptedFile(fileInput, file)) {
            rejectFile(file);
            return;
        }

        var transfer = new DataTransfer();
        transfer.items.add(file);
        fileInput.files = transfer.files;
        pressed();
    });
})();

window.autoGrowTextArea = function(el) {
    el.style.height = 'auto';
    el.style.height = el.scrollHeight + 'px';
};

window.selectSource = function(type) {
    document.querySelectorAll('.upload-source-btn').forEach(b => b.classList.remove('active'));
    document.getElementById('src-btn-' + type).classList.add('active');
    ['file', 'url', 'text'].forEach(t => {
        var area = document.getElementById('source-' + t);
        if (area) {
            if (t === type) {
                area.classList.remove('upload-source-hidden');
            } else {
                area.classList.add('upload-source-hidden');
            }
        }
    });
    if (type === 'text') {
        enabledButtons();
    }
    // Remember the selected source mode
    try { localStorage.setItem('uploadSourceMode', type); } catch(e) {}
};

window.pressed = function() {
    var label = document.getElementById('file');
    if (label.value != "") {
        var theSplit = label.value.split('\\');
        document.getElementById('fileLabel').textContent = theSplit[theSplit.length - 1];
        document.getElementById('gdocURL').value = "";
        var textArea = document.getElementById('textArea');
        if (textArea) { textArea.value = ""; }
        try { localStorage.removeItem('uploadTextArea'); } catch(e) {}
        const form = document.getElementById("upload_form");
        form.querySelectorAll('input[name="hashes"]').forEach(el => el.remove());
        selectSource('file');
        enabledButtons();
        document.getElementById('clearFileBtn').style.display = 'block';
    }
};

window.clearFile = function() {
    var input = document.getElementById('file');
    input.value = '';
    document.getElementById('fileLabel').innerHTML = 'Drop file here or <span class="upload-browse-link">browse</span><span class="upload-file-hint">CSV, TXT, XLS, XLSX - max 5MB</span>';
    document.getElementById('clearFileBtn').style.display = 'none';
    enabledButtons();
};

window.onload = (event) => {
    var textArea = document.getElementById('textArea');
    if (textArea) {
        var savedText = localStorage.getItem('uploadTextArea') || '';
        textArea.value = savedText;
    }
    var savedMode = localStorage.getItem("uploadMode");
    if (savedMode === "buylist" || savedMode === "retail") {
        var radio = document.getElementById(savedMode);
        if (radio && !radio.disabled) {
            radio.checked = true;
        } else {
            savedMode = "retail";
        }
    } else {
        savedMode = window.BAN_UPLOAD_FORM.buylist ? "buylist" : "retail";
    }
    reloadSelect(savedMode);

    var savedTab = localStorage.getItem("uploadTab");
    selectTab(savedTab === "sealed" ? "sealed" : "singles");
    if (window.UploadPresets) window.UploadPresets.mount(document);

    var gdocInput = document.getElementById('gdocURL');
    if (gdocInput) {
        // Fires on any change (paste OR typing). Clearing
        // already-empty fields is a no-op, so it's safe to
        // run on every keystroke after the first.
        gdocInput.addEventListener('input', function() {
            if (!this.value.trim()) return;
            var fileInput = document.getElementById('file');
            if (fileInput) fileInput.value = "";
            document.getElementById('fileLabel').innerHTML = 'Drop file here or <span class="upload-browse-link">browse</span><span class="upload-file-hint">CSV, TXT, XLS, XLSX - max 5MB</span>';
            document.getElementById('clearFileBtn').style.display = 'none';
            var ta = document.getElementById('textArea');
            if (ta) ta.value = "";
            try { localStorage.removeItem('uploadTextArea'); } catch(e) {}
            const form = document.getElementById("upload_form");
            form.querySelectorAll('input[name="hashes"]').forEach(el => el.remove());
            selectSource('url');
            enabledButtons();
        });
    }

    var textAreaEl = document.getElementById('textArea');
    if (textAreaEl) {
        textAreaEl.addEventListener('input', function() {
            if (!this.value.trim()) {
                enabledButtons();
                return;
            }
            // Symmetric with the URL/file handlers: any
            // content here means text is the active source,
            // so clear URL + file. localStorage stays
            // populated via the inline oninput attribute on
            // the textarea — the user's typed text is the
            // payload we want to remember.
            var urlInput = document.getElementById('gdocURL');
            if (urlInput) urlInput.value = "";
            var fileInput = document.getElementById('file');
            if (fileInput) fileInput.value = "";
            document.getElementById('fileLabel').innerHTML = 'Drop file here or <span class="upload-browse-link">browse</span><span class="upload-file-hint">CSV, TXT, XLS, XLSX - max 5MB</span>';
            document.getElementById('clearFileBtn').style.display = 'none';
            const form = document.getElementById("upload_form");
            form.querySelectorAll('input[name="hashes"]').forEach(el => el.remove());
            selectSource('text');
            enabledButtons();
        });
    }
};
