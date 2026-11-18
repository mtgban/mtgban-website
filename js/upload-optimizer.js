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
// still ticked, in its header and in its entry in the list above the stores,
// and takes its share button away when none is left to share.
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
    var share = section.querySelector('.opt-share-btn');
    if (share) share.hidden = !cards;
}

// After the row's own handler has marked it, as wireLoadLists does
document.addEventListener('change', function(e) {
    var section = e.target.closest && e.target.closest('.opt-store');
    if (section) {
        updateOptTotals(section);
        saveOptUnticked();
        var t = e.target;
        if (t.classList && t.classList.contains('opt-row-check')) {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.optimizer', 'row_check');
        } else if (t.type === 'checkbox' && t.closest('.opt-store thead')) {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.optimizer', 'check_all');
        }
    }
});

wireLoadLists({section: '.opt-store', removed: 'opt-removed'});

// The unticked rows, by card, condition and store, are kept in the tab's
// session so a reload of the page (a move, a store dropped or added, the
// Reload button or the browser's) unticks them again; a new list starts ticked.
function optRowKey(tr) {
    var section = tr.closest('.opt-store');
    return tr.dataset.optId + '\t' + (tr.dataset.optCond || '') + '\t' + section.id.replace(/^opt-/, '');
}

function saveOptUnticked() {
    var keys = [];
    document.querySelectorAll('.opt-store tr.opt-removed[data-opt-id]').forEach(function(tr) {
        keys.push(optRowKey(tr));
    });
    try {
        if (keys.length) sessionStorage.setItem('uploadOptUnticked', JSON.stringify(keys));
        else sessionStorage.removeItem('uploadOptUnticked');
    } catch (e) {}
}

// Unticks the rows kept from before the reload, then has each section they
// sit in recount its totals and rebuild its lists, as a change does.
function restoreOptUnticked() {
    var keys = null;
    try {
        if (window.BAN_UPLOAD_RELOAD) keys = JSON.parse(sessionStorage.getItem('uploadOptUnticked') || 'null');
        else sessionStorage.removeItem('uploadOptUnticked');
    } catch (e) {}
    if (!Array.isArray(keys) || !keys.length) return;
    var unticked = {};
    keys.forEach(function(k) { unticked[k] = true; });
    document.querySelectorAll('.opt-store').forEach(function(section) {
        var any = false;
        var ticked = false;
        section.querySelectorAll('tr[data-opt-id]').forEach(function(tr) {
            var cb = tr.querySelector('.opt-row-check');
            if (cb && unticked[optRowKey(tr)]) {
                cb.checked = false;
                toggleOptRow(cb);
                any = true;
            } else if (cb) {
                ticked = true;
            }
        });
        if (!any) return;
        var all = section.querySelector('thead input[type="checkbox"]');
        if (all) all.checked = ticked;
        section.dispatchEvent(new Event('change', {bubbles: true}));
    });
}

// A row's Move to menu is built when it opens, from the row's data-move:
// the page's other stores that offer for the card, best first. It opens
// under its button, or over it in the lower part of the window, and closes
// on a pick or on a scroll, which would leave it behind its row.
document.addEventListener('beforetoggle', function(e) {
    var menu = e.target;
    if (!menu.classList || !menu.classList.contains('opt-move-menu') || e.newState !== 'open') return;
    var btn = document.querySelector('[popovertarget="' + menu.id + '"]');
    if (!btn) return;
    fillMoveMenu(menu, btn.closest('tr'));
    var r = btn.getBoundingClientRect();
    menu.style.right = Math.max(8, window.innerWidth - r.right) + 'px';
    if (r.bottom > window.innerHeight * 0.6) {
        menu.style.top = 'auto';
        menu.style.bottom = (window.innerHeight - r.top + 4) + 'px';
    } else {
        menu.style.top = (r.bottom + 4) + 'px';
        menu.style.bottom = 'auto';
    }
}, true);

function fillMoveMenu(menu, row) {
    var names = window.BAN_OPT_STORE_NAMES || {};
    menu.textContent = '';
    var title = document.createElement('div');
    title.className = 'opt-move-title';
    title.textContent = 'Move to';
    menu.appendChild(title);
    (row.dataset.move || '').split(',').forEach(function(pair) {
        var at = pair.lastIndexOf(':');
        if (at <= 0) return;
        var store = pair.slice(0, at);
        menu.appendChild(moveMenuItem(names[store] || store, '$ ' + pair.slice(at + 1), store));
    });
    if (row.hasAttribute('data-opt-moved')) {
        menu.appendChild(moveMenuItem('Let the optimizer place it', '', ''));
    }
}

function moveMenuItem(label, price, store) {
    var item = document.createElement('button');
    item.type = 'button';
    item.dataset.store = store;
    item.appendChild(document.createTextNode(label));
    if (price) {
        var span = document.createElement('span');
        span.textContent = price;
        item.appendChild(span);
    }
    return item;
}

// moveOptRow puts the row's card in store whatever the optimizer's rules
// say, or back in the optimizer's hands when store is empty, and prices the
// list again, landing back on the card. The move is the page's alone: the
// next re-post carries it (ensureHashesLoaded) and nothing stores it.
function moveOptRow(row, store) {
    var id = row.dataset.optId;
    var cond = row.dataset.optCond || '';
    document.querySelectorAll('.opt-store tr[data-opt-moved]').forEach(function(tr) {
        if (tr.dataset.optId === id && (tr.dataset.optCond || '') === cond) {
            tr.removeAttribute('data-opt-moved');
        }
    });
    if (store) row.setAttribute('data-opt-moved', store);
    if (window.BAN && window.BAN.track) {
        if (store) window.BAN.track('ui.optimizer', 'row_move');
        else window.BAN.track('ui.optimizer', 'row_unmove');
    }
    try {
        sessionStorage.setItem('uploadOptFocus', id + '\t' + cond);
        sessionStorage.setItem('uploadResView', 'optimizer');
    } catch (e) {}
    if (window.reprocessUploadResults) reprocessUploadResults();
}

document.addEventListener('click', function(e) {
    var pick = e.target.closest && e.target.closest('.opt-move-menu button');
    if (pick) {
        var menu = pick.closest('.opt-move-menu');
        var btn = document.querySelector('[popovertarget="' + menu.id + '"]');
        menu.hidePopover();
        if (btn) moveOptRow(btn.closest('tr'), pick.dataset.store);
    }
    if (e.target.closest && e.target.closest('.opt-copy')) {
        if (window.BAN && window.BAN.track) window.BAN.track('ui.optimizer', 'copy_name');
    }
});

// Captured, so a scroll inside any container closes it too
document.addEventListener('scroll', function() {
    document.querySelectorAll('.opt-move-menu:popover-open').forEach(function(menu) {
        menu.hidePopover();
    });
}, {capture: true, passive: true});

// After a move the page lands back on the card, in the store it went to.
// Run after upload-tabs.js has opened the optimizer.
document.addEventListener('DOMContentLoaded', function() {
    restoreOptUnticked();
    var key = null;
    try {
        key = sessionStorage.getItem('uploadOptFocus');
        sessionStorage.removeItem('uploadOptFocus');
    } catch (e) {}
    if (!key) return;
    var parts = key.split('\t');
    var rows = document.querySelectorAll('.opt-store tr[data-opt-id]');
    for (var i = 0; i < rows.length; i++) {
        if (rows[i].dataset.optId === parts[0] && (rows[i].dataset.optCond || '') === parts[1]) {
            rows[i].scrollIntoView({block: 'center'});
            rows[i].classList.add('opt-move-landed');
            return;
        }
    }
});

// resubmitOptStores prices the rows on the page again against these stores,
// back on the optimizer. The list goes the way the exports send it.
function resubmitOptStores(stores, sealed) {
    ensureHashesLoaded('all');
    resExportFields.forEach(function(id) {
        document.getElementById(id).value = "";
    });
    var scope = document.getElementById("res_csvscope");
    if (scope) scope.value = "";
    var form = document.getElementById("upload_form");
    form.querySelectorAll('input[name="stores"], input[name="sealed_stores"]').forEach(function(el) {
        el.remove();
    });
    [['stores', stores], ['sealed_stores', sealed]].forEach(function(field) {
        field[1].forEach(function(key) {
            var input = document.createElement("input");
            input.type = "hidden";
            input.name = field[0];
            input.value = key;
            form.appendChild(input);
        });
    });
    try {
        sessionStorage.setItem('uploadReload', '1');
        sessionStorage.setItem('uploadResView', 'optimizer');
    } catch (e) {}
    form.target = '';
    if (window.showUploadProcessing) showUploadProcessing();
    form.submit();
}

function optStores() {
    var picked = window.BAN_OPT_STORES || {};
    return {stores: (picked.stores || []).slice(), sealed: (picked.sealed || []).slice()};
}

// dropOptStore prices the list again without the button's store.
function dropOptStore(button) {
    var key = button.dataset.store;
    var picked = optStores();
    var keep = function(k) { return k !== key; };
    resubmitOptStores(picked.stores.filter(keep), picked.sealed.filter(keep));
}

// addOptStore prices the list again with the store picked from the menu.
function addOptStore(select) {
    var option = select.options[select.selectedIndex];
    if (!option || !option.value) return;
    var picked = optStores();
    if (option.hasAttribute('data-sealed')) {
        picked.sealed.push(option.value);
    } else {
        picked.stores.push(option.value);
    }
    if (window.BAN && window.BAN.track) window.BAN.track('ui.optimizer', 'store_add');
    resubmitOptStores(picked.stores, picked.sealed);
}
