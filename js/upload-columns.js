// The Results tab's store columns. A column's × prices the list again
// without its store; a header dragged onto another moves its column there,
// in every table of its kind, and the page's next re-post carries the order,
// which the server keeps in the order it was posted.
(function() {
    var dragged = null;

    function storeHeads(table, kind) {
        var heads = table.tHead.rows[table.tHead.rows.length - 1].cells;
        return Array.prototype.filter.call(heads, function(th) { return th.dataset.storeKind === kind; });
    }

    function storeTables(kind) {
        return Array.prototype.filter.call(document.querySelectorAll('table.ures-table'), function(table) {
            return table.tHead && storeHeads(table, kind).length > 0;
        });
    }

    // order is the stores of a kind as the page's columns show them.
    function order(kind) {
        var tables = storeTables(kind);
        if (!tables.length) return [];
        return storeHeads(tables[0], kind).map(function(th) { return th.dataset.store; });
    }

    // post has the page's re-posts price against these stores, in order.
    function post(kind, stores) {
        var form = document.getElementById('upload_form');
        var name = kind === 'sealed' ? 'sealed_stores' : 'stores';
        form.querySelectorAll('input[name="' + name + '"]').forEach(function(el) { el.remove(); });
        stores.forEach(function(key) {
            var input = document.createElement('input');
            input.type = 'hidden';
            input.name = name;
            input.value = key;
            form.appendChild(input);
        });
        // The optimizer's own store buttons post this list
        var picked = window.BAN_OPT_STORES;
        var field = kind === 'sealed' ? 'sealed' : 'stores';
        if (picked && picked[field]) {
            picked[field] = stores.concat(picked[field].filter(function(k) { return stores.indexOf(k) < 0; }));
        }
    }

    // arrange puts a table's store columns in order, row by row.
    function arrange(table, kind, keys) {
        var heads = table.tHead.rows[table.tHead.rows.length - 1].cells;
        var slots = [];
        Array.prototype.forEach.call(heads, function(th, i) {
            if (th.dataset.storeKind === kind) slots.push(i);
        });
        var now = slots.map(function(i) { return heads[i].dataset.store; });
        var want = keys.filter(function(k) { return now.indexOf(k) >= 0; });
        Array.prototype.forEach.call(table.rows, function(row) {
            var cells = row.cells;
            if (cells.length !== heads.length) return;
            var moving = want.map(function(k) { return cells[slots[now.indexOf(k)]]; });
            var after = cells[slots[slots.length - 1]].nextElementSibling;
            moving.forEach(function(cell) { row.insertBefore(cell, after); });
        });
    }

    function move(from, to) {
        var kind = from.dataset.storeKind;
        var keys = order(kind);
        var a = keys.indexOf(from.dataset.store);
        var b = keys.indexOf(to.dataset.store);
        if (a < 0 || b < 0 || a === b) return;
        keys.splice(a, 1);
        keys.splice(b, 0, from.dataset.store);
        storeTables(kind).forEach(function(table) { arrange(table, kind, keys); });
        post(kind, keys);
        if (window.BAN && window.BAN.track) window.BAN.track('ui.upload.result', 'store_move');
    }

    function drop(btn) {
        var th = btn.closest('th');
        var kind = th.dataset.storeKind;
        var keys = order(kind).filter(function(k) { return k !== th.dataset.store; });
        if (!keys.length) return;
        post(kind, keys);
        if (window.BAN && window.BAN.track) window.BAN.track('ui.upload.result', 'store_drop');
        if (window.reprocessUploadResults) window.reprocessUploadResults();
    }

    function clearMarks() {
        document.querySelectorAll('.ures-table th.ures-drop-before, .ures-table th.ures-drop-after, .ures-table th.ures-dragging').forEach(function(th) {
            th.classList.remove('ures-drop-before', 'ures-drop-after', 'ures-dragging');
        });
    }

    // target is the header a dragged one may land on: another store of its
    // kind in its own table.
    function target(e) {
        var th = e.target.closest && e.target.closest('th[data-store]');
        if (!th || !dragged || th === dragged) return null;
        if (th.dataset.storeKind !== dragged.dataset.storeKind || th.closest('table') !== dragged.closest('table')) return null;
        return th;
    }

    // Captured, so the header's own handlers, which sort, never see it
    document.addEventListener('click', function(e) {
        var btn = e.target.closest && e.target.closest('.ures-store-drop');
        if (!btn) return;
        e.preventDefault();
        e.stopPropagation();
        drop(btn);
    }, true);
    document.addEventListener('keydown', function(e) {
        if (e.target.classList && e.target.classList.contains('ures-store-drop')) e.stopPropagation();
    }, true);

    document.addEventListener('dragstart', function(e) {
        var th = e.target.closest && e.target.closest('th[data-store]');
        if (!th) return;
        dragged = th;
        th.classList.add('ures-dragging');
        e.dataTransfer.effectAllowed = 'move';
        e.dataTransfer.setData('text/plain', th.dataset.store);
    });
    document.addEventListener('dragover', function(e) {
        var th = target(e);
        if (!th) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        var heads = Array.prototype.slice.call(th.parentNode.cells);
        var right = heads.indexOf(dragged) < heads.indexOf(th);
        th.classList.toggle('ures-drop-after', right);
        th.classList.toggle('ures-drop-before', !right);
    });
    document.addEventListener('dragleave', function(e) {
        var th = target(e);
        if (th && !th.contains(e.relatedTarget)) th.classList.remove('ures-drop-before', 'ures-drop-after');
    });
    document.addEventListener('drop', function(e) {
        var th = target(e);
        if (!th) return;
        e.preventDefault();
        move(dragged, th);
    });
    document.addEventListener('dragend', function() {
        dragged = null;
        clearMarks();
    });
})();
