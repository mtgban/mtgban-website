// The upload optimizer and the arbit page list a store's cards in a table
// whose rows can be unticked, and send them to the store with load buttons.
// Every list a button sends is built by the server from all of the rows, so
// each time a row is ticked or unticked the section's lists are rebuilt from
// the rows still ticked, or put back as the server built them when none is
// unticked. A link opened by middle click or from its menu is current too.
//
// Each row carries data-load-idx, its place in the server's lists, and the
// fields a list is built from (data-load-qty, -name, -ckid, -tcgid, -set,
// -number). An input or link holding a list names its format in
// data-load-list; a form without one lists rows as hashes inputs, one group
// per row, and the groups of unticked rows are disabled.

var loadListFormats = {
    ck: function(rows) {
        return rows.map(function(r) { return r.qty + ' ' + r.name + '||'; }).join('');
    },
    csi: function(rows) {
        return rows.map(function(r) { return r.qty + ' ' + r.name + '|'; }).join('');
    },
    tcg: function(rows) {
        return rows.map(function(r) { return r.qty + '-' + r.tcgid + '||'; }).join('');
    },
    ckbuylist: function(rows) {
        var contents = rows.filter(function(r) { return r.ckid; }).map(function(r) {
            return '{"id":' + r.ckid + ',"qty":' + r.qty + '}';
        });
        contents.push('{}');
        return '{"contents":[' + contents.join(',') + ']}';
    },
    manapool: function(rows) {
        var deck = rows.map(function(r) {
            return r.qty + ' ' + r.name + ' [' + r.set + '] ' + r.number;
        }).join('\n');
        // base64 of the UTF-8 bytes, as the server's base64enc writes it
        var bytes = new TextEncoder().encode(deck);
        var binary = '';
        for (var i = 0; i < bytes.length; i++) {
            binary += String.fromCharCode(bytes[i]);
        }
        return btoa(binary);
    }
};

// The original value of every list rewritten so far, to put back when the
// rows are all ticked again.
var loadListOriginals = new WeakMap();

function loadListRows(section, removedClass) {
    var rows = [];
    section.querySelectorAll('tr[data-load-idx]').forEach(function(tr) {
        rows.push({
            idx: parseInt(tr.dataset.loadIdx, 10),
            removed: tr.classList.contains(removedClass),
            qty: tr.dataset.loadQty || '1',
            name: tr.dataset.loadName || '',
            ckid: tr.dataset.loadCkid || '',
            tcgid: tr.dataset.loadTcgid || '',
            set: tr.dataset.loadSet || '',
            number: tr.dataset.loadNumber || ''
        });
    });
    // A sorted table has moved its rows: the lists keep the server's order
    rows.sort(function(a, b) { return a.idx - b.idx; });
    return rows;
}

// cartLink rebuilds a store cart link's #ban= list of "id:qty" pairs. The
// link's data-load-items holds each row's store item id by data-load-idx,
// empty for a row the store lists no id for.
function cartLink(href, items, rows) {
    var ids = [];
    var quantities = {};
    rows.forEach(function(r) {
        var id = items[r.idx];
        if (!id) return;
        if (!(id in quantities)) {
            ids.push(id);
            quantities[id] = 0;
        }
        quantities[id] += parseInt(r.qty, 10);
    });
    var pairs = ids.map(function(id) { return id + ':' + quantities[id]; });
    return href.replace(/([#&]ban=)[^&]*/, '$1' + pairs.join(','));
}

// rebuildLoadLists rewrites every list in section from its ticked rows.
function rebuildLoadLists(section, removedClass) {
    var rows = loadListRows(section, removedClass);
    var active = rows.filter(function(r) { return !r.removed; });
    var whole = active.length === rows.length;

    section.querySelectorAll('[data-load-list]').forEach(function(el) {
        var format = el.dataset.loadList;
        var field = format === 'cart' ? 'href' : 'value';
        if (!loadListOriginals.has(el)) {
            loadListOriginals.set(el, el[field]);
        }
        if (whole) {
            el[field] = loadListOriginals.get(el);
        } else if (format === 'cart') {
            el.href = cartLink(loadListOriginals.get(el), el.dataset.loadItems.split(','), active);
        } else if (loadListFormats[format]) {
            el.value = loadListFormats[format](active);
        }
    });

    var removed = {};
    rows.forEach(function(r) {
        if (r.removed) removed[r.idx] = true;
    });
    section.querySelectorAll('form').forEach(function(form) {
        var group = -1;
        form.querySelectorAll('input[type="hidden"]').forEach(function(input) {
            if (input.name && input.name.match(/hashes$/)) {
                group++;
            }
            if (group >= 0) {
                input.disabled = removed[group] === true;
            }
        });
    });
}

// wireLoadLists rebuilds a section's lists when one of its rows is ticked or
// unticked, after the page's own handler has marked the row. opts names the
// page's section and unticked row classes.
function wireLoadLists(opts) {
    document.addEventListener('change', function(e) {
        var section = e.target.closest(opts.section);
        if (section) {
            rebuildLoadLists(section, opts.removed);
        }
    });
}
