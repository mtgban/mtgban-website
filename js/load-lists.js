// The upload optimizer and the arbit page list a store's cards in a table
// whose rows can be unticked, and send them to the store with load buttons.
// Every list a button sends is built by the server from all of the rows, in
// its order. Each time a row is ticked or unticked, or the table is sorted
// (a rowsmoved event), the section's lists are rebuilt from the rows still
// ticked in the order they stand, or put back as the server built them when
// every row is ticked in the server's order. A link opened by middle click
// or from its menu is current too.
//
// A buylist's limit holds for a card in every condition together, and an
// arbit table lists each condition as a row asking for its own copies. The
// ticked rows sharing an offer fill it in the order they stand, and the ones
// past it are left out of every list. A section where that matters, or where
// Card Kingdom's list names a product twice, is rebuilt as the page loads.
//
// Each row carries data-load-idx, its place in the server's lists, and the
// fields a list is built from (data-load-qty, -name, -ckid, -tcgid, -set,
// -number). One a buylist limits also carries data-load-limit and, with
// data-arb-id, the offer it sells into, data-load-offer. An input or link holding a list names its format in
// data-load-list; a form without one lists rows as hashes inputs, one group
// per row, moved to follow the rows, and the groups of unticked rows are
// disabled.

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
        // The import keeps only the first line of a product it meets twice
        var quantities = new Map();
        rows.filter(function(r) { return r.ckid; }).forEach(function(r) {
            quantities.set(r.ckid, (quantities.get(r.ckid) || 0) + parseInt(r.qty, 10));
        });
        var contents = [];
        quantities.forEach(function(qty, ckid) {
            contents.push('{"id":' + ckid + ',"qty":' + qty + '}');
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

// Each hashes form's input groups in the server's order, read before any
// group has moved.
var loadListGroups = new WeakMap();

// loadOffer names the offer a limited row sells into. Conditions a buylist
// limits apart, under no id of their own, are told apart by the limit.
function loadOffer(tr) {
    return [tr.dataset.arbId, tr.dataset.loadOffer, tr.dataset.loadLimit].join(' ');
}

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
            number: tr.dataset.loadNumber || '',
            limit: parseInt(tr.dataset.loadLimit, 10) || 0,
            offer: loadOffer(tr),
            tr: tr
        });
    });
    return rows;
}

// cappedRows is the rows with each offer's quantities held to its limit, the
// first rows filling it, and the rows past it dropped. qtys, where set, is
// what a list asks for each row, by its data-load-idx, in place of its own.
function cappedRows(rows, qtys) {
    var taken = new Map();
    var out = [];
    rows.forEach(function(r) {
        var asked = parseInt(qtys ? qtys[r.idx] : r.qty, 10);
        var qty = asked;
        if (r.limit) {
            var used = taken.get(r.offer) || 0;
            qty = Math.min(asked, r.limit - used);
            if (qty <= 0) return;
            taken.set(r.offer, used + qty);
        }
        out.push(Object.assign({}, r, {qty: String(qty), cut: qty < asked}));
    });
    return out;
}

// servedAs tells whether the server's own list already says what rows do:
// all of the section's, in its order, none cut, and for Card Kingdom's
// buylist no product twice.
function servedAs(format, list, all) {
    if (list.length !== all.length) return false;
    var ckids = new Set();
    return list.every(function(r, i) {
        if (r.cut || (i > 0 && list[i - 1].idx > r.idx)) return false;
        if (format !== 'ckbuylist' || !r.ckid) return true;
        var repeated = ckids.has(r.ckid);
        ckids.add(r.ckid);
        return !repeated;
    });
}

// cartLink rebuilds a store cart link's #ban= list of "id:qty" pairs. The
// link's data-load-items holds each row's store item id by data-load-idx,
// empty for a row the store lists no id for.
function cartLink(href, items, rows) {
    var ids = [];
    var quantities = {};
    var skipped = 0;
    rows.forEach(function(r) {
        var id = items[r.idx];
        if (!id) {
            skipped++;
            return;
        }
        if (!(id in quantities)) {
            ids.push(id);
            quantities[id] = 0;
        }
        quantities[id] += parseInt(r.qty, 10);
    });
    var pairs = ids.map(function(id) { return id + ':' + quantities[id]; });
    var page = cartPage(href);
    var list = page.replace(/([#&]ban=)[^&]*/, '$1' + pairs.join(',')).replace(/&skip=\d*/, '');
    if (skipped > 0) {
        list += '&skip=' + skipped;
    }
    if (page === href) {
        return list;
    }
    var outer = new URL(href);
    outer.searchParams.set('u', list);
    return outer.href;
}

// cartPage is the cart page a link opens, list and all: the link itself, or
// the u query of SCG's or TCGplayer's partner redirector, which carries the
// list inside it.
function cartPage(href) {
    var page = new URL(href).searchParams.get('u');
    return page && page.indexOf('#') >= 0 ? page : href;
}

// rebuildLoadLists rewrites every list in section from its ticked rows, in
// the order they stand.
function rebuildLoadLists(section, removedClass) {
    var rows = loadListRows(section, removedClass);
    var active = rows.filter(function(r) { return !r.removed; });
    // Ticked rows a list had no room for
    var left = new Set();
    function capped(qtys) {
        var list = cappedRows(active, qtys);
        var kept = new Set(list.map(function(r) { return r.idx; }));
        active.forEach(function(r) {
            if (!kept.has(r.idx)) left.add(r.idx);
        });
        return list;
    }

    section.querySelectorAll('[data-load-list]').forEach(function(el) {
        var format = el.dataset.loadList;
        var field = format === 'cart' ? 'href' : 'value';
        if (!loadListOriginals.has(el)) {
            loadListOriginals.set(el, el[field]);
        }
        // data-load-qtys, where set, is what the link asks for each row
        var list = capped(el.dataset.loadQtys ? el.dataset.loadQtys.split(',') : null);
        if (servedAs(format, list, rows)) {
            el[field] = loadListOriginals.get(el);
        } else if (format === 'cart') {
            el.href = cartLink(loadListOriginals.get(el), el.dataset.loadItems.split(','), list);
        } else if (loadListFormats[format]) {
            el.value = loadListFormats[format](list);
        }
        // A cart left with no row the store lists has no button, as the
        // server gives none to such a split
        if (format === 'cart') {
            el.closest('.cart-load').hidden = /[#&]ban=(&|$)/.test(cartPage(el.href));
        }
    });

    var loaded = new Map();
    capped(null).forEach(function(r) { loaded.set(r.idx, r.qty); });
    rows.forEach(function(r) {
        if (!r.limit) return;
        var full = left.has(r.idx);
        r.tr.classList.toggle('load-full', full);
        r.tr.title = full ? 'The rows above fill the ' + r.limit + ' this buylist takes in all conditions' : '';
    });

    section.querySelectorAll('form').forEach(function(form) {
        var groups = loadListGroups.get(form);
        if (!groups) {
            groups = [];
            form.querySelectorAll('input[type="hidden"]').forEach(function(input) {
                if (input.name && input.name.match(/hashes$/)) {
                    groups.push([]);
                }
                if (groups.length) {
                    groups[groups.length - 1].push(input);
                }
            });
            loadListGroups.set(form, groups);
        }
        if (!groups.length) return;
        // The groups stand together in the form: put them back where they
        // stand, in the order the rows do
        var inputs = form.querySelectorAll('input[type="hidden"]');
        var last = inputs[inputs.length - 1];
        var after = last.nextSibling;
        var parent = last.parentNode;
        rows.forEach(function(r) {
            (groups[r.idx] || []).forEach(function(input) {
                input.disabled = !loaded.has(r.idx);
                if (r.limit && loaded.has(r.idx) && /hashesQtys$/.test(input.name)) {
                    input.value = loaded.get(r.idx);
                }
                parent.insertBefore(input, after);
            });
        });
    });
}

// needsRebuild tells whether the lists the server built for a section say
// other than its rows do, which only a repeated offer or product can do.
function needsRebuild(section) {
    var seen = new Set();
    var ck = section.querySelector('[data-load-list="ckbuylist"]');
    return Array.prototype.some.call(section.querySelectorAll('tr[data-load-idx]'), function(tr) {
        var keys = [];
        if (tr.dataset.loadLimit) keys.push('offer ' + loadOffer(tr));
        if (ck && tr.dataset.loadCkid) keys.push('ck ' + tr.dataset.loadCkid);
        var repeated = keys.some(function(key) { return seen.has(key); });
        keys.forEach(function(key) { seen.add(key); });
        return repeated;
    });
}

// wireLoadLists rebuilds a section's lists when one of its rows is ticked or
// unticked, after the page's own handler has marked the row, and when its
// table is sorted. opts names the page's section and unticked row classes.
function wireLoadLists(opts) {
    function rebuild(e) {
        var section = e.target.closest(opts.section);
        if (section) {
            rebuildLoadLists(section, opts.removed);
        }
    }
    document.querySelectorAll(opts.section).forEach(function(section) {
        if (needsRebuild(section)) {
            rebuildLoadLists(section, opts.removed);
        }
    });
    document.addEventListener('change', rebuild);
    document.addEventListener('rowsmoved', rebuild);
}
