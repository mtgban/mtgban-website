// Sorts a results or optimizer table by the column whose header was clicked.
// The rows move on the page itself: the exports read them back off the page
// in the order they stand (upload-exports.js), so a CSV follows the order
// shown.

// What a cell sorts by: its data-sort, else its text, or a row's attr. A
// cell with nothing to sort by goes last whichever way the column is sorted.
function uresSortKey(cell, numeric, attr) {
    if (!cell) return null;
    var raw = attr ? cell.getAttribute(attr) : cell.hasAttribute('data-sort') ? cell.getAttribute('data-sort') : cell.textContent;
    raw = (raw || '').trim();
    if (raw === '') return null;
    if (!numeric) return raw.toLowerCase();
    var n = parseFloat(raw.replace(/[^0-9.+-]/g, ''));
    return isNaN(n) ? null : n;
}

// Each row's place in the order the server sent, noted before a sort first
// moves it.
var uresServerPlace = new WeakMap();

// The rows in the column's order: missing values last either way, ties by
// the tie-breakers (uresTieOrder), then in the order they had. With no
// column, the tie-breakers' ties fall back to the server's order, as on a
// reload.
function uresSortedRows(rows, col, numeric, descending, ties) {
    var keyed = rows.map(function(row, i) {
        var index = col === null && uresServerPlace.has(row) ? uresServerPlace.get(row) : i;
        return {row: row, key: uresSortKey(row.cells[col], numeric), index: index};
    });
    keyed.sort(function(a, b) {
        if (a.key === null || b.key === null) {
            if (a.key === b.key) return uresTieOrder(a.row, b.row, ties) || a.index - b.index;
            return a.key === null ? 1 : -1;
        }
        var c = numeric ? a.key - b.key : a.key.localeCompare(b.key, undefined, {numeric: true});
        if (descending) c = -c;
        return c || uresTieOrder(a.row, b.row, ties) || a.index - b.index;
    });
    return keyed.map(function(k) { return k.row; });
}

// Sorts the header's table by its column. The first click goes the way the
// header asks (data-sort-descending, bare or "true"), each one after turns
// it round. A row marked data-sort-method="none", the totals, keeps the end
// of the table.
function uresSortBy(th) {
    var table = th.closest('table');
    var numeric = th.getAttribute('data-sort-method') === 'number';
    var was = th.getAttribute('aria-sort');
    var first = th.getAttribute('data-sort-descending');
    var descending = was ? was === 'ascending' : first !== null && first !== 'false';
    uresMoveRows(table, th.cellIndex, numeric, descending);

    // The header's own row: an optimizer table heads it with its store
    Array.prototype.forEach.call(th.parentNode.cells, function(cell) {
        cell.removeAttribute('aria-sort');
    });
    th.setAttribute('aria-sort', descending ? 'descending' : 'ascending');
}

// Puts the table's rows in the column's order, col null for none: the
// sorting setting's tie groups then lead.
function uresMoveRows(table, col, numeric, descending) {
    var tbody = table.tBodies[0];
    if (!tbody) return;
    var entries = [], rest = [];
    Array.prototype.forEach.call(tbody.rows, function(row, i) {
        if (!uresServerPlace.has(row)) uresServerPlace.set(row, i);
        (row.getAttribute('data-sort-method') === 'none' ? rest : entries).push(row);
    });
    uresSortedRows(entries, col, numeric, descending, uresTies(table, col === null)).concat(rest).forEach(function(row) {
        tbody.appendChild(row);
    });

    // The optimizer's load lists follow the rows (load-lists.js)
    table.dispatchEvent(new Event('rowsmoved', {bubbles: true}));
}

// The tie-breakers: card properties picked from the Card header's menu,
// which order the rows the column (or else the sorting setting) ties on.
// The card properties ties can be broken by. Each row carries its value as
// data-k-<key> (internal/uploadsort); rarity and condition are ranks.
var uresTieKeys = [
    {key: 'name', label: 'Name'},
    {key: 'set', label: 'Set'},
    {key: 'number', label: 'Number'},
    {key: 'finish', label: 'Finish'},
    {key: 'color', label: 'Color'},
    {key: 'rarity', label: 'Rarity', numeric: true},
    {key: 'cond', label: 'Condition', numeric: true}
];

// Where the chains are kept, one per area: "results" for the results
// tables, "opt" for the optimizer's, each "key:a,key:d" in order.
var UPLOAD_SORT_STORE = 'mtgban_upload_sort';

// The tie-breakers in force, by area: [{key, descending}]
var uresChains = {results: [], opt: []};

function uresTieKey(key) {
    for (var i = 0; i < uresTieKeys.length; i++) {
        if (uresTieKeys[i].key === key) return uresTieKeys[i];
    }
    return null;
}

// A stored chain, keeping the keys this page knows, each once.
function uresParseChain(text) {
    var chain = [];
    (text || '').split(',').forEach(function(part) {
        var bits = part.split(':');
        if (!uresTieKey(bits[0])) return;
        if (chain.some(function(c) { return c.key === bits[0]; })) return;
        chain.push({key: bits[0], descending: bits[1] === 'd'});
    });
    return chain;
}

function uresFormatChain(chain) {
    return chain.map(function(c) { return c.key + ':' + (c.descending ? 'd' : 'a'); }).join(',');
}

function uresLoadChains() {
    try {
        var saved = JSON.parse(localStorage.getItem(UPLOAD_SORT_STORE) || '{}');
        uresChains = {results: uresParseChain(saved.results), opt: uresParseChain(saved.opt)};
    } catch (e) {
        uresChains = {results: [], opt: []};
    }
}

function uresSaveChains() {
    try {
        localStorage.setItem(UPLOAD_SORT_STORE, JSON.stringify({
            results: uresFormatChain(uresChains.results),
            opt: uresFormatChain(uresChains.opt)
        }));
    } catch (e) {}
}

function uresArea(table) {
    return table.classList.contains('opt-table') ? 'opt' : 'results';
}

// An optimizer store's own order, picked from its own Card header for this
// page; a store without one follows the stores' order (uresChains.opt).
var uresStoreChains = new WeakMap();

// The order a menu shows: the area's, or with table an optimizer store's
// own, else the stores'. To edit a store's, own begins it as a copy.
function uresChainOf(area, table, own) {
    if (!table) return uresChains[area];
    if (!own) return uresStoreChains.get(table) || uresChains.opt;
    own = uresStoreChains.get(table);
    if (!own) {
        own = uresChains.opt.map(function(c) { return {key: c.key, descending: c.descending}; });
        uresStoreChains.set(table, own);
    }
    return own;
}

// The store a button sorts alone: an optimizer store's Card header button,
// not the toolbar's, which sorts them all.
function uresButtonTable(btn) {
    return btn.getAttribute('data-sort-area') === 'opt' && btn.closest ? btn.closest('table') : null;
}

// The steps that break the column's ties: the sorting setting's tie groups
// when no column leads, then the area's chain.
function uresTies(table, led) {
    var ties = led ? [{attr: 'data-k-lead', numeric: true}] : [];
    var own = uresArea(table) === 'opt' && uresStoreChains.get(table);
    (own || uresChains[uresArea(table)]).forEach(function(c) {
        ties.push({attr: 'data-k-' + c.key, numeric: !!uresTieKey(c.key).numeric, descending: c.descending});
    });
    return ties;
}

// How two rows order under the tie-breakers: each step decides only between
// rows the steps before it tie on, a missing value last either way.
function uresTieOrder(x, y, ties) {
    for (var s = 0; s < ties.length; s++) {
        var a = uresSortKey(x, ties[s].numeric, ties[s].attr);
        var b = uresSortKey(y, ties[s].numeric, ties[s].attr);
        if (a === b) continue;
        if (a === null || b === null) return a === null ? 1 : -1;
        var c = ties[s].numeric ? a - b : a.localeCompare(b, undefined, {numeric: true});
        if (c) return ties[s].descending ? -c : c;
    }
    return 0;
}

// Sorts a table again after its tie-breakers changed, under the column it
// is sorted by, if any.
function uresResort(table) {
    var heads = table.tHead.rows[table.tHead.rows.length - 1].cells;
    var th = Array.prototype.find.call(heads, function(cell) { return cell.hasAttribute('aria-sort'); });
    if (th) {
        uresMoveRows(table, th.cellIndex, th.getAttribute('data-sort-method') === 'number', th.getAttribute('aria-sort') === 'descending');
    } else {
        uresMoveRows(table, null, false, false);
    }
}

function uresAreaTables(area) {
    return Array.prototype.filter.call(document.querySelectorAll('.ures-table, .opt-table'), function(table) {
        return uresArea(table) === area;
    });
}

// The tie-breakers any row in the area (or table) has a value for, as the
// menu lists them: the chain's in its order, then the rest.
function uresMenuKeys(area, table) {
    var tables = table ? [table] : uresAreaTables(area);
    var shown = uresTieKeys.filter(function(def) {
        return tables.some(function(table) {
            return table.querySelector('tbody tr[data-k-' + def.key + ']:not([data-k-' + def.key + '=""])');
        });
    });
    var chain = uresChainOf(area, table);
    return chain.map(function(c) { return uresTieKey(c.key); }).filter(function(def) {
        return shown.indexOf(def) >= 0;
    }).concat(shown.filter(function(def) {
        return !chain.some(function(c) { return c.key === def.key; });
    }));
}

function uresDescribe(area, table) {
    var chain = uresChainOf(area, table);
    var all = area === 'opt' && !table;
    if (!chain.length) return all ? 'Sort every store by card properties' : 'Sort by card properties';
    return (all ? 'Stores sorted by ' : 'Sorted by ') + chain.map(function(c) {
        return uresTieKey(c.key).label + (c.descending ? ' ▼' : ' ▲');
    }).join(', ');
}

function uresRenderMenu(menu, area, table) {
    var chain = uresChainOf(area, table);
    var html = '';
    uresMenuKeys(area, table).forEach(function(def) {
        var at = -1;
        chain.forEach(function(c, i) { if (c.key === def.key) at = i; });
        var on = at >= 0;
        var desc = on && chain[at].descending;
        html += '<div class="sort-ties-row' + (on ? ' on' : '') + '" data-key="' + def.key + '">' +
            '<label><input type="checkbox" data-act="toggle"' + (on ? ' checked' : '') + '>' +
            (on ? '<span class="sort-ties-pos">' + (at + 1) + '</span>' : '') + def.label + '</label>' +
            (on ? '<button type="button" data-act="dir" title="' + (desc ? 'Descending' : 'Ascending') + '">' + (desc ? '▼' : '▲') + '</button>' +
                '<button type="button" data-act="up" title="Earlier"' + (at === 0 ? ' disabled' : '') + '>↑</button>' +
                '<button type="button" data-act="down" title="Later"' + (at === chain.length - 1 ? ' disabled' : '') + '>↓</button>' : '') +
            '</div>';
    });
    html += '<button type="button" class="sort-ties-clear" data-act="clear"' + (chain.length ? '' : ' disabled') + '>Clear</button>';
    menu.innerHTML = html;
}

// The area's buttons say their order in their tooltip, and light up while
// it has one.
function uresShowChain(area) {
    document.querySelectorAll('[data-sort-area="' + area + '"]').forEach(function(btn) {
        var table = uresButtonTable(btn);
        btn.title = uresDescribe(area, table);
        btn.classList.toggle('on', uresChainOf(area, table).length > 0);
    });
}

// After a change to an order: a store's own sorts that store; the area's is
// kept, replaces every store's own, and sorts the area's tables.
function uresChainChanged(area, table) {
    if (table) {
        uresShowChain(area);
        uresResort(table);
        return;
    }
    if (area === 'opt') uresStoreChains = new WeakMap();
    uresSaveChains();
    uresShowChain(area);
    uresAreaTables(area).forEach(uresResort);
}

// What a pick in the menu does to the area's order, or with table to an
// optimizer store's own.
function uresMenuAct(area, key, act, table) {
    var chain = uresChainOf(area, table, true);
    var at = -1;
    chain.forEach(function(c, i) { if (c.key === key) at = i; });
    if (act === 'clear') {
        chain.length = 0;
    } else if (act === 'toggle') {
        if (at >= 0) chain.splice(at, 1);
        else chain.push({key: key, descending: false});
    } else if (act === 'dir' && at >= 0) {
        chain[at].descending = !chain[at].descending;
    } else if (act === 'up' && at > 0) {
        chain.splice(at - 1, 0, chain.splice(at, 1)[0]);
    } else if (act === 'down' && at >= 0 && at < chain.length - 1) {
        chain.splice(at + 1, 0, chain.splice(at, 1)[0]);
    }
    uresChainChanged(area, table);
}

// The area's menu, made on first use: one popover the area's buttons share,
// opened under the button pressed.
function uresMenu(area) {
    var id = 'sort-ties-' + area;
    var menu = document.getElementById(id);
    if (menu) return menu;
    menu = document.createElement('div');
    menu.id = id;
    menu.className = 'sort-ties-menu';
    menu.setAttribute('popover', '');
    menu.addEventListener('click', function(e) {
        var el = e.target.closest('[data-act]');
        if (!el || el.disabled) return;
        var row = el.closest('[data-key]');
        var key = row ? row.getAttribute('data-key') : '';
        var act = el.getAttribute('data-act');
        var table = uresButtonTable(uresMenuButton);
        uresMenuAct(area, key, act, table);
        uresRenderMenu(menu, area, table);
        // The menu is drawn anew: keep the keyboard on the same control
        var again = menu.querySelector(key ? '[data-key="' + key + '"] [data-act="' + act + '"]' : '[data-act="clear"]');
        if (again && !again.disabled) again.focus();
    });
    document.body.appendChild(menu);
    return menu;
}

var uresMenuButton = null;

// Puts the menu under the button that opened it, closing it once the button
// has scrolled off the screen.
function uresPlaceMenu(menu) {
    var r = uresMenuButton.getBoundingClientRect();
    if (r.bottom < 0 || r.top > window.innerHeight) {
        menu.hidePopover();
        return;
    }
    menu.style.left = Math.max(8, Math.min(r.left, window.innerWidth - 248)) + 'px';
    menu.style.top = (r.bottom + 4) + 'px';
}

document.addEventListener('beforetoggle', function(e) {
    var menu = e.target;
    if (!menu.classList || !menu.classList.contains('sort-ties-menu') || e.newState !== 'open' || !uresMenuButton) return;
    uresRenderMenu(menu, uresMenuButton.getAttribute('data-sort-area'), uresButtonTable(uresMenuButton));
    uresPlaceMenu(menu);
}, true);

// Captured, so a scroll inside any container moves it too
document.addEventListener('scroll', function() {
    if (!uresMenuButton) return;
    document.querySelectorAll('.sort-ties-menu:popover-open').forEach(uresPlaceMenu);
}, {capture: true, passive: true});

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

document.addEventListener('DOMContentLoaded', function() {
    uresLoadChains();
    ['results', 'opt'].forEach(function(area) {
        var buttons = document.querySelectorAll('[data-sort-area="' + area + '"]');
        if (!buttons.length) return;
        var menu = uresMenu(area);
        buttons.forEach(function(btn) {
            btn.setAttribute('popovertarget', menu.id);
            // Kept from the header, which would sort by the Card column
            btn.addEventListener('click', function(e) {
                e.stopPropagation();
                uresMenuButton = btn;
            });
            btn.addEventListener('keydown', function(e) { e.stopPropagation(); });
        });
        uresShowChain(area);
        if (uresChains[area].length) uresAreaTables(area).forEach(uresResort);
    });
});
