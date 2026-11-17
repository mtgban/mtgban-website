// Editing a result's condition, copies and price. The Results rows are the
// list: every re-post and export packs them (packRows), so an edit only
// rewrites their data-cond/data-qtys/data-price, and the offers catch up
// when the reader reloads. An Optimizer row edits the Results rows of its
// card and grade. A list sent from the backpack takes each condition and
// copies edit back to it; the backpack keeps no price.
(function() {
    var CONDS = ['NM', 'SP', 'MP', 'HP', 'PO'];
    var QTYS = 20;
    var MAX_PRICE = 1000000;
    var menu = null;
    var opener = null;

    // listRows is the Results rows a button edits: its own row, or for an
    // Optimizer row every Results row of the same card and grade.
    function listRows(btn) {
        var own = btn.closest('tr[data-hash]');
        if (own) return [own];
        var opt = btn.closest('tr[data-opt-id]');
        if (!opt) return [];
        return Array.prototype.filter.call(document.querySelectorAll('.ures-table tr[data-hash]'), function(tr) {
            return tr.dataset.hash === opt.dataset.optId && (tr.dataset.grade || '') === (opt.dataset.optCond || '');
        });
    }

    // editable is whether each row has its own edit buttons: the rows of
    // an opened product do not, as they are its contents.
    function editable(rows) {
        return rows.length > 0 && rows.every(function(tr) { return tr.querySelector('.ures-edit-btn'); });
    }

    function copies(rows) {
        return rows.reduce(function(n, tr) { return n + (parseInt(tr.dataset.qtys, 10) || 1); }, 0);
    }

    function price(tr) { return parseFloat(tr.dataset.price) || 0; }

    function input(kind, placeholder, value) {
        var box = document.createElement('input');
        box.type = 'number';
        box.min = kind === 'price' ? '0' : '1';
        box.max = kind === 'price' ? String(MAX_PRICE) : '999';
        if (kind === 'price') box.step = '0.01';
        box.placeholder = placeholder;
        box.className = 'ures-edit-input';
        box.setAttribute('aria-label', kind === 'price' ? 'Your price' : 'Other number of copies');
        if (value !== undefined) box.value = value;
        return box;
    }

    function item(label, value, current) {
        var b = document.createElement('button');
        b.type = 'button';
        b.dataset.value = value;
        b.textContent = label;
        if (current) b.setAttribute('aria-current', 'true');
        return b;
    }

    function fill(kind, rows) {
        menu.textContent = '';
        menu.className = 'opt-move-menu ures-edit-menu ' + kind;
        var title = document.createElement('div');
        title.className = 'opt-move-title';
        title.textContent = kind === 'cond' ? 'Condition' : kind === 'price' ? 'Your price' : 'Copies in your list';
        menu.appendChild(title);
        if (kind === 'price') {
            menu.appendChild(input('price', '0.00', price(rows[0]).toFixed(2)));
            var set = item('Set', '', false);
            set.className = 'ures-edit-set';
            menu.appendChild(set);
            return;
        }
        var items = document.createElement('div');
        items.className = 'ures-edit-items';
        menu.appendChild(items);
        if (kind === 'cond') {
            var cur = rows[0].dataset.cond || '';
            CONDS.forEach(function(c) { items.appendChild(item(c, c, c === cur)); });
            // A list line may give no grade, priced as NM
            items.appendChild(item('None', '', cur === ''));
            return;
        }
        var qty = copies(rows);
        // Each list line keeps a copy at least
        for (var n = rows.length; n <= QTYS; n++) items.appendChild(item(String(n), String(n), n === qty));
        if (qty > QTYS) items.appendChild(item(String(qty), String(qty), true));
        menu.appendChild(input('qty', 'Other'));
    }

    function open(btn) {
        var rows = listRows(btn);
        if (!editable(rows)) return;
        if (!menu) {
            menu = document.createElement('div');
            menu.id = 'ures-edit-menu';
            menu.setAttribute('popover', '');
            document.body.appendChild(menu);
        }
        if (menu.matches(':popover-open')) menu.hidePopover();
        opener = btn;
        fill(btn.dataset.edit, rows);
        var r = btn.getBoundingClientRect();
        menu.style.left = Math.max(8, r.left) + 'px';
        menu.style.right = 'auto';
        if (r.bottom > window.innerHeight * 0.6) {
            menu.style.top = 'auto';
            menu.style.bottom = (window.innerHeight - r.top + 4) + 'px';
        } else {
            menu.style.top = (r.bottom + 4) + 'px';
            menu.style.bottom = 'auto';
        }
        menu.showPopover();
        var cur = btn.dataset.edit === 'price' ? menu.querySelector('input') : menu.querySelector('[aria-current]') || menu.querySelector('button');
        if (!cur) return;
        cur.focus();
        if (cur.select) cur.select();
    }

    function track(btn, value) {
        if (!window.BAN || !window.BAN.track) return;
        if (btn.closest('.opt-store')) window.BAN.track('ui.optimizer', value);
        else window.BAN.track('ui.upload.result', value);
    }

    // syncPack takes an edit back to the backpack the list was sent from.
    function syncPack(id, was, cond, qty) {
        var pack = window.Backpack && window.Backpack.sentPack ? window.Backpack.sentPack() : 0;
        if (!pack || !window.ListStorage) return;
        var key = window.ListStorage.backpackKey({id: id, cond: was, pack: pack});
        // The backpack keeps no grade as NM
        if (cond !== was) window.Backpack.setCond(key, cond || 'NM');
        else window.Backpack.setQty(key, qty);
        if (window.renderBackpack) window.renderBackpack();
    }

    // remember keeps what a row came with, before its first edit.
    function remember(tr) {
        if ('origCond' in tr.dataset) return;
        tr.dataset.origCond = tr.dataset.cond || '';
        tr.dataset.origQtys = tr.dataset.qtys || '';
        tr.dataset.origPrice = tr.dataset.price || '';
    }

    // mark flags a row whose value differs from what the page came with.
    function mark(tr) {
        var condBtn = tr.querySelector('.ures-edit-btn[data-edit="cond"]');
        var qtyBtn = tr.querySelector('.ures-edit-btn[data-edit="qty"]');
        var priceBtn = tr.querySelector('.ures-edit-btn[data-edit="price"]');
        if (condBtn) condBtn.classList.toggle('edited', tr.dataset.cond !== tr.dataset.origCond);
        if (qtyBtn) qtyBtn.classList.toggle('edited', tr.dataset.qtys !== tr.dataset.origQtys);
        if (priceBtn) priceBtn.classList.toggle('edited', price(tr) !== (parseFloat(tr.dataset.origPrice) || 0));
    }

    function optRows(id, grade) {
        return Array.prototype.filter.call(document.querySelectorAll('.opt-store tr[data-opt-id]'), function(tr) {
            return tr.dataset.optId === id && (tr.dataset.optCond || '') === grade;
        });
    }

    function setCond(rows, cond) {
        rows.forEach(function(tr) {
            var was = tr.dataset.cond || '';
            if (was === cond) return;
            remember(tr);
            var grade = tr.dataset.grade;
            optRows(tr.dataset.hash, grade || '').forEach(function(opt) {
                var b = opt.querySelector('.ures-edit-btn[data-edit="cond"]');
                if (grade !== undefined) {
                    // The page's move keys and later edits read the new grade
                    opt.dataset.optCond = cond;
                    if (b) b.textContent = cond || 'NM';
                }
                if (b) b.classList.toggle('edited', cond !== tr.dataset.origCond);
            });
            tr.dataset.cond = cond;
            if (grade !== undefined) tr.dataset.grade = cond;
            var rank = cond ? String(CONDS.indexOf(cond)) : '';
            tr.dataset.kCond = rank;
            var b = tr.querySelector('.ures-edit-btn[data-edit="cond"]');
            if (b) {
                b.textContent = cond;
                b.classList.remove('ignored');
                b.parentNode.dataset.sort = rank;
            }
            mark(tr);
            syncPack(tr.dataset.hash, was, cond, 0);
        });
    }

    // setQty gives the rows qty copies between them, one each at least:
    // the first takes any more, and any fewer come off the rows in order.
    function setQty(rows, qty) {
        var counts = rows.map(function(tr) { return parseInt(tr.dataset.qtys, 10) || 1; });
        var have = copies(rows);
        if (qty > have) counts[0] += qty - have;
        for (var i = 0, take = have - qty; i < counts.length && take > 0; i++) {
            var off = Math.min(take, counts[i] - 1);
            counts[i] -= off;
            take -= off;
        }
        var conds = [];
        rows.forEach(function(tr, i) {
            if (counts[i] === (parseInt(tr.dataset.qtys, 10) || 1)) return;
            remember(tr);
            tr.dataset.qtys = String(counts[i]);
            var b = tr.querySelector('.ures-edit-btn[data-edit="qty"]');
            if (b) b.textContent = String(counts[i]);
            mark(tr);
            if (conds.indexOf(tr.dataset.cond || '') < 0) conds.push(tr.dataset.cond || '');
        });
        optRows(rows[0].dataset.hash, rows[0].dataset.grade || '').forEach(function(opt) {
            var ob = opt.querySelector('.ures-edit-btn[data-edit="qty"]');
            if (ob) {
                ob.classList.add('edited');
                ob.title = qty + ' in your list; reload to update';
            }
        });
        // The backpack holds one entry for the card in a grade
        conds.forEach(function(cond) {
            var held = Array.prototype.filter.call(document.querySelectorAll('.ures-table tr[data-hash]'), function(x) {
                return x.dataset.hash === rows[0].dataset.hash && (x.dataset.cond || '') === cond;
            });
            syncPack(rows[0].dataset.hash, cond, cond, copies(held));
        });
    }

    // setPrice gives every row the price, which the offers are judged
    // against when the page reloads.
    function setPrice(rows, p) {
        rows.forEach(function(tr) {
            remember(tr);
            tr.dataset.price = String(p);
            var b = tr.querySelector('.ures-edit-btn[data-edit="price"]');
            if (b) {
                b.textContent = '$ ' + p.toFixed(2);
                b.parentNode.dataset.sort = p ? p.toFixed(2) : '';
            }
            mark(tr);
            optRows(tr.dataset.hash, tr.dataset.grade || '').forEach(function(opt) {
                var ob = opt.querySelector('.ures-edit-btn[data-edit="price"]');
                if (!ob) return;
                ob.textContent = p.toFixed(2);
                ob.classList.add('edited');
            });
        });
    }

    function pick(value) {
        var btn = opener;
        if (!btn) return;
        menu.hidePopover();
        var rows = listRows(btn);
        if (!editable(rows)) return;
        if (btn.dataset.edit === 'cond') {
            if (value !== '' && CONDS.indexOf(value) < 0) return;
            setCond(rows, value);
            track(btn, 'edit_cond');
        } else if (btn.dataset.edit === 'price') {
            var p = Math.round(parseFloat(value) * 100) / 100;
            if (!(p >= 0 && p <= MAX_PRICE) || rows.every(function(tr) { return price(tr) === p; })) return;
            setPrice(rows, p);
            track(btn, 'edit_price');
        } else {
            var qty = parseInt(value, 10);
            if (!(qty >= rows.length && qty <= 999) || qty === copies(rows)) return;
            setQty(rows, qty);
            track(btn, 'edit_qty');
        }
        update();
        btn.focus();
    }

    // update counts the edited rows on the reload bar, and holds back the
    // store sends, which carry the page's old quantities, until a reload.
    function update() {
        var dirty = !!document.querySelector('.ures-table tr[data-hash] .ures-edit-btn.edited');
        document.body.classList.toggle('ures-dirty', dirty);
        if (window.updateReloadBar) window.updateReloadBar();
    }

    document.addEventListener('click', function(e) {
        if (!e.target.closest) return;
        var btn = e.target.closest('.ures-edit-btn');
        if (btn) {
            e.preventDefault();
            open(btn);
            return;
        }
        if (e.target.closest('.ures-edit-set')) {
            var box = menu.querySelector('.ures-edit-input');
            pick(box ? box.value : '');
            return;
        }
        var choice = e.target.closest('.ures-edit-menu button');
        if (choice) {
            pick(choice.dataset.value);
            return;
        }
        if (document.body.classList.contains('ures-dirty') && e.target.closest('.opt-header-actions')) {
            e.preventDefault();
            e.stopPropagation();
            var bar = document.getElementById('reload-bar');
            if (bar) {
                bar.classList.remove('nudge');
                void bar.offsetWidth;
                bar.classList.add('nudge');
            }
        }
    }, true);

    document.addEventListener('keydown', function(e) {
        if (e.key !== 'Enter' || !e.target.classList || !e.target.classList.contains('ures-edit-input')) return;
        e.preventDefault();
        pick(e.target.value);
    });

    // Captured, so a scroll inside any container closes it too
    document.addEventListener('scroll', function() {
        if (menu && menu.matches(':popover-open')) menu.hidePopover();
    }, {capture: true, passive: true});

    // An Optimizer row of an opened product's card edits nothing.
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('.opt-store .ures-edit-btn').forEach(function(btn) {
            if (!editable(listRows(btn))) btn.remove();
        });
    });
})();
