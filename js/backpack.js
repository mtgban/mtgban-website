// The backpack: cards collected across searches with a count each, kept in
// localStorage (synced by user-state.js), shown in a side panel from the
// navbar, and sent to Upload as one list.
(function () {
    "use strict";

    var KEY = "mtgban_backpack";
    var EMPTY_AFTER_KEY = "mtgban_backpack_empty_after";
    var PENDING_KEY = "mtgban_backpack_pending_clear";
    var SENT_KEY = "mtgban_backpack_sent";
    var UNDO_KEY = "mtgban_backpack_undo";
    var ACTIVE_KEY = "mtgban_backpack_active";
    var TABS_KEY = "mtgban_backpack_tabs";
    var NAME_MAX = 40;
    // A dragged panel row carries its key under this type, which only the
    // backpack tabs take.
    var DRAG_TYPE = "application/x-mtgban-backpack";
    var TAB_DRAG_TYPE = "application/x-mtgban-backpack-tab";
    var UNDO_MAX = 20;
    // The reader's tier sets each backpack's size and how many backpacks
    // they keep; the page's base template hands both over.
    var MAX = window.BAN_BACKPACK_MAX > 0 ? window.BAN_BACKPACK_MAX : 100;
    var TABS = window.BAN_BACKPACK_TABS > 0 ? window.BAN_BACKPACK_TABS : 1;
    var MAX_QTY = 999;

    var CONDS = ListStorage.backpackConds;

    // read drops entries without a string id, holds each qty to 1..999 and
    // gives each a grade, NM when it has none, and a backpack, 1 when it
    // has none.
    function read() {
        return ListStorage.read(KEY).filter(function (e) { return e && typeof e.id === "string" && e.id !== ""; }).map(function (e) {
            e.qty = Math.max(1, Math.min(MAX_QTY, parseInt(e.qty, 10) || 1));
            e.cond = ListStorage.backpackCond(e);
            e.pack = ListStorage.backpackPack(e);
            return e;
        });
    }
    // An entry is one card in one grade in one backpack; key names it.
    var key = ListStorage.backpackKey;
    // idOf is the card a key names, and packOf its backpack.
    function idOf(k) { return String(k).split("/").pop().split("|")[0]; }
    function packOf(k) {
        var cut = String(k).indexOf("/");
        return cut < 0 ? 1 : ListStorage.backpackPack({ pack: k.slice(0, cut) });
    }
    function find(list, k) {
        for (var i = 0; i < list.length; i++) { if (key(list[i]) === k) return i; }
        return -1;
    }
    // now stamps on the server's clock when user-state.js has one.
    function now() { return window.UserState && typeof window.UserState.now === "function" ? window.UserState.now() : Date.now(); }
    function live() { return read().filter(ListStorage.isLive); }
    // tabs lists the backpacks in strip order, each {pack, name}: the synced
    // list, backpack 1 alone when there is none, then any backpack holding
    // cards the list does not name, so no card is out of reach.
    function tabs() {
        var saved;
        try { saved = JSON.parse(localStorage.getItem(TABS_KEY) || "[]"); } catch (e) { saved = []; }
        if (!Array.isArray(saved) || !saved.length) saved = [{ pack: 1 }];
        var out = [], seen = {};
        saved.forEach(function (t) {
            var p = t && ListStorage.backpackPack(t);
            if (!p || seen[p]) return;
            seen[p] = true;
            out.push({ pack: p, name: String(t.name || "").slice(0, NAME_MAX) || "Backpack " + p });
        });
        live().map(function (e) { return e.pack; }).sort(function (a, b) { return a - b; }).forEach(function (p) {
            if (seen[p]) return;
            seen[p] = true;
            out.push({ pack: p, name: "Backpack " + p });
        });
        return out;
    }
    function saveTabs(list) { try { localStorage.setItem(TABS_KEY, JSON.stringify(list)); } catch (e) {} }

    // active is the backpack the search buttons and the panel act on, the
    // first tab when the one last picked is gone.
    function active() {
        var p;
        try { p = ListStorage.backpackPack({ pack: localStorage.getItem(ACTIVE_KEY) }); } catch (e) { p = 1; }
        var list = tabs();
        return list.some(function (t) { return t.pack === p; }) ? p : list[0].pack;
    }
    function setActive(p) { try { localStorage.setItem(ACTIVE_KEY, String(p)); } catch (e) {} }

    // sentPack is, on the Upload page showing a send's cards, the backpack
    // that send came from, which the page takes from whatever tab is open.
    var sentPack = 0;
    function source() { return sentPack || active(); }
    function packName(p) {
        var list = tabs();
        if (list.length < 2) return "the backpack";
        var t = list.filter(function (x) { return x.pack === p; })[0];
        return t ? t.name : "the backpack";
    }
    function inPack(p) { return live().filter(function (e) { return e.pack === p; }); }
    // ordered is backpack p's own order, the active one's by default,
    // newest first and a card's grades best first, which Clear, a send and
    // the Upload list follow; the panel shows it under the reader's sort.
    function ordered(p) {
        return inPack(p || active()).sort(function (a, b) { return (b.t || 0) - (a.t || 0) || CONDS.indexOf(a.cond) - CONDS.indexOf(b.cond); });
    }
    // A Clear tombstones every card, so keep as many tombstones as cards.
    function save(list) {
        var kept = ListStorage.capBackpack(list, MAX, MAX * TABS).map(function (e) { return e.del ? ListStorage.backpackGone(e) : e; });
        ListStorage.save(KEY, kept, kept.length, MAX * TABS);
    }
    // full says, with a toast, when backpack p or all of them together have
    // no room for another product.
    function full(p) {
        if (inPack(p).length >= MAX) toast("Backpack is full (" + MAX + " products)");
        else if (live().length >= MAX * TABS) toast("Backpacks are full (" + MAX * TABS + " products in all)");
        else return false;
        return true;
    }

    function count() {
        var copies = 0, cards = 0;
        inPack(active()).forEach(function (e) { copies += e.qty || 1; cards++; });
        return { copies: copies, cards: cards };
    }

    function toast(msg) {
        var t = document.getElementById("m-fav-toast") || document.getElementById("desktop-fav-toast") || document.getElementById("backpack-toast");
        if (!t) {
            t = document.createElement("div");
            t.setAttribute("class", "search-toast");
            t.setAttribute("id", "backpack-toast");
            document.body.appendChild(t);
        }
        t.textContent = msg;
        t.classList.add("show");
        setTimeout(function () { t.classList.remove("show"); }, 2000);
    }

    // ---- undo ----

    // The tab's undo steps, oldest first: each holds the entries one change
    // touched as they were before it, {k, gone: true} for one not in, and
    // {tabs} for the backpack list when the change was to it.
    function undoSteps() {
        try {
            var s = JSON.parse(sessionStorage.getItem(UNDO_KEY) || "[]");
            return Array.isArray(s) ? s : [];
        } catch (e) { return []; }
    }
    function saveUndoSteps(steps) {
        try { sessionStorage.setItem(UNDO_KEY, JSON.stringify(steps.slice(-UNDO_MAX))); } catch (e) {}
    }

    // remember records the entries keys name in list before a change to
    // them, and the backpack list when given it.
    function remember(list, keys, tabsBefore) {
        var step = keys.map(function (k) {
            var i = find(list, k);
            if (i >= 0 && !list[i].del) return JSON.parse(JSON.stringify(list[i]));
            return { k: k, gone: true };
        });
        if (tabsBefore) step.push({ tabs: tabsBefore });
        var steps = undoSteps();
        steps.push(step);
        saveUndoSteps(steps);
    }

    // undo puts back the cards the last change touched, stamped now so the
    // sync merge keeps them over what that change wrote, and opens the
    // backpack they are in.
    function undo() {
        var steps = undoSteps();
        var step = steps.pop();
        if (!step) return false;
        saveUndoSteps(steps);
        var list = read();
        var t = now();
        var pack = 0;
        step.forEach(function (was) {
            if (was.tabs) { saveTabs(was.tabs); return; }
            var k = was.k || key(was);
            pack = pack || packOf(k);
            var idx = find(list, k);
            if (was.gone) {
                if (idx >= 0 && !list[idx].del) { list[idx].del = t; list[idx].m = t; }
                return;
            }
            if (idx >= 0) list.splice(idx, 1);
            was.m = t;
            list.unshift(was);
        });
        save(list);
        if (pack) setActive(pack);
        return true;
    }

    // addTab opens a new, empty backpack under the lowest number free.
    function addTab() {
        var list = tabs();
        if (list.length >= TABS) return false;
        var p = 1;
        while (list.some(function (t) { return t.pack === p; })) p++;
        list.push({ pack: p, name: "Backpack " + p });
        saveTabs(list);
        setActive(p);
        return true;
    }

    // moveTab puts backpack p where backpack q is in the strip, q stepping
    // aside toward where p was.
    function moveTab(p, q) {
        var list = tabs();
        var packs = list.map(function (t) { return t.pack; });
        var from = packs.indexOf(p), to = packs.indexOf(q);
        if (from < 0 || to < 0 || from === to) return false;
        list.splice(to, 0, list.splice(from, 1)[0]);
        saveTabs(list);
        return true;
    }

    // renameTab names backpack p; a blank name keeps the one it has.
    function renameTab(p, name) {
        name = String(name || "").trim().slice(0, NAME_MAX);
        if (!name) return;
        saveTabs(tabs().map(function (t) { return t.pack === p ? { pack: t.pack, name: name } : t; }));
    }

    // deleteTab drops backpack p and its cards as one undo step; the last
    // backpack stays.
    function deleteTab(p) {
        var before = tabs();
        if (before.length < 2) return;
        var list = read();
        var t = now();
        var gone = list.filter(function (e) { return !e.del && e.pack === p; });
        remember(list, gone.map(key), before);
        gone.forEach(function (e) { e.del = t; e.m = t; });
        save(list);
        saveTabs(before.filter(function (x) { return x.pack !== p; }));
    }

    function toastCeiling() { toast(MAX_QTY + " copies is the most for one product"); }

    // add puts one more NM copy of the row's card in the active backpack; a
    // removed card comes back as one copy.
    function add(data) {
        if (!data || !data.id) return false;
        var list = read();
        var t = now();
        var p = active();
        var k = key({ id: data.id, pack: p });
        var idx = find(list, k);
        if (idx >= 0 && !list[idx].del) {
            var next = Math.min(MAX_QTY, list[idx].qty + 1);
            if (next === list[idx].qty) { toastCeiling(); return false; }
            remember(list, [k]);
            list[idx].qty = next;
            list[idx].m = t;
        } else {
            if (full(p)) return false;
            remember(list, [k]);
            if (idx >= 0) list.splice(idx, 1);
            list.unshift({
                id: data.id, name: data.name || "", edition: data.edition || "", set: data.set || "",
                number: data.number || "", finishTag: data.finishTag || "", finishClass: data.finishClass || "",
                img: data.img || "", cw: !!data.cw, cond: "NM", pack: p, qty: 1, t: t, m: t
            });
        }
        save(list);
        return true;
    }

    // setQty sets the copies of the entry k names; below one removes it.
    function setQty(k, qty) {
        var list = read();
        var t = now();
        for (var i = 0; i < list.length; i++) {
            if (key(list[i]) !== k || list[i].del) continue;
            var next = Math.min(MAX_QTY, qty);
            if (qty >= 1 && next === list[i].qty) { if (qty > MAX_QTY) toastCeiling(); return; }
            remember(list, [k]);
            if (qty < 1) { list[i].del = t; list[i].m = t; }
            else { list[i].qty = next; list[i].m = t; }
        }
        save(list);
    }

    function remove(k) { setQty(k, 0); }

    // setCond moves the entry k names to grade cond, keeping its copies and
    // its place; when the card already holds that grade the copies join it.
    function setCond(k, cond) { relocate(k, cond, 0); }

    // moveTo moves the entry k names, every copy, to backpack p; when p holds
    // the card in that grade the copies join it.
    function moveTo(k, p) { return relocate(k, "", p); }

    // relocate moves the entry k names to grade cond in backpack p, each
    // left as it is when not given, keeping its copies and its place. A new
    // entry in another backpack needs room there, and copies joining one
    // must stay within 999; says whether it moved.
    function relocate(k, cond, p) {
        var list = read();
        var i = find(list, k);
        if (i < 0 || list[i].del) return false;
        var e = list[i];
        cond = cond || e.cond;
        p = p || e.pack;
        if (cond === e.cond && p === e.pack) return false;
        var to = key({ id: e.id, cond: cond, pack: p });
        var j = find(list, to);
        var joining = j >= 0 && !list[j].del;
        if (!joining && p !== e.pack && inPack(p).length >= MAX) {
            toast(packName(p) + " is full (" + MAX + " products)");
            return false;
        }
        if (joining && list[j].qty + e.qty > MAX_QTY) { toastCeiling(); return false; }
        var t = now();
        remember(list, [k, to]);
        if (j >= 0 && !list[j].del) {
            list[j].qty += e.qty;
            list[j].m = t;
        } else {
            var moved = JSON.parse(JSON.stringify(e));
            moved.cond = cond;
            moved.pack = p;
            moved.m = t;
            if (j >= 0) list.splice(j, 1);
            list.unshift(moved);
        }
        e.del = t; e.m = t;
        save(list);
        return true;
    }

    // addCond adds one copy of the card k names in grade cond, a grade the
    // card does not hold yet.
    function addCond(k, cond) {
        var list = read();
        var i = find(list, k);
        if (i < 0 || list[i].del) return false;
        var to = key({ id: list[i].id, cond: cond, pack: list[i].pack });
        var j = find(list, to);
        if (j >= 0 && !list[j].del) return false;
        if (full(list[i].pack)) return false;
        remember(list, [to]);
        var dup = JSON.parse(JSON.stringify(list[i]));
        dup.cond = cond;
        dup.qty = 1;
        dup.m = now();
        if (j >= 0) list.splice(j, 1);
        list.unshift(dup);
        save(list);
        return true;
    }

    // take takes counts[key] copies of each entry out as one undo step, the
    // entry itself once none is left, and says how many copies went.
    function take(counts) {
        var list = read();
        var t = now();
        var hit = list.filter(function (e) { return !e.del && counts[key(e)] > 0; });
        if (!hit.length) return 0;
        remember(list, hit.map(key));
        var copies = 0;
        hit.forEach(function (e) {
            var n = Math.min(e.qty, counts[key(e)]);
            copies += n;
            if (n === e.qty) e.del = t; else e.qty -= n;
            e.m = t;
        });
        save(list);
        return copies;
    }

    // clear removes the entries keys names, or every entry in every backpack
    // without it.
    function clear(keys) {
        var list = read();
        var t = now();
        var gone = list.filter(function (e) { return !e.del && (!keys || keys.indexOf(key(e)) !== -1); });
        if (!gone.length) return;
        remember(list, gone.map(key));
        gone.forEach(function (e) { e.del = t; e.m = t; });
        save(list);
    }

    function emptyAfter() { try { return localStorage.getItem(EMPTY_AFTER_KEY) === "1"; } catch (e) { return false; } }
    function setEmptyAfter(on) { try { localStorage.setItem(EMPTY_AFTER_KEY, on ? "1" : "0"); } catch (e) {} }

    // The entries a send asked to empty after, by key, held in this tab
    // until Upload shows their results; every send replaces or removes them.
    function setPending(keys) {
        try {
            if (keys) sessionStorage.setItem(PENDING_KEY, JSON.stringify(keys));
            else sessionStorage.removeItem(PENDING_KEY);
        } catch (e) {}
    }
    function takePending() {
        try {
            var s = sessionStorage.getItem(PENDING_KEY);
            sessionStorage.removeItem(PENDING_KEY);
            return s ? JSON.parse(s) : null;
        } catch (e) { return null; }
    }

    // sendForm builds the Upload POST the search sidebar and favorites use,
    // with a quantity and a grade beside each card.
    function sendForm(mode) {
        var entries = ordered();
        var form = document.createElement("form");
        form.setAttribute("method", "post");
        form.setAttribute("action", "/upload");
        form.style.display = "none";
        var m = document.createElement("input");
        m.type = "hidden"; m.name = "mode"; m.value = mode === "buylist" ? "true" : "false";
        form.appendChild(m);
        entries.forEach(function (e) {
            var h = document.createElement("input");
            h.type = "hidden"; h.name = "hashes"; h.value = e.id;
            form.appendChild(h);
            var q = document.createElement("input");
            q.type = "hidden"; q.name = "hashesQtys"; q.value = String(e.qty || 1);
            form.appendChild(q);
            var c = document.createElement("input");
            c.type = "hidden"; c.name = "hashesCond"; c.value = e.cond;
            form.appendChild(c);
        });
        return form;
    }

    // Upload checks its own grant; a page without BAN_BACKPACK sends as before.
    function canUpload() { return !(window.BAN_BACKPACK && window.BAN_BACKPACK.canUpload === false); }

    function send(mode) {
        if (!canUpload() || !ordered().length) return;
        var form = sendForm(mode);
        setPending(emptyAfter() ? ordered().map(key) : null);
        try { sessionStorage.setItem(SENT_KEY, JSON.stringify({ pack: active(), ids: ordered().map(function (e) { return e.id; }) })); } catch (e) {}
        document.body.appendChild(form);
        form.submit();
    }

    // clearIfPriced empties the backpack on the Upload page whose results
    // are the cards a send asked to empty after. Any other Upload page, an
    // error or the bare form, drops the request and keeps the backpack.
    function clearIfPriced() {
        var ban = window.BAN_BACKPACK;
        if (!ban || !("priced" in ban)) return;
        var sent = null;
        try { sent = JSON.parse(sessionStorage.getItem(SENT_KEY) || "null"); } catch (e) {}
        if (sent && Array.isArray(sent.ids) && Array.isArray(ban.priced) && sent.ids.join(",") === ban.priced.join(",")) sentPack = ListStorage.backpackPack(sent);
        var pending = takePending();
        if (!Array.isArray(pending) || !Array.isArray(ban.priced)) return;
        var ids = pending.map(idOf);
        if (ids.join(",") === ban.priced.join(",")) clear(pending);
    }

    // ---- result rows and the navbar ----

    // describe sets a button's title, its accessible name, which the copy
    // count it shows would otherwise become, and the text labels the phone
    // menu and the collapsed desktop menu give it.
    function describe(b, s) {
        b.setAttribute("title", s);
        b.setAttribute("aria-label", s);
        b.querySelectorAll(".pack-btn-label, .qi-label").forEach(function (n) { n.textContent = s; });
    }

    // markRows marks each card's buttons, which add and take NM copies in the
    // active backpack: the count is those NM copies, and a card held there
    // only in other grades shows no minus and words the add for NM.
    function markRows() {
        var nm = {}, other = {};
        inPack(active()).forEach(function (e) { if (e.cond === "NM") nm[e.id] = e.qty; else other[e.id] = true; });
        document.querySelectorAll(".pack-btn").forEach(function (b) {
            var id = b.getAttribute("data-card-id");
            var qty = nm[id], grade = other[id] ? " NM" : "";
            b.classList.toggle("active", !!(qty || other[id]));
            describe(b, qty ? "Add another" + grade + " copy" : other[id] ? "Add an NM copy" : "Add to backpack");
            var span = b.querySelector(".pack-btn-count");
            if (span) { span.textContent = qty ? String(qty) : ""; span.hidden = !qty; }
        });
        document.querySelectorAll(".pack-minus-btn").forEach(function (b) {
            var id = b.getAttribute("data-card-id");
            var qty = nm[id];
            b.hidden = !qty;
            describe(b, qty > 1 ? "Remove one" + (other[id] ? " NM" : "") + " copy" : other[id] ? "Remove the NM copy" : "Remove from backpack");
        });
    }

    function markNav() {
        var btn = document.getElementById("nav-backpack");
        if (!btn) return;
        btn.hidden = false;
        var c = count();
        var span = document.getElementById("nav-backpack-count");
        if (span) { span.textContent = String(c.copies); span.hidden = c.copies === 0; }
        // Named by aria-label, which hides the badge, so the name carries it
        btn.setAttribute("aria-label", c.copies ? "Backpack, " + c.copies + (c.copies === 1 ? " copy" : " copies") : "Backpack");
        markNavMenu(btn);
    }

    // markNavMenu fills the switcher the navbar button shows on hover while
    // there are backpacks to pick from: picking one sends the result rows'
    // buttons there, without opening the panel. Its title would cover it, so
    // markNav's aria-label names the button; a rebuild keeps a focused pick.
    function markNavMenu(btn) {
        var menu = document.getElementById("nav-backpack-menu");
        if (!menu) return;
        var list = tabs(), cur = active();
        var focused = document.activeElement && document.activeElement.parentNode === menu ? document.activeElement.getAttribute("data-pack") : null;
        menu.hidden = list.length < 2;
        if (menu.hidden) btn.setAttribute("title", "Backpack"); else btn.removeAttribute("title");
        while (menu.children.length) menu.children[0].remove();
        if (menu.hidden) return;
        var copies = {};
        live().forEach(function (e) { copies[e.pack] = (copies[e.pack] || 0) + e.qty; });
        list.forEach(function (t) {
            var on = t.pack === cur;
            var b = text("button", "nav2-backpack-pick" + (on ? " active" : ""));
            b.setAttribute("type", "button");
            b.setAttribute("aria-pressed", on ? "true" : "false");
            b.setAttribute("data-pack", String(t.pack));
            b.append(text("span", "nav2-backpack-pick-name", t.name), text("span", "nav2-backpack-pick-count", String(copies[t.pack] || 0)));
            b.addEventListener("click", function () {
                setActive(t.pack);
                render();
            });
            menu.appendChild(b);
            if (focused === String(t.pack)) b.focus();
        });
    }

    window.addToBackpack = function (btn) {
        var data = window.CardRow && window.CardRow.read ? window.CardRow.read(btn) : null;
        if (!data || !data.id) {
            var id = btn.getAttribute("data-card-id");
            if (!id) return;
            data = { id: id, name: "" };
        }
        if (add(data)) render();
    };

    // takeFromBackpack takes one NM copy of the button's card out, the last
    // one with the entry. Taking the last hides the minus, so a focused minus
    // hands focus to the add button beside it.
    window.takeFromBackpack = function (btn) {
        var id = btn.getAttribute("data-card-id");
        var k = key({ id: id, pack: active() });
        var e = live().filter(function (x) { return key(x) === k; })[0];
        if (!e) return;
        var focused = document.activeElement === btn;
        setQty(k, e.qty - 1);
        render();
        if (!focused || !btn.hidden || !btn.parentNode) return;
        btn.parentNode.querySelectorAll(".pack-btn").forEach(function (add) {
            if (add.getAttribute("data-card-id") === id) add.focus();
        });
    };

    // ---- the Upload optimizer ----

    // picked adds up the copies of each entry in a store section's ticked
    // rows, in backpack p, by each row's grade. A row without one, from an
    // upload that ignored grades, takes the card's copies in any grade, best
    // first.
    function picked(section, p) {
        var counts = {}, any = {};
        section.querySelectorAll("tr[data-opt-id]").forEach(function (tr) {
            if (tr.classList.contains("opt-removed")) return;
            var id = tr.getAttribute("data-opt-id"), cond = tr.getAttribute("data-opt-cond");
            var n = parseInt(tr.getAttribute("data-load-qty"), 10) || 1;
            if (!cond) { any[id] = (any[id] || 0) + n; return; }
            var k = key({ id: id, cond: cond, pack: p });
            counts[k] = (counts[k] || 0) + n;
        });
        inPack(p).sort(function (a, b) { return CONDS.indexOf(a.cond) - CONDS.indexOf(b.cond); }).forEach(function (e) {
            var k = key(e);
            var n = Math.min(any[e.id] || 0, e.qty - (counts[k] || 0));
            if (n <= 0) return;
            counts[k] = (counts[k] || 0) + n;
            any[e.id] -= n;
        });
        return counts;
    }

    // markSections shows a section's button while one of its ticked rows is
    // a card in the backpack.
    function markSections() {
        var by = {};
        live().forEach(function (e) { by[key(e)] = true; });
        document.querySelectorAll(".pack-take-btn").forEach(function (b) {
            var section = b.closest(".opt-store");
            b.hidden = !section || !Object.keys(picked(section, source())).some(function (k) { return by[k]; });
        });
    }

    // takeRowsFromBackpack takes the copies a store section's ticked rows
    // list out of the backpack they came from, once sent to that store and
    // the reader confirms it. Taking the last hides the button, so a focused
    // one hands focus to the section's fold button.
    window.takeRowsFromBackpack = function (btn) {
        var section = btn.closest(".opt-store");
        if (!section) return;
        var doTake = function () {
            var focused = document.activeElement === btn;
            var p = source();
            var copies = take(picked(section, p));
            if (!copies) return;
            render();
            toast("Removed " + copies + (copies === 1 ? " copy" : " copies") + " from " + packName(p));
            var fold = section.querySelector(".section-fold");
            if (focused && btn.hidden && fold) fold.focus();
        };
        var ask = "Remove this store's ticked cards from " + packName(source()) + "?";
        // The dialog hands focus back to the button before it calls doTake
        if (typeof window.confirmDialog === "function") window.confirmDialog(ask, doTake, { confirmLabel: "Remove" });
        else if (window.confirm(ask)) doTake();
    };

    // ---- sorting the panel ----

    // The panel's sorts, each with its label, the way it runs when picked
    // and what each way reads as, which names the arrow that reverses it.
    // They order the panel only; Clear and a send keep the backpack's own
    // order.
    var SORTS = {
        added: { label: "Added", dir: "desc", asc: "Oldest first", desc: "Newest first" },
        name: { label: "Name", dir: "asc", asc: "A–Z", desc: "Z–A" },
        edition: { label: "Edition", dir: "asc", asc: "A–Z", desc: "Z–A" },
        retail: { label: "Retail $", dir: "desc", asc: "Lowest first", desc: "Highest first" },
        buylist: { label: "Buylist $", dir: "desc", asc: "Lowest first", desc: "Highest first" }
    };
    var SORT_KEY = "mtgban_backpack_sort";
    var PRICES_KEY = "mtgban_backpack_prices";
    // How long the tab trusts a fetched price, the most ids /data/prices
    // takes at once, and the gap between calls, under the signed reader's
    // three requests a second.
    var PRICE_TTL = 60 * 60 * 1000;
    var PRICE_BATCH = 50;
    var PRICE_GAP = 400;

    function sortPref() {
        var s;
        try { s = JSON.parse(localStorage.getItem(SORT_KEY) || "null"); } catch (e) { s = null; }
        if (!s || !SORTS[s.by]) return { by: "added", dir: SORTS.added.dir };
        return { by: s.by, dir: s.dir === "asc" ? "asc" : "desc" };
    }
    function setSortPref(s) { try { localStorage.setItem(SORT_KEY, JSON.stringify(s)); } catch (e) {} }
    function isPriceSort(by) { return by === "retail" || by === "buylist"; }

    // prices are each card's NM prices as /data/prices gave them, by id,
    // stamped when fetched; a card it priced at nothing keeps the stamp.
    // pricesSaved holds the last save too, for a tab whose storage refuses
    // it, which would otherwise fetch the same prices again on every draw.
    var pricesSaved = {};
    function prices() {
        var p;
        try { p = JSON.parse(sessionStorage.getItem(PRICES_KEY) || "{}"); } catch (e) { p = null; }
        if (!p || typeof p !== "object") p = {};
        Object.keys(pricesSaved).forEach(function (id) {
            if (!(p[id] && p[id].at >= pricesSaved[id].at)) p[id] = pricesSaved[id];
        });
        return p;
    }
    function savePrices(p) {
        var t = Date.now();
        Object.keys(p).forEach(function (id) { if (!(t - p[id].at < PRICE_TTL)) delete p[id]; });
        pricesSaved = p;
        try { sessionStorage.setItem(PRICES_KEY, JSON.stringify(p)); } catch (e) {}
    }
    // priceOf is the entry's card's NM price on the side by names, with the
    // store quoting it, or null when there is none.
    function priceOf(e, by, p) {
        var got = p[e.id];
        var v = got && (by === "retail" ? got.sellPrice : got.buyPrice);
        return typeof v === "number" ? { v: v, store: by === "retail" ? got.sellVendor : got.buyVendor } : null;
    }

    function cmpText(a, b) { return String(a || "").localeCompare(String(b || ""), undefined, { numeric: true, sensitivity: "base" }); }
    // cmpCard orders cards by name and printing, and byGrade a card's
    // entries best first; byCard keeps a card's entries together, best
    // grade first, under the field a sort compares.
    function cmpCard(a, b) {
        return cmpText(a.name || a.id, b.name || b.id) || cmpText(a.edition, b.edition) || cmpText(a.number, b.number) || cmpText(a.id, b.id);
    }
    function byGrade(a, b) { return CONDS.indexOf(a.cond) - CONDS.indexOf(b.cond); }
    function byCard(a, b) { return cmpCard(a, b) || byGrade(a, b); }

    // viewOrder puts the entries in the order the reader picked; a card
    // with no price yet sorts last whichever way a price sort runs.
    function viewOrder(entries, s) {
        var dir = s.dir === "asc" ? 1 : -1;
        var p = isPriceSort(s.by) ? prices() : null;
        return entries.slice().sort(function (a, b) {
            switch (s.by) {
            case "name":
                return dir * cmpCard(a, b) || byGrade(a, b);
            case "edition":
                return dir * (cmpText(a.edition, b.edition) || cmpText(a.number, b.number)) || byCard(a, b);
            case "retail":
            case "buylist":
                var pa = priceOf(a, s.by, p), pb = priceOf(b, s.by, p);
                if (!pa !== !pb) return pa ? -1 : 1;
                return (pa && pb && dir * (pa.v - pb.v)) || byCard(a, b);
            default:
                return dir * ((a.t || 0) - (b.t || 0)) || byGrade(a, b);
            }
        });
    }

    // loadPrices fetches, for a price sort in the open panel, the prices the
    // tab lacks for the open backpack's cards, one batch at a time, then
    // redraws the list once. Closing the panel stops it after the call in
    // flight; a refusal stops it until the sort is picked again or the
    // panel reopens.
    var pricesLoading = false, priceRefusal = "";
    function loadPrices() {
        if (pricesLoading || priceRefusal || !panel || !panel.classList.contains("open") || !isPriceSort(sortPref().by)) return;
        var have = prices(), t = Date.now(), seen = {};
        var ids = inPack(active()).map(function (e) { return e.id; }).filter(function (id) {
            if (seen[id] || (have[id] && t - have[id].at < PRICE_TTL)) return false;
            seen[id] = true;
            return true;
        });
        if (!ids.length || typeof window.fetch !== "function") return;
        pricesLoading = true;
        var batches = [];
        for (var i = 0; i < ids.length; i += PRICE_BATCH) batches.push(ids.slice(i, i + PRICE_BATCH));
        var done = 0;
        var note = function () { setSortNote("Loading prices" + (batches.length > 1 ? " " + (done + 1) + "/" + batches.length : "") + "…"); };
        var finish = function (refusal) {
            pricesLoading = false;
            priceRefusal = refusal || "";
            renderPanel();
        };
        var next = function (retried) {
            if (done === batches.length || !panel.classList.contains("open")) { finish(); return; }
            note();
            var batch = batches[done];
            window.fetch("/data/prices/" + encodeURIComponent(batch.join(","))).then(function (r) {
                if (r.status === 429 && !retried) { setTimeout(function () { next(true); }, 3 * PRICE_GAP); return; }
                if (!r.ok) { finish(priceRefusalText(r.status)); return; }
                return r.json().then(function (data) {
                    var p = prices(), at = Date.now();
                    batch.forEach(function (id) {
                        var got = data && data[id] || {};
                        p[id] = { sellPrice: got.sellPrice, sellVendor: got.sellVendor || "", buyPrice: got.buyPrice, buyVendor: got.buyVendor || "", at: at };
                    });
                    savePrices(p);
                    done++;
                    setTimeout(function () { next(false); }, done === batches.length ? 0 : PRICE_GAP);
                });
            }).catch(function () { finish(priceRefusalText(0)); });
        };
        next(false);
    }

    function priceRefusalText(status) {
        if (status === 429) return "Too many requests, pick the sort again in a moment";
        if (status === 401) return "Log in to sort by price";
        return "Prices could not load";
    }

    // ---- the panel ----

    var panel = null, overlay = null, stripEl = null, listEl = null, countEl = null, emptyEl = null;
    var sendRetail = null, sendBuylist = null, emptySwitch = null, undoBtn = null;
    var sortBar = null, sortSel = null, sortDirBtn = null, sortNote = null;
    // draggedTab is the backpack whose tab is being dragged along the strip.
    var draggedTab = 0;

    function text(tag, cls, s) {
        var n = document.createElement(tag);
        if (cls) n.setAttribute("class", cls);
        if (s != null) n.textContent = s;
        return n;
    }

    function build() {
        if (panel) return;
        var mobile = document.body.classList.contains("mobile");

        overlay = text("div", "backpack-overlay");
        overlay.setAttribute("id", "backpack-overlay");
        overlay.addEventListener("click", close);

        panel = text("aside", "backpack-panel" + (mobile ? " backpack-sheet" : ""));
        panel.setAttribute("id", "backpack-panel");
        panel.setAttribute("role", "dialog");
        panel.setAttribute("aria-modal", "true");
        panel.setAttribute("aria-labelledby", "backpack-title");

        if (mobile) {
            var handle = text("div", "m-drawer-handle");
            handle.appendChild(text("span"));
            handle.addEventListener("click", close);
            panel.appendChild(handle);
        }

        var header = text("div", "backpack-header");
        var title = text("h2", "backpack-title", "Backpack");
        title.setAttribute("id", "backpack-title");
        countEl = text("span", "backpack-count");
        countEl.setAttribute("id", "backpack-count");
        var closeBtn = text("button", "backpack-close", "×");
        closeBtn.setAttribute("id", "backpack-close");
        closeBtn.setAttribute("type", "button");
        closeBtn.setAttribute("aria-label", "Close");
        closeBtn.addEventListener("click", close);
        header.append(title, countEl, closeBtn);

        stripEl = text("div", "backpack-tabs");
        stripEl.setAttribute("id", "backpack-tabs");
        stripEl.setAttribute("role", "tablist");
        stripEl.setAttribute("aria-label", "Backpacks");
        // The strip draws no scrollbar, so a vertical wheel scrolls it sideways.
        stripEl.addEventListener("wheel", function (ev) {
            if (!ev.deltaY || Math.abs(ev.deltaX) > Math.abs(ev.deltaY) || stripEl.scrollWidth <= stripEl.clientWidth) return;
            ev.preventDefault();
            stripEl.scrollLeft += ev.deltaY * (ev.deltaMode === 1 ? 16 : ev.deltaMode === 2 ? stripEl.clientWidth : 1);
        }, { passive: false });

        listEl = text("div", "backpack-list");
        listEl.setAttribute("id", "backpack-list");
        emptyEl = text("p", "backpack-empty", "Add products from any search with the backpack button.");
        emptyEl.setAttribute("id", "backpack-empty");

        var footer = text("div", "backpack-footer");
        var label = text("label", "backpack-switch");
        emptySwitch = document.createElement("input");
        emptySwitch.type = "checkbox";
        emptySwitch.setAttribute("id", "backpack-empty-after");
        emptySwitch.checked = emptyAfter();
        emptySwitch.addEventListener("change", function () { setEmptyAfter(emptySwitch.checked); });
        label.append(emptySwitch, text("span", null, "Empty the backpack after sending"));

        // One row: the sort, Undo and Clear as icons, the sends taking the rest.
        buildSortBar();
        var actions = text("div", "backpack-actions");
        undoBtn = text("button", "backpack-btn backpack-btn-plain backpack-btn-icon");
        undoBtn.setAttribute("id", "backpack-undo");
        undoBtn.setAttribute("aria-label", "Undo");
        undoBtn.setAttribute("title", "Undo");
        icon(undoBtn, "undo-2");
        undoBtn.setAttribute("type", "button");
        undoBtn.addEventListener("click", function () { if (undo()) render(); });
        var clearBtn = text("button", "backpack-btn backpack-btn-plain backpack-btn-icon");
        clearBtn.setAttribute("id", "backpack-clear");
        clearBtn.setAttribute("aria-label", "Empty the backpack");
        clearBtn.setAttribute("title", "Empty the backpack");
        icon(clearBtn, "trash-2");
        clearBtn.setAttribute("type", "button");
        clearBtn.addEventListener("click", function () {
            var keys = ordered().map(key);
            if (!keys.length) return;
            var doClear = function () { clear(keys); render(); };
            // confirm-dialog.js is callback-style; anchored, it covers just the panel.
            if (typeof window.confirmDialog === "function") window.confirmDialog("Empty the backpack?", doClear, { anchor: panel, confirmLabel: "Empty" });
            else if (window.confirm("Empty the backpack?")) doClear();
        });
        sendRetail = text("button", "backpack-btn backpack-btn-retail", "Retail");
        sendRetail.setAttribute("id", "backpack-send-retail");
        sendRetail.setAttribute("type", "button");
        sendRetail.addEventListener("click", function () { send("retail"); });
        sendBuylist = text("button", "backpack-btn backpack-btn-buylist", "Buylist");
        sendBuylist.setAttribute("id", "backpack-send-buylist");
        sendBuylist.setAttribute("type", "button");
        sendBuylist.addEventListener("click", function () { send("buylist"); });
        actions.append(sortBar, undoBtn, clearBtn, sendRetail, sendBuylist);
        if (!canUpload()) {
            sendRetail.setAttribute("title", "Upload needs a higher tier");
            sendBuylist.setAttribute("title", "Upload needs a higher tier");
            emptySwitch.disabled = true;
        }
        footer.append(label, sortNote, actions);

        panel.append(header, stripEl, listEl, emptyEl, footer);
        document.body.append(overlay, panel);
    }

    // buildSortBar makes the sort picker, the button that turns its order
    // around, and the line that says how fetching the prices went.
    function buildSortBar() {
        sortBar = text("div", "backpack-sort");
        sortBar.setAttribute("id", "backpack-sort");
        sortSel = text("select", "backpack-sort-by");
        sortSel.setAttribute("id", "backpack-sort-by");
        sortSel.setAttribute("aria-label", "Sort by");
        sortSel.setAttribute("title", "Sort by");
        Object.keys(SORTS).forEach(function (by) { sortSel.appendChild(option(by, SORTS[by].label, SORTS[by].label)); });
        sortSel.addEventListener("change", function () {
            if (!SORTS[sortSel.value]) return;
            setSortPref({ by: sortSel.value, dir: SORTS[sortSel.value].dir });
            priceRefusal = "";
            renderPanel();
        });
        sortDirBtn = text("button", "backpack-sort-dir");
        sortDirBtn.setAttribute("id", "backpack-sort-dir");
        sortDirBtn.setAttribute("type", "button");
        sortDirBtn.addEventListener("click", function () {
            var s = sortPref();
            setSortPref({ by: s.by, dir: s.dir === "asc" ? "desc" : "asc" });
            renderPanel();
        });
        sortNote = text("span", "backpack-sort-note");
        sortNote.setAttribute("id", "backpack-sort-note");
        sortNote.setAttribute("aria-live", "polite");
        sortBar.append(sortSel, sortDirBtn);
    }

    // icon puts the lucide icon named in button b, painted once lucide has
    // loaded.
    function icon(b, name) {
        while (b.children.length) b.children[0].remove();
        var i = text("i");
        i.setAttribute("data-lucide", name);
        b.appendChild(i);
        if (typeof window.paintIcons === "function") window.paintIcons(b);
    }

    function setSortNote(s) {
        sortNote.textContent = s;
        sortNote.hidden = !s || sortBar.hidden;
    }

    // renderSortBar shows the sort picked, while there is more than one
    // entry to order.
    function renderSortBar(s, n) {
        sortBar.hidden = n < 2;
        sortSel.value = s.by;
        icon(sortDirBtn, s.dir === "asc" ? "arrow-up-narrow-wide" : "arrow-down-wide-narrow");
        sortDirBtn.setAttribute("aria-label", SORTS[s.by][s.dir] + ", reverse");
        sortDirBtn.setAttribute("title", SORTS[s.by][s.dir]);
        setSortNote(isPriceSort(s.by) ? priceRefusal || (pricesLoading ? sortNote.textContent : "") : "");
    }

    var COND_NAMES = { NM: "Near Mint", SP: "Slightly Played", MP: "Moderately Played", HP: "Heavily Played", PO: "Poor" };

    function option(value, label, title) {
        var o = text("option", null, label);
        o.value = value;
        o.setAttribute("title", title);
        return o;
    }

    // moveCard moves the entry k names to backpack p and says so.
    function moveCard(k, p) {
        if (!moveTo(k, p)) return;
        render();
        toast("Moved to " + packName(p));
    }

    // condSelect moves the entry to a grade, or adds the card in one more,
    // never offering the grades its other entries hold, or moves it to one
    // of the other backpacks.
    function condSelect(e, held, others) {
        var sel = text("select", "backpack-cond");
        sel.setAttribute("aria-label", "Condition");
        CONDS.forEach(function (c) {
            if (c === e.cond || held.indexOf(c) === -1) sel.appendChild(option(c, c, COND_NAMES[c]));
        });
        var free = CONDS.filter(function (c) { return c !== e.cond && held.indexOf(c) === -1; });
        if (free.length) {
            var group = text("optgroup");
            group.setAttribute("label", "Add another condition");
            free.forEach(function (c) { group.appendChild(option("+" + c, "Also as " + c, COND_NAMES[c])); });
            sel.appendChild(group);
        }
        if (others.length) {
            var to = text("optgroup");
            to.setAttribute("label", "Move to");
            others.forEach(function (t) { to.appendChild(option("@" + t.pack, t.name, "Move every copy to " + t.name)); });
            sel.appendChild(to);
        }
        sel.value = e.cond;
        sel.addEventListener("change", function () {
            var v = sel.value;
            sel.value = e.cond;
            if (v.charAt(0) === "@") {
                moveCard(key(e), parseInt(v.slice(1), 10));
                focusTab(active());
                return;
            }
            var adding = v.charAt(0) === "+";
            if (adding) addCond(key(e), v.slice(1)); else setCond(key(e), v);
            render();
            // The list was rebuilt; keep the keyboard on this entry's grade.
            focusCond(adding ? key(e) : key({ id: e.id, cond: v, pack: e.pack }));
        });
        return sel;
    }

    function focusCond(k) {
        Array.prototype.forEach.call(listEl.children, function (r) {
            var sel = r.getAttribute("data-key") === k && r.querySelector(".backpack-cond");
            if (sel) sel.focus();
        });
    }

    // priceLine is the row's line under a price sort: the card's NM price and
    // who quotes it, or that it has none once the prices are in.
    function priceLine(e, by, p) {
        if (!p[e.id]) return null;
        var got = priceOf(e, by, p);
        if (!got) return text("div", "backpack-row-price none", "No NM price");
        return text("div", "backpack-row-price", "NM $ " + got.v.toFixed(2) + (got.store ? " · " + got.store : ""));
    }

    function row(e, held, others, price) {
        var r = text("div", "backpack-row");
        r.setAttribute("data-card-id", e.id);
        r.setAttribute("data-key", key(e));
        var art = text("div", "backpack-row-art" + (e.cw ? " blurred" : ""));
        if (e.img) {
            var img = document.createElement("img");
            img.setAttribute("src", e.img);
            img.setAttribute("alt", "");
            img.setAttribute("loading", "lazy");
            img.setAttribute("draggable", "false");
            art.appendChild(img);
        }
        // The art is the handle, so the row's text stays selectable.
        if (others.length) {
            art.setAttribute("draggable", "true");
            art.addEventListener("dragstart", function (ev) {
                ev.dataTransfer.setData(DRAG_TYPE, key(e));
                ev.dataTransfer.effectAllowed = "move";
                r.classList.add("dragging");
            });
            art.addEventListener("dragend", function () { r.classList.remove("dragging"); });
        }
        var body = text("div", "backpack-row-body");
        var name = text("div", "backpack-row-name", e.name || e.id);
        var where = text("div", "backpack-row-where", (e.edition || "") + (e.set ? " (" + e.set + ")" : "") + (e.number ? " #" + e.number : ""));
        body.append(name, where);
        if (e.finishTag) body.appendChild(text("span", "backpack-row-finish " + (e.finishClass || ""), e.finishTag));
        if (price) body.appendChild(price);

        // The minus takes the last copy with the card; Undo brings it back.
        var ctl = text("div", "backpack-row-ctl");
        var minus = text("button", "backpack-minus", "−");
        minus.setAttribute("type", "button");
        minus.setAttribute("aria-label", (e.qty || 1) > 1 ? "One fewer" : "Remove");
        minus.addEventListener("click", function () { setQty(key(e), (e.qty || 1) - 1); render(); });
        var qty = text("span", "backpack-qty", String(e.qty || 1));
        var plus = text("button", "backpack-plus", "+");
        plus.setAttribute("type", "button");
        plus.setAttribute("aria-label", "One more");
        plus.addEventListener("click", function () { setQty(key(e), (e.qty || 1) + 1); render(); });
        ctl.append(condSelect(e, held, others), minus, qty, plus);

        r.append(art, body, ctl);
        return r;
    }

    // renderTabs draws the strip: a tab per backpack with its copies, a ×
    // on the open one while there are others, and a + while the tier allows
    // more. One backpack and no room for another shows no strip.
    function renderTabs() {
        var list = tabs(), cur = active();
        while (stripEl.children.length) stripEl.children[0].remove();
        stripEl.hidden = TABS < 2 && list.length < 2;
        var copies = {};
        live().forEach(function (e) { copies[e.pack] = (copies[e.pack] || 0) + e.qty; });
        list.forEach(function (t, i) {
            var on = t.pack === cur;
            var b = text("button", "backpack-tab" + (on ? " active" : ""));
            b.setAttribute("type", "button");
            b.setAttribute("role", "tab");
            b.setAttribute("aria-selected", on ? "true" : "false");
            b.setAttribute("tabindex", on ? "0" : "-1");
            b.setAttribute("data-pack", String(t.pack));
            b.setAttribute("title", on ? "Rename" : t.name);
            b.append(text("span", "backpack-tab-name", t.name), text("span", "backpack-tab-count", String(copies[t.pack] || 0)));
            if (!on) dropOn(b, t.pack);
            if (list.length > 1) reorderBy(b, t.pack, i, list);
            b.addEventListener("click", function () {
                if (on) { rename(b, t); return; }
                setActive(t.pack);
                render();
                focusTab(t.pack);
            });
            b.addEventListener("keydown", function (ev) {
                var step = ev.key === "ArrowRight" ? 1 : ev.key === "ArrowLeft" ? -1 : 0;
                if (!step) return;
                ev.preventDefault();
                // Alt carries the tab a place along the strip instead.
                if (ev.altKey) {
                    var by = list[i + step];
                    if (by && moveTab(t.pack, by.pack)) { render(); focusTab(t.pack); }
                    return;
                }
                var next = list[(i + step + list.length) % list.length];
                setActive(next.pack);
                render();
                focusTab(next.pack);
            });
            stripEl.appendChild(b);
            if (on && list.length > 1) {
                var del = text("button", "backpack-tab-del", "×");
                del.setAttribute("type", "button");
                del.setAttribute("aria-label", "Delete " + t.name);
                del.addEventListener("click", function () { askDelete(t); });
                stripEl.appendChild(del);
            }
        });
        if (list.length < TABS) {
            var add = text("button", "backpack-tab-add", "+");
            add.setAttribute("type", "button");
            add.setAttribute("id", "backpack-tab-add");
            add.setAttribute("aria-label", "Add a backpack");
            add.addEventListener("click", function () { if (addTab()) { render(); focusTab(active()); } });
            stripEl.appendChild(add);
        }
    }

    // dropOn lets a panel row dragged onto tab b move to backpack p.
    function dropOn(b, p) {
        var ours = function (ev) { return ev.dataTransfer && Array.prototype.indexOf.call(ev.dataTransfer.types, DRAG_TYPE) !== -1; };
        b.addEventListener("dragover", function (ev) {
            if (!ours(ev)) return;
            ev.preventDefault();
            ev.dataTransfer.dropEffect = "move";
            b.classList.add("drop-target");
        });
        b.addEventListener("dragleave", function () { b.classList.remove("drop-target"); });
        b.addEventListener("drop", function (ev) {
            if (!ours(ev)) return;
            ev.preventDefault();
            // A refused move renders nothing, so the outline goes here
            b.classList.remove("drop-target");
            moveCard(ev.dataTransfer.getData(DRAG_TYPE), p);
        });
    }

    // reorderBy lets tab b be dragged along the strip: dropped on another
    // tab it takes that one's place, and the mark shows the side it lands.
    function reorderBy(b, p, i, list) {
        var mark = function () {
            var from = list.map(function (t) { return t.pack; }).indexOf(draggedTab);
            return from < i ? "drop-after" : "drop-before";
        };
        var unmark = function () { b.classList.remove("drop-before"); b.classList.remove("drop-after"); };
        b.setAttribute("draggable", "true");
        b.addEventListener("dragstart", function (ev) {
            ev.dataTransfer.setData(TAB_DRAG_TYPE, String(p));
            ev.dataTransfer.effectAllowed = "move";
            draggedTab = p;
            b.classList.add("dragging");
        });
        b.addEventListener("dragend", function () { draggedTab = 0; b.classList.remove("dragging"); });
        b.addEventListener("dragover", function (ev) {
            if (!draggedTab || draggedTab === p) return;
            ev.preventDefault();
            ev.dataTransfer.dropEffect = "move";
            b.classList.add(mark());
        });
        b.addEventListener("dragleave", unmark);
        b.addEventListener("drop", function (ev) {
            if (!draggedTab || draggedTab === p) return;
            ev.preventDefault();
            unmark();
            var moved = draggedTab;
            draggedTab = 0;
            if (moveTab(moved, p)) render();
        });
    }

    function focusTab(p) {
        Array.prototype.forEach.call(stripEl.children, function (b) {
            if (b.getAttribute("data-pack") === String(p)) b.focus();
        });
    }

    // rename swaps the open tab for a field: Enter or leaving it saves,
    // Escape keeps the name.
    function rename(b, t) {
        var field = document.createElement("input");
        field.type = "text";
        field.setAttribute("class", "backpack-tab-field");
        field.setAttribute("aria-label", "Backpack name");
        field.setAttribute("maxlength", String(NAME_MAX));
        field.value = t.name;
        var done = false;
        var finish = function (save) {
            if (done) return;
            done = true;
            if (save) renameTab(t.pack, field.value);
            render();
            focusTab(t.pack);
        };
        field.addEventListener("keydown", function (ev) {
            if (ev.key !== "Enter" && ev.key !== "Escape") return;
            ev.preventDefault();
            // Escape here cancels the rename, not the panel
            ev.stopPropagation();
            finish(ev.key === "Enter");
        });
        field.addEventListener("blur", function () { finish(true); });
        b.replaceWith(field);
        field.focus();
        if (field.select) field.select();
    }

    function askDelete(t) {
        var doDelete = function () { deleteTab(t.pack); render(); focusTab(active()); };
        var cards = inPack(t.pack).length;
        if (!cards) { doDelete(); return; }
        var ask = "Delete " + t.name + " and its " + cards + (cards === 1 ? " product?" : " products?");
        if (typeof window.confirmDialog === "function") window.confirmDialog(ask, doDelete, { anchor: panel, confirmLabel: "Delete" });
        else if (window.confirm(ask)) doDelete();
    }

    function countLine(c) {
        return c.copies + (c.copies === 1 ? " copy" : " copies") + " of " + c.cards + (c.cards === 1 ? " product" : " products");
    }

    function renderPanel() {
        if (!panel) return;
        var s = sortPref();
        var entries = viewOrder(ordered(), s);
        while (listEl.children.length) listEl.children[0].remove();
        var grades = {};
        entries.forEach(function (e) { (grades[e.id] = grades[e.id] || []).push(e.cond); });
        var cur = active();
        var others = tabs().filter(function (t) { return t.pack !== cur; });
        var p = isPriceSort(s.by) ? prices() : null;
        entries.forEach(function (e) {
            listEl.appendChild(row(e, grades[e.id].filter(function (c) { return c !== e.cond; }), others, p && priceLine(e, s.by, p)));
        });
        renderTabs();
        renderSortBar(s, entries.length);
        if (entries.length > 1) loadPrices();
        var c = count();
        countEl.textContent = countLine(c);
        emptyEl.hidden = entries.length > 0;
        sendRetail.disabled = entries.length === 0 || !canUpload();
        sendBuylist.disabled = entries.length === 0 || !canUpload();
        undoBtn.disabled = undoSteps().length === 0;
    }

    function render() {
        markRows();
        markSections();
        markNav();
        renderPanel();
    }
    window.renderBackpack = render;

    function open() {
        build();
        priceRefusal = "";
        overlay.classList.add("open");
        panel.classList.add("open");
        renderPanel();
        var nav = document.getElementById("nav-backpack");
        if (nav) nav.setAttribute("aria-expanded", "true");
        var c = document.getElementById("backpack-close");
        if (c && c.focus) c.focus();
    }

    function close() {
        if (!panel || !panel.classList.contains("open")) return;
        overlay.classList.remove("open");
        panel.classList.remove("open");
        var nav = document.getElementById("nav-backpack");
        if (nav) { nav.setAttribute("aria-expanded", "false"); if (nav.focus) nav.focus(); }
    }

    // trapTab keeps Tab and Shift+Tab cycling inside the open panel.
    function trapTab(ev) {
        var items = Array.prototype.filter.call(panel.querySelectorAll("button, input, select, [tabindex]"), function (n) {
            if (n.disabled || n.closest("#ban-confirm-dialog")) return false;
            for (var a = n; a && a !== panel.parentNode; a = a.parentNode) if (a.hidden) return false;
            return true;
        });
        if (!items.length) return;
        var first = items[0], last = items[items.length - 1];
        var at = items.indexOf(document.activeElement);
        if (ev.shiftKey && at <= 0) { ev.preventDefault(); last.focus(); }
        else if (!ev.shiftKey && (at < 0 || at === items.length - 1)) { ev.preventDefault(); first.focus(); }
    }

    function onKey(ev) {
        if (!panel || !panel.classList.contains("open")) return;
        // The confirm dialog handles its own keys while it is up.
        var dialog = document.getElementById("ban-confirm-dialog");
        if (dialog && !dialog.hidden) return;
        if (ev.key === "Escape") close();
        else if (ev.key === "Tab") trapTab(ev);
    }

    function toggle() {
        if (panel && panel.classList.contains("open")) close(); else open();
    }

    window.Backpack = { read: read, add: add, setQty: setQty, remove: remove, setCond: setCond, addCond: addCond, moveTo: moveTo, take: take, clear: clear, undo: undo, sendForm: sendForm, count: count, tabs: tabs, addTab: addTab, renameTab: renameTab, deleteTab: deleteTab, open: open, close: close };

    function init() {
        var nav = document.getElementById("nav-backpack");
        if (nav) nav.addEventListener("click", toggle);
        document.addEventListener("keydown", onKey);
        // After the row's own handler has marked it, as upload-optimizer.js counts it
        document.addEventListener("change", function (ev) {
            if (ev.target && ev.target.closest && ev.target.closest(".opt-store")) markSections();
        });
        window.addEventListener("storage", function (ev) { if (!ev || !ev.key || ev.key === KEY || ev.key === ACTIVE_KEY || ev.key === TABS_KEY) render(); });
        window.addEventListener("pageshow", function (ev) { if (ev && ev.persisted) render(); });
        clearIfPriced();
        render();
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
})();
