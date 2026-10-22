// The backpack: cards collected across searches with a count each, kept in
// localStorage (synced by user-state.js), shown in a side panel from the
// navbar, and sent to Upload as one list.
(function () {
    "use strict";

    var KEY = "mtgban_backpack";
    var EMPTY_AFTER_KEY = "mtgban_backpack_empty_after";
    var PENDING_KEY = "mtgban_backpack_pending_clear";
    var MAX = 200;
    var MAX_QTY = 999;

    // read drops entries without a string id and holds each qty to 1..999.
    function read() {
        return ListStorage.read(KEY).filter(function (e) { return e && typeof e.id === "string" && e.id !== ""; }).map(function (e) {
            e.qty = Math.max(1, Math.min(MAX_QTY, parseInt(e.qty, 10) || 1));
            return e;
        });
    }
    // now stamps on the server's clock when user-state.js has one.
    function now() { return window.UserState && typeof window.UserState.now === "function" ? window.UserState.now() : Date.now(); }
    function live() { return read().filter(ListStorage.isLive); }
    // ordered is the panel's order, newest first, which the Upload list follows.
    function ordered() { return live().sort(function (a, b) { return (b.t || 0) - (a.t || 0); }); }
    // A Clear tombstones every card, so keep as many tombstones as cards.
    function save(list) { ListStorage.save(KEY, list, MAX, MAX); }

    function count() {
        var copies = 0, cards = 0;
        live().forEach(function (e) { copies += e.qty || 1; cards++; });
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

    function toastCeiling() { toast(MAX_QTY + " copies is the most for one card"); }

    // add puts one more copy of the row's card in; a removed card comes back
    // as one copy.
    function add(data) {
        if (!data || !data.id) return false;
        var list = read();
        var t = now();
        var idx = -1;
        for (var i = 0; i < list.length; i++) { if (list[i].id === data.id) { idx = i; break; } }
        if (idx >= 0 && !list[idx].del) {
            var next = Math.min(MAX_QTY, (list[idx].qty || 1) + 1);
            if (next === list[idx].qty) { toastCeiling(); return false; }
            list[idx].qty = next;
            list[idx].m = t;
        } else {
            if (live().length >= MAX) { toast("Backpack is full (" + MAX + " cards)"); return false; }
            if (idx >= 0) list.splice(idx, 1);
            list.unshift({
                id: data.id, name: data.name || "", edition: data.edition || "", set: data.set || "",
                number: data.number || "", finishTag: data.finishTag || "", finishClass: data.finishClass || "",
                img: data.img || "", cw: !!data.cw, qty: 1, t: t, m: t
            });
        }
        save(list);
        return true;
    }

    function setQty(id, qty) {
        var list = read();
        var t = now();
        for (var i = 0; i < list.length; i++) {
            if (list[i].id !== id || list[i].del) continue;
            if (qty < 1) { list[i].del = t; list[i].m = t; }
            else {
                var next = Math.min(MAX_QTY, qty);
                if (next === list[i].qty) { if (qty > MAX_QTY) toastCeiling(); return; }
                list[i].qty = next; list[i].m = t;
            }
        }
        save(list);
    }

    function remove(id) { setQty(id, 0); }

    // clear removes the cards ids names, or every card without it.
    function clear(ids) {
        var list = read();
        var t = now();
        list.forEach(function (e) { if (!e.del && (!ids || ids.indexOf(e.id) !== -1)) { e.del = t; e.m = t; } });
        save(list);
    }

    function emptyAfter() { try { return localStorage.getItem(EMPTY_AFTER_KEY) === "1"; } catch (e) { return false; } }
    function setEmptyAfter(on) { try { localStorage.setItem(EMPTY_AFTER_KEY, on ? "1" : "0"); } catch (e) {} }

    // The ids a send asked to empty after, held in this tab until Upload
    // shows their results; every send replaces or removes them.
    function setPending(ids) {
        try {
            if (ids) sessionStorage.setItem(PENDING_KEY, JSON.stringify(ids));
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
    // with a quantity beside each card.
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
        });
        return form;
    }

    // Upload checks its own grant; a page without BAN_BACKPACK sends as before.
    function canUpload() { return !(window.BAN_BACKPACK && window.BAN_BACKPACK.canUpload === false); }

    function send(mode) {
        if (!canUpload() || !live().length) return;
        var form = sendForm(mode);
        setPending(emptyAfter() ? ordered().map(function (e) { return e.id; }) : null);
        document.body.appendChild(form);
        form.submit();
    }

    // clearIfPriced empties the backpack on the Upload page whose results
    // are the cards a send asked to empty after. Any other Upload page, an
    // error or the bare form, drops the request and keeps the backpack.
    function clearIfPriced() {
        var ban = window.BAN_BACKPACK;
        if (!ban || !("priced" in ban)) return;
        var pending = takePending();
        if (Array.isArray(pending) && Array.isArray(ban.priced) && pending.join(",") === ban.priced.join(",")) clear(pending);
    }

    // ---- result rows and the navbar ----

    function markRows() {
        var by = {};
        live().forEach(function (e) { by[e.id] = e.qty || 1; });
        document.querySelectorAll(".pack-btn").forEach(function (b) {
            var id = b.getAttribute("data-card-id");
            var qty = by[id];
            b.classList.toggle("active", !!qty);
            var span = b.querySelector(".pack-btn-count");
            if (span) { span.textContent = qty ? String(qty) : ""; span.hidden = !qty; }
        });
    }

    function markNav() {
        var btn = document.getElementById("nav-backpack");
        if (!btn) return;
        btn.hidden = false;
        var c = count();
        var span = document.getElementById("nav-backpack-count");
        if (span) { span.textContent = String(c.copies); span.hidden = c.copies === 0; }
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

    // ---- the panel ----

    var panel = null, overlay = null, listEl = null, countEl = null, emptyEl = null;
    var sendRetail = null, sendBuylist = null, emptySwitch = null;

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

        listEl = text("div", "backpack-list");
        listEl.setAttribute("id", "backpack-list");
        emptyEl = text("p", "backpack-empty", "Add cards from any search with the backpack button.");
        emptyEl.setAttribute("id", "backpack-empty");

        var footer = text("div", "backpack-footer");
        var label = text("label", "backpack-switch");
        emptySwitch = document.createElement("input");
        emptySwitch.type = "checkbox";
        emptySwitch.setAttribute("id", "backpack-empty-after");
        emptySwitch.checked = emptyAfter();
        emptySwitch.addEventListener("change", function () { setEmptyAfter(emptySwitch.checked); });
        label.append(emptySwitch, text("span", null, "Empty the backpack after sending"));

        var actions = text("div", "backpack-actions");
        var clearBtn = text("button", "backpack-btn backpack-btn-plain", "Clear");
        clearBtn.setAttribute("id", "backpack-clear");
        clearBtn.setAttribute("type", "button");
        clearBtn.addEventListener("click", function () {
            if (!live().length) return;
            var doClear = function () { clear(); render(); };
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
        actions.append(clearBtn, sendRetail, sendBuylist);
        if (!canUpload()) {
            sendRetail.setAttribute("title", "Upload needs a higher tier");
            sendBuylist.setAttribute("title", "Upload needs a higher tier");
            emptySwitch.disabled = true;
        }
        footer.append(label, actions);

        panel.append(header, listEl, emptyEl, footer);
        document.body.append(overlay, panel);
    }

    function row(e) {
        var r = text("div", "backpack-row");
        r.setAttribute("data-card-id", e.id);
        var art = text("div", "backpack-row-art" + (e.cw ? " blurred" : ""));
        if (e.img) {
            var img = document.createElement("img");
            img.setAttribute("src", e.img);
            img.setAttribute("alt", "");
            img.setAttribute("loading", "lazy");
            art.appendChild(img);
        }
        var body = text("div", "backpack-row-body");
        var name = text("div", "backpack-row-name", e.name || e.id);
        var where = text("div", "backpack-row-where", (e.edition || "") + (e.set ? " (" + e.set + ")" : "") + (e.number ? " #" + e.number : ""));
        body.append(name, where);
        if (e.finishTag) body.appendChild(text("span", "backpack-row-finish " + (e.finishClass || ""), e.finishTag));

        var ctl = text("div", "backpack-row-ctl");
        var minus = text("button", "backpack-minus", "−");
        minus.setAttribute("type", "button");
        minus.setAttribute("aria-label", "One fewer");
        minus.addEventListener("click", function () { setQty(e.id, (e.qty || 1) - 1); render(); });
        var qty = text("span", "backpack-qty", String(e.qty || 1));
        var plus = text("button", "backpack-plus", "+");
        plus.setAttribute("type", "button");
        plus.setAttribute("aria-label", "One more");
        plus.addEventListener("click", function () { setQty(e.id, (e.qty || 1) + 1); render(); });
        var rm = text("button", "backpack-remove", "×");
        rm.setAttribute("type", "button");
        rm.setAttribute("aria-label", "Remove");
        rm.addEventListener("click", function () { remove(e.id); render(); });
        ctl.append(minus, qty, plus, rm);

        r.append(art, body, ctl);
        return r;
    }

    function countLine(c) {
        return c.copies + (c.copies === 1 ? " copy" : " copies") + " of " + c.cards + (c.cards === 1 ? " card" : " cards");
    }

    function renderPanel() {
        if (!panel) return;
        var entries = ordered();
        while (listEl.children.length) listEl.children[0].remove();
        entries.forEach(function (e) { listEl.appendChild(row(e)); });
        var c = count();
        countEl.textContent = countLine(c);
        emptyEl.hidden = entries.length > 0;
        sendRetail.disabled = entries.length === 0 || !canUpload();
        sendBuylist.disabled = entries.length === 0 || !canUpload();
    }

    function render() {
        markRows();
        markNav();
        renderPanel();
    }
    window.renderBackpack = render;

    function open() {
        build();
        renderPanel();
        overlay.classList.add("open");
        panel.classList.add("open");
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
        var items = Array.prototype.filter.call(panel.querySelectorAll("button, input, [tabindex]"), function (n) {
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

    window.Backpack = { read: read, add: add, setQty: setQty, remove: remove, clear: clear, sendForm: sendForm, count: count, open: open, close: close };

    function init() {
        var nav = document.getElementById("nav-backpack");
        if (nav) nav.addEventListener("click", toggle);
        document.addEventListener("keydown", onKey);
        window.addEventListener("storage", function (ev) { if (!ev || !ev.key || ev.key === KEY) render(); });
        window.addEventListener("pageshow", function (ev) { if (ev && ev.persisted) render(); });
        clearIfPriced();
        render();
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
    else init();
})();
