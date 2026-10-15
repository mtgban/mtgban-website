// Shared favorites page: card art and, for a signed-in viewer, prices, plus
// Merge, which copies the shared cards the viewer lacks into their own
// favorites once. The list itself is rendered by the server.
(function() {
    var data = window.BAN_SHARED_FAVORITES || {};
    var rows = data.rows || [];
    var STORAGE_KEY = 'mtgban_favorites';
    var MAX_FAVORITES = 50;
    var BATCH_SIZE = 50;
    var prices = {};

    function isMobile() {
        return !!(document.body && document.body.classList && document.body.classList.contains('mobile'));
    }

    function rowEl(id) {
        var all = document.querySelectorAll('[data-fav-id]');
        for (var i = 0; i < all.length; i++) {
            if (all[i].getAttribute('data-fav-id') === id) return all[i];
        }
        return null;
    }

    function showToast(msg) {
        var toast = document.getElementById('m-fav-toast') || document.getElementById('desktop-fav-toast');
        if (!toast) return;
        toast.textContent = msg;
        toast.classList.add('show');
        setTimeout(function() { toast.classList.remove('show'); }, 2500);
    }

    /* mergeInto adds the shared rows the viewer lacks to their favorites, up
     * to the cap, and says what happened. A card the viewer had deleted
     * comes back live, its tombstone dropped. Pure: lists in, lists out. */
    function mergeInto(existing, shared, now, priceMap) {
        var have = {};
        var liveCount = 0;
        existing.forEach(function(f) {
            if (f && f.id != null && ListStorage.isLive(f)) { have[f.id] = true; liveCount++; }
        });
        var out = existing.slice();
        var added = 0, already = 0, skipped = 0;
        shared.forEach(function(r) {
            if (!r || !r.id) return;
            if (have[r.id]) { already++; return; }
            if (liveCount + added >= MAX_FAVORITES) { skipped++; return; }
            out = out.filter(function(f) { return !(f && f.id === r.id && !ListStorage.isLive(f)); });
            var p = (priceMap && priceMap[r.id]) || {};
            out.push({
                id: r.id, name: r.name, set: r.set || '', edition: r.edition || '', number: r.number || '',
                foil: !!r.foil, etched: !!r.etched,
                finishTag: r.finishTag || '', finishClass: r.finishClass || '',
                treatments: r.treatments || [], img: r.img || '', cw: !!r.cw,
                query: r.query || r.name,
                sellPrice: p.sellPrice == null ? null : p.sellPrice, sellVendor: p.sellVendor || '',
                buyPrice: p.buyPrice == null ? null : p.buyPrice, buyVendor: p.buyVendor || '',
                t: now, m: now
            });
            have[r.id] = true;
            added++;
        });
        return { list: out, added: added, already: already, skipped: skipped };
    }

    function toastText(res) {
        var parts = [];
        if (res.added) parts.push('Added ' + res.added);
        if (res.already) parts.push((res.added ? 'already had ' : 'Already had ') + res.already);
        if (res.skipped) parts.push(res.skipped + ' skipped (favorites are capped at ' + MAX_FAVORITES + ')');
        if (!parts.length) return 'Nothing to merge';
        return parts.join(', ');
    }

    function merge() {
        var res = mergeInto(ListStorage.read(STORAGE_KEY), rows, Date.now(), prices);
        if (res.added) ListStorage.save(STORAGE_KEY, res.list, MAX_FAVORITES);
        showToast(toastText(res));
    }

    /* A signed-in viewer's list may not be read from the server yet: merge
     * only once the first sync has settled, or the merge evicts unread cards. */
    function mergeWhenSynced(btn) {
        var sync = window.UserStateSync;
        if (!data.signedIn || !sync || !sync.ready) { merge(); return; }
        var text = btn.textContent;
        btn.disabled = true;
        btn.textContent = 'Syncing your favorites';
        sync.ready.then(function() {
            btn.disabled = false;
            btn.textContent = text;
            merge();
        });
    }

    /* Card art, drawn the way the owner's pane draws it. */
    function renderThumbs() {
        if (typeof thumbHtml !== 'function') return;
        rows.forEach(function(r) {
            if (!r.img) return;
            var el = rowEl(r.id);
            if (!el) return;
            var thumb = el.querySelector('.landing-item-thumb, [data-shared-thumb]');
            if (thumb) thumb.innerHTML = thumbHtml(r.img, r.foil, r.cw);
        });
    }

    function priceHtml(p) {
        var mobile = isMobile();
        var html = '';
        if (p.sellPrice != null) {
            html += mobile
                ? '<span class="m-fav-price sell">Sellers' + (p.sellVendor ? ' (' + escapeHtml(p.sellVendor) + ')' : '') + ': $ ' + Number(p.sellPrice).toFixed(2) + '</span>'
                : '<span class="landing-item-price-label sell">Sellers' + (p.sellVendor ? ' (' + escapeHtml(p.sellVendor) + ')' : '') + '</span><span class="landing-item-price-value sell">$ ' + Number(p.sellPrice).toFixed(2) + '</span>';
        }
        if (p.buyPrice != null) {
            html += mobile
                ? '<span class="m-fav-price buy">Buyers' + (p.buyVendor ? ' (' + escapeHtml(p.buyVendor) + ')' : '') + ': $ ' + Number(p.buyPrice).toFixed(2) + '</span>'
                : '<span class="landing-item-price-label buy">Buyers' + (p.buyVendor ? ' (' + escapeHtml(p.buyVendor) + ')' : '') + '</span><span class="landing-item-price-value buy">$ ' + Number(p.buyPrice).toFixed(2) + '</span>';
        }
        return html;
    }

    function renderPrices() {
        rows.forEach(function(r) {
            var p = prices[r.id];
            if (!p) return;
            var el = rowEl(r.id);
            if (!el) return;
            var cell = el.querySelector('[data-shared-prices]');
            if (cell) cell.innerHTML = priceHtml(p);
            if (p.imageURL && !r.img) { r.img = p.imageURL; }
        });
        renderThumbs();
    }

    /* Prices only for a signed-in viewer, with their own store settings, as
     * the owner's pane fetches them. A refused batch leaves its rows bare. */
    function fetchPrices() {
        if (!data.signedIn || rows.length === 0) return;
        var ids = rows.map(function(r) { return r.id; });
        var batches = [];
        for (var i = 0; i < ids.length; i += BATCH_SIZE) batches.push(ids.slice(i, i + BATCH_SIZE));
        Promise.all(batches.map(function(batch) {
            return fetch('/data/prices/' + encodeURIComponent(batch.join(',')))
                .then(function(r) { return r.ok ? r.json() : {}; })
                .catch(function() { return {}; });
        })).then(function(results) {
            results.forEach(function(found) {
                Object.keys(found).forEach(function(k) { prices[k] = found[k]; });
            });
            renderPrices();
        });
    }

    function init() {
        var btn = document.getElementById('shared-merge');
        if (btn) btn.addEventListener('click', function(ev) { ev.preventDefault(); mergeWhenSynced(btn); });
        renderThumbs();
        fetchPrices();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    window.SharedFavorites = { mergeInto: mergeInto, toastText: toastText, renderPrices: renderPrices };
})();
