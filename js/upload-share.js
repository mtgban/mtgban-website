// Share: stores rows from the page under a short-lived key and copies the
// link, for the whole list or one optimizer store. The server keeps them for
// seven days.
(function () {
    // The links with a share running or a flash showing, each on its own:
    // a click on the confirmation does nothing, and one on another store
    // still works.
    var busy = new WeakSet();

    // Swaps the link's text for 1.5 s, the way the old inline script did.
    function flash(el, html, title) {
        var orig = el.innerHTML;
        var origTitle = el.title;
        el.innerHTML = html;
        if (title) el.title = title;
        if (window.lucide) lucide.createIcons();
        setTimeout(function () {
            busy.delete(el);
            el.innerHTML = orig;
            el.title = origTitle;
            if (window.lucide) lucide.createIcons();
        }, 1500);
    }

    function postShare(el, rows, kind) {
        if (busy.has(el)) return;
        var mode = document.getElementById('res_mode');
        var buylist = !!(mode && mode.value === 'true');
        busy.add(el);
        return fetch('/api/upload/share', {
            method: 'POST',
            credentials: 'same-origin',
            headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'fetch' },
            body: JSON.stringify({ rows: rows, buylist: buylist })
        }).then(function (res) {
            return res.json().catch(function () { return {}; }).then(function (body) {
                if (res.status !== 201 || !body.url) {
                    throw new Error(body.error || ('share failed (' + res.status + ')'));
                }
                return navigator.clipboard.writeText(window.location.origin + body.url);
            });
        }).then(function () {
            if (window.BAN && window.BAN.track) window.BAN.track('ui.upload.share', kind === 'section' ? 'section' : 'list');
            flash(el, '<i data-lucide="check" style="width:14px;height:14px;vertical-align:-2px"></i> Copied!');
        }).catch(function (err) {
            flash(el, 'Could not share', err && err.message ? err.message : 'share failed');
        });
    }

    function copyShareLink(el) {
        return postShare(el, window.packRows ? packRows('all') : '', 'list');
    }

    // A store's ticked rows in packRows' seven fields, each with the copies
    // its section lists. Copies opened from different products are one row
    // here, so they travel as plain cards rather than by product.
    function packSection(section) {
        var lines = [];
        section.querySelectorAll('tr[data-opt-id]').forEach(function (tr) {
            if (tr.classList.contains('opt-removed')) return;
            lines.push([tr.dataset.optId, tr.dataset.loadQty, tr.dataset.shareCond, tr.dataset.sharePrice, '', '', ''].join('\t'));
        });
        return lines.join('\n');
    }

    function copySectionShareLink(el) {
        return postShare(el, packSection(el.closest('.opt-store')), 'section');
    }

    window.copyShareLink = copyShareLink;
    window.copySectionShareLink = copySectionShareLink;
})();
