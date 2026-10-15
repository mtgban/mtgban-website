// Share: stores the rows on the page under a short-lived key and copies
// the link. The server keeps them for seven days.
(function () {
    var inFlight = false;
    // Held through the flash, so a click on the confirmation does nothing.
    var flashing = false;

    // Swaps the link's text for 1.5 s, the way the old inline script did.
    function flash(el, html, title) {
        var orig = el.innerHTML;
        var origTitle = el.title;
        el.innerHTML = html;
        if (title) el.title = title;
        if (window.lucide) lucide.createIcons();
        flashing = true;
        setTimeout(function () {
            flashing = false;
            el.innerHTML = orig;
            el.title = origTitle;
            if (window.lucide) lucide.createIcons();
        }, 1500);
    }

    function copyShareLink(el) {
        if (inFlight || flashing) return;
        var rows = window.packRows ? packRows('all') : '';
        var mode = document.getElementById('res_mode');
        var buylist = !!(mode && mode.value === 'true');
        inFlight = true;
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
            flash(el, '<i data-lucide="check" style="width:14px;height:14px;vertical-align:-2px"></i> Copied!');
        }).catch(function (err) {
            flash(el, 'Could not share', err && err.message ? err.message : 'share failed');
        }).finally(function () {
            inFlight = false;
        });
    }

    window.copyShareLink = copyShareLink;
})();
