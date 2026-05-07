// Custom in-page confirm dialog - replaces window.confirm() for Clear actions
// Usage: window.confirmDialog("Clear all favorites?", function() { ... });
//        window.confirmDialog(msg, onOk, { anchor: someEl, confirmLabel: 'Clear all' });
// When `anchor` is supplied the overlay scopes to that element's box instead of fullscreen.
(function() {
    var hostId = 'ban-confirm-dialog';
    var host = null;

    function buildHost() {
        var h = document.createElement('div');
        h.id = hostId;
        h.className = 'ban-confirm-dialog-host';
        h.hidden = true;
        h.innerHTML =
            '<div class="ban-confirm-backdrop" data-role="cancel"></div>' +
            '<div class="ban-confirm-modal" role="dialog" aria-modal="true" aria-label="Confirm action">' +
                '<p class="ban-confirm-message"></p>' +
                '<div class="ban-confirm-actions">' +
                    '<button type="button" class="ban-confirm-btn" data-role="cancel">Cancel</button>' +
                    '<button type="button" class="ban-confirm-btn ban-confirm-btn-danger" data-role="confirm">Clear all</button>' +
                '</div>' +
            '</div>';
        return h;
    }

    function ensureHost(anchor) {
        var parent = anchor || document.body;
        if (!host) host = buildHost();
        if (host.parentElement !== parent) {
            if (host.parentElement) host.parentElement.removeChild(host);
            parent.appendChild(host);
        }
        if (anchor) {
            host.classList.add('anchored');
            // Anchor must establish a positioning context so position:absolute fills it.
            if (getComputedStyle(anchor).position === 'static') {
                anchor.style.position = 'relative';
            }
        } else {
            host.classList.remove('anchored');
        }
        return host;
    }

    window.confirmDialog = function(message, onConfirm, opts) {
        opts = opts || {};
        var h = ensureHost(opts.anchor || null);
        if (!h.hidden) return; // re-entrant call while open: ignore
        h.querySelector('.ban-confirm-message').textContent = message;
        var confirmBtn = h.querySelector('[data-role="confirm"]');
        confirmBtn.textContent = opts.confirmLabel || 'Clear all';
        var trigger = document.activeElement;
        h.hidden = false;
        confirmBtn.focus();

        function cleanup() {
            h.hidden = true;
            h.removeEventListener('click', onClick);
            document.removeEventListener('keydown', onKey);
            if (trigger && typeof trigger.focus === 'function') trigger.focus();
        }
        function onClick(e) {
            var role = e.target.getAttribute && e.target.getAttribute('data-role');
            if (role === 'confirm') { cleanup(); onConfirm(); }
            else if (role === 'cancel') { cleanup(); }
        }
        function onKey(e) {
            if (e.key === 'Escape') cleanup();
            if (e.key === 'Enter') { cleanup(); onConfirm(); }
        }
        h.addEventListener('click', onClick);
        document.addEventListener('keydown', onKey);
    };
})();
