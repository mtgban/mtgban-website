// Custom in-page confirm dialog - replaces window.confirm() for Clear actions
// Usage: window.confirmDialog("Clear all favorites?", function() { ... });
(function() {
    var hostId = 'ban-confirm-dialog';
    var host = null;

    function ensureHost() {
        if (host && document.body.contains(host)) return host;
        host = document.createElement('div');
        host.id = hostId;
        host.className = 'ban-confirm-dialog-host';
        host.hidden = true;
        host.innerHTML =
            '<div class="ban-confirm-backdrop" data-role="cancel"></div>' +
            '<div class="ban-confirm-modal" role="dialog" aria-modal="true">' +
                '<p class="ban-confirm-message"></p>' +
                '<div class="ban-confirm-actions">' +
                    '<button type="button" class="ban-confirm-btn" data-role="cancel">Cancel</button>' +
                    '<button type="button" class="ban-confirm-btn ban-confirm-btn-danger" data-role="confirm">Clear all</button>' +
                '</div>' +
            '</div>';
        document.body.appendChild(host);
        return host;
    }

    window.confirmDialog = function(message, onConfirm, opts) {
        opts = opts || {};
        var h = ensureHost();
        h.querySelector('.ban-confirm-message').textContent = message;
        var confirmBtn = h.querySelector('[data-role="confirm"]');
        confirmBtn.textContent = opts.confirmLabel || 'Clear all';
        h.hidden = false;

        function cleanup() {
            h.hidden = true;
            h.removeEventListener('click', onClick);
            document.removeEventListener('keydown', onKey);
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
