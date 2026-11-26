// The admin's Invites tab: the mint form starts its features on the chosen
// tier's own, a page the tier opens ticked and fixed, and each open
// invite's Copy button copies its link.
(function () {
    var config = window.BAN_INVITES || {};

    function applyTier(form, tiers) {
        var tier = form.querySelector('[name=inviteTier]').value;
        var values = (tiers || {})[tier] || {};
        form.querySelectorAll('.admin-invite-feature').forEach(function (row) {
            var page = row.getAttribute('data-page');
            var opened = Object.prototype.hasOwnProperty.call(values, page);
            var box = row.querySelector('input[type=checkbox]');
            box.checked = opened;
            box.disabled = opened;
            var options = values[page] || {};
            row.querySelectorAll('input[data-option]').forEach(function (input) {
                var key = input.getAttribute('data-option');
                input.value = Object.prototype.hasOwnProperty.call(options, key) ? options[key] : '';
            });
        });
    }

    var form = document.getElementById('admin-invite-form');
    if (form) {
        form.querySelector('[name=inviteTier]').addEventListener('change', function () {
            applyTier(form, config.tiers);
        });
        applyTier(form, config.tiers);
    }

    document.querySelectorAll('[data-invite-copy]').forEach(function (button) {
        button.addEventListener('click', function () {
            if (!navigator.clipboard) {
                return;
            }
            navigator.clipboard.writeText(button.getAttribute('data-invite-copy')).then(function () {
                button.textContent = 'Copied';
            });
        });
    });

    window.AdminInvites = { applyTier: applyTier };
})();
