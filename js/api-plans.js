// Configurator total for the API plans page. The gateway recomputes it.
(function () {
    // computeTotal mirrors billing.Plan.LineItems: package, extra stores past
    // the included count on an explicit package, extra games past the
    // included count, each checked mode add-on once, all times the interval count.
    function computeTotal(data, choice) {
        var pkg = null;
        for (var i = 0; i < data.packages.length; i++) {
            if (data.packages[i].key === choice.package) pkg = data.packages[i];
        }
        if (!pkg) return null;
        var count = 1;
        for (var j = 0; j < data.intervals.length; j++) {
            if (data.intervals[j].key === choice.interval) count = data.intervals[j].count;
        }
        var monthly = pkg.monthly;
        if (pkg.explicit) {
            var extraStores = Math.max(0, choice.stores - pkg.includedStores);
            monthly += extraStores * (data.addons.extra_store || 0);
        }
        var extraGames = Math.max(0, choice.games - data.includedGames);
        monthly += extraGames * (data.addons.extra_game || 0);
        var modeAddons = choice.modeAddons || [];
        var applies = data.addon_applies || {};
        for (var m = 0; m < modeAddons.length; m++) {
            // Each card carries its own box, so one add-on can arrive twice.
            if (modeAddons.indexOf(modeAddons[m]) !== m) continue;
            if ((data.mode_addons || []).indexOf(modeAddons[m]) === -1) continue;
            // A missing or non-array list applies to no package, same as the backend's Addon.Applies.
            var list = applies[modeAddons[m]];
            if (!Array.isArray(list) || list.indexOf(choice.package) === -1) continue;
            monthly += data.addons[modeAddons[m]] || 0;
        }
        return {cents: monthly * count, count: count};
    }

    function formatUSD(cents) {
        var dollars = String(Math.floor(cents / 100));
        dollars = dollars.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        var rem = cents % 100;
        return '$' + dollars + (rem ? '.' + (rem < 10 ? '0' : '') + rem : '');
    }

    if (typeof window !== 'undefined') {
        window.BanApiPlans = {computeTotal: computeTotal, formatUSD: formatUSD};
    }
    if (typeof document === 'undefined') return;

    var form = document.getElementById('api-config-form');
    var data = window.__BAN_API_PLANS;
    if (!form || !data) return;

    function checkedValues(name) {
        var out = [];
        var inputs = form.querySelectorAll('input[name="' + name + '"]');
        for (var i = 0; i < inputs.length; i++) {
            if (inputs[i].checked) out.push(inputs[i].value);
        }
        return out;
    }

    // The add-ons to bill: checked boxes on the chosen card, each value once.
    function chosenAddons() {
        var out = [];
        var inputs = form.querySelectorAll('input[name="addons"]');
        for (var i = 0; i < inputs.length; i++) {
            if (inputs[i].checked && !inputs[i].disabled && out.indexOf(inputs[i].value) === -1) out.push(inputs[i].value);
        }
        return out;
    }

    function selectedPackage() {
        var key = checkedValues('package')[0];
        for (var i = 0; i < data.packages.length; i++) {
            if (data.packages[i].key === key) return data.packages[i];
        }
        return null;
    }

    // The user's store picks on an explicit package, kept across preset packages.
    var pickedStores = new Set();
    var wasExplicit = false;

    function choiceRow(box) {
        return box.closest ? box.closest('.api-choice') : null;
    }

    // An explicit package takes the user's picks; a preset one lights what its scope includes.
    // While explicit it refreshes pickedStores from the boxes before applying them.
    function lightStores(pkg, explicit) {
        var stores = document.getElementById('api-stores');
        if (!stores) return;
        var storeBoxes = stores.querySelectorAll('input[name="stores"]');
        // Entering an explicit package with no picks starts on the first store, as the server does.
        if (explicit && !wasExplicit && pickedStores.size === 0 && storeBoxes.length) pickedStores.add(storeBoxes[0].value);
        for (var k = 0; k < storeBoxes.length; k++) {
            var box = storeBoxes[k];
            var row = choiceRow(box);
            if (explicit && wasExplicit) {
                if (box.checked) pickedStores.add(box.value); else pickedStores.delete(box.value);
            }
            var lit = explicit ? pickedStores.has(box.value) :
                pkg.scope === 'ALL_ACCESS' || (pkg.scope === 'BASE_ACCESS' && !!row && row.dataset.base === 'true');
            box.disabled = !explicit;
            box.checked = lit;
            if (row) row.classList.toggle('api-choice-off', !explicit && !lit);
        }
        var sealedRow = document.getElementById('api-stores-sealed');
        var sealedBoxes = sealedRow ? sealedRow.querySelectorAll('input') : [];
        for (var sb = 0; sb < sealedBoxes.length; sb++) {
            sealedBoxes[sb].checked = !!pkg.sealed;
            var sealedLabel = choiceRow(sealedBoxes[sb]);
            if (sealedLabel) sealedLabel.classList.toggle('api-choice-off', !pkg.sealed);
        }
        var notes = stores.querySelectorAll('[data-when]');
        for (var n = 0; n < notes.length; n++) {
            notes[n].hidden = notes[n].dataset.when !== (explicit ? 'explicit' : 'preset');
        }
    }

    // Only the chosen card's add-on box submits, and only if the add-on applies to it.
    function enableAddons(pkg) {
        var applies = data.addon_applies || {};
        var addonBoxes = form.querySelectorAll('input[name="addons"]');
        for (var ab = 0; ab < addonBoxes.length; ab++) {
            var box = addonBoxes[ab];
            // A missing or non-array list applies to no package, same as the backend's Addon.Applies.
            var list = applies[box.value];
            var allowed = Array.isArray(list) && list.indexOf(pkg.key) !== -1;
            box.disabled = !allowed || box.dataset.package !== pkg.key;
        }
    }

    // A change on one card's add-on box carries to its namesakes on the other cards.
    function mirrorAddon(changed) {
        var addonBoxes = form.querySelectorAll('input[name="addons"]');
        for (var ab = 0; ab < addonBoxes.length; ab++) {
            if (addonBoxes[ab].value === changed.value) addonBoxes[ab].checked = changed.checked;
        }
    }

    function update() {
        var pkg = selectedPackage();
        var explicit = !!(pkg && pkg.explicit);
        if (pkg) {
            lightStores(pkg, explicit);
            enableAddons(pkg);
        }
        wasExplicit = explicit;
        var checkedStores = explicit ? checkedValues('stores').length : 0;
        var checkedGames = form.querySelectorAll('input[name="games"]:checked').length;
        // Checkout needs the included stores picked on an explicit package, and at least the included games.
        var submitButton = form.querySelector('button[type="submit"]');
        if (submitButton) {
            submitButton.disabled = (explicit && checkedStores < pkg.includedStores) || checkedGames < data.includedGames;
        }
        var total = computeTotal(data, {
            package: pkg ? pkg.key : '',
            interval: checkedValues('interval')[0] || 'monthly',
            stores: checkedStores,
            games: checkedGames,
            modeAddons: chosenAddons()
        });
        if (!total) return;
        var name = document.getElementById('api-total-package');
        if (name && pkg) name.textContent = pkg.name;
        var ctas = form.querySelectorAll('.api-cta');
        for (var c = 0; c < ctas.length; c++) {
            var mine = pkg && ctas[c].getAttribute('data-package') === pkg.key;
            ctas[c].textContent = ctas[c].getAttribute(mine ? 'data-selected' : 'data-label');
        }
        document.getElementById('api-total').textContent = formatUSD(total.cents);
        document.getElementById('api-total-period').textContent = total.count === 1 ? '/month' : '/' + total.count + ' months';
    }

    // A change-plan link prefills the form from its own query string.
    function prefill() {
        var params = new URLSearchParams(window.location.search);
        if (params.get('package')) {
            var radios = form.querySelectorAll('input[name="package"]');
            for (var r = 0; r < radios.length; r++) {
                if (radios[r].value === params.get('package')) radios[r].checked = true;
            }
        }
        ['games', 'stores', 'addons'].forEach(function (name) {
            // The server resolves legacy store shorthands to family keys.
            var wanted = name === 'stores' && data.storeKeys ? data.storeKeys : params.getAll(name).join(',').split(',');
            wanted = wanted.map(function (w) { return w.trim().toLowerCase(); }).filter(Boolean);
            if (!wanted.length) return;
            var boxes = form.querySelectorAll('input[name="' + name + '"]');
            for (var i = 0; i < boxes.length; i++) {
                if (boxes[i].disabled) continue;
                boxes[i].checked = wanted.indexOf(boxes[i].value.toLowerCase()) !== -1;
            }
        });
    }

    // The card's button picks the package and brings the rest of the form into view.
    var ctas = form.querySelectorAll('.api-cta');
    for (var b = 0; b < ctas.length; b++) {
        ctas[b].addEventListener('click', function (ev) {
            ev.stopPropagation();
            var radio = form.querySelector('input[name="package"][value="' + this.getAttribute('data-package') + '"]');
            if (radio) radio.checked = true;
            update();
            var target = document.getElementById('api-configure');
            if (target && target.scrollIntoView) target.scrollIntoView({behavior: 'smooth', block: 'start'});
        });
    }

    // A click anywhere on a package card picks it; the radio inside is hidden.
    var cards = form.querySelectorAll('.api-card');
    for (var c = 0; c < cards.length; c++) {
        cards[c].addEventListener('click', function () {
            var radio = this.querySelector('input[name="package"]');
            if (radio && !radio.checked) {
                radio.checked = true;
                update();
            }
        });
    }

    prefill();
    // The boxes checked at load are the first picks only on an explicit default.
    var initial = selectedPackage();
    wasExplicit = !!(initial && initial.explicit);
    form.addEventListener('change', function (ev) {
        if (ev && ev.target && ev.target.name === 'addons') mirrorAddon(ev.target);
        update();
    });
    update();
})();
