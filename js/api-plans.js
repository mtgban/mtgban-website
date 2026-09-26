// Configurator total for the API plans page. The gateway recomputes it.
(function () {
    // computeTotal mirrors billing.Plan.LineItems: package, extra stores past
    // the included count on an explicit package, extra games past the
    // included count, all times the interval count.
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

    function selectedPackage() {
        var key = checkedValues('package')[0];
        for (var i = 0; i < data.packages.length; i++) {
            if (data.packages[i].key === key) return data.packages[i];
        }
        return null;
    }

    function update() {
        var pkg = selectedPackage();
        var explicit = !!(pkg && pkg.explicit);
        var stores = document.getElementById('api-stores');
        if (stores) {
            stores.hidden = !explicit;
            // hidden alone does not stop submission, so disable too
            var storeBoxes = stores.querySelectorAll('input[name="stores"]');
            for (var k = 0; k < storeBoxes.length; k++) {
                storeBoxes[k].disabled = !explicit;
            }
        }
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
            games: checkedGames
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
        ['games', 'stores'].forEach(function (name) {
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
    form.addEventListener('change', update);
    update();
})();
