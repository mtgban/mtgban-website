// Configurator total for the API plans page. The gateway recomputes it.
(function () {
    // computeTotal mirrors billing.Plan.LineItems: package, extra stores past
    // the included count on an explicit package, extra games past the
    // catalog's included games, all times the interval count.
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
        var total = computeTotal(data, {
            package: pkg ? pkg.key : '',
            interval: checkedValues('interval')[0] || 'monthly',
            stores: explicit ? checkedValues('stores').length : 0,
            games: form.querySelectorAll('input[name="games"]:checked').length
        });
        if (!total) return;
        document.getElementById('api-total').textContent = formatUSD(total.cents);
        document.getElementById('api-total-period').textContent = total.count === 1 ? '/month' : '/' + total.count + ' months';
    }

    // A change-plan link prefills the form from its own query string.
    function prefill() {
        var params = new URLSearchParams(window.location.search);
        if (params.get('package')) {
            var radio = form.querySelector('input[name="package"][value="' + params.get('package') + '"]');
            if (radio) radio.checked = true;
        }
        ['games', 'stores'].forEach(function (name) {
            var wanted = params.getAll(name).join(',').split(',').filter(Boolean);
            if (!wanted.length) return;
            var boxes = form.querySelectorAll('input[name="' + name + '"]');
            for (var i = 0; i < boxes.length; i++) {
                if (boxes[i].disabled) continue;
                boxes[i].checked = wanted.indexOf(boxes[i].value) !== -1;
            }
        });
    }

    prefill();
    form.addEventListener('change', update);
    update();
})();
