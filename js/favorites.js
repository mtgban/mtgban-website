// Favorites — localStorage-backed card favorites for mobile
(function() {
    var STORAGE_KEY = 'mtgban_favorites';

    function getFavorites() {
        try {
            var data = localStorage.getItem(STORAGE_KEY);
            return data ? JSON.parse(data) : [];
        } catch (e) {
            return [];
        }
    }

    function saveFavorites(favs) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(favs));
        } catch (e) {}
    }

    function extractCardData(btn) {
        var card = btn.closest('.m-card');
        if (!card) return null;

        var header = card.querySelector('.m-card-header');
        var cardId = btn.getAttribute('data-card');
        var name = card.querySelector('.m-card-name').textContent.trim();
        var setCode = header.getAttribute('data-setcode') || '';
        var setLine = card.querySelector('.m-card-set').textContent.trim();

        // Parse "Edition · #Number"
        var edition = '';
        var number = '';
        var parts = setLine.split(' · ');
        if (parts.length >= 1) edition = parts[0].trim();
        if (parts.length >= 2) number = parts[1].replace('#', '').trim();

        var isFoil = card.querySelector('.m-badge.foil') !== null;
        var isEtched = card.querySelector('.m-badge.etched') !== null;

        // Get best sell price (NM condition, first vendor in sellers panel)
        var sellPrice = null;
        var sellersPanel = card.querySelector('[id^="sellers-"]');
        if (sellersPanel) {
            var activeGroup = sellersPanel.querySelector('.m-cond-group.active');
            if (activeGroup) {
                var priceEl = activeGroup.querySelector('.m-vendor-price');
                if (priceEl) {
                    var parsed = parseFloat(priceEl.textContent.trim().replace('$', '').trim());
                    if (!isNaN(parsed)) sellPrice = parsed;
                }
            }
        }

        // Get best buy price (NM condition, first vendor in buyers panel)
        var buyPrice = null;
        var buyersPanel = card.querySelector('[id^="buyers-"]');
        if (buyersPanel) {
            var activeGroup = buyersPanel.querySelector('.m-cond-group.active');
            if (activeGroup) {
                var priceEl = activeGroup.querySelector('.m-vendor-price');
                if (priceEl) {
                    var parsed = parseFloat(priceEl.textContent.trim().replace('$', '').trim());
                    if (!isNaN(parsed)) buyPrice = parsed;
                }
            }
        }

        // Build search query
        var query = name;
        if (setCode) query += ' s:' + setCode;
        if (number) query += ' cn:' + number;
        if (isEtched) query += ' f:etched';
        else if (isFoil) query += ' f:foil';

        return {
            id: cardId,
            name: name,
            set: setCode,
            edition: edition,
            number: number,
            foil: isFoil,
            etched: isEtched,
            sellPrice: sellPrice,
            buyPrice: buyPrice,
            query: query,
            t: Date.now()
        };
    }

    // Toggle favorite on star click
    window.toggleFavorite = function(btn) {
        var cardId = btn.getAttribute('data-card');
        var favs = getFavorites();
        var idx = -1;
        for (var i = 0; i < favs.length; i++) {
            if (favs[i].id === cardId) { idx = i; break; }
        }

        if (idx >= 0) {
            favs.splice(idx, 1);
            btn.classList.remove('active');
        } else {
            var data = extractCardData(btn);
            if (data) {
                favs.unshift(data);
                btn.classList.add('active');
            }
        }

        saveFavorites(favs);
    };

    // Mark stars on page load for already-favorited cards
    function markExistingFavorites() {
        var favs = getFavorites();
        if (favs.length === 0) return;

        var favIds = {};
        favs.forEach(function(f) { favIds[f.id] = true; });

        document.querySelectorAll('.m-fav-btn').forEach(function(btn) {
            if (favIds[btn.getAttribute('data-card')]) {
                btn.classList.add('active');
            }
        });
    }

    // Render favorites on landing page
    function renderFavorites() {
        var container = document.getElementById('m-favorites');
        if (!container) return;

        var favs = getFavorites();
        if (favs.length === 0) return;

        var html = '<div class="m-fav-header">';
        html += '<span class="m-fav-title">Favorites</span>';
        html += '<button class="m-fav-clear" onclick="window.clearFavorites()">Clear</button>';
        html += '</div>';
        html += '<div class="m-fav-list">';

        favs.forEach(function(f) {
            html += '<a class="m-fav-item" href="?q=' + encodeURIComponent(f.query) + '">';
            html += '<div class="m-fav-item-top">';
            html += '<span class="m-fav-name">' + escapeHtml(f.name) + '</span>';
            html += '<span class="m-fav-set">' + escapeHtml(f.set) + '</span>';
            if (f.foil) html += '<span class="m-badge foil">Foil</span>';
            if (f.etched) html += '<span class="m-badge etched">Etched</span>';
            html += '</div>';
            html += '<div class="m-fav-item-prices">';
            if (f.sellPrice !== null) html += '<span class="m-fav-price sell">Sell: $ ' + f.sellPrice.toFixed(2) + '</span>';
            if (f.buyPrice !== null) html += '<span class="m-fav-price buy">Buy: $ ' + f.buyPrice.toFixed(2) + '</span>';
            html += '</div>';
            html += '</a>';
        });

        html += '</div>';
        container.innerHTML = html;
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    window.clearFavorites = function() {
        localStorage.removeItem(STORAGE_KEY);
        var container = document.getElementById('m-favorites');
        if (container) container.innerHTML = '';
    };

    // Initialize
    function init() {
        markExistingFavorites();
        renderFavorites();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Re-render when page is restored from bfcache (back/forward navigation)
    window.addEventListener('pageshow', function(e) {
        if (e.persisted) {
            init();
        }
    });
})();
