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

        // Get best sell price + vendor name (NM condition, first vendor in sellers panel)
        var sellPrice = null;
        var sellVendor = '';
        var sellersPanel = card.querySelector('[id^="sellers-"]');
        if (sellersPanel) {
            var activeGroup = sellersPanel.querySelector('.m-cond-group.active');
            if (activeGroup) {
                var bestRow = activeGroup.querySelector('.m-vendor-row:not(.m-vendor-locked)');
                if (bestRow) {
                    var priceEl = bestRow.querySelector('.m-vendor-price');
                    if (priceEl) {
                        var parsed = parseFloat(priceEl.textContent.trim().replace('$', '').trim());
                        if (!isNaN(parsed)) sellPrice = parsed;
                    }
                    var nameEl = bestRow.querySelector('.m-vendor-name');
                    if (nameEl) {
                        sellVendor = nameEl.textContent.replace('Best', '').trim();
                    }
                }
            }
        }

        // Get best buy price + vendor name (NM condition, first vendor in buyers panel)
        var buyPrice = null;
        var buyVendor = '';
        var buyersPanel = card.querySelector('[id^="buyers-"]');
        if (buyersPanel) {
            var activeGroup = buyersPanel.querySelector('.m-cond-group.active');
            if (activeGroup) {
                var bestRow = activeGroup.querySelector('.m-vendor-row:not(.m-vendor-locked)');
                if (bestRow) {
                    var priceEl = bestRow.querySelector('.m-vendor-price');
                    if (priceEl) {
                        var parsed = parseFloat(priceEl.textContent.trim().replace('$', '').trim());
                        if (!isNaN(parsed)) buyPrice = parsed;
                    }
                    var nameEl = bestRow.querySelector('.m-vendor-name');
                    if (nameEl) {
                        buyVendor = nameEl.textContent.replace('Best', '').trim();
                    }
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
            sellVendor: sellVendor,
            buyPrice: buyPrice,
            buyVendor: buyVendor,
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
        html += '<button class="m-fav-refresh" onclick="window.manualRefreshFavorites()" title="Refresh Favorites"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/></svg></button>';
        html += '<button class="m-fav-clear" onclick="window.clearFavorites()">Clear</button>';
        html += '</div>';
        html += '<div class="m-fav-list">';

        favs.forEach(function(f) {
            html += '<a class="m-fav-item" href="?q=' + encodeURIComponent(f.query) + '">';
            html += '<div class="m-fav-item-top">';
            html += '<span class="m-fav-name">' + escapeHtml(f.name) + '</span>';
            html += '<span class="m-fav-set">' + escapeHtml(f.set) + (f.number ? ' #' + escapeHtml(f.number) : '') + '</span>';
            if (f.foil) html += '<span class="m-badge foil">Foil</span>';
            if (f.etched) html += '<span class="m-badge etched">Etched</span>';
            html += '</div>';
            html += '<div class="m-fav-item-prices">';
            if (f.sellPrice !== null) {
                html += '<span class="m-fav-price sell">Sellers' + (f.sellVendor ? ' (' + escapeHtml(f.sellVendor) + ')' : '') + ': $ ' + f.sellPrice.toFixed(2) + '</span>';
            }
            if (f.buyPrice !== null) {
                html += '<span class="m-fav-price buy">Buyers' + (f.buyVendor ? ' (' + escapeHtml(f.buyVendor) + ')' : '') + ': $ ' + f.buyPrice.toFixed(2) + '</span>';
            }
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

    // Refresh stale favorites from server
    var STALE_MS = 60 * 60 * 1000; // 1 hour
    var lastRefreshAttempt = 0;

    function refreshFavorites() {
        var favs = getFavorites();
        if (favs.length === 0) return;

        // Check if any favorites are stale
        var now = Date.now();
        var stale = favs.some(function(f) { return (now - f.t) > STALE_MS; });
        if (!stale) return;

        doRefresh();
    }

    function doRefresh() {
        var favs = getFavorites();
        if (favs.length === 0) return;

        var ids = favs.map(function(f) { return f.id; }).join(',');

        fetch('/api/prices/?ids=' + encodeURIComponent(ids))
            .then(function(r) {
                if (!r.ok) return null;
                return r.json();
            })
            .then(function(data) {
                if (!data) return;

                var favs = getFavorites();
                var updated = false;

                favs.forEach(function(f) {
                    var prices = data[f.id];
                    if (!prices) return;

                    if (prices.sellPrice !== undefined && prices.sellPrice !== null) {
                        f.sellPrice = prices.sellPrice;
                        f.sellVendor = prices.sellVendor || f.sellVendor;
                        updated = true;
                    }
                    if (prices.buyPrice !== undefined && prices.buyPrice !== null) {
                        f.buyPrice = prices.buyPrice;
                        f.buyVendor = prices.buyVendor || f.buyVendor;
                        updated = true;
                    }
                    f.t = Date.now();
                });

                if (updated) {
                    saveFavorites(favs);
                    renderFavorites();
                }
            })
            .catch(function() {
                // Silent failure — prices stay at last known value
            });
    }

    function scheduleRefresh() {
        if (typeof requestIdleCallback === 'function') {
            requestIdleCallback(refreshFavorites);
        } else {
            setTimeout(refreshFavorites, 1500);
        }
    }

    // Manual refresh — rate limited to once per hour
    window.manualRefreshFavorites = function() {
        var now = Date.now();
        if ((now - lastRefreshAttempt) < STALE_MS) {
            return; // Rate limited
        }
        lastRefreshAttempt = now;
        doRefresh();
    };

    // Initialize
    function init() {
        markExistingFavorites();
        renderFavorites();
        scheduleRefresh();
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
