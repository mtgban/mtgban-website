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
            var MAX_FAVORITES = 50;
            if (favs.length > MAX_FAVORITES) {
                favs = favs.slice(0, MAX_FAVORITES);
            }
            localStorage.setItem(STORAGE_KEY, JSON.stringify(favs));
        } catch (e) {}
    }

    function extractCardData(btn) {
        // Walk to the row container by class. Both button and row carry data-card-id,
        // so a [data-card-id] selector would match the button itself first.
        var row = btn.closest('.m-card-header, .result-header');
        if (!row) return null;

        var cardId = row.getAttribute('data-card-id') || btn.getAttribute('data-card-id');
        if (!cardId) return null;

        var name = row.getAttribute('data-card-name') || '';
        var setCode = row.getAttribute('data-set-code') || '';
        var edition = row.getAttribute('data-edition') || '';
        var number = row.getAttribute('data-number') || '';
        var imageUrl = row.getAttribute('data-image-url') || '';
        var finishTag = row.getAttribute('data-finish-tag') || '';
        var finishClass = row.getAttribute('data-finish-class') || '';
        var treatmentsAttr = row.getAttribute('data-treatments') || '';
        var treatments = treatmentsAttr ? treatmentsAttr.split(',').filter(function(t) { return t.length > 0; }) : [];

        var isFoil = finishClass === 'foil' || finishClass === 'altfoil';
        var isEtched = finishClass === 'etched';

        // Locate the surrounding card container to find best-price rows.
        // Mobile: .m-card. Desktop: each card's results sit between .result-header rows; the .result-body follows.
        var cardContainer = row.closest('.m-card') || row.parentNode;

        var sellPrice = null;
        var sellVendor = '';
        var sellersPanel = cardContainer.querySelector('[id^="sellers-"]');
        if (sellersPanel) {
            var bestSell = sellersPanel.querySelector('.m-best-price');
            if (bestSell) {
                var sp = bestSell.querySelector('.m-vendor-price');
                if (sp) {
                    var psp = parseFloat(sp.textContent.trim().replace('$', '').trim());
                    if (!isNaN(psp)) sellPrice = psp;
                }
                var sn = bestSell.querySelector('.m-vendor-name');
                if (sn) sellVendor = sn.textContent.replace('Best', '').trim();
            }
        }

        var buyPrice = null;
        var buyVendor = '';
        var buyersPanel = cardContainer.querySelector('[id^="buyers-"]');
        if (buyersPanel) {
            var bestBuy = buyersPanel.querySelector('.m-best-price');
            if (bestBuy) {
                var bp = bestBuy.querySelector('.m-vendor-price');
                if (bp) {
                    var pbp = parseFloat(bp.textContent.trim().replace('$', '').trim());
                    if (!isNaN(pbp)) buyPrice = pbp;
                }
                var bn = bestBuy.querySelector('.m-vendor-name');
                if (bn) buyVendor = bn.textContent.replace('Best', '').trim();
            }
        }

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
            finishTag: finishTag,
            finishClass: finishClass,
            treatments: treatments,
            sellPrice: sellPrice,
            sellVendor: sellVendor,
            buyPrice: buyPrice,
            buyVendor: buyVendor,
            query: query,
            t: Date.now(),
            img: imageUrl
        };
    }

    // Toggle favorite on star click
    window.toggleFavorite = function(btn) {
        var cardId = btn.getAttribute('data-card-id') || btn.getAttribute('data-card');
        if (!cardId) return;
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

        document.querySelectorAll('.fav-btn').forEach(function(btn) {
            var id = btn.getAttribute('data-card-id') || btn.getAttribute('data-card');
            if (id && favIds[id]) {
                btn.classList.add('active');
            }
        });
    }

    // Render favorites on landing page
    function renderFavorites() {
        renderFavoritesInto(document.getElementById('m-favorites'), 'mobile');
        renderFavoritesInto(document.getElementById('desktop-favorites'), 'desktop');
    }

    var paginationState = {}; // { containerId: { page: 0 } }

    function renderFavoritesInto(container, mode) {
        if (!container) return;
        var favs = getFavorites();

        var containerId = container.id;
        if (!paginationState[containerId]) paginationState[containerId] = { page: 0 };
        var pageSize = mode === 'desktop' ? 10 : favs.length || 1;
        var totalPages = Math.max(1, Math.ceil(favs.length / pageSize));
        if (paginationState[containerId].page >= totalPages) paginationState[containerId].page = 0;
        var page = paginationState[containerId].page;

        if (favs.length === 0) {
            if (mode === 'desktop') {
                container.innerHTML = '<div class="landing-empty">Star cards from any search to favorite them.</div>';
            } else {
                container.innerHTML = '';
            }
            return;
        }

        var html = '';
        if (mode === 'mobile') {
            html += '<div class="m-fav-header">';
            html += '<span class="m-fav-title">Favorites</span>';
            html += '<span class="m-fav-actions">';
            html += '<button class="m-fav-refresh" onclick="window.manualRefreshFavorites()" title="Refresh prices"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/></svg></button>';
            html += '<button class="m-fav-clear" onclick="window.clearFavorites()">Clear</button>';
            html += '</span>';
            html += '</div>';
            html += '<div class="m-fav-list">';

            favs.forEach(function(f) {
                html += '<a class="m-fav-item" href="?q=' + encodeURIComponent(f.query) + '">';
                if (f.img) {
                    html += '<img class="m-fav-thumb" src="' + escapeAttr(f.img) + '" loading="lazy" alt="">';
                }
                html += '<div class="m-fav-item-body">';
                html += '<div class="m-fav-item-top">';
                html += '<span class="m-fav-name">' + escapeHtml(f.name) + '</span>';
                html += '<span class="m-fav-set">' + escapeHtml(f.set) + (f.number ? ' #' + escapeHtml(f.number) : '') + '</span>';
                if (f.finishTag) html += '<span class="m-badge ' + (f.finishClass || 'foil') + '">' + escapeHtml(f.finishTag) + '</span>';
                if (f.treatments) f.treatments.forEach(function(tag) { html += '<span class="m-badge treatment">' + escapeHtml(tag) + '</span>'; });
                html += '</div>';
                html += '<div class="m-fav-item-prices">';
                if (f.sellPrice !== null && f.sellPrice !== undefined) {
                    html += '<span class="m-fav-price sell">Sellers' + (f.sellVendor ? ' (' + escapeHtml(f.sellVendor) + ')' : '') + ': $ ' + f.sellPrice.toFixed(2) + '</span>';
                }
                if (f.buyPrice !== null && f.buyPrice !== undefined) {
                    html += '<span class="m-fav-price buy">Buyers' + (f.buyVendor ? ' (' + escapeHtml(f.buyVendor) + ')' : '') + ': $ ' + f.buyPrice.toFixed(2) + '</span>';
                }
                html += '</div>';
                html += '</div>';
                html += '</a>';
            });
            html += '</div>';
        } else {
            // desktop
            var start = page * pageSize;
            var slice = favs.slice(start, start + pageSize);

            html += '<div class="landing-pane-header">';
            html += '<span class="landing-pane-title">Favorites</span>';
            html += '<span class="landing-pane-actions">';
            html += '<button class="landing-pane-btn" onclick="window.manualRefreshFavorites()" title="Refresh prices">Refresh</button>';
            html += '<button class="landing-pane-btn" onclick="window.clearFavorites()">Clear</button>';
            html += '</span>';
            html += '</div>';
            html += '<div class="landing-pane-body">';
            slice.forEach(function(f) {
                html += '<a class="landing-item landing-item-fav" href="?q=' + encodeURIComponent(f.query) + '">';
                html += '<div class="landing-item-thumb">';
                if (f.img) {
                    html += '<img src="' + escapeAttr(f.img) + '" loading="lazy" alt="">';
                } else {
                    html += '<span class="landing-item-thumb-placeholder">&#9733;</span>';
                }
                html += '</div>';
                html += '<div class="landing-item-info">';
                html += '<div class="landing-item-line1">';
                html += '<span class="landing-item-name">' + escapeHtml(f.name) + '</span>';
                html += '<span class="landing-item-set">' + escapeHtml(f.set) + (f.number ? ' #' + escapeHtml(f.number) : '') + '</span>';
                if (f.finishTag) html += '<span class="m-badge ' + (f.finishClass || 'foil') + '">' + escapeHtml(f.finishTag) + '</span>';
                html += '</div>';
                if (f.sellPrice !== null && f.sellPrice !== undefined) {
                    html += '<div class="landing-item-price-row sell">';
                    html += '<span class="landing-item-price-label">Sellers' + (f.sellVendor ? ' (' + escapeHtml(f.sellVendor) + ')' : '') + '</span>';
                    html += '<span class="landing-item-price-value">$ ' + f.sellPrice.toFixed(2) + '</span>';
                    html += '</div>';
                }
                if (f.buyPrice !== null && f.buyPrice !== undefined) {
                    html += '<div class="landing-item-price-row buy">';
                    html += '<span class="landing-item-price-label">Buyers' + (f.buyVendor ? ' (' + escapeHtml(f.buyVendor) + ')' : '') + '</span>';
                    html += '<span class="landing-item-price-value">$ ' + f.buyPrice.toFixed(2) + '</span>';
                    html += '</div>';
                }
                html += '</div>';
                html += '</a>';
            });
            html += '</div>';
            if (totalPages > 1) {
                html += '<div class="landing-pane-footer">';
                html += '<button class="landing-page-btn" onclick="window.favPage(\'' + containerId + '\', -1)" ' + (page === 0 ? 'disabled' : '') + '>&lsaquo;</button>';
                html += '<span class="landing-page-label">' + (page + 1) + ' / ' + totalPages + '</span>';
                html += '<button class="landing-page-btn" onclick="window.favPage(\'' + containerId + '\', 1)" ' + (page === totalPages - 1 ? 'disabled' : '') + '>&rsaquo;</button>';
                html += '</div>';
            }
        }
        container.innerHTML = html;
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function escapeAttr(str) {
        return String(str).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
    }

    window.favPage = function(containerId, delta) {
        if (!paginationState[containerId]) paginationState[containerId] = { page: 0 };
        paginationState[containerId].page += delta;
        renderFavorites();
    };

    window.clearFavorites = function() {
        localStorage.removeItem(STORAGE_KEY);
        var mobile = document.getElementById('m-favorites');
        if (mobile) mobile.innerHTML = '';
        var desktop = document.getElementById('desktop-favorites');
        if (desktop) renderFavoritesInto(desktop, 'desktop');
    };

    // Refresh stale favorites from server
    var STALE_MS = 60 * 60 * 1000; // 1 hour
    var lastRefreshAttempt = 0;

    function refreshFavorites() {
        var favs = getFavorites();
        if (favs.length === 0) return;

        // Refresh if any entry is older than STALE_MS, or if any entry is missing
        // prices (desktop favorites have no inline DOM to scrape best-price from).
        var now = Date.now();
        var needsRefresh = favs.some(function(f) {
            return (now - f.t) > STALE_MS || (f.sellPrice == null && f.buyPrice == null);
        });
        if (!needsRefresh) return;

        doRefresh();
    }

    function showToast(msg) {
        var toast = document.getElementById('m-fav-toast');
        if (!toast) return;
        toast.textContent = msg;
        toast.classList.add('show');
        setTimeout(function() { toast.classList.remove('show'); }, 2000);
    }

    function doRefresh(showNotification) {
        var favs = getFavorites();
        if (favs.length === 0) return;

        // Chunk into batches of 50
        var BATCH_SIZE = 50;
        var allIds = favs.map(function(f) { return f.id; });
        var batches = [];
        for (var i = 0; i < allIds.length; i += BATCH_SIZE) {
            batches.push(allIds.slice(i, i + BATCH_SIZE));
        }

        // Fetch all batches in parallel
        var fetches = batches.map(function(batch) {
            return fetch('/api/prices/?ids=' + encodeURIComponent(batch.join(',')))
                .then(function(r) { return r.ok ? r.json() : {}; })
                .catch(function() { return {}; });
        });

        Promise.all(fetches).then(function(results) {
            // Merge all batch results
            var merged = {};
            results.forEach(function(data) {
                Object.keys(data).forEach(function(k) { merged[k] = data[k]; });
            });

            var favs = getFavorites();
            var updated = false;

            favs.forEach(function(f) {
                var prices = merged[f.id];
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
                if (prices.imageURL && !f.img) {
                    f.img = prices.imageURL;
                    updated = true;
                }
                f.t = Date.now();
            });

            if (updated) {
                saveFavorites(favs);
                renderFavorites();
                if (showNotification) showToast('Favorites refreshed!');
            } else if (showNotification) {
                showToast('Prices are up to date');
            }
        });
    }

    function scheduleRefresh() {
        if (typeof requestIdleCallback === 'function') {
            requestIdleCallback(refreshFavorites);
        } else {
            setTimeout(refreshFavorites, 1500);
        }
    }

    // Manual refresh - rate limited to once per hour
    window.manualRefreshFavorites = function() {
        var now = Date.now();
        if ((now - lastRefreshAttempt) < STALE_MS) {
            return; // Rate limited
        }
        lastRefreshAttempt = now;
        doRefresh(true);
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
