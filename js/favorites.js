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

    var SORT_KEY = 'mtgban_fav_sort';
    var SORT_DIR_KEY = 'mtgban_fav_sort_dir';

    function getSort() {
        return localStorage.getItem(SORT_KEY) || 'chrono';
    }
    function getSortDir() {
        return localStorage.getItem(SORT_DIR_KEY) || 'desc';
    }
    function setSort(key, dir) {
        try {
            localStorage.setItem(SORT_KEY, key);
            localStorage.setItem(SORT_DIR_KEY, dir);
        } catch (e) {}
    }

    function sortFavs(list) {
        var key = getSort();
        var dir = getSortDir() === 'asc' ? 1 : -1;
        var sorted = list.slice();
        sorted.sort(function(a, b) {
            var av, bv;
            switch (key) {
                case 'alpha':
                    av = (a.name || '').toLowerCase();
                    bv = (b.name || '').toLowerCase();
                    return av < bv ? -1 * dir : av > bv ? 1 * dir : 0;
                case 'sell':
                    av = a.sellPrice == null ? -Infinity : a.sellPrice;
                    bv = b.sellPrice == null ? -Infinity : b.sellPrice;
                    return (av - bv) * dir;
                case 'buy':
                    av = a.buyPrice == null ? -Infinity : a.buyPrice;
                    bv = b.buyPrice == null ? -Infinity : b.buyPrice;
                    return (av - bv) * dir;
                case 'manual':
                    return 0;
                case 'chrono':
                default:
                    return ((a.t || 0) - (b.t || 0)) * dir;
            }
        });
        return sorted;
    }

    function pinnedFirst(list) {
        // Stable two-pass: pinned items first (by pin time desc), unpinned after (original order)
        var pinned = [];
        var unpinned = [];
        list.forEach(function(item) {
            if (item.pinned) pinned.push(item); else unpinned.push(item);
        });
        pinned.sort(function(a, b) { return (b.pinned || 0) - (a.pinned || 0); });
        return pinned.concat(unpinned);
    }

    function sortPillsHtml() {
        var key = getSort();
        var dir = getSortDir();
        var pills = [
            { val: 'chrono', icon: 'clock', title: 'Added' },
            { val: 'alpha', icon: 'a-large-small', title: 'Name' },
            { val: 'sell', icon: 'tag', title: 'Sell price' },
            { val: 'buy', icon: 'shopping-cart', title: 'Buy price' }
        ];
        var html = '';
        pills.forEach(function(p) {
            var active = p.val === key;
            var arrow = (active && key !== 'manual') ? (dir === 'asc' ? '<i data-lucide="arrow-up" class="fav-sort-dir asc"></i>' : '<i data-lucide="arrow-down" class="fav-sort-dir desc"></i>') : '';
            html += '<button class="fav-sort-pill' + (active ? ' active' : '') + '" data-val="' + p.val + '" onclick="window.cycleFavSort(\'' + p.val + '\')" title="' + p.title + '"><i data-lucide="' + p.icon + '"></i>' + arrow + '</button>';
        });
        return html;
    }

    function extractCardData(btn) {
        // Walk to the row container by class. Both button and row carry data-card-id,
        // so a [data-card-id] selector would match the button itself first.
        var row = btn.closest('.m-card-header, .result-header');
        if (!row) {
            // A fav button can sit outside the header (e.g. the mobile actions
            // menu is a sibling of the header) — fall back to the card container.
            var card = btn.closest('.m-card');
            if (card) row = card.querySelector('.m-card-header');
        }
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
        var hasContentWarning = row.getAttribute('data-has-warning') === 'true';

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
            img: imageUrl,
            cw: hasContentWarning
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

        var active;
        if (idx >= 0) {
            favs.splice(idx, 1);
            active = false;
        } else {
            var data = extractCardData(btn);
            if (!data) return;
            favs.unshift(data);
            active = true;
        }

        saveFavorites(favs);

        // Keep every star for this card in sync — the inline header button and
        // its copy inside the mobile actions menu point at the same card.
        document.querySelectorAll('.fav-btn').forEach(function(b) {
            var id = b.getAttribute('data-card-id') || b.getAttribute('data-card');
            if (id === cardId) b.classList.toggle('active', active);
        });
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
    window.renderFavorites = renderFavorites;

    var paginationState = {}; // { containerId: { page: 0 } }

    function renderFavoritesInto(container, mode) {
        if (!container) return;
        var favs = pinnedFirst(sortFavs(getFavorites()));

        var containerId = container.id;
        if (!paginationState[containerId]) paginationState[containerId] = { page: 0 };
        var pageSize = mode === 'desktop' ? 8 : favs.length || 1;
        var totalPages = Math.max(1, Math.ceil(favs.length / pageSize));
        if (paginationState[containerId].page >= totalPages) paginationState[containerId].page = 0;
        var page = paginationState[containerId].page;

        if (favs.length === 0) {
            if (mode === 'desktop') {
                container.innerHTML = renderFavEmptyState();
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
            html += '<span class="m-fav-sort">' + sortPillsHtml() + '</span>';
            html += '<button class="m-fav-refresh" onclick="window.manualRefreshFavorites()" title="Refresh prices"><svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8"/><path d="M21 3v5h-5"/><path d="M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16"/><path d="M3 21v-5h5"/></svg></button>';
            html += '<button class="m-fav-clear" onclick="window.clearFavorites(this)">Clear</button>';
            html += '</span>';
            html += '</div>';
            html += '<div class="m-fav-list">';

            favs.forEach(function(f) {
                html += '<a class="m-fav-item" href="?q=' + encodeURIComponent(f.query) + '">';
                if (f.img) {
                    html += '<div class="m-fav-thumb">' + thumbHtml(f.img, f.foil, f.cw) + '</div>';
                }
                html += '<div class="m-fav-item-body">';
                html += '<div class="m-fav-item-top">';
                html += '<span class="m-fav-name">' + escapeHtml(f.name) + '</span>';
                html += '<span class="m-fav-set">' + escapeHtml(f.set) + (f.number ? ' #' + escapeHtml(f.number) : '') + '</span>';
                html += '<span class="m-fav-chips">';
                if (f.finishTag) html += '<span class="m-badge ' + (f.finishClass || 'foil') + '">' + escapeHtml(f.finishTag) + '</span>';
                if (f.treatments) f.treatments.forEach(function(tag) { html += '<span class="m-badge treatment">' + escapeHtml(tag) + '</span>'; });
                html += '</span>';
                html += '<button class="m-fav-pin' + (f.pinned ? ' pinned' : '') + '" data-id="' + escapeAttr(f.id) + '" onclick="event.preventDefault(); event.stopPropagation(); window.toggleFavoritePin(this.dataset.id, event)" title="' + (f.pinned ? 'Unpin' : 'Pin to top') + '"><svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="' + (f.pinned ? 'currentColor' : 'none') + '" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17v5"/><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/></svg></button>';
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
            html += '<span class="landing-pane-sort">' + sortPillsHtml() + '</span>';
            html += '<button class="landing-pane-btn landing-pane-btn-icon" onclick="window.manualRefreshFavorites()" title="Update prices" aria-label="Update prices"><i data-lucide="refresh-cw"></i></button>';
            html += '<button class="landing-pane-btn landing-pane-btn-icon" onclick="window.clearFavorites(this)" title="Clear favorites" aria-label="Clear favorites"><i data-lucide="trash-2"></i></button>';
            html += '</span>';
            html += '</div>';
            html += '<div class="landing-pane-body">';
            slice.forEach(function(f) {
                html += '<a class="landing-item landing-item-fav" href="?q=' + encodeURIComponent(f.query) + '"' + (f.pinned ? '' : ' draggable="true"') + ' data-fav-id="' + escapeAttr(f.id) + '">';
                html += '<div class="landing-item-thumb">';
                if (f.img) {
                    html += thumbHtml(f.img, f.foil, f.cw);
                } else {
                    html += '<span class="landing-item-thumb-placeholder">&#9733;</span>';
                }
                html += '</div>';
                html += '<div class="landing-item-info">';
                html += '<div class="landing-item-line1">';
                html += '<span class="landing-item-name">' + escapeHtml(f.name) + '</span>';
                html += '<span class="landing-item-set">' + escapeHtml(f.set) + (f.number ? ' · #' + escapeHtml(f.number) : '') + '</span>';
                if (f.finishTag) html += '<span class="result-badge ' + (f.finishClass || 'foil') + '">' + escapeHtml(f.finishTag) + '</span>';
                html += '</div>';
                var hasSell = f.sellPrice !== null && f.sellPrice !== undefined;
                var hasBuy = f.buyPrice !== null && f.buyPrice !== undefined;
                if (hasSell || hasBuy) {
                    html += '<div class="landing-item-prices">';
                    if (hasSell) {
                        html += '<span class="landing-item-price-label sell">Sellers' + (f.sellVendor ? ' (' + escapeHtml(f.sellVendor) + ')' : '') + '</span>';
                        html += '<span class="landing-item-price-value sell">$ ' + f.sellPrice.toFixed(2) + '</span>';
                    }
                    if (hasBuy) {
                        html += '<span class="landing-item-price-label buy">Buyers' + (f.buyVendor ? ' (' + escapeHtml(f.buyVendor) + ')' : '') + '</span>';
                        html += '<span class="landing-item-price-value buy">$ ' + f.buyPrice.toFixed(2) + '</span>';
                    }
                    html += '</div>';
                }
                html += '</div>';
                html += '<button class="landing-item-pin' + (f.pinned ? ' pinned' : '') + '" data-id="' + escapeAttr(f.id) + '" onclick="window.toggleFavoritePin(this.dataset.id, event)" title="' + (f.pinned ? 'Unpin' : 'Pin to top') + '">';
                html += '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="' + (f.pinned ? 'currentColor' : 'none') + '" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17v5"/><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/></svg>';
                html += '</button>';
                html += '<button class="landing-item-delete" data-id="' + escapeAttr(f.id) + '" onclick="window.deleteFavorite(this.dataset.id, event)" title="Remove from favorites">';
                html += '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
                html += '</button>';
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
        if (typeof lucide !== 'undefined' && lucide.createIcons) {
            lucide.createIcons({ nameAttr: 'data-lucide', attrs: {} });
        }
        if (mode === 'desktop') initDragDrop(container);
    }

    var dragSrcId = null;

    function initDragDrop(container) {
        var items = container.querySelectorAll('.landing-item-fav[draggable]');
        items.forEach(function(el) {
            el.addEventListener('dragstart', function(e) {
                dragSrcId = el.dataset.favId;
                el.classList.add('fav-dragging');
                e.dataTransfer.effectAllowed = 'move';
                e.dataTransfer.setData('text/plain', dragSrcId);
            });
            el.addEventListener('dragend', function() {
                dragSrcId = null;
                el.classList.remove('fav-dragging');
                container.querySelectorAll('.fav-drag-over').forEach(function(x) {
                    x.classList.remove('fav-drag-over');
                });
            });
            el.addEventListener('dragover', function(e) {
                if (!dragSrcId || dragSrcId === el.dataset.favId || el.querySelector('.landing-item-pin.pinned')) return;
                e.preventDefault();
                e.dataTransfer.dropEffect = 'move';
                el.classList.add('fav-drag-over');
            });
            el.addEventListener('dragleave', function() {
                el.classList.remove('fav-drag-over');
            });
            el.addEventListener('drop', function(e) {
                e.preventDefault();
                el.classList.remove('fav-drag-over');
                var targetId = el.dataset.favId;
                if (!dragSrcId || dragSrcId === targetId) return;
                reorderFavorite(dragSrcId, targetId);
            });
        });
    }

    function reorderFavorite(fromId, toId) {
        var favs = getFavorites();
        var fromIdx = -1, toIdx = -1;
        for (var i = 0; i < favs.length; i++) {
            if (favs[i].id === fromId) fromIdx = i;
            if (favs[i].id === toId) toIdx = i;
        }
        if (fromIdx < 0 || toIdx < 0 || fromIdx === toIdx) return;
        var item = favs.splice(fromIdx, 1)[0];
        favs.splice(toIdx, 0, item);
        saveFavorites(favs);
        setSort('manual', 'desc');
        renderFavorites();
    }

    function renderFavEmptyState() {
        return '' +
            '<div class="landing-pane-header">' +
                '<span class="landing-pane-title">Favorites</span>' +
            '</div>' +
            '<div class="landing-empty-fav">' +
                '<div class="landing-empty-headline">' +
                    '<h3>Track your watchlist here</h3>' +
                    '<p>Star a card from search results and its best sell &amp; buy prices appear in this pane.</p>' +
                '</div>' +
                '<div class="landing-empty-flow">' +
                    '<div class="landing-empty-side">' +
                        '<div class="landing-empty-side-label">From any search</div>' +
                        '<div class="landing-empty-mini-result">' +
                            '<div class="landing-empty-mini-result-head">' +
                                '<i class="ss ss-pmei ss-timeshifted ss-2x ss-fw landing-empty-mini-seticon" aria-hidden="true"></i>' +
                                '<div class="landing-empty-mini-text">' +
                                    '<div class="landing-empty-mini-title-row">' +
                                        '<span class="landing-empty-mini-title">Mox Opal</span>' +
                                        '<span class="result-badge etched">Etched</span>' +
                                    '</div>' +
                                    '<div class="landing-empty-mini-meta">SLD &middot; #1072</div>' +
                                '</div>' +
                                '<div class="landing-empty-mini-tools">' +
                                    '<svg class="landing-empty-star" xmlns="http://www.w3.org/2000/svg" width="18" height="18" viewBox="0 0 24 24" fill="currentColor" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
                                        '<path d="M11.525 2.295a.53.53 0 0 1 .95 0l2.31 4.679a2.123 2.123 0 0 0 1.595 1.16l5.166.756a.53.53 0 0 1 .294.904l-3.736 3.638a2.123 2.123 0 0 0-.611 1.878l.882 5.14a.53.53 0 0 1-.771.56l-4.618-2.428a2.122 2.122 0 0 0-1.973 0L6.396 21.01a.53.53 0 0 1-.77-.56l.881-5.139a2.122 2.122 0 0 0-.611-1.879L2.16 9.795a.53.53 0 0 1 .294-.906l5.165-.755a2.122 2.122 0 0 0 1.597-1.16z"/>' +
                                    '</svg>' +
                                '</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="landing-empty-tooltip">Click the star to favorite</div>' +
                    '</div>' +
                    '<div class="landing-empty-arrow" aria-hidden="true">→</div>' +
                    '<div class="landing-empty-side">' +
                        '<div class="landing-empty-side-label">Saved here</div>' +
                        '<div class="landing-empty-mini-fav">' +
                            '<div class="landing-empty-mini-fav-thumb">' +
                                '<img src="https://cards.scryfall.io/normal/front/6/a/6a2dbb1a-4b83-47b6-92ca-145fa5c9c16b.jpg" alt="" loading="lazy">' +
                            '</div>' +
                            '<div class="landing-empty-mini-fav-info">' +
                                '<div class="landing-empty-mini-fav-name-row">' +
                                    '<span class="landing-empty-mini-fav-name">Mox Opal</span>' +
                                    '<span class="result-badge etched">Etched</span>' +
                                '</div>' +
                                '<div class="landing-empty-mini-fav-set">SLD &middot; #1072</div>' +
                                '<div class="landing-empty-mini-fav-prices">' +
                                    '<span class="sell">Sell</span><span class="sell">$ 214.04</span>' +
                                    '<span class="buy">Buy</span><span class="buy">$ 204.76</span>' +
                                '</div>' +
                            '</div>' +
                        '</div>' +
                        '<div class="landing-empty-tooltip">Best prices, kept fresh</div>' +
                    '</div>' +
                '</div>' +
            '</div>';
    }

    window.favPage = function(containerId, delta) {
        if (!paginationState[containerId]) paginationState[containerId] = { page: 0 };
        paginationState[containerId].page += delta;
        renderFavorites();
    };

    window.deleteFavorite = function(cardId, ev) {
        if (ev) { ev.preventDefault(); ev.stopPropagation(); }
        if (!cardId) return;
        var favs = getFavorites().filter(function(f) { return f.id !== cardId; });
        saveFavorites(favs);
        renderFavorites();
        // Clear active state on any star buttons for this card on the same page.
        document.querySelectorAll('.fav-btn[data-card-id="' + cardId + '"]').forEach(function(btn) {
            btn.classList.remove('active');
        });
    };

    window.toggleFavoritePin = function(cardId, ev) {
        if (ev) { ev.preventDefault(); ev.stopPropagation(); }
        if (!cardId) return;
        var favs = getFavorites();
        var changed = false;
        for (var i = 0; i < favs.length; i++) {
            if (favs[i].id === cardId) {
                if (favs[i].pinned) {
                    delete favs[i].pinned;
                } else {
                    favs[i].pinned = Date.now();
                }
                changed = true;
                break;
            }
        }
        if (changed) {
            saveFavorites(favs);
            renderFavorites();
        }
    };

    window.cycleFavSort = function(val) {
        var current = getSort();
        var dir = getSortDir();
        if (val === current) {
            dir = dir === 'asc' ? 'desc' : 'asc';
        } else {
            dir = 'desc';
        }
        setSort(val, dir);
        renderFavorites();
    };

    window.clearFavorites = function(trigger) {
        var doClear = function() {
            localStorage.removeItem(STORAGE_KEY);
            var mobile = document.getElementById('m-favorites');
            if (mobile) mobile.innerHTML = '';
            var desktop = document.getElementById('desktop-favorites');
            if (desktop) renderFavoritesInto(desktop, 'desktop');
        };
        if (typeof window.confirmDialog === 'function') {
            var anchor = trigger && trigger.closest ? trigger.closest('#desktop-favorites') : null;
            window.confirmDialog('Clear all favorites? This cannot be undone.', doClear, { anchor: anchor });
        } else {
            doClear();
        }
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
            var lastFetched = f.refreshedAt || f.t;
            return (now - lastFetched) > STALE_MS || (f.sellPrice == null && f.buyPrice == null);
        });
        if (!needsRefresh) return;

        doRefresh();
    }

    function showToast(msg) {
        var toast = document.getElementById('m-fav-toast') || document.getElementById('desktop-fav-toast');
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
                // Track last-fetched time separately from added time (f.t),
                // so chrono sort by add order isn't shuffled on refresh.
                f.refreshedAt = Date.now();
            });

            if (updated) {
                saveFavorites(favs);
                renderFavorites();
                if (showNotification) showToast('Prices updated');
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
