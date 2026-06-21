// Recent Searches - localStorage-backed search history for mobile
(function() {
    var STORAGE_KEY = 'mtgban_recent_searches';
    var MAX_ENTRIES = 15;

    // Parse a query for set tokens. Returns {set, keyrune} only when the query is
    // a "pure set search" - the first token is s:/e:/ee:. A query like "Birds s:7ed"
    // is a card search with a set filter, not a set browse, so no keyrune.
    function parseSetToken(query) {
        if (!query) return { set: '', keyrune: '' };
        var trimmed = query.trim();

        // Must start with s:, e:, or ee: to count as a pure set search.
        if (!/^(?:s|e|ee):/i.test(trimmed)) {
            return { set: '', keyrune: '' };
        }

        // Quoted set name: s:"Aether Revolt" - can't resolve to keyrune client-side.
        if (/^s:"[^"]+"/i.test(trimmed)) {
            return { set: '', keyrune: '' };
        }

        var cm = trimmed.match(/^(?:s|e|ee):([A-Za-z0-9]{2,6})\b/i);
        if (cm) {
            var code = cm[1].toUpperCase();
            var keyrunes = window.BAN_SET_KEYRUNES || {};
            return { set: code, keyrune: keyrunes[code] || '' };
        }

        return { set: '', keyrune: '' };
    }

    function getRecentSearches() {
        try {
            var data = localStorage.getItem(STORAGE_KEY);
            return data ? JSON.parse(data) : [];
        } catch (e) {
            return [];
        }
    }

    function saveRecentSearches(searches) {
        try {
            localStorage.setItem(STORAGE_KEY, JSON.stringify(searches));
        } catch (e) {
            // localStorage full or unavailable - silently fail
        }
    }

    function pinnedFirst(list) {
        var pinned = [];
        var unpinned = [];
        list.forEach(function(item) {
            if (item.pinned) pinned.push(item); else unpinned.push(item);
        });
        pinned.sort(function(a, b) { return (b.pinned || 0) - (a.pinned || 0); });
        return pinned.concat(unpinned);
    }

    function addSearch(query) {
        query = query.trim();
        if (!query || query.length < 2) return;

        var searches = getRecentSearches();

        // Remove existing entry with same query (case-insensitive dedup)
        searches = searches.filter(function(s) {
            return s.q.toLowerCase() !== query.toLowerCase();
        });

        var token = parseSetToken(query);

        searches.unshift({
            q: query,
            t: Date.now(),
            img: '',
            set: token.set,
            keyrune: token.keyrune
        });

        if (searches.length > MAX_ENTRIES) {
            searches = searches.slice(0, MAX_ENTRIES);
        }

        saveRecentSearches(searches);
    }

    function clearRecentSearches(trigger) {
        var doClear = function() {
            localStorage.removeItem(STORAGE_KEY);
            var mobile = document.getElementById('m-recent-searches');
            if (mobile) mobile.innerHTML = '';
            var desktop = document.getElementById('desktop-recent-searches');
            if (desktop) renderRecentSearchesInto(desktop, 'desktop');
        };
        if (typeof window.confirmDialog === 'function') {
            var anchor = trigger && trigger.closest ? trigger.closest('#desktop-recent-searches') : null;
            window.confirmDialog('Clear all recent searches?', doClear, { anchor: anchor });
        } else {
            doClear();
        }
    }

    function renderRecentSearches() {
        renderRecentSearchesInto(document.getElementById('m-recent-searches'), 'mobile');
        renderRecentSearchesInto(document.getElementById('desktop-recent-searches'), 'desktop');
    }
    window.renderRecentSearches = renderRecentSearches;

    function renderRecentSearchesInto(container, mode) {
        if (!container) return;
        var oldBody = container.querySelector('.landing-pane-body');
        var savedScroll = oldBody ? oldBody.scrollTop : 0;
        var searches = pinnedFirst(getRecentSearches());

        if (searches.length === 0) {
            if (mode === 'desktop') {
                container.innerHTML = '<div class="landing-empty">Your recent searches will appear here.</div>';
            } else {
                container.innerHTML = '';
            }
            return;
        }

        var html = '';
        if (mode === 'mobile') {
            html += '<div class="m-recent-header">';
            html += '<span class="m-recent-title">Recent Searches</span>';
            html += '<button class="m-recent-clear" onclick="window.clearRecentSearches(this)">Clear</button>';
            html += '</div>';
            html += '<div class="m-recent-list">';
            searches.forEach(function(s) {
                html += '<a class="m-recent-item" href="?q=' + encodeURIComponent(s.q) + '">';
                html += '<span class="m-recent-icon">&#128269;</span>';
                html += '<span class="m-recent-query">' + escapeHtml(s.q) + '</span>';
                html += '<span class="m-recent-arrow">&rsaquo;</span>';
                html += '</a>';
            });
            html += '</div>';
        } else {
            html += '<div class="landing-pane-header">';
            html += '<span class="landing-pane-title">Recent Searches</span>';
            html += '<span class="landing-pane-actions">';
            html += '<button class="landing-pane-btn landing-pane-btn-icon" onclick="window.clearRecentSearches(this)" title="Clear recent searches" aria-label="Clear recent searches"><i data-lucide="trash-2"></i></button>';
            html += '</span>';
            html += '</div>';
            html += '<div class="landing-pane-body">';
            searches.forEach(function(s) {
                var cropSrc = s.crop || '';
                var token = parseSetToken(s.q);
                html += '<a class="landing-item landing-item-recent' + (cropSrc ? ' has-crop' : '') + '"' + (cropSrc ? ' style="background-image:url(\'' + escapeAttr(cropSrc) + '\')"' : '') + ' href="?q=' + encodeURIComponent(s.q) + '">';
                if (!cropSrc) {
                    html += '<div class="landing-item-thumb">';
                    if (token.keyrune) {
                        html += '<i class="ss ' + escapeAttr(token.keyrune) + ' ss-fw"></i>';
                    } else if (s.img) {
                        html += thumbHtml(s.img, s.foil, s.cw);
                    } else {
                        html += '<span class="landing-item-thumb-placeholder"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg></span>';
                    }
                    html += '</div>';
                }
                html += '<div class="landing-item-info">';
                html += '<span class="landing-item-query">' + escapeHtml(s.q) + '</span>';
                html += '</div>';
                html += '<div class="landing-item-actions">';
                html += '<button class="landing-item-pin' + (s.pinned ? ' pinned' : '') + '" data-q="' + escapeAttr(s.q) + '" onclick="window.toggleRecentPin(this.dataset.q, event)" title="' + (s.pinned ? 'Unpin' : 'Pin to top') + '">';
                html += '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="' + (s.pinned ? 'currentColor' : 'none') + '" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 17v5"/><path d="M9 10.76a2 2 0 0 1-1.11 1.79l-1.78.9A2 2 0 0 0 5 15.24V16a1 1 0 0 0 1 1h12a1 1 0 0 0 1-1v-.76a2 2 0 0 0-1.11-1.79l-1.78-.9A2 2 0 0 1 15 10.76V7a1 1 0 0 1 1-1 2 2 0 0 0 0-4H8a2 2 0 0 0 0 4 1 1 0 0 1 1 1z"/></svg>';
                html += '</button>';
                html += '<button class="landing-item-delete" data-q="' + escapeAttr(s.q) + '" onclick="window.deleteRecentSearch(this.dataset.q, event)" title="Remove from recent searches">';
                html += '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
                html += '</button>';
                html += '</div>';
                html += '</a>';
            });
            html += '</div>';
        }
        container.innerHTML = html;
        var newBody = container.querySelector('.landing-pane-body');
        if (newBody && savedScroll) newBody.scrollTop = savedScroll;
        if (typeof lucide !== 'undefined' && lucide.createIcons) {
            lucide.createIcons({ nameAttr: 'data-lucide', attrs: {} });
        }
    }


    window.deleteRecentSearch = function(query, ev) {
        if (ev) { ev.preventDefault(); ev.stopPropagation(); }
        if (!query) return;
        var searches = getRecentSearches().filter(function(s) { return s.q !== query; });
        saveRecentSearches(searches);
        renderRecentSearches();
    };

    window.toggleRecentPin = function(query, ev) {
        if (ev) { ev.preventDefault(); ev.stopPropagation(); }
        if (!query) return;
        var searches = getRecentSearches();
        var changed = false;
        for (var i = 0; i < searches.length; i++) {
            if (searches[i].q === query) {
                if (searches[i].pinned) {
                    delete searches[i].pinned;
                } else {
                    searches[i].pinned = Date.now();
                }
                changed = true;
                break;
            }
        }
        if (changed) {
            saveRecentSearches(searches);
            renderRecentSearches();
        }
    };

    // Record search on form submit (page bars and navbar share this store)
    function hookFormSubmit() {
        var pairs = [['searchform', 'searchbox'], ['nav-searchform', 'nav-searchbox']];
        pairs.forEach(function(ids) {
            var form = document.getElementById(ids[0]);
            if (!form) return;
            form.addEventListener('submit', function() {
                var input = document.getElementById(ids[1]);
                if (input && input.value.trim()) {
                    addSearch(input.value);
                }
            });
        });
    }

    function captureFirstResultImage() {
        var params = new URLSearchParams(window.location.search);
        var q = (params.get('q') || '').trim();
        if (!q) return;

        var firstRow = document.querySelector('.result-header[data-image-url], .m-card-header[data-image-url]');
        if (!firstRow) return;

        var img = firstRow.getAttribute('data-image-url');
        if (!img) return;

        var finishClass = firstRow.getAttribute('data-finish-class') || '';
        var foil = finishClass === 'foil' || finishClass === 'altfoil';
        var cw = firstRow.getAttribute('data-has-warning') === 'true';
        var crop = firstRow.getAttribute('data-crop-url') || '';

        var searches = getRecentSearches();
        var qLower = q.toLowerCase();
        var changed = false;
        for (var i = 0; i < searches.length; i++) {
            if (searches[i].q.toLowerCase() === qLower) {
                if (!searches[i].img) {
                    searches[i].img = img;
                    changed = true;
                }
                if (crop && searches[i].crop !== crop) {
                    searches[i].crop = crop;
                    changed = true;
                }
                if (searches[i].foil !== foil || searches[i].cw !== cw) {
                    searches[i].foil = foil;
                    searches[i].cw = cw;
                    changed = true;
                }
                break;
            }
        }
        if (changed) saveRecentSearches(searches);
    }

    // Expose clear function globally for onclick handler
    window.clearRecentSearches = clearRecentSearches;

    // Initialize on DOM ready
    function init() {
        hookFormSubmit();
        captureFirstResultImage();
        renderRecentSearches();
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

    // Re-render when page is restored from bfcache (back/forward navigation)
    window.addEventListener('pageshow', function(e) {
        if (e.persisted) {
            renderRecentSearches();
        }
    });
})();