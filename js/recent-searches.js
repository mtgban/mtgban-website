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

    function clearRecentSearches() {
        localStorage.removeItem(STORAGE_KEY);
        var mobile = document.getElementById('m-recent-searches');
        if (mobile) mobile.innerHTML = '';
        var desktop = document.getElementById('desktop-recent-searches');
        if (desktop) renderRecentSearchesInto(desktop, 'desktop');
    }

    function renderRecentSearches() {
        renderRecentSearchesInto(document.getElementById('m-recent-searches'), 'mobile');
        renderRecentSearchesInto(document.getElementById('desktop-recent-searches'), 'desktop');
    }

    var rsPaginationState = {};

    function renderRecentSearchesInto(container, mode) {
        if (!container) return;
        var searches = getRecentSearches();

        var containerId = container.id;
        if (!rsPaginationState[containerId]) rsPaginationState[containerId] = { page: 0 };
        var pageSize = mode === 'desktop' ? 10 : searches.length || 1;
        var totalPages = Math.max(1, Math.ceil(searches.length / pageSize));
        if (rsPaginationState[containerId].page >= totalPages) rsPaginationState[containerId].page = 0;
        var page = rsPaginationState[containerId].page;

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
            html += '<button class="m-recent-clear" onclick="window.clearRecentSearches()">Clear</button>';
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
            var start = page * pageSize;
            var slice = searches.slice(start, start + pageSize);

            html += '<div class="landing-pane-header">';
            html += '<span class="landing-pane-title">Recent Searches</span>';
            html += '<span class="landing-pane-actions">';
            html += '<button class="landing-pane-btn" onclick="window.clearRecentSearches()">Clear</button>';
            html += '</span>';
            html += '</div>';
            html += '<div class="landing-pane-body">';
            slice.forEach(function(s) {
                html += '<a class="landing-item landing-item-recent" href="?q=' + encodeURIComponent(s.q) + '">';
                // Re-derive thumbnail treatment so legacy entries (with stale set/keyrune
                // for non-pure-set queries) render correctly.
                var token = parseSetToken(s.q);
                html += '<div class="landing-item-thumb">';
                if (token.keyrune) {
                    html += '<i class="ss ' + escapeAttr(token.keyrune) + ' ss-fw"></i>';
                } else if (s.img) {
                    html += '<img src="' + escapeAttr(s.img) + '" loading="lazy" alt="">';
                } else {
                    html += '<span class="landing-item-thumb-placeholder">&#128269;</span>';
                }
                html += '</div>';
                html += '<div class="landing-item-info">';
                html += '<span class="landing-item-query">' + escapeHtml(s.q) + '</span>';
                html += '</div>';
                html += '<button class="landing-item-delete" data-q="' + escapeAttr(s.q) + '" onclick="window.deleteRecentSearch(this.dataset.q, event)" title="Remove from recent searches">';
                html += '<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 6h18"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>';
                html += '</button>';
                html += '<span class="landing-item-arrow">&rsaquo;</span>';
                html += '</a>';
            });
            html += '</div>';
            if (totalPages > 1) {
                html += '<div class="landing-pane-footer">';
                html += '<button class="landing-page-btn" onclick="window.recentPage(\'' + containerId + '\', -1)" ' + (page === 0 ? 'disabled' : '') + '>&lsaquo;</button>';
                html += '<span class="landing-page-label">' + (page + 1) + ' / ' + totalPages + '</span>';
                html += '<button class="landing-page-btn" onclick="window.recentPage(\'' + containerId + '\', 1)" ' + (page === totalPages - 1 ? 'disabled' : '') + '>&rsaquo;</button>';
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

    window.recentPage = function(containerId, delta) {
        if (!rsPaginationState[containerId]) rsPaginationState[containerId] = { page: 0 };
        rsPaginationState[containerId].page += delta;
        renderRecentSearches();
    };

    window.deleteRecentSearch = function(query, ev) {
        if (ev) { ev.preventDefault(); ev.stopPropagation(); }
        if (!query) return;
        var searches = getRecentSearches().filter(function(s) { return s.q !== query; });
        saveRecentSearches(searches);
        renderRecentSearches();
    };

    // Record search on form submit
    function hookFormSubmit() {
        var form = document.getElementById('searchform');
        if (!form) return;

        form.addEventListener('submit', function() {
            var input = document.getElementById('searchbox');
            if (input && input.value.trim()) {
                addSearch(input.value);
            }
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

        var searches = getRecentSearches();
        var qLower = q.toLowerCase();
        var changed = false;
        for (var i = 0; i < searches.length; i++) {
            if (searches[i].q.toLowerCase() === qLower && !searches[i].img) {
                searches[i].img = img;
                changed = true;
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