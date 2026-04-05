// Recent Searches - localStorage-backed search history for mobile
(function() {
    var STORAGE_KEY = 'mtgban_recent_searches';
    var MAX_ENTRIES = 15;

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

        // Add to front with current timestamp
        searches.unshift({ q: query, t: Date.now() });

        // Cap at MAX_ENTRIES
        if (searches.length > MAX_ENTRIES) {
            searches = searches.slice(0, MAX_ENTRIES);
        }

        saveRecentSearches(searches);
    }

    function clearRecentSearches() {
        localStorage.removeItem(STORAGE_KEY);
        var container = document.getElementById('m-recent-searches');
        if (container) container.innerHTML = '';
    }

    function renderRecentSearches() {
        var container = document.getElementById('m-recent-searches');
        if (!container) return;

        var searches = getRecentSearches();
        if (searches.length === 0) return;

        var html = '<div class="m-recent-header">';
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
        container.innerHTML = html;
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

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

    // Expose clear function globally for onclick handler
    window.clearRecentSearches = clearRecentSearches;

    // Initialize on DOM ready
    function init() {
        hookFormSubmit();
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