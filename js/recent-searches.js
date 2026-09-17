// Recent Searches - localStorage-backed search history for mobile
(function() {
    var STORAGE_KEY = 'mtgban_recent_searches';
    var PENDING_KEY = 'mtgban_pending_search'; // sessionStorage: query awaiting its answer
    var MAX_ENTRIES = 15;
    var ART_REFRESH_CONCURRENCY = 3;
    var artRefreshInFlight = false;
    var TOMB_TTL_MS = 30 * 24 * 60 * 60 * 1000;
    var TOMB_CAP = 50;
    function isLive(s) { return !s.del; }
    // What the entry reads as. q stays the identity - the dedup key and what
    // pin and delete address - so a relabelled search still names exactly what
    // was typed.
    function displayQuery(s) { return s.d || s.q; }
    // Where it goes. A search that named one printing carries that printing's
    // own canonical path, which is shorter, survives changes to the query
    // syntax, and does not depend on which route the reader is looking from.
    // Anything else re-runs the query from where it stands.
    //
    // The path is only ever written by the server, but it is read back out of
    // localStorage, which the sync round-trips and anything on the origin can
    // write. So it is checked rather than trusted: one leading slash and no
    // second one means a path on this site, which is the only shape the server
    // produces and the only one that cannot carry a scheme. A "javascript:"
    // or "//evil.test" that got into the store is dropped for the query form,
    // which was the only link this list had before.
    function samePathOnThisSite(u) {
        return typeof u === 'string' && u.charAt(0) === '/' && u.charAt(1) !== '/' && u.charAt(1) !== '\\';
    }
    function entryHref(s) {
        if (samePathOnThisSite(s.u)) return s.u;
        return '?q=' + encodeURIComponent(s.q);
    }
    function artRefreshHref(s) {
        if (samePathOnThisSite(s.u)) return s.u;
        return '/search?q=' + encodeURIComponent(s.q);
    }
    function mtime(s) { return s.m || s.t || 0; }
    function getLiveSearches() { return getRecentSearches().filter(isLive); }

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
            var now = Date.now();
            var live = searches.filter(isLive);
            var tombs = searches.filter(function(s) { return !isLive(s) && (now - mtime(s)) <= TOMB_TTL_MS; });
            if (live.length > MAX_ENTRIES) live = live.slice(0, MAX_ENTRIES);
            tombs.sort(function(a, b) { return mtime(b) - mtime(a); });
            if (tombs.length > TOMB_CAP) tombs = tombs.slice(0, TOMB_CAP);
            localStorage.setItem(STORAGE_KEY, JSON.stringify(live.concat(tombs)));
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

    // The label is the readable query the server rebuilt for this search, and
    // is stored only when it says something the raw query doesn't: an ordinary
    // search is already its own best label, while a uuid is a wall of letters.
    function addSearch(query, label, href) {
        query = query.trim();
        if (!query || query.length < 2) return;

        var searches = getRecentSearches();

        // Remove existing entry with same query (case-insensitive dedup)
        searches = searches.filter(function(s) {
            return s.q.toLowerCase() !== query.toLowerCase();
        });

        var token = parseSetToken(query);

        var t = Date.now();
        var entry = {
            q: query,
            t: t,
            m: t,
            img: '',
            set: token.set,
            keyrune: token.keyrune
        };
        label = (label || '').trim();
        if (label && label.toLowerCase() !== query.toLowerCase()) {
            entry.d = label;
        }
        href = (href || '').trim();
        if (href) {
            entry.u = href;
        }
        searches.unshift(entry);

        saveRecentSearches(searches);
    }

    function clearRecentSearches(trigger) {
        var doClear = function() {
            var now = Date.now();
            var searches = getRecentSearches();
            searches.forEach(function(s) {
                if (!s.del) { s.del = now; s.m = now; }
            });
            saveRecentSearches(searches);
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
        var searches = pinnedFirst(getLiveSearches());

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
                html += '<a class="m-recent-item" href="' + escapeAttr(entryHref(s)) + '">';
                html += '<span class="m-recent-icon">&#128269;</span>';
                html += '<span class="m-recent-query">' + escapeHtml(displayQuery(s)) + '</span>';
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
                // Prefer the art crop, but keep older/crop-less entries from
                // falling back to the oversized thumbnail row. The first
                // result image is still useful background art for searches
                // whose result has no crop URL (for example a product query).
                var cropSrc = httpURL(s.crop || '');
                var imageSrc = httpURL(s.img || '');
                // Content-warning images stay in the gated thumbnail path
                // unless a real crop is available, as with existing crops.
                var backgroundSrc = cropSrc || (!s.cw ? imageSrc : '');
                var backgroundClass = backgroundSrc ? ' has-background' + (cropSrc ? '' : ' has-image') : '';
                var token = parseSetToken(s.q);
                html += '<a class="landing-item landing-item-recent' + backgroundClass + '"' + (backgroundSrc ? ' style="background-image:url(&quot;' + escapeAttr(backgroundSrc) + '&quot;)"' : '') + ' href="' + escapeAttr(entryHref(s)) + '">';
                if (!backgroundSrc) {
                    html += '<div class="landing-item-thumb">';
                    if (token.keyrune) {
                        html += '<i class="ss ' + escapeAttr(token.keyrune) + ' ss-fw"></i>';
                    } else if (imageSrc) {
                        html += thumbHtml(imageSrc, s.foil, s.cw);
                    } else {
                        html += '<span class="landing-item-thumb-placeholder"><svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg></span>';
                    }
                    html += '</div>';
                }
                html += '<div class="landing-item-info">';
                html += '<span class="landing-item-query">' + escapeHtml(displayQuery(s)) + '</span>';
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
        var searches = getRecentSearches();
        var now = Date.now();
        searches.forEach(function(s) {
            if (s.q === query && !s.del) { s.del = now; s.m = now; }
        });
        saveRecentSearches(searches);
        renderRecentSearches();
    };

    window.toggleRecentPin = function(query, ev) {
        if (ev) { ev.preventDefault(); ev.stopPropagation(); }
        if (!query) return;
        var searches = getRecentSearches();
        var changed = false;
        for (var i = 0; i < searches.length; i++) {
            if (searches[i].q === query && !searches[i].del) {
                if (searches[i].pinned) {
                    delete searches[i].pinned;
                } else {
                    searches[i].pinned = Date.now();
                }
                searches[i].m = Date.now();
                changed = true;
                break;
            }
        }
        if (changed) {
            saveRecentSearches(searches);
            renderRecentSearches();
        }
    };

    // Note the search on form submit (page bars and navbar share this store).
    // Submitting only remembers the question; the results page decides whether
    // it was worth keeping, so a search that finds nothing never reaches the
    // list. The marker is per-tab and consumed by the page that answers it.
    function hookFormSubmit() {
        var pairs = [['searchform', 'searchbox'], ['nav-searchform', 'nav-searchbox']];
        pairs.forEach(function(ids) {
            var form = document.getElementById(ids[0]);
            if (!form) return;
            form.addEventListener('submit', function() {
                var input = document.getElementById(ids[1]);
                if (input && input.value.trim()) {
                    try {
                        sessionStorage.setItem(PENDING_KEY, input.value.trim());
                    } catch (e) {
                        // No sessionStorage: fall back to recording the search
                        // unconditionally, which is what always happened before.
                        addSearch(input.value);
                    }
                }
            });
        });
    }

    // The other half of hookFormSubmit: this page is the answer to whatever
    // was submitted last. Keep the search only when it found something, and
    // label it with the readable query the server rebuilt - a uuid search
    // comes back as the card's own name, set and number.
    function recordPendingSearch() {
        var params = new URLSearchParams(window.location.search);
        var q = (params.get('q') || '').trim();
        // No query means this is not the answer to anything, so leave a
        // pending search waiting for the page that is.
        if (!q) return;

        var pending;
        try {
            pending = sessionStorage.getItem(PENDING_KEY);
            if (!pending) return;
            sessionStorage.removeItem(PENDING_KEY);
        } catch (e) {
            return;
        }
        if (pending.trim().toLowerCase() !== q.toLowerCase()) return;

        var answer = window.BAN_SEARCH_RESULT || {};
        if (!answer.found) return;
        var href = answer.url;
        // A multi-result sealed search has no per-card canonical URL, but its
        // route still matters when the landing page later refreshes its art.
        if (!href && window.location.pathname === '/sealed') {
            href = '/sealed?q=' + encodeURIComponent(q);
        }
        addSearch(q, answer.label, href);
    }

    function updateResultArt(searches, query, img, crop, foil, cw) {
        if (!query || !img) return false;
        var qLower = query.toLowerCase();
        var changed = false;
        for (var i = 0; i < searches.length; i++) {
            if (searches[i].q.toLowerCase() === qLower && !searches[i].del) {
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
        return changed;
    }

    function saveResultArt(query, img, crop, foil, cw) {
        var searches = getRecentSearches();
        var changed = updateResultArt(searches, query, img, crop, foil, cw);
        if (changed) saveRecentSearches(searches);
        return changed;
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
        saveResultArt(q, img, crop, foil, cw);
    }

    // A new browser can receive the recent-search list through user-state sync
    // before it has visited any of the result pages that provide card art. Fill
    // those local-only gaps in the background, without delaying the landing
    // page or sending the art back over the sync wire.
    function refreshMissingArt() {
        var params = new URLSearchParams(window.location.search);
        if (artRefreshInFlight || params.get('q') || typeof fetch !== 'function' || typeof DOMParser === 'undefined') return;

        var searches = getLiveSearches().filter(function(s) {
            return !s.img && !s.crop;
        });
        if (!searches.length) return;

        artRefreshInFlight = true;
        var next = 0;
        var updates = [];
        function refreshOne() {
            if (next >= searches.length) return Promise.resolve();
            var search = searches[next++];
            return fetch(artRefreshHref(search), { credentials: 'same-origin' })
                .then(function(response) { return response.ok ? response.text() : ''; })
                .then(function(markup) {
                    if (!markup) return;
                    var doc = new DOMParser().parseFromString(markup, 'text/html');
                    var firstRow = doc.querySelector('.result-header[data-image-url], .m-card-header[data-image-url]');
                    if (!firstRow) return;

                    var img = firstRow.getAttribute('data-image-url') || '';
                    var crop = firstRow.getAttribute('data-crop-url') || '';
                    var finishClass = firstRow.getAttribute('data-finish-class') || '';
                    var foil = finishClass === 'foil' || finishClass === 'altfoil';
                    var cw = firstRow.getAttribute('data-has-warning') === 'true';
                    if (img) updates.push({ query: search.q, img: img, crop: crop, foil: foil, cw: cw });
                })
                .catch(function() {})
                .then(refreshOne);
        }

        var workers = [];
        var workerCount = Math.min(ART_REFRESH_CONCURRENCY, searches.length);
        for (var i = 0; i < workerCount; i++) workers.push(refreshOne());
        Promise.all(workers).then(function() {
            var current = getRecentSearches();
            var changed = false;
            updates.forEach(function(update) {
                changed = updateResultArt(current, update.query, update.img, update.crop, update.foil, update.cw) || changed;
            });
            if (changed) {
                saveRecentSearches(current);
                renderRecentSearches();
            }
            artRefreshInFlight = false;
        }, function() {
            artRefreshInFlight = false;
        });
    }

    // Expose clear function globally for onclick handler
    window.clearRecentSearches = clearRecentSearches;

    // Initialize on DOM ready
    function init() {
        hookFormSubmit();
        recordPendingSearch();
        captureFirstResultImage();
        renderRecentSearches();
        refreshMissingArt();
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
            refreshMissingArt();
        }
    });
})();
