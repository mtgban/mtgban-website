/* Command Palette - keyboard-driven search, navigation, help, and saved commands */
(function() {
    'use strict';

    // ── Mobile guard ─────────────────────────────────────────────────
    if (!window.__BAN_PALETTE || window.innerWidth < 768) return;

    var palette = window.__BAN_PALETTE;
    var guide = window.__BAN_GUIDE || { sections: [] };

    // ── State ────────────────────────────────────────────────────────
    var activeIndex = -1;
    var resultItems = [];
    var previousFocus = null;
    var isOpen = false;
    var cardNames = null;
    var cardNamesLoading = false;
    var chips = null;
    var suppressChipOnChange = false;

    // ── Nav parent detection ─────────────────────────────────────────
    // Maps the nav entry name (from palette.nav) to the key in
    // __BAN_PALETTE_TARGETS that holds its sub-views.
    var navParentKeys = {
        'Newspaper': 'newspaper',
        'Sleepers': 'sleepers',
        'Arbitrage': 'arbit',
        'Reverse': 'reverse',
        'Global': 'global'
    };

    function isParentNav(name) {
        return !!navParentKeys[name];
    }

    function getNavTargets(name) {
        var key = navParentKeys[name];
        if (!key) return null;
        var targets = (window.__BAN_PALETTE_TARGETS || {})[key];
        return targets || null;
    }

    // Used by sub-view URL composition. For arbit/reverse/global, distinguishes
    // whether a sub-view value is a sort option (goes in ?sort=) or a filter (?key=true).
    function isArbitSortValue(key, value) {
        var targets = (window.__BAN_PALETTE_TARGETS || {})[key];
        if (!targets || !targets.sorts) return false;
        for (var i = 0; i < targets.sorts.length; i++) {
            if (targets.sorts[i].value === value) return true;
        }
        return false;
    }

    // ── Card meta cache ──────────────────────────────────────────────
    var cardMetaCache = {}; // { [name]: response }
    var cardMetaInflight = {};

    // Re-render dropdown when provider data (sets/stores) finishes loading
    if (window.__palette_providers && typeof window.__palette_providers.setOnDataReady === 'function') {
        window.__palette_providers.setOnDataReady(function () {
            if (isOpen && typeof handleInput === 'function') handleInput();
        });
    }

    function fetchCardMeta(name) {
        if (!name) return Promise.resolve(null);
        if (cardMetaCache[name]) return Promise.resolve(cardMetaCache[name]);
        if (cardMetaInflight[name]) return cardMetaInflight[name];
        cardMetaInflight[name] = fetch('/api/palette/card/' + encodeURIComponent(name))
            .then(function (r) { return r.ok ? r.json() : { found: false }; })
            .then(function (data) {
                if (data && data.found) {
                    cardMetaCache[name] = data;
                }
                delete cardMetaInflight[name];
                // Re-run filter so dependent providers (s:, r:, c:) get narrowed results
                if (typeof handleInput === 'function') handleInput();
                return data;
            })
            .catch(function () {
                delete cardMetaInflight[name];
                return { found: false };
            });
        return cardMetaInflight[name];
    }

    function activeCardMeta() {
        if (!chips) return null;
        var list = chips.all();
        for (var i = 0; i < list.length; i++) {
            if (list[i].type === 'card') {
                return cardMetaCache[list[i]._cardName || list[i].value] || null;
            }
        }
        return null;
    }

    // Returns a navigation URL if the chip set is a nav composition, else null.
    // A nav composition is: exactly one nav chip (parent), optionally followed by
    // nav-sub chips for the same parent.
    function chipsNavURL(chipArray) {
        if (!chipArray || chipArray.length === 0) return null;
        var first = chipArray[0];
        if (!first || first.type !== 'nav') return null;
        var parentKey = first.navName ? navParentKeys[first.navName] : null;

        // Leaf nav (not a parent page) - navigate directly
        if (!parentKey) {
            return first.navLink || null;
        }

        // Parent nav - compose params from subsequent nav-sub chips
        var base = (first.navLink || '').split('?')[0];
        var params = [];
        for (var i = 1; i < chipArray.length; i++) {
            var c = chipArray[i];
            if (c.type !== 'nav-sub' || c._parentKey !== parentKey) {
                // Not a pure nav composition - bail out
                return null;
            }
            if (c._urlParam) params.push(c._urlParam);
        }
        return base + (params.length > 0 ? '?' + params.join('&') : '');
    }

    // ── localStorage helpers ─────────────────────────────────────────
    var RECENT_KEY = 'mtgban_recent_searches';
    var SAVED_KEY = 'mtgban_saved_commands';
    var MAX_SAVED = 50;
    var MAX_NAME = 60;

    function getJSON(key) {
        try {
            var data = localStorage.getItem(key);
            return data ? JSON.parse(data) : [];
        } catch (e) {
            return [];
        }
    }

    function setJSON(key, val) {
        try {
            localStorage.setItem(key, JSON.stringify(val));
        } catch (e) {}
    }

    function recordRecentSearch(query) {
        if (!query || query.trim().length < 2) return;
        query = query.trim();
        var recent = getJSON(RECENT_KEY);
        recent = recent.filter(function(s) {
            return (s.q || '').toLowerCase() !== query.toLowerCase();
        });
        recent.unshift({ q: query, t: Date.now() });
        if (recent.length > 15) recent = recent.slice(0, 15);
        setJSON(RECENT_KEY, recent);
    }

    // Check if a section is accessible based on nav permissions
    var navNames = {};
    var nav = palette.nav || [];
    for (var ni = 0; ni < nav.length; ni++) {
        navNames[nav[ni].name] = true;
    }
    function isSectionAllowed(section) {
        if (!section.requiresNav) return true;
        return !!navNames[section.requiresNav];
    }

    function escapeHtml(str) {
        var div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function categoryKeyFor(title) {
        var t = (title || '').toLowerCase();
        if (t.indexOf('recent') >= 0) return 'recent';
        if (t.indexOf('saved') >= 0) return 'saved';
        if (t.indexOf('page') >= 0 || t.indexOf('navigate') >= 0) return 'pages';
        if (t.indexOf('card') >= 0) return 'cards';
        if (t.indexOf('command') >= 0 || t.indexOf('action') >= 0) return 'commands';
        if (t.indexOf('help') >= 0) return 'help';
        if (t.indexOf('syntax') >= 0) return 'syntax';
        return 'other';
    }

    function categoryIconFor(title) {
        var key = categoryKeyFor(title);
        var map = {
            recent: 'clock',
            saved: 'bookmark',
            pages: 'compass',
            cards: 'search',
            commands: 'zap',
            help: 'help-circle',
            syntax: 'code'
        };
        return map[key] || null;
    }

    // ── DOM creation ─────────────────────────────────────────────────
    var overlay = document.createElement('div');
    overlay.className = 'cp-overlay';
    overlay.id = 'cp-overlay';

    var dialog = document.createElement('div');
    dialog.className = 'cp-dialog';
    dialog.setAttribute('role', 'dialog');
    dialog.setAttribute('aria-modal', 'true');

    // Input row
    var inputRow = document.createElement('div');
    inputRow.className = 'cp-input-row';

    var modeIndicator = document.createElement('span');
    modeIndicator.className = 'cp-mode-indicator';
    modeIndicator.id = 'cp-mode';

    var chipContainer = document.createElement('div');
    chipContainer.className = 'cp-chip-container';
    chipContainer.id = 'cp-chips';
    chipContainer.setAttribute('role', 'group');
    chipContainer.setAttribute('aria-label', 'Search composition');

    var input = document.createElement('input');
    input.className = 'cp-input';
    input.id = 'cp-input';
    input.type = 'text';
    input.placeholder = 'Search cards, commands, help...';
    input.setAttribute('autocomplete', 'off');
    chipContainer.appendChild(input);

    var escKbd = document.createElement('kbd');
    escKbd.className = 'cp-shortcut';
    escKbd.textContent = 'ESC';

    inputRow.appendChild(modeIndicator);
    inputRow.appendChild(chipContainer);
    inputRow.appendChild(escKbd);

    // Results
    var resultsEl = document.createElement('div');
    resultsEl.className = 'cp-results';
    resultsEl.id = 'cp-results';
    resultsEl.setAttribute('role', 'listbox');
    resultsEl.setAttribute('aria-label', 'Results');

    // Footer
    var footer = document.createElement('div');
    footer.className = 'cp-footer';
    footer.innerHTML = '<span><kbd>\u2191\u2193</kbd> Navigate</span>' +
        '<span><kbd>Enter</kbd> Select</span>' +
        '<span class="cp-footer-hint-delete" style="display:none"><kbd>Shift+Del</kbd> Remove</span>' +
        '<span><kbd>?</kbd> Help</span>' +
        '<span><kbd>Esc</kbd> Close</span>';

    dialog.appendChild(inputRow);
    dialog.appendChild(resultsEl);
    dialog.appendChild(footer);

    var chipLive = document.createElement('div');
    chipLive.className = 'cp-sr-only';
    chipLive.id = 'cp-chip-announce';
    chipLive.setAttribute('aria-live', 'polite');
    chipLive.setAttribute('aria-atomic', 'true');
    dialog.appendChild(chipLive);

    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

    // Initialize chip manager (B1) - wire container + input + filter callback
    var lastChipCount = 0;
    if (window.__palette_chips && typeof window.__palette_chips.create === 'function') {
        chips = window.__palette_chips.create(chipContainer, input, function () {
            var now = chips ? chips.count() : 0;
            var live = document.getElementById('cp-chip-announce');
            if (live) {
                if (now > lastChipCount) {
                    var latest = chips.get(now - 1);
                    live.textContent = 'Added chip: ' + (latest ? (latest.label || latest.value) : '');
                } else if (now < lastChipCount) {
                    live.textContent = 'Removed chip';
                }
            }
            lastChipCount = now;
            if (!suppressChipOnChange && typeof handleInput === 'function') handleInput();
        });
    }

    // Toast
    var toast = document.createElement('div');
    toast.className = 'cp-toast';
    toast.id = 'cp-toast';
    document.body.appendChild(toast);

    // ── Toast helper ─────────────────────────────────────────────────
    var toastTimer = null;
    function showToast(msg) {
        toast.textContent = msg;
        toast.classList.add('show');
        if (toastTimer) clearTimeout(toastTimer);
        toastTimer = setTimeout(function() {
            toast.classList.remove('show');
        }, 2000);
    }

    // ── Open / Close ─────────────────────────────────────────────────
    function openPalette() {
        if (isOpen) return;
        isOpen = true;
        previousFocus = document.activeElement;
        overlay.classList.add('open');
        document.body.style.overflow = 'hidden';
        input.value = '';
        modeIndicator.textContent = '';
        modeIndicator.className = 'cp-mode-indicator';
        modeIndicator.removeAttribute('data-mode');
        activeIndex = -1;
        renderDefault();
        input.focus();

        // Lazy-load card names on first open
        if (!cardNames && !cardNamesLoading && typeof fetchNames === 'function') {
            cardNamesLoading = true;
            fetchNames('false').then(function(names) {
                cardNames = names || [];
                cardNamesLoading = false;
            }).catch(function() {
                cardNamesLoading = false;
            });
        }
    }

    function closePalette() {
        if (!isOpen) return;
        isOpen = false;
        overlay.classList.remove('open');
        document.body.style.overflow = '';
        removeSaveRow();
        if (previousFocus) {
            previousFocus.focus();
            previousFocus = null;
        }
    }

    // ── Click overlay to close ───────────────────────────────────────
    overlay.addEventListener('click', function(e) {
        if (e.target === overlay) closePalette();
    });

    // ── Mode detection ───────────────────────────────────────────────
    function detectMode(val) {
        if (val.charAt(0) === '?' || /^(help:|syntax:)/i.test(val)) return 'help';
        if (val.charAt(0) === '>') return 'nav';
        if (/^saved:/i.test(val)) return 'saved';
        return 'search';
    }

    function stripPrefix(val) {
        if (/^(\?\s*|help:|syntax:|\?:)/i.test(val)) return val.replace(/^(\?\s*|help:|syntax:|\?:)/i, '').trim();
        if (val.charAt(0) === '>') return val.substring(1).trim();
        if (/^saved:/i.test(val)) return val.replace(/^saved:/i, '').trim();
        return val;
    }

    // ── Matching algorithm ───────────────────────────────────────────
    function scoreMatch(query, name, keywords) {
        var q = query.toLowerCase();
        var n = name.toLowerCase();

        // Prefix match
        if (n.indexOf(q) === 0) return 3;

        // Word-boundary match
        var words = n.split(/[\s\-_]+/);
        for (var i = 0; i < words.length; i++) {
            if (words[i].indexOf(q) === 0) return 2;
        }

        // Substring in name
        if (n.indexOf(q) >= 0) return 1;

        // Keywords
        if (keywords) {
            var kw = keywords;
            if (typeof kw === 'string') kw = kw.split(/[\s,]+/);
            for (var j = 0; j < kw.length; j++) {
                if (kw[j].toLowerCase().indexOf(q) >= 0) return 1;
            }
        }

        return 0;
    }

    // ── Card name matching (mirrors autocomplete.js) ─────────────────
    function matchCardName(query, name) {
        var q = query.toUpperCase();
        if (name.substr(0, query.length).toUpperCase() === q) return true;
        if (name.normalize('NFD').replace(/[\u0300-\u036f]/g, '').substr(0, query.length).toUpperCase() === q) return true;
        if (name.replace(/^The /g, '').substr(0, query.length).toUpperCase() === q) return true;
        if (name.replace(/[^A-Za-z0-9 ]/g, '').substr(0, query.length).toUpperCase() === q) return true;
        return false;
    }

    // ── Search sources ───────────────────────────────────────────────
    function getRecentResults(query, limit) {
        var recent = getJSON(RECENT_KEY);
        var results = [];
        for (var i = 0; i < recent.length && results.length < limit; i++) {
            var r = recent[i];
            if (!query || scoreMatch(query, r.q, null) > 0) {
                results.push({
                    type: 'recent',
                    title: r.q,
                    subtitle: 'Recent search',
                    icon: 'clock',
                    recentQuery: r.q,
                    action: function(q) { return function() { recordRecentSearch(q); window.location.href = '/search?q=' + encodeURIComponent(q); }; }(r.q)
                });
            }
        }
        return results;
    }

    function getNavResults(query) {
        var nav = palette.nav || [];
        var results = [];
        for (var i = 0; i < nav.length; i++) {
            var n = nav[i];
            if (!query || scoreMatch(query, n.name, null) > 0) {
                results.push({
                    type: 'nav',
                    title: n.name,
                    subtitle: 'Navigate to ' + n.name,
                    icon: n.icon || 'compass',
                    navName: n.name,
                    navLink: n.link,
                    action: function(link) { return function() { window.location.href = link; }; }(n.link),
                    score: query ? scoreMatch(query, n.name, null) : 0
                });
            }
        }
        if (query) {
            results.sort(function(a, b) { return b.score - a.score; });
        }
        return results;
    }

    function getStaticCommands(query) {
        var commands = [
            {
                name: 'Toggle Theme',
                icon: (localStorage.getItem('theme') === 'dark') ? 'sun' : 'moon',
                keywords: ['dark', 'light', 'night', 'day', 'theme', 'mode'],
                action: function() {
                    var t = localStorage.getItem('theme') === 'dark' ? 'light' : 'dark';
                    document.body.classList.toggle('dark-theme', t === 'dark');
                    document.body.classList.toggle('light-theme', t === 'light');
                    localStorage.setItem('theme', t);
                    var toggle = document.getElementById('theme-toggle');
                    if (toggle) toggle.title = t === 'dark' ? 'Nightbound' : 'Daybound';
                    closePalette();
                    showToast('Theme: ' + t);
                }
            },
            {
                name: 'Random Card',
                icon: 'dice-5',
                keywords: ['random', 'surprise', 'lucky'],
                action: function() { window.location.href = '/random'; }
            },
            {
                name: 'Random Sealed',
                icon: 'package',
                keywords: ['random', 'sealed', 'booster', 'pack'],
                action: function() { window.location.href = '/randomsealed'; }
            },
            {
                name: 'Open Guide',
                icon: 'book-open',
                keywords: ['guide', 'help', 'documentation', 'syntax'],
                action: function() { window.location.href = '/guide'; }
            },
            {
                name: 'Copy Page URL',
                icon: 'link',
                keywords: ['copy', 'url', 'link', 'share', 'clipboard'],
                action: function() {
                    if (navigator.clipboard) {
                        navigator.clipboard.writeText(window.location.href).then(function() {
                            showToast('URL copied to clipboard');
                        });
                    } else {
                        showToast('Clipboard not available');
                    }
                    closePalette();
                }
            }
        ];

        // Conditionally add "Save Current Search"
        var hasComposed = chips && chips.count() > 0 && chips.composedQuery();
        var searchInput = document.getElementById('searchbox');
        var hasSearchbox = searchInput && searchInput.value && searchInput.value.trim();
        if (hasComposed || hasSearchbox) {
            commands.push({
                name: 'Save Current Search',
                icon: 'bookmark-plus',
                keywords: ['save', 'bookmark', 'store', 'command'],
                action: function() { showSaveRow(); }
            });
        }

        var results = [];
        for (var i = 0; i < commands.length; i++) {
            var c = commands[i];
            if (!query || scoreMatch(query, c.name, c.keywords) > 0) {
                results.push({
                    type: 'command',
                    title: c.name,
                    subtitle: '',
                    icon: c.icon,
                    action: c.action,
                    score: query ? scoreMatch(query, c.name, c.keywords) : 0
                });
            }
        }
        if (query) {
            results.sort(function(a, b) { return b.score - a.score; });
        }
        return results;
    }

    function getCardResults(query, limit) {
        if (!cardNames || !query || query.length < 2) return [];
        var results = [];
        for (var i = 0; i < cardNames.length && results.length < limit; i++) {
            if (matchCardName(query, cardNames[i])) {
                results.push({
                    type: 'card',
                    title: cardNames[i],
                    subtitle: 'Search for "' + cardNames[i] + '"',
                    icon: 'search',
                    cardName: cardNames[i],
                    action: (function(name) { return function() { recordRecentSearch(name); window.location.href = '/search?q=' + encodeURIComponent(name); }; })(cardNames[i])
                });
            }
        }
        return results;
    }

    function getHelpResults(query) {
        var sections = guide.sections || [];
        var results = [];
        for (var i = 0; i < sections.length && results.length < 10; i++) {
            var s = sections[i];
            if (!isSectionAllowed(s)) continue;
            var match = !query || scoreMatch(query, s.title, s.keywords) > 0;
            if (!match && s.summary) {
                match = scoreMatch(query, s.summary, null) > 0;
            }
            if (!match && s.snippets) {
                for (var j = 0; j < s.snippets.length; j++) {
                    if (s.snippets[j].toLowerCase().indexOf(query.toLowerCase()) >= 0) {
                        match = true;
                        break;
                    }
                }
            }
            if (match) {
                var isSyntax = s.category === 'Search Syntax';
                var subtitle = s.summary || '';
                var snippetText = '';
                if (isSyntax && s.snippets && s.snippets.length > 0) {
                    snippetText = s.snippets.join('  ');
                }
                results.push({
                    type: 'help',
                    title: s.title,
                    subtitle: subtitle,
                    snippets: snippetText,
                    icon: s.icon || 'help-circle',
                    isSyntax: isSyntax,
                    sectionId: s.id,
                    action: isSyntax
                        ? (function(snip) { return function() {
                            if (navigator.clipboard && snip) {
                                navigator.clipboard.writeText(snip).then(function() {
                                    showToast('Copied: ' + snip);
                                });
                            }
                            closePalette();
                        }; })(s.snippets && s.snippets[0] ? s.snippets[0] : '')
                        : (function(id) { return function() { window.location.href = '/guide#' + id; }; })(s.id),
                    altAction: isSyntax
                        ? (function(id) { return function() { window.location.href = '/guide#' + id; }; })(s.id)
                        : null,
                    score: query ? scoreMatch(query, s.title, s.keywords) : 0
                });
            }
        }
        if (query) {
            results.sort(function(a, b) { return b.score - a.score; });
        }
        return results;
    }

    function getSavedResults(query) {
        var saved = getJSON(SAVED_KEY);
        var results = [];
        for (var i = 0; i < saved.length; i++) {
            var s = saved[i];
            if (!query || scoreMatch(query, s.name, s.query) > 0) {
                results.push({
                    type: 'saved',
                    title: s.name,
                    subtitle: s.query,
                    icon: s.icon || 'bookmark',
                    savedId: s.id,
                    action: (function(cmd) { return function() {
                        // Update usage tracking
                        var allSaved = getJSON(SAVED_KEY);
                        for (var k = 0; k < allSaved.length; k++) {
                            if (allSaved[k].id === cmd.id) {
                                allSaved[k].lastUsed = Date.now();
                                allSaved[k].useCount = (allSaved[k].useCount || 0) + 1;
                                break;
                            }
                        }
                        setJSON(SAVED_KEY, allSaved);
                        // If this saved command is a nav composition, navigate to the composed URL
                        var navUrl = chipsNavURL(cmd.chips);
                        if (navUrl) {
                            window.location.href = navUrl;
                            return;
                        }
                        // Otherwise treat as a search query
                        recordRecentSearch(cmd.query);
                        window.location.href = '/search?q=' + encodeURIComponent(cmd.query);
                    }; })(s),
                    altAction: (function(cmd) { return function() {
                        // Shift+Enter: restore chips into the palette input for editing
                        if (!chips) {
                            input.value = cmd.query || '';
                            input.focus();
                            handleInput();
                            return;
                        }
                        chips.clear();
                        if (cmd.chips && cmd.chips.length > 0) {
                            for (var ci = 0; ci < cmd.chips.length; ci++) {
                                chips.add(cmd.chips[ci]);
                            }
                            // Prefetch card meta for any restored card chips so filter narrowing works
                            for (var cj = 0; cj < cmd.chips.length; cj++) {
                                if (cmd.chips[cj].type === 'card' && cmd.chips[cj]._cardName) {
                                    fetchCardMeta(cmd.chips[cj]._cardName);
                                }
                            }
                        } else if (cmd.query) {
                            // V1 saved command (no chips field) - restore as plain input text
                            input.value = cmd.query;
                        }
                        input.focus();
                        handleInput();
                    }; })(s)
                });
            }
        }
        return results;
    }

    // ── Default results ──────────────────────────────────────────────
    function renderDefault() {
        var items = [];
        var recent = getRecentResults(null, 5);
        var saved = getSavedResults(null);
        var nav = getNavResults(null);

        if (recent.length > 0) {
            items.push({ type: 'header', title: 'Recent Searches' });
            items = items.concat(recent);
        }
        if (saved.length > 0) {
            items.push({ type: 'header', title: 'Saved Commands' });
            items = items.concat(saved.slice(0, 3));
        }
        if (nav.length > 0) {
            items.push({ type: 'header', title: 'Pages' });
            items = items.concat(nav);
        }

        renderResults(items);
    }

    // ── Provider-mode rendering ──────────────────────────────────────
    var PROVIDER_DROPDOWN_CAP = 30;

    function renderProviderResults(prefix, provider, query) {
        var ctx = {
            chips: chips ? chips.all() : [],
            cardMeta: activeCardMeta()
        };
        var candidates = provider.getCandidates(query, ctx) || [];
        if (candidates.length > PROVIDER_DROPDOWN_CAP) {
            candidates = candidates.slice(0, PROVIDER_DROPDOWN_CAP);
        }
        var items = [];

        // Group candidates by their `group` field, if any
        var grouped = {};
        var groupOrder = [];
        var ungrouped = [];
        for (var i = 0; i < candidates.length; i++) {
            var c = candidates[i];
            if (c.group) {
                if (!grouped[c.group]) {
                    grouped[c.group] = [];
                    groupOrder.push(c.group);
                }
                grouped[c.group].push(c);
            } else {
                ungrouped.push(c);
            }
        }

        if (groupOrder.length === 0) {
            items.push({ type: 'header', title: provider.name });
            for (var j = 0; j < ungrouped.length; j++) {
                items.push(buildProviderItem(prefix, provider, ungrouped[j]));
            }
        } else {
            for (var g = 0; g < groupOrder.length; g++) {
                var groupName = groupOrder[g];
                items.push({ type: 'header', title: provider.name + ' · ' + groupName });
                var list = grouped[groupName];
                for (var k = 0; k < list.length; k++) {
                    items.push(buildProviderItem(prefix, provider, list[k]));
                }
            }
            for (var u = 0; u < ungrouped.length; u++) {
                if (u === 0) items.push({ type: 'header', title: provider.name });
                items.push(buildProviderItem(prefix, provider, ungrouped[u]));
            }
        }

        if (items.length === 0 || (items.length === 1 && items[0].type === 'header')) {
            items = [{ type: 'header', title: provider.name + ' - no matches' }];
        }

        renderResults(items);
    }

    function buildProviderItem(prefix, provider, candidate) {
        var item = {
            type: 'filter-candidate',
            title: candidate.label,
            subtitle: candidate.sublabel || '',
            icon: candidate.icon || provider.icon,
            disabled: !!candidate.disabled,
            _providerPrefix: prefix,
            _providerCandidate: candidate,
            action: function () {
                if (candidate.disabled) return;
                // Lock as filter chip AND execute (Enter behavior)
                if (chips) {
                    chips.add({
                        type: 'filter',
                        prefix: prefix,
                        value: prefix + candidate.value,
                        label: prefix + (candidate.label || candidate.value),
                        icon: provider.icon
                    });
                }
                input.value = '';
                // Execute composed query immediately
                var q = chips ? chips.composedQuery() : '';
                if (q) {
                    recordRecentSearch(q);
                    window.location.href = '/search?q=' + encodeURIComponent(q);
                }
            }
        };
        if (candidate.keyrune) {
            var kr = String(candidate.keyrune).toLowerCase().replace(/[^a-z0-9]/g, '');
            item.iconHtml = '<i class="ss ss-' + kr + '"></i>';
        }
        if (candidate.iconColor) {
            item.iconStyle = 'color: ' + candidate.iconColor;
        }
        return item;
    }

    // ── Sub-view rendering (parent nav chip locked) ──────────────────
    function renderSubViewResults(parentChip, targets, query) {
        var items = [];

        function pushEntries(entries, headerLabel) {
            if (!entries || entries.length === 0) return;
            var filtered = window.__palette_providers
                ? window.__palette_providers.filterEntries(entries, query)
                : entries;
            if (filtered.length === 0) return;
            if (headerLabel) items.push({ type: 'header', title: headerLabel });
            for (var i = 0; i < filtered.length; i++) {
                items.push(buildSubViewItem(parentChip, filtered[i]));
            }
        }

        if (Array.isArray(targets)) {
            // Newspaper / Sleepers shape: flat array, optionally grouped by .group
            var byGroup = {};
            var orderedGroups = [];
            var hadAnyGroup = false;
            for (var i = 0; i < targets.length; i++) {
                var g = targets[i].group || 'Views';
                if (targets[i].group) hadAnyGroup = true;
                if (!byGroup[g]) { byGroup[g] = []; orderedGroups.push(g); }
                byGroup[g].push(targets[i]);
            }
            if (hadAnyGroup) {
                for (var gi = 0; gi < orderedGroups.length; gi++) {
                    pushEntries(byGroup[orderedGroups[gi]], parentChip.navName + ' · ' + orderedGroups[gi]);
                }
            } else {
                pushEntries(targets, parentChip.navName + ' Views');
            }
        } else {
            // Arbit/Reverse/Global shape: { filters: [...], sorts: [...] }
            pushEntries(targets.sorts, parentChip.navName + ' · Sort');
            pushEntries(targets.filters, parentChip.navName + ' · Filters');
        }

        if (items.length === 0) {
            items.push({ type: 'header', title: parentChip.navName + ' - no matching sub-views' });
        }
        renderResults(items);
    }

    function buildSubViewItem(parentChip, entry) {
        return {
            type: 'nav-sub',
            title: entry.label,
            subtitle: entry.group || '',
            icon: 'arrow-right',
            _subView: entry,
            _parentChip: parentChip,
            action: function () {
                var url = composeSubViewURL(parentChip, entry);
                window.location.href = url;
            }
        };
    }

    function composeSubViewURL(parentChip, entry) {
        var key = navParentKeys[parentChip.navName];
        var base = (parentChip.navLink || '').split('?')[0];
        var params = [];

        if (key === 'newspaper' || key === 'sleepers') {
            params.push('page=' + encodeURIComponent(entry.value));
        } else {
            // arbit / reverse / global
            if (isArbitSortValue(key, entry.value)) {
                params.push('sort=' + encodeURIComponent(entry.value));
            } else {
                params.push(encodeURIComponent(entry.value) + '=true');
            }
            // Merge prior nav-sub chips for the same parent
            if (chips) {
                var list = chips.all();
                for (var i = 0; i < list.length; i++) {
                    if (list[i].type === 'nav-sub' && list[i]._parentKey === key && list[i]._urlParam) {
                        params.push(list[i]._urlParam);
                    }
                }
            }
        }
        return base + (params.length > 0 ? '?' + params.join('&') : '');
    }

    // ── Render results ───────────────────────────────────────────────
    function renderResults(items) {
        resultItems = [];
        activeIndex = -1;
        var html = '';
        var idx = 0;

        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            if (item.type === 'header') {
                var headerKey = categoryKeyFor(item.title);
                var headerIcon = categoryIconFor(item.title);
                var iconHtml = headerIcon ? '<i data-lucide="' + headerIcon + '"></i>' : '';
                html += '<div class="cp-category-header" data-category="' + escapeHtml(headerKey) + '">' + iconHtml + '<span>' + escapeHtml(item.title) + '</span></div>';
                continue;
            }

            var activeClass = idx === 0 ? ' active' : '';
            var disabledClass = item.disabled ? ' disabled' : '';
            html += '<div class="cp-result' + activeClass + disabledClass + '" role="option" data-index="' + idx + '"' + (item.disabled ? ' aria-disabled="true"' : '') + '>';
            if (item.iconHtml) {
                html += '<div class="cp-result-icon">' + item.iconHtml + '</div>';
            } else {
                var iconStyleAttr = item.iconStyle ? ' style="' + escapeHtml(item.iconStyle) + '"' : '';
                html += '<div class="cp-result-icon"' + iconStyleAttr + '><i data-lucide="' + escapeHtml(item.icon || 'search') + '"></i></div>';
            }
            html += '<div class="cp-result-body">';
            html += '<div class="cp-result-title">' + escapeHtml(item.title) + '</div>';
            if (item.snippets) {
                html += '<div class="cp-result-inline">' + escapeHtml(item.snippets) + '</div>';
            } else if (item.subtitle) {
                html += '<div class="cp-result-subtitle">' + escapeHtml(item.subtitle) + '</div>';
            }
            html += '</div>';
            html += '<div class="cp-result-right">';
            var badgeLabel = item.type === 'recent' ? 'Recent' : item.type === 'nav' ? 'Navigate' : item.type === 'card' ? 'Card' : item.type === 'command' ? 'Action' : item.type === 'saved' ? 'Saved' : item.type === 'syntax' ? 'Syntax' : item.type === 'help' ? item.badge || 'Help' : '';
            if (badgeLabel) {
                html += '<span class="cp-result-badge">' + escapeHtml(badgeLabel) + '</span>';
            }
            if (item.type === 'saved') {
                html += '<button class="cp-result-delete" data-saved-id="' + escapeHtml(item.savedId) + '" title="Delete">';
                html += '<i data-lucide="trash-2"></i>';
                html += '</button>';
            }
            html += '</div>';
            html += '</div>';

            resultItems.push(item);
            idx++;
        }

        resultsEl.innerHTML = html;

        // Auto-select the first result UNLESS chips are locked and input is empty.
        // In that case, Enter should run the chip composition, not a default item.
        var skipAutoSelect = chips && chips.count() > 0 && input && input.value.trim() === '';
        if (idx > 0 && !skipAutoSelect) {
            activeIndex = 0;
        } else {
            activeIndex = -1;
            // Clear any lingering .active class on result rows
            var activeEls = resultsEl.querySelectorAll('.cp-result.active');
            for (var ai = 0; ai < activeEls.length; ai++) {
                activeEls[ai].classList.remove('active');
            }
        }
        updateDeleteHint();

        // Render Lucide icons
        if (typeof lucide !== 'undefined' && lucide.createIcons) {
            lucide.createIcons({ nodes: resultsEl.querySelectorAll('[data-lucide]') });
        }

        // Bind click handlers
        var resultEls = resultsEl.querySelectorAll('.cp-result');
        for (var r = 0; r < resultEls.length; r++) {
            (function(index) {
                resultEls[index].addEventListener('click', function(e) {
                    // Check if delete button was clicked
                    var deleteBtn = e.target.closest('.cp-result-delete');
                    if (deleteBtn) {
                        e.stopPropagation();
                        var savedId = deleteBtn.getAttribute('data-saved-id');
                        deleteSavedCommand(savedId);
                        return;
                    }
                    if (resultItems[index] && resultItems[index].disabled) return;
                    activeIndex = index;
                    executeResult(false);
                });
            })(r);
        }
    }

    // ── Navigation helpers ───────────────────────────────────────────
    function setActive(index) {
        var els = resultsEl.querySelectorAll('.cp-result');
        for (var i = 0; i < els.length; i++) {
            els[i].classList.remove('active');
        }
        if (index >= 0 && index < els.length) {
            els[index].classList.add('active');
            // Scroll into view
            els[index].scrollIntoView({ block: 'nearest' });
        }
        activeIndex = index;
        // Flag the item as explicitly picked by the user so Enter executes it
        // rather than the chip-composition fallback.
        if (index >= 0 && index < resultItems.length && resultItems[index]) {
            resultItems[index]._userPicked = true;
        }
        updateDeleteHint();
    }

    function updateDeleteHint() {
        var hint = footer && footer.querySelector('.cp-footer-hint-delete');
        if (!hint) return;
        var item = (activeIndex >= 0 && activeIndex < resultItems.length) ? resultItems[activeIndex] : null;
        var canDelete = item && (item.type === 'recent' || item.type === 'saved');
        hint.style.display = canDelete ? '' : 'none';
    }

    function executeResult(shiftKey) {
        if (activeIndex < 0 || activeIndex >= resultItems.length) return;
        var item = resultItems[activeIndex];
        if (item.disabled) return;
        if (shiftKey && item.altAction) {
            item.altAction();
        } else if (item.action) {
            item.action();
        }
    }

    // ── Search dispatcher ────────────────────────────────────────────
    function handleInput() {
        var raw = input.value;

        // Check for filter prefix first - takes precedence over card/nav/help modes
        if (window.__palette_providers) {
            var detected = window.__palette_providers.detectPrefix(raw);
            if (detected && chips) {
                var provider = window.__palette_providers.getProvider(detected.prefix);
                if (provider) {
                    // Clear mode indicator when in provider mode
                    modeIndicator.textContent = '';
                    modeIndicator.className = 'cp-mode-indicator';
                    modeIndicator.removeAttribute('data-mode');
                    renderProviderResults(detected.prefix, provider, detected.query);
                    return;
                }
            }
        }

        // Sub-view mode: if the last chip is a parent nav chip (and no provider
        // prefix took over above), dropdown shows that page's sub-views.
        if (chips) {
            var chipsList = chips.all();
            var parentNavChip = null;
            for (var ci = chipsList.length - 1; ci >= 0; ci--) {
                if (chipsList[ci].type === 'nav' && isParentNav(chipsList[ci].navName)) {
                    parentNavChip = chipsList[ci];
                    break;
                }
            }
            if (parentNavChip) {
                var targets = getNavTargets(parentNavChip.navName);
                if (targets) {
                    // Clear mode indicator when in sub-view mode
                    modeIndicator.textContent = '';
                    modeIndicator.className = 'cp-mode-indicator';
                    modeIndicator.removeAttribute('data-mode');
                    renderSubViewResults(parentNavChip, targets, raw.trim());
                    return;
                }
            }
        }

        var mode = detectMode(raw);
        var query = stripPrefix(raw).trim();

        // Update mode indicator
        if (mode === 'help') {
            modeIndicator.textContent = 'HELP';
            modeIndicator.setAttribute('data-mode', 'help');
            modeIndicator.className = 'cp-mode-indicator active';
        } else if (mode === 'nav') {
            modeIndicator.textContent = 'NAV';
            modeIndicator.setAttribute('data-mode', 'nav');
            modeIndicator.className = 'cp-mode-indicator active';
        } else if (mode === 'saved') {
            modeIndicator.textContent = 'SAVED';
            modeIndicator.setAttribute('data-mode', 'saved');
            modeIndicator.className = 'cp-mode-indicator active';
        } else {
            modeIndicator.textContent = '';
            modeIndicator.className = 'cp-mode-indicator';
            modeIndicator.removeAttribute('data-mode');
        }

        // Empty input → show defaults
        if (!raw.trim()) {
            renderDefault();
            return;
        }

        var items = [];

        if (mode === 'help') {
            var helpItems = getHelpResults(query);
            if (helpItems.length > 0) {
                items.push({ type: 'header', title: 'Help' });
                items = items.concat(helpItems);
            }
        } else if (mode === 'nav') {
            var navItems = getNavResults(query);
            if (navItems.length > 0) {
                items.push({ type: 'header', title: 'Pages' });
                items = items.concat(navItems);
            }
        } else if (mode === 'saved') {
            var savedItems = getSavedResults(query);
            if (savedItems.length > 0) {
                items.push({ type: 'header', title: 'Saved Commands' });
                items = items.concat(savedItems);
            }
        } else {
            // Always offer direct search with full query (supports syntax like s:3ED)
            var composedValue = chips ? chips.composedQuery() : query;
            if (composedValue) {
                items.push({
                    type: 'search',
                    title: 'Search: ' + composedValue,
                    subtitle: 'Run full search with syntax support',
                    icon: 'search',
                    action: function() {
                        var q = chips ? chips.composedQuery() : composedValue;
                        recordRecentSearch(q);
                        window.location.href = '/search?q=' + encodeURIComponent(q);
                    }
                });
            }

            // General search - combine sources
            var recentItems = getRecentResults(query, 3);
            var cmdItems = getStaticCommands(query);
            var savedItems2 = getSavedResults(query);
            var cardItems = getCardResults(query, 5);
            var navItems2 = getNavResults(query);

            if (recentItems.length > 0) {
                items.push({ type: 'header', title: 'Recent Searches' });
                items = items.concat(recentItems.slice(0, 3));
            }
            if (savedItems2.length > 0) {
                items.push({ type: 'header', title: 'Saved Commands' });
                items = items.concat(savedItems2.slice(0, 3));
            }
            if (cmdItems.length > 0) {
                items.push({ type: 'header', title: 'Commands' });
                items = items.concat(cmdItems.slice(0, 3));
            }
            if (cardItems.length > 0) {
                items.push({ type: 'header', title: 'Cards' });
                items = items.concat(cardItems);
            }
            if (navItems2.length > 0) {
                items.push({ type: 'header', title: 'Pages' });
                items = items.concat(navItems2.slice(0, 3));
            }
        }

        // Enforce global 10-item cap (excluding headers)
        var nonHeaders = [];
        var headers = [];
        for (var x = 0; x < items.length; x++) {
            if (items[x].type === 'header') {
                headers.push({ item: items[x], nextIndex: nonHeaders.length });
            } else {
                nonHeaders.push(items[x]);
            }
        }
        if (nonHeaders.length > 10) {
            nonHeaders = nonHeaders.slice(0, 10);
        }
        // Rebuild with headers only for items that survived the cap
        var capped = [];
        var hi = 0;
        for (var y = 0; y < nonHeaders.length; y++) {
            while (hi < headers.length && headers[hi].nextIndex <= y) {
                capped.push(headers[hi].item);
                hi++;
            }
            capped.push(nonHeaders[y]);
        }
        items = capped;

        renderResults(items);
    }

    var inputTimer = null;
    input.addEventListener('input', function() {
        if (inputTimer) clearTimeout(inputTimer);
        inputTimer = setTimeout(handleInput, 80);
    });

    // ── Saved commands ───────────────────────────────────────────────
    function showSaveRow() {
        removeSaveRow();

        var queryToSave;
        if (chips && chips.count() > 0) {
            queryToSave = chips.composedQuery();
        } else {
            // V1 behavior: fall back to page searchbox value
            var searchInput = document.getElementById('searchbox');
            queryToSave = searchInput ? searchInput.value.trim() : '';
        }
        if (!queryToSave) {
            showToast('No search to save');
            return;
        }

        var row = document.createElement('div');
        row.className = 'cp-save-row';
        row.id = 'cp-save-row';

        var label = document.createElement('span');
        label.className = 'cp-save-label';
        label.textContent = 'Name:';

        var saveInput = document.createElement('input');
        saveInput.className = 'cp-save-input';
        saveInput.id = 'cp-save-input';
        saveInput.placeholder = 'Enter a name for this search...';
        saveInput.maxLength = MAX_NAME;

        row.appendChild(label);
        row.appendChild(saveInput);
        dialog.appendChild(row);
        saveInput.focus();

        var pendingConflict = null;

        saveInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.keyCode === 13) {
                e.preventDefault();

                // If awaiting overwrite confirmation
                if (pendingConflict) {
                    var answer = saveInput.value.trim().toLowerCase();
                    if (answer === 'y' || answer === 'yes') {
                        saveCommand(pendingConflict.name, pendingConflict.query, true);
                        removeSaveRow();
                        input.focus();
                    } else {
                        // Cancel - go back to name input
                        pendingConflict = null;
                        label.textContent = 'Name:';
                        saveInput.value = '';
                        saveInput.placeholder = 'Enter a name for this search...';
                        saveInput.maxLength = MAX_NAME;
                    }
                    return;
                }

                var name = saveInput.value.trim();
                if (!name) {
                    showToast('Please enter a name');
                    return;
                }
                var conflict = saveCommand(name, queryToSave, false);
                if (conflict) {
                    // Show confirmation prompt in the save row
                    pendingConflict = { name: name, query: queryToSave };
                    label.textContent = '"' + name + '" exists with: ' + conflict.existing.query + ' - Overwrite?';
                    saveInput.value = '';
                    saveInput.placeholder = 'y / n';
                    saveInput.maxLength = 3;
                } else {
                    removeSaveRow();
                    input.focus();
                }
            } else if (e.key === 'Escape' || e.keyCode === 27) {
                e.preventDefault();
                removeSaveRow();
                input.focus();
            }
        });
    }

    function removeSaveRow() {
        var row = document.getElementById('cp-save-row');
        if (row) row.parentNode.removeChild(row);
    }

    // Returns null if saved, or a conflict object if confirmation needed
    function saveCommand(name, query, forceOverwrite) {
        var saved = getJSON(SAVED_KEY);

        // Build chips snapshot from current manager state
        var chipsSnapshot = [];
        if (chips && typeof chips.all === 'function') {
            var currentChips = chips.all();
            for (var ci = 0; ci < currentChips.length; ci++) {
                var c = currentChips[ci];
                chipsSnapshot.push({
                    type: c.type,
                    prefix: c.prefix,
                    value: c.value,
                    label: c.label,
                    icon: c.icon,
                    navName: c.navName,
                    navLink: c.navLink,
                    _cardName: c._cardName,
                    _parentKey: c._parentKey,
                    _urlParam: c._urlParam
                });
            }
        }

        // Same query already saved - just update the name silently
        for (var i = 0; i < saved.length; i++) {
            if (saved[i].query === query) {
                saved[i].name = name.substring(0, MAX_NAME);
                saved[i].chips = chipsSnapshot;
                saved[i].lastUsed = Date.now();
                setJSON(SAVED_KEY, saved);
                showToast('Updated: ' + name);
                return null;
            }
        }

        // Same name exists with different query - needs confirmation
        for (var j = 0; j < saved.length; j++) {
            if (saved[j].name.toLowerCase() === name.toLowerCase()) {
                if (!forceOverwrite) {
                    return { existing: saved[j] };
                }
                // Overwrite confirmed
                saved[j].query = query;
                saved[j].chips = chipsSnapshot;
                saved[j].lastUsed = Date.now();
                setJSON(SAVED_KEY, saved);
                showToast('Overwritten: ' + name);
                return null;
            }
        }

        if (saved.length >= MAX_SAVED) {
            showToast('Maximum ' + MAX_SAVED + ' saved commands reached');
            return null;
        }

        saved.push({
            id: 'cmd_' + Date.now(),
            name: name.substring(0, MAX_NAME),
            query: query,
            chips: chipsSnapshot,
            icon: 'bookmark',
            userEmail: palette.user || '',
            created: Date.now(),
            lastUsed: Date.now(),
            useCount: 0
        });
        setJSON(SAVED_KEY, saved);
        showToast('Saved: ' + name);
        return null;
    }

    function deleteSavedCommand(savedId) {
        var saved = getJSON(SAVED_KEY);
        var target = null;
        for (var i = 0; i < saved.length; i++) {
            if (saved[i].id === savedId) {
                target = saved[i];
                break;
            }
        }
        if (!target) return;

        if (!window.confirm('Delete saved command "' + target.name + '"?')) return;

        saved = saved.filter(function(s) { return s.id !== savedId; });
        setJSON(SAVED_KEY, saved);
        showToast('Command deleted');

        // Re-render current results
        handleInput();
    }

    // Delete without confirmation - used by Shift+Delete keyboard shortcut.
    function deleteSavedCommandSilent(savedId) {
        var saved = getJSON(SAVED_KEY);
        var target = null;
        for (var i = 0; i < saved.length; i++) {
            if (saved[i].id === savedId) {
                target = saved[i];
                break;
            }
        }
        if (!target) return;
        saved = saved.filter(function(s) { return s.id !== savedId; });
        setJSON(SAVED_KEY, saved);
        showToast('Deleted: ' + target.name);
    }

    function deleteRecentSearch(query) {
        if (!query) return;
        var recent = getJSON(RECENT_KEY);
        recent = recent.filter(function(r) {
            return (r.q || '').toLowerCase() !== query.toLowerCase();
        });
        setJSON(RECENT_KEY, recent);
        showToast('Removed from recent');
    }

    // ── Keyboard: global ─────────────────────────────────────────────
    document.addEventListener('keydown', function(e) {
        // Ctrl/Cmd+K to toggle
        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.keyCode === 75)) {
            e.preventDefault();
            if (isOpen) {
                closePalette();
            } else {
                openPalette();
            }
            return;
        }

        // "/" when no input focused
        if (e.key === '/' && !isOpen) {
            var tag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
            var isInput = tag === 'input' || tag === 'textarea' || tag === 'select';
            var isEditable = document.activeElement && document.activeElement.isContentEditable;
            if (!isInput && !isEditable) {
                e.preventDefault();
                openPalette();
                return;
            }
        }
    });

    // ── Focus trap on dialog level ─────────────────────────────────────
    dialog.addEventListener('keydown', function(e) {
        if ((e.key === 'Tab' || e.keyCode === 9) && e.target !== input) {
            e.preventDefault();
            input.focus();
        }
    });

    // ── Keyboard: internal (palette open) ────────────────────────────
    input.addEventListener('keydown', function(e) {
        var key = e.key || '';
        var code = e.keyCode || 0;

        // Arrow down
        if (key === 'ArrowDown' || code === 40) {
            e.preventDefault();
            if (resultItems.length === 0) return;
            var next = activeIndex + 1;
            if (next >= resultItems.length) next = 0;
            setActive(next);
            return;
        }

        // Arrow up
        if (key === 'ArrowUp' || code === 38) {
            e.preventDefault();
            if (resultItems.length === 0) return;
            var prev = activeIndex - 1;
            if (prev < 0) prev = resultItems.length - 1;
            setActive(prev);
            return;
        }

        // Shift+Delete → remove active recent/saved entry without confirmation
        if (e.shiftKey && (key === 'Delete' || code === 46)) {
            if (activeIndex < 0 || activeIndex >= resultItems.length) return;
            var delItem = resultItems[activeIndex];
            if (!delItem) return;
            if (delItem.type === 'recent' && delItem.recentQuery) {
                e.preventDefault();
                deleteRecentSearch(delItem.recentQuery);
                handleInput();
                return;
            }
            if (delItem.type === 'saved' && delItem.savedId) {
                e.preventDefault();
                deleteSavedCommandSilent(delItem.savedId);
                handleInput();
                return;
            }
            return;
        }

        // Left arrow at cursor position 0 with no chip active → activate last chip
        if ((key === 'ArrowLeft' || code === 37) && chips && chips.count() > 0
            && chips.activeIndex() === -1
            && input.selectionStart === 0 && input.selectionEnd === 0) {
            e.preventDefault();
            chips.activate(chips.count() - 1);
            return;
        }

        // Backspace on empty input → activate last chip (rather than doing nothing)
        if ((key === 'Backspace' || code === 8) && input.value === ''
            && chips && chips.count() > 0 && chips.activeIndex() === -1) {
            e.preventDefault();
            chips.activate(chips.count() - 1);
            return;
        }

        // Enter
        if (key === 'Enter' || code === 13) {
            // Chips locked + empty input: default to executing the composed query
            // rather than whatever default-view result happens to be highlighted.
            // If the user wants to pick a default-view item instead, they can arrow
            // to it first (that changes activeIndex to a user-selected value, not
            // the auto-select-first-result).
            if (chips && chips.count() > 0 && input.value.trim() === '') {
                var activeItem = (activeIndex >= 0 && activeIndex < resultItems.length)
                    ? resultItems[activeIndex] : null;
                // Only fall through to executeResult when the active item was explicitly
                // arrowed-to (userPickedResult flag), otherwise treat Enter as "run chips".
                if (!activeItem || !activeItem._userPicked) {
                    e.preventDefault();
                    var navUrl = chipsNavURL(chips.all());
                    if (navUrl) {
                        window.location.href = navUrl;
                        return;
                    }
                    var composed = chips.composedQuery();
                    if (composed) {
                        recordRecentSearch(composed);
                        window.location.href = '/search?q=' + encodeURIComponent(composed);
                    }
                    return;
                }
            }

            e.preventDefault();
            executeResult(e.shiftKey);
            return;
        }

        // Escape
        if (key === 'Escape' || code === 27) {
            e.preventDefault();
            closePalette();
            return;
        }

        // Ctrl/Cmd+S - save current search
        if ((e.ctrlKey || e.metaKey) && (key === 's' || code === 83)) {
            e.preventDefault();
            showSaveRow();
            return;
        }

        // Tab - lock highlighted dropdown result as a chip (filter / card / nav)
        if ((key === 'Tab' || code === 9) && !e.shiftKey
            && activeIndex >= 0 && resultItems[activeIndex]
            && !resultItems[activeIndex].disabled
            && chips) {
            var item = resultItems[activeIndex];
            var locked = false;

            if (item.type === 'filter-candidate' && item._providerPrefix && item._providerCandidate) {
                var cand = item._providerCandidate;
                suppressChipOnChange = true;
                chips.add({
                    type: 'filter',
                    prefix: item._providerPrefix,
                    value: item._providerPrefix + cand.value,
                    label: item._providerPrefix + (cand.label || cand.value),
                    icon: item.icon || 'filter'
                });
                suppressChipOnChange = false;
                locked = true;
            } else if (item.type === 'card' && item.cardName) {
                suppressChipOnChange = true;
                chips.add({
                    type: 'card',
                    value: '"' + item.cardName + '"',
                    label: item.cardName,
                    icon: 'search',
                    _cardName: item.cardName
                });
                suppressChipOnChange = false;
                fetchCardMeta(item.cardName);
                locked = true;
            } else if (item.type === 'nav' && item.navName) {
                suppressChipOnChange = true;
                chips.add({
                    type: 'nav',
                    value: item.navLink || '',
                    label: item.navName,
                    icon: 'compass',
                    navName: item.navName,
                    navLink: item.navLink
                });
                suppressChipOnChange = false;
                locked = true;
            } else if (item.type === 'nav-sub' && item._subView && item._parentChip) {
                var pKey = navParentKeys[item._parentChip.navName];
                var urlParam;
                var isSingleton = false;
                if (pKey === 'newspaper' || pKey === 'sleepers') {
                    urlParam = 'page=' + encodeURIComponent(item._subView.value);
                    isSingleton = true;
                } else if (isArbitSortValue(pKey, item._subView.value)) {
                    urlParam = 'sort=' + encodeURIComponent(item._subView.value);
                    isSingleton = true;
                } else {
                    urlParam = encodeURIComponent(item._subView.value) + '=true';
                }
                // Remove duplicates / singletons before adding
                var existingChips = chips.all();
                for (var dup = existingChips.length - 1; dup >= 0; dup--) {
                    var ec = existingChips[dup];
                    if (ec.type !== 'nav-sub' || ec._parentKey !== pKey) continue;
                    if (isSingleton) {
                        // Replace: remove any existing nav-sub for this parent with the same param prefix (sort= or page=)
                        var ecPrefix = ec._urlParam ? ec._urlParam.split('=')[0] : '';
                        var newPrefix = urlParam.split('=')[0];
                        if (ecPrefix === newPrefix) {
                            chips.remove(dup);
                        }
                    } else {
                        // Filter: dedupe identical urlParam
                        if (ec._urlParam === urlParam) {
                            chips.remove(dup);
                        }
                    }
                }
                suppressChipOnChange = true;
                chips.add({
                    type: 'nav-sub',
                    value: item._subView.value,
                    label: item._subView.label,
                    icon: 'arrow-right',
                    _parentKey: pKey,
                    _urlParam: urlParam
                });
                suppressChipOnChange = false;
                locked = true;
            }

            if (locked) {
                e.preventDefault();
                input.value = '';
                handleInput();
                return;
            }
        }

        // Focus trap - Tab cycles within palette
        if (key === 'Tab' || code === 9) {
            e.preventDefault();
            input.focus();
            return;
        }
    });

    // ── Keyboard: chip container (chip is active) ────────────────────
    chipContainer.addEventListener('keydown', function (e) {
        if (!chips) return;
        var idx = chips.activeIndex();
        if (idx < 0) return; // input handler owns this

        // Left arrow - go to previous chip
        if (e.key === 'ArrowLeft' || e.keyCode === 37) {
            e.preventDefault();
            if (idx > 0) chips.activate(idx - 1);
            return;
        }
        // Right arrow - go to next chip, or back to input if at end
        if (e.key === 'ArrowRight' || e.keyCode === 39) {
            e.preventDefault();
            if (idx < chips.count() - 1) {
                chips.activate(idx + 1);
            } else {
                chips.activate(-1); // input
            }
            return;
        }
        // Delete removes current, keeps position (or moves to input if last)
        if (e.key === 'Delete' || e.keyCode === 46) {
            e.preventDefault();
            var nextIdx = idx; // Delete: current position, but chips shift left
            chips.remove(idx);
            if (nextIdx >= 0 && nextIdx < chips.count()) {
                chips.activate(nextIdx);
            } else {
                chips.activate(-1);
            }
            return;
        }
        // Backspace removes current, moves focus left (or to input)
        if (e.key === 'Backspace' || e.keyCode === 8) {
            e.preventDefault();
            var prevIdx = idx - 1;
            chips.remove(idx);
            if (prevIdx >= 0) {
                chips.activate(prevIdx);
            } else {
                chips.activate(-1);
            }
            return;
        }
        // Escape returns focus to input
        if (e.key === 'Escape' || e.keyCode === 27) {
            e.preventDefault();
            chips.activate(-1);
            return;
        }
        // Enter executes composed query (same as Enter from input)
        if (e.key === 'Enter' || e.keyCode === 13) {
            e.preventDefault();
            chips.activate(-1);
            // Find and execute the highlighted dropdown result, or run composed query
            if (activeIndex >= 0 && resultItems[activeIndex] && resultItems[activeIndex].action) {
                resultItems[activeIndex].action();
            } else if (chips.composedQuery()) {
                var q = chips.composedQuery();
                recordRecentSearch(q);
                window.location.href = '/search?q=' + encodeURIComponent(q);
            }
            return;
        }
        // Tab on active chip → edit: remove chip and put value into input (will reopen dropdown)
        if (e.key === 'Tab' || e.keyCode === 9) {
            e.preventDefault();
            var chip = chips.get(idx);
            if (!chip) return;
            chips.remove(idx);
            // For filter chips, put "prefix + first value" back into input so the dropdown
            // shows that provider. For other chip types, just drop the value into input.
            var restored;
            if (chip.type === 'filter' && chip.prefix) {
                var stripped = chip.value.indexOf(chip.prefix) === 0
                    ? chip.value.substring(chip.prefix.length).split(',')[0]
                    : chip.value.split(',')[0];
                restored = chip.prefix + stripped;
            } else {
                restored = chip.value;
            }
            input.value = restored;
            chips.activate(-1); // back to input
            input.setSelectionRange(input.value.length, input.value.length);
            if (typeof handleInput === 'function') handleInput();
            return;
        }
    });

    // Also handle Escape when save input is focused
    dialog.addEventListener('keydown', function(e) {
        if ((e.key === 'Escape' || e.keyCode === 27) && e.target.id !== 'cp-input') {
            e.preventDefault();
            if (document.getElementById('cp-save-row')) {
                removeSaveRow();
                input.focus();
            } else {
                closePalette();
            }
        }
    });

})();
