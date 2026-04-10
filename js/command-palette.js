/* Command Palette — keyboard-driven search, navigation, help, and saved commands */
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

    var input = document.createElement('input');
    input.className = 'cp-input';
    input.id = 'cp-input';
    input.placeholder = 'Search cards, commands, help...';
    input.setAttribute('autocomplete', 'off');

    var escKbd = document.createElement('kbd');
    escKbd.className = 'cp-shortcut';
    escKbd.textContent = 'ESC';

    inputRow.appendChild(modeIndicator);
    inputRow.appendChild(input);
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
        '<span><kbd>?</kbd> Help</span>' +
        '<span><kbd>Esc</kbd> Close</span>';

    dialog.appendChild(inputRow);
    dialog.appendChild(resultsEl);
    dialog.appendChild(footer);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);

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
        var searchInput = document.getElementById('searchbox');
        if (searchInput && searchInput.value && searchInput.value.trim()) {
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
                        var all = getJSON(SAVED_KEY);
                        for (var k = 0; k < all.length; k++) {
                            if (all[k].id === cmd.id) {
                                all[k].lastUsed = Date.now();
                                all[k].useCount = (all[k].useCount || 0) + 1;
                                break;
                            }
                        }
                        setJSON(SAVED_KEY, all);
                        recordRecentSearch(cmd.query);
                        window.location.href = '/search?q=' + encodeURIComponent(cmd.query);
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

    // ── Render results ───────────────────────────────────────────────
    function renderResults(items) {
        resultItems = [];
        activeIndex = -1;
        var html = '';
        var idx = 0;

        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            if (item.type === 'header') {
                html += '<div class="cp-category-header">' + escapeHtml(item.title) + '</div>';
                continue;
            }

            var activeClass = idx === 0 ? ' active' : '';
            html += '<div class="cp-result' + activeClass + '" role="option" data-index="' + idx + '">';
            html += '<div class="cp-result-icon"><i data-lucide="' + escapeHtml(item.icon || 'search') + '"></i></div>';
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

        if (idx > 0) {
            activeIndex = 0;
        }

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
    }

    function executeResult(shiftKey) {
        if (activeIndex < 0 || activeIndex >= resultItems.length) return;
        var item = resultItems[activeIndex];
        if (shiftKey && item.altAction) {
            item.altAction();
        } else if (item.action) {
            item.action();
        }
    }

    // ── Search dispatcher ────────────────────────────────────────────
    function handleInput() {
        var raw = input.value;
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
            // General search — combine sources
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

        var searchInput = document.getElementById('searchbox');
        if (!searchInput || !searchInput.value || !searchInput.value.trim()) {
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

        saveInput.addEventListener('keydown', function(e) {
            if (e.key === 'Enter' || e.keyCode === 13) {
                e.preventDefault();
                var name = saveInput.value.trim();
                if (!name) {
                    showToast('Please enter a name');
                    return;
                }
                saveCommand(name, searchInput.value.trim());
                removeSaveRow();
                input.focus();
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

    function saveCommand(name, query) {
        var saved = getJSON(SAVED_KEY);

        if (saved.length >= MAX_SAVED) {
            showToast('Maximum ' + MAX_SAVED + ' saved commands reached');
            return;
        }

        var cmd = {
            id: 'cmd_' + Date.now(),
            name: name.substring(0, MAX_NAME),
            query: query,
            icon: 'bookmark',
            userEmail: palette.user || '',
            created: Date.now(),
            lastUsed: Date.now(),
            useCount: 0
        };

        saved.push(cmd);
        setJSON(SAVED_KEY, saved);
        showToast('Saved: ' + name);
    }

    function deleteSavedCommand(savedId) {
        var saved = getJSON(SAVED_KEY);
        var found = false;
        for (var i = 0; i < saved.length; i++) {
            if (saved[i].id === savedId) {
                found = true;
                break;
            }
        }
        if (!found) return;

        // Simple confirmation
        saved = saved.filter(function(s) { return s.id !== savedId; });
        setJSON(SAVED_KEY, saved);
        showToast('Command deleted');

        // Re-render current results
        handleInput();
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

        // Enter
        if (key === 'Enter' || code === 13) {
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

        // Ctrl/Cmd+S — save current search
        if ((e.ctrlKey || e.metaKey) && (key === 's' || code === 83)) {
            e.preventDefault();
            showSaveRow();
            return;
        }

        // Focus trap — Tab cycles within palette
        if (key === 'Tab' || code === 9) {
            e.preventDefault();
            input.focus();
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
