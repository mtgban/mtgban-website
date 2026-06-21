/* Command Palette - keyboard-driven search, navigation, help, and saved commands */
(function () {
    'use strict';

    // Mobile guard + externals
    if (!window.__BAN_PALETTE || window.innerWidth < 768) return;

    var palette   = window.__BAN_PALETTE;
    var guide     = window.__BAN_GUIDE || { sections: [] };
    var providers = window.__palette_providers || null;
    var chipsAPI  = window.__palette_chips || null;

    // Constants
    var RECENT_KEY      = 'mtgban_recent_searches';
    var SAVED_KEY       = 'mtgban_saved_commands';
    var MAX_SAVED       = 50;
    var MAX_NAME        = 60;
    var MAX_RECENT      = 15;
    var DROPDOWN_CAP    = 30;
    var GLOBAL_ITEM_CAP = 10;
    var DEFAULT_PLACEHOLDER = 'Search...';

    // Maps nav entry name → key in __BAN_PALETTE_TARGETS that holds sub-views.
    var NAV_PARENTS = {
        Newspaper: 'newspaper',
        Sleepers:  'sleepers',
        Arbitrage: 'arbit',
        Reverse:   'reverse',
        Global:    'global'
    };

    // Allowlist of nav entries the user actually has access to. Used to gate help sections.
    var NAV_NAMES = (function () {
        var out = {};
        var nav = palette.nav || [];
        for (var i = 0; i < nav.length; i++) out[nav[i].name] = true;
        return out;
    })();

    // State
    var S = {
        open:               false,
        items:              [],     // current rendered result items
        activeIndex:        -1,
        previousFocus:      null,
        cardNames:          null,
        cardNamesLoading:   false,
        sealedNames:        null,
        sealedNamesLoading: false,
        cardMetaCache:      {},
        cardMetaInflight:   {},
        sealedMetaCache:    {},
        sealedMetaInflight: {},
        lastChipCount:      0,
        suppressChipOnChange: false,
        saveModalOpen:      false,
        inputTimer:         null,
        toastTimer:         null
    };

    // ════════════════════════════════════════════════════════════════
    //  Pure utilities
    // ════════════════════════════════════════════════════════════════

    function esc(str) {
        var d = document.createElement('div');
        d.textContent = str == null ? '' : String(str);
        return d.innerHTML;
    }

    function scoreMatch(query, name, keywords) {
        var q = query.toLowerCase();
        var n = name.toLowerCase();
        if (n.indexOf(q) === 0) return 3;                    // prefix
        var words = n.split(/[\s\-_]+/);
        for (var i = 0; i < words.length; i++) {
            if (words[i].indexOf(q) === 0) return 2;          // word-boundary
        }
        if (n.indexOf(q) >= 0) return 1;                      // substring
        if (keywords) {
            var kw = typeof keywords === 'string' ? keywords.split(/[\s,]+/) : keywords;
            for (var j = 0; j < kw.length; j++) {
                if (kw[j].toLowerCase().indexOf(q) >= 0) return 1;
            }
        }
        return 0;
    }

    // Mirrors autocomplete.js semantics for card-name prefix matching.
    function matchCardName(query, name) {
        var q = query.toUpperCase();
        var L = query.length;
        if (name.substr(0, L).toUpperCase() === q) return true;
        if (name.normalize('NFD').replace(/[\u0300-\u036f]/g, '').substr(0, L).toUpperCase() === q) return true;
        if (name.replace(/^The /g, '').substr(0, L).toUpperCase() === q) return true;
        if (name.replace(/[^A-Za-z0-9 ]/g, '').substr(0, L).toUpperCase() === q) return true;
        return false;
    }

    function categoryKeyFor(title) {
        var t = (title || '').toLowerCase();
        if (t.indexOf('recent')  >= 0) return 'recent';
        if (t.indexOf('saved')   >= 0) return 'saved';
        if (t.indexOf('page')    >= 0 || t.indexOf('navigate') >= 0) return 'pages';
        if (t.indexOf('card')    >= 0) return 'cards';
        if (t.indexOf('command') >= 0 || t.indexOf('action')   >= 0) return 'commands';
        if (t.indexOf('help')    >= 0) return 'help';
        if (t.indexOf('syntax')  >= 0) return 'syntax';
        return 'other';
    }

    function categoryIconFor(title) {
        var key = categoryKeyFor(title);
        return ({
            recent: 'clock', saved: 'bookmark', pages: 'compass', cards: 'search',
            commands: 'zap', help: 'help-circle', syntax: 'code'
        })[key] || null;
    }

    // ════════════════════════════════════════════════════════════════
    //  Storage helpers
    // ════════════════════════════════════════════════════════════════

    function getJSON(key) {
        try { var v = localStorage.getItem(key); return v ? JSON.parse(v) : []; }
        catch (e) { return []; }
    }

    function setJSON(key, val) {
        try { localStorage.setItem(key, JSON.stringify(val)); } catch (e) {}
    }

    function recordRecentSearch(query) {
        if (!query || query.trim().length < 2) return;
        query = query.trim();
        var recent = getJSON(RECENT_KEY).filter(function (s) {
            return (s.q || '').toLowerCase() !== query.toLowerCase();
        });
        recent.unshift({ q: query, t: Date.now() });
        if (recent.length > MAX_RECENT) recent = recent.slice(0, MAX_RECENT);
        setJSON(RECENT_KEY, recent);
    }

    // Current query: page box, navbar box, then the URL's q param.
    function currentPageQuery() {
        var sb = document.getElementById('searchbox') || document.getElementById('nav-searchbox');
        if (sb && sb.value.trim()) return sb.value.trim();
        try { return (new URLSearchParams(location.search).get('q') || '').trim(); }
        catch (e) { return ''; }
    }

    function parseUploadURL(s) {
        try {
            var u = new URL(s);
            if (u.host === 'store.tcgplayer.com')                            return { label: 'TCGplayer collection' };
            if (u.host === 'moxfield.com' || u.host === 'www.moxfield.com')  return { label: 'Moxfield deck' };
            if (u.host === 'docs.google.com')                                 return { label: 'Google Sheets' };
            return null;
        } catch (e) {
            return null;
        }
    }

    function pageUploadHashInputs() {
        // Search results render hashes as hidden inputs in a sidebar /upload form.
        // Upload-results pages render them as tr[data-hash] rows.
        var inputs = document.querySelectorAll('form[action="/upload"] input[name="hashes"]');
        if (inputs.length > 0) return inputs;
        return document.querySelectorAll('tr[data-hash]');
    }

    function countDataHashRows() {
        return pageUploadHashInputs().length;
    }

    function appendHidden(form, name, value) {
        var i = document.createElement('input');
        i.type  = 'hidden';
        i.name  = name;
        i.value = value;
        form.appendChild(i);
    }

    function showUploadingState(msg) {
        resultsEl.innerHTML =
            '<div class="cp-result"><div class="cp-result-icon cp-spinner">'
            + '<i data-lucide="loader-2"></i></div>'
            + '<div class="cp-result-body"><div class="cp-result-title">' + esc(msg) + '</div>'
            + '<div class="cp-result-subtitle">Hang tight, this can take a few seconds...</div>'
            + '</div></div>';
        S.items = [];
        S.activeIndex = -1;
        if (typeof lucide !== 'undefined' && lucide.createIcons) {
            lucide.createIcons({ nodes: resultsEl.querySelectorAll('[data-lucide]') });
        }
    }

    // upload.go's cookie fallback for stores only fires when hashes is non-empty;
    // URL/file submissions must include the saved store list explicitly.
    function appendUserStores(form) {
        if (typeof getCookie !== 'function') return;
        var combined = (getCookie('enabledSellers') || '') + '|' + (getCookie('enabledVendors') || '');
        var seen = {};
        combined.split('|').forEach(function (s) {
            s = s.trim();
            if (!s || seen[s]) return;
            seen[s] = true;
            appendHidden(form, 'stores', s);
        });
    }

    function submitUploadURL(url) {
        var form = document.createElement('form');
        form.method = 'post';
        form.action = '/upload';
        form.style.display = 'none';
        appendHidden(form, 'gdocURL', url);
        appendUserStores(form);
        document.body.appendChild(form);
        showUploadingState('Submitting URL to Uploader...');
        form.submit();
    }

    function triggerUploadFilePicker() {
        var form = document.createElement('form');
        form.method  = 'post';
        form.action  = '/upload';
        form.enctype = 'multipart/form-data';
        form.style.display = 'none';

        var picker = document.createElement('input');
        picker.type   = 'file';
        picker.name   = 'cardListFile';
        picker.accept = '.csv,.xls,.xlsx,text/csv,application/vnd.ms-excel,application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
        picker.addEventListener('change', function () {
            if (!picker.files || !picker.files[0]) return;
            appendUserStores(form);
            showUploadingState('Uploading ' + picker.files[0].name + '...');
            form.submit();
        });

        form.appendChild(picker);
        document.body.appendChild(form);
        picker.click();   // MUST be synchronous in the user-gesture handler
    }

    function submitUploadPageResults() {
        var sources = pageUploadHashInputs();
        if (sources.length === 0) { showToast('No results on this page'); return; }
        var form = document.createElement('form');
        form.method = 'post';
        form.action = '/upload';
        form.style.display = 'none';
        sources.forEach(function (el) {
            // input[name="hashes"] (sidebar form) → use el.value
            // tr[data-hash] (upload results) → use el.dataset.* with qty/cond/price
            if (el.tagName === 'INPUT') {
                appendHidden(form, 'hashes', el.value || '');
            } else {
                appendHidden(form, 'hashes',      el.dataset.hash  || '');
                appendHidden(form, 'hashesQtys',  el.dataset.qtys  || '');
                appendHidden(form, 'hashesCond',  el.dataset.cond  || '');
                appendHidden(form, 'hashesPrice', el.dataset.price || '');
            }
        });
        document.body.appendChild(form);
        showUploadingState('Sending ' + sources.length + ' result' + (sources.length === 1 ? '' : 's') + ' to Uploader...');
        form.submit();
    }

    function sealedAction(kind, name) {
        // contents:/unpack: must route through /search; /sealed force-sets SearchMode="sealed".
        var path;
        if      (kind === 'contents') path = '/search?q=' + encodeURIComponent('contents:"' + name + '"');
        else if (kind === 'unpack')   path = '/search?q=' + encodeURIComponent('unpack:"'   + name + '"');
        else                          path = '/sealed?q=' + encodeURIComponent(name);
        window.location.href = path;
    }

    function deleteRecentSearch(query) {
        if (!query) return;
        var recent = getJSON(RECENT_KEY).filter(function (r) {
            return (r.q || '').toLowerCase() !== query.toLowerCase();
        });
        setJSON(RECENT_KEY, recent);
        showToast('Removed from recent');
    }

    // ════════════════════════════════════════════════════════════════
    //  Nav helpers (parent/sub-view URL composition)
    // ════════════════════════════════════════════════════════════════

    function isParentNav(name) { return !!NAV_PARENTS[name]; }

    function getNavTargets(name) {
        var key = NAV_PARENTS[name];
        if (!key) return null;
        return (window.__BAN_PALETTE_TARGETS || {})[key] || null;
    }

    function isSectionAllowed(section) {
        if (!section.requiresNav) return true;
        return !!NAV_NAMES[section.requiresNav];
    }

    // For arbit/reverse/global, distinguishes whether a sub-view value goes in
    // ?sort= (singleton) or ?key=true (filter, multi).
    function isArbitSortValue(key, value) {
        var targets = (window.__BAN_PALETTE_TARGETS || {})[key];
        if (!targets || !targets.sorts) return false;
        for (var i = 0; i < targets.sorts.length; i++) {
            if (targets.sorts[i].value === value) return true;
        }
        return false;
    }

    // Returns a navigation URL if the chip set is a "nav composition" (one parent
    // nav chip + zero or more nav-sub chips for that parent), else null.
    function chipsNavURL(chipArray) {
        if (!chipArray || chipArray.length === 0) return null;
        var first = chipArray[0];
        if (!first || first.type !== 'nav') return null;
        var parentKey = first.navName ? NAV_PARENTS[first.navName] : null;
        if (!parentKey) return first.navLink || null;     // leaf nav

        var base = (first.navLink || '').split('?')[0];
        var params = [];
        for (var i = 1; i < chipArray.length; i++) {
            var c = chipArray[i];
            if (c.type !== 'nav-sub' || c._parentKey !== parentKey) return null;
            if (c._urlParam) params.push(c._urlParam);
        }
        return base + (params.length ? '?' + params.join('&') : '');
    }

    function composeSubViewURL(parentChip, entry) {
        var key  = NAV_PARENTS[parentChip.navName];
        var base = (parentChip.navLink || '').split('?')[0];
        var params = [];

        if (key === 'newspaper' || key === 'sleepers') {
            params.push('page=' + encodeURIComponent(entry.value));
        } else {
            if (isArbitSortValue(key, entry.value)) {
                params.push('sort=' + encodeURIComponent(entry.value));
            } else {
                params.push(encodeURIComponent(entry.value) + '=true');
            }
            // Merge prior nav-sub chips for the same parent.
            if (chips) {
                var list = chips.all();
                for (var i = 0; i < list.length; i++) {
                    if (list[i].type === 'nav-sub' && list[i]._parentKey === key && list[i]._urlParam) {
                        params.push(list[i]._urlParam);
                    }
                }
            }
        }
        return base + (params.length ? '?' + params.join('&') : '');
    }

    // ════════════════════════════════════════════════════════════════
    //  Card meta cache (for filter narrowing)
    // ════════════════════════════════════════════════════════════════

    function fetchCardMeta(name) {
        if (!name) return Promise.resolve(null);
        if (S.cardMetaCache[name])    return Promise.resolve(S.cardMetaCache[name]);
        if (S.cardMetaInflight[name]) return S.cardMetaInflight[name];
        S.cardMetaInflight[name] = fetch('/api/palette/card/' + encodeURIComponent(name))
            .then(function (r) { return r.ok ? r.json() : { found: false }; })
            .then(function (data) {
                if (data && data.found) S.cardMetaCache[name] = data;
                delete S.cardMetaInflight[name];
                handleInput();
                return data;
            })
            .catch(function () {
                delete S.cardMetaInflight[name];
                return { found: false };
            });
        return S.cardMetaInflight[name];
    }

    function fetchSealedMeta(name) {
        if (!name) return Promise.resolve(null);
        if (S.sealedMetaCache[name])    return Promise.resolve(S.sealedMetaCache[name]);
        if (S.sealedMetaInflight[name]) return S.sealedMetaInflight[name];
        S.sealedMetaInflight[name] = fetch('/api/palette/sealed/' + encodeURIComponent(name))
            .then(function (r) { return r.ok ? r.json() : { found: false }; })
            .then(function (data) {
                if (data && data.found) S.sealedMetaCache[name] = data;
                delete S.sealedMetaInflight[name];
                if (S.open) handleInput();
                return data;
            })
            .catch(function () {
                delete S.sealedMetaInflight[name];
                return { found: false };
            });
        return S.sealedMetaInflight[name];
    }

    function activeCardMeta() {
        if (!chips) return null;
        var list = chips.all();
        for (var i = 0; i < list.length; i++) {
            if (list[i].type === 'card') {
                return S.cardMetaCache[list[i]._cardName || list[i].value] || null;
            }
        }
        return null;
    }

    function ensureSealedNames() {
        if (S.sealedNames || S.sealedNamesLoading) return;
        if (typeof fetchNames !== 'function') return;
        S.sealedNamesLoading = true;
        fetchNames('true')
            .then(function (names) {
                S.sealedNames = names || [];
                S.sealedNamesLoading = false;
                if (S.open) handleInput();
            })
            .catch(function () { S.sealedNamesLoading = false; });
    }

    // ════════════════════════════════════════════════════════════════
    //  DOM construction
    // ════════════════════════════════════════════════════════════════

    function buildDOM() {
        var overlay = document.createElement('div');
        overlay.className = 'cp-overlay';
        overlay.id = 'cp-overlay';
        overlay.innerHTML =
            '<div class="cp-dialog" role="dialog" aria-modal="true">' +
              '<div class="cp-input-row">' +
                '<span class="cp-mode-indicator" id="cp-mode"></span>' +
                '<div class="cp-chip-container" id="cp-chips" role="group" aria-label="Search composition">' +
                  '<input class="cp-input" id="cp-input" type="text" autocomplete="off" placeholder="' + DEFAULT_PLACEHOLDER + '">' +
                '</div>' +
                '<kbd class="cp-shortcut">ESC</kbd>' +
              '</div>' +
              '<div class="cp-results" id="cp-results" role="listbox" aria-label="Results"></div>' +
              '<div class="cp-footer">' +
                '<span><kbd>\u2191\u2193</kbd> Navigate</span>' +
                '<span class="cp-footer-action"><kbd>Enter</kbd> Select</span>' +
                '<span class="cp-footer-tab" style="display:none"></span>' +
                '<span class="cp-footer-hint-delete" style="display:none"><kbd>Shift+Del</kbd> Remove</span>' +
                '<span><kbd>?</kbd> Help</span>' +
                '<span><kbd>Esc</kbd> Close</span>' +
              '</div>' +
              '<div class="cp-sr-only" id="cp-chip-announce" aria-live="polite" aria-atomic="true"></div>' +
            '</div>';
        document.body.appendChild(overlay);

        var toast = document.createElement('div');
        toast.className = 'cp-toast';
        toast.id = 'cp-toast';
        document.body.appendChild(toast);

        return {
            overlay:   overlay,
            dialog:    overlay.firstChild,
            input:     overlay.querySelector('#cp-input'),
            chipBox:   overlay.querySelector('#cp-chips'),
            modeTag:   overlay.querySelector('#cp-mode'),
            resultsEl: overlay.querySelector('#cp-results'),
            footer:    overlay.querySelector('.cp-footer'),
            chipLive:  overlay.querySelector('#cp-chip-announce'),
            toast:     toast
        };
    }

    var DOM = buildDOM();
    var input     = DOM.input;
    var resultsEl = DOM.resultsEl;
    var modeTag   = DOM.modeTag;

    // Click overlay to close (but not clicks inside the dialog).
    DOM.overlay.addEventListener('click', function (e) {
        if (e.target === DOM.overlay) closePalette();
    });

    // ════════════════════════════════════════════════════════════════
    //  Toast
    // ════════════════════════════════════════════════════════════════

    function showToast(msg) {
        DOM.toast.textContent = msg;
        DOM.toast.classList.add('show');
        if (S.toastTimer) clearTimeout(S.toastTimer);
        S.toastTimer = setTimeout(function () { DOM.toast.classList.remove('show'); }, 2000);
    }

    // ════════════════════════════════════════════════════════════════
    //  Chip manager init + chip helpers
    // ════════════════════════════════════════════════════════════════

    var chips = null;

    if (chipsAPI && typeof chipsAPI.create === 'function') {
        chips = chipsAPI.create(DOM.chipBox, input, onChipChange);
    }

    function onChipChange() {
        var now = chips ? chips.count() : 0;
        if (DOM.chipLive) {
            if (now > S.lastChipCount) {
                var latest = chips.get(now - 1);
                DOM.chipLive.textContent = 'Added chip: ' + (latest ? (latest.label || latest.value) : '');
            } else if (now < S.lastChipCount) {
                DOM.chipLive.textContent = 'Removed chip';
            }
        }
        S.lastChipCount = now;
        // Always refresh placeholder (chip add/remove changes context).
        applyPlaceholder(resolveContext(input.value));
        // Defer full re-render only when explicitly suppressed (e.g. inside Tab handler).
        if (!S.suppressChipOnChange) handleInput();
    }

    function addChipSilent(chip) {
        if (!chips) return;
        S.suppressChipOnChange = true;
        chips.add(chip);
        S.suppressChipOnChange = false;
    }

    function lockFilterChip(item) {
        var c = item._providerCandidate;
        addChipSilent({
            type:   'filter',
            prefix: item._providerPrefix,
            value:  item._providerPrefix + c.value,
            label:  item._providerPrefix + (c.label || c.value),
            icon:   item.icon || 'filter'
        });
    }

    function lockCardChip(item) {
        addChipSilent({
            type:      'card',
            value:     '"' + item.cardName + '"',
            label:     item.cardName,
            icon:      'search',
            _cardName: item.cardName
        });
        fetchCardMeta(item.cardName);
    }

    function lockSealedChip(item) {
        addChipSilent({
            type:        'sealed',
            value:       item.sealedName,
            label:       item.sealedName,
            icon:        'package',
            _sealedName: item.sealedName
        });
        fetchSealedMeta(item.sealedName);
        input.value = '';
    }

    function lockParentNavChip(item) {
        addChipSilent({
            type:    'nav',
            value:   item.navLink || '',
            label:   item.navName,
            icon:    'compass',
            navName: item.navName,
            navLink: item.navLink
        });
    }

    function lockSubViewChip(item) {
        var pKey = NAV_PARENTS[item._parentChip.navName];
        var urlParam, isSingleton = false;

        if (pKey === 'newspaper' || pKey === 'sleepers') {
            urlParam = 'page=' + encodeURIComponent(item._subView.value);
            isSingleton = true;
        } else if (isArbitSortValue(pKey, item._subView.value)) {
            urlParam = 'sort=' + encodeURIComponent(item._subView.value);
            isSingleton = true;
        } else {
            urlParam = encodeURIComponent(item._subView.value) + '=true';
        }

        // Replace any existing chip that conflicts (same singleton kind, or duplicate filter).
        var existing = chips.all();
        for (var i = existing.length - 1; i >= 0; i--) {
            var ec = existing[i];
            if (ec.type !== 'nav-sub' || ec._parentKey !== pKey) continue;
            if (isSingleton) {
                var ecPrefix  = ec._urlParam ? ec._urlParam.split('=')[0] : '';
                var newPrefix = urlParam.split('=')[0];
                if (ecPrefix === newPrefix) chips.remove(i);
            } else if (ec._urlParam === urlParam) {
                chips.remove(i);
            }
        }

        addChipSilent({
            type:       'nav-sub',
            value:      item._subView.value,
            label:      item._subView.label,
            icon:       'arrow-right',
            _parentKey: pKey,
            _urlParam:  urlParam
        });
    }

    function runComposedQuery() {
        if (!chips) return;
        var navUrl = chipsNavURL(chips.all());
        if (navUrl) { window.location.href = navUrl; return; }
        var q = chips.composedQuery();
        if (!q) return;
        recordRecentSearch(q);
        window.location.href = '/search?q=' + encodeURIComponent(q);
    }

    // Re-render dropdown when provider data (sets/stores) finishes loading.
    if (providers && typeof providers.setOnDataReady === 'function') {
        providers.setOnDataReady(function () {
            if (S.open) handleInput();
        });
    }

    // ════════════════════════════════════════════════════════════════
    //  Mode prefixes & context resolution
    // ════════════════════════════════════════════════════════════════

    // Single source of truth for everything per-mode. Adding a new mode is one entry here.
    //
    // Required fields:
    //   prefix       - single character shown on the shortcut tile (also typed by user)
    //   label        - mode-indicator text in the input row
    //   placeholder  - input placeholder when this mode is active
    //   tile         - { title, subtitle, icon } for the default-view Shortcuts row
    //   test(v)      - returns true when raw input v should enter this mode
    //   strip(v)     - returns the prefix-stripped query
    //
    // Optional fields:
    //   builder(ctx)   - per-mode item builder; falls back to buildModeItems when absent
    //   skipCap        - true to bypass GLOBAL_ITEM_CAP (the builder is expected to self-cap)
    //   requiresNav    - nav entry name; mode is hidden (and tile suppressed) when absent
    //
    // Iteration order matters: it determines tile order in renderDefault and the
    // scan order for resolveContext's prefix detection. All current tests are
    // mutually exclusive on the first character, so detection order is
    // behaviorally irrelevant; tile order is what users see.
    //
    // Forward references to buildSealedItems / buildUploadItems are fine: function
    // declarations are hoisted to the top of the IIFE, and these slots are only
    // dereferenced at call time (inside handleInput), well after hoisting completes.
    var MODES = {
        nav: {
            prefix: '>',
            label: 'NAV',
            placeholder: 'Filter pages...',
            tile: { title: 'Pages', subtitle: 'Browse navigation and sub-pages', icon: 'compass' },
            test:  function (v) { return v.charAt(0) === '>'; },
            strip: function (v) { return v.substring(1).trim(); }
        },
        help: {
            prefix: '?',
            label: 'HELP',
            placeholder: 'Search help & syntax...',
            tile: { title: 'Help & syntax', subtitle: 'Search reference and snippets', icon: 'help-circle' },
            test:  function (v) { return v.charAt(0) === '?' || /^(help:|syntax:)/i.test(v); },
            strip: function (v) { return v.replace(/^(\?\s*|help:|syntax:|\?:)/i, '').trim(); }
        },
        saved: {
            prefix: '*',
            label: 'SAVED',
            placeholder: 'Filter saved searches...',
            tile: { title: 'Saved', subtitle: 'Your saved searches and commands', icon: 'bookmark' },
            test:  function (v) { return v.charAt(0) === '*' || /^saved:/i.test(v); },
            strip: function (v) { return v.replace(/^(\*|saved:)/i, '').trim(); }
        },
        recent: {
            prefix: '<',
            label: 'RECENT',
            placeholder: 'Filter recent searches...',
            tile: { title: 'Recent', subtitle: 'Your recent searches', icon: 'clock' },
            test:  function (v) { return v.charAt(0) === '<' || /^recent:/i.test(v); },
            strip: function (v) { return v.replace(/^(<|recent:)/i, '').trim(); }
        },
        sealed: {
            prefix: '$',
            label: 'SEALED',
            placeholder: 'Search sealed products...',
            tile: { title: 'Sealed', subtitle: 'Search sealed products and open contents', icon: 'package' },
            builder: buildSealedItems,
            skipCap: true,
            test:  function (v) { return v.charAt(0) === '$'; },
            strip: function (v) { return v.substring(1).trim(); }
        },
        upload: {
            prefix: '+',
            label: 'UPLOAD',
            placeholder: 'Paste a Sheets, Moxfield, or TCG URL, or pick a file...',
            tile: { title: 'Upload', subtitle: 'Send a URL, file, or page results', icon: 'upload' },
            builder: buildUploadItems,
            skipCap: true,
            requiresNav: 'Upload',
            test:  function (v) {
                if (!NAV_NAMES['Upload']) return false;
                if (v.charAt(0) !== '+')   return false;
                // Only treat `+` as upload-mode if it's bare, followed by a space, or starts a URL.
                // Preserves common card/search-prefix queries like "+1 counter", "+aurora" so they
                // still flow through the default search path for tier-permitted users.
                if (v.length === 1)        return true;
                if (v.charAt(1) === ' ')   return true;
                if (/^\+https?:\/\//.test(v)) return true;
                return false;
            },
            strip: function (v) { return v.substring(1).trim(); }
        }
    };

    // Returns one of:
    //   { kind: 'provider', prefix, provider, query }
    //   { kind: 'subview',  parentChip, targets, query }
    //   { kind: 'mode',     mode, query }
    //   { kind: 'search',   query }
    function resolveContext(raw) {
        // 1. Provider prefix takes precedence over everything else.
        if (providers && chips) {
            var d = providers.detectPrefix(raw);
            if (d) {
                var p = providers.getProvider(d.prefix);
                if (p) return { kind: 'provider', prefix: d.prefix, provider: p, query: d.query };
            }
        }
        // 2. Parent nav chip locked → sub-view mode.
        if (chips) {
            var list = chips.all();
            for (var i = list.length - 1; i >= 0; i--) {
                if (list[i].type === 'nav' && isParentNav(list[i].navName)) {
                    var t = getNavTargets(list[i].navName);
                    if (t) return { kind: 'subview', parentChip: list[i], targets: t, query: raw.trim() };
                    break;
                }
            }
        }
        // 2b. Sealed chip locked → sealed-actions menu.
        if (chips) {
            var sealedList = chips.all();
            for (var si = sealedList.length - 1; si >= 0; si--) {
                if (sealedList[si].type === 'sealed') {
                    return { kind: 'sealed-actions', sealedChip: sealedList[si], query: raw.trim() };
                }
            }
        }
        // 3. Mode prefix in input.
        var modeKeys = Object.keys(MODES);
        for (var m = 0; m < modeKeys.length; m++) {
            var mk = modeKeys[m];
            if (MODES[mk].test(raw)) {
                return { kind: 'mode', mode: mk, query: MODES[mk].strip(raw) };
            }
        }
        // 4. Default search.
        return { kind: 'search', query: raw.trim() };
    }

    function applyPlaceholder(ctx) {
        if (ctx.kind === 'provider') {
            input.placeholder = 'Filter ' + (ctx.provider.name || 'options').toLowerCase() + '...';
            return;
        }
        if (ctx.kind === 'subview') {
            input.placeholder = 'Filter ' + ctx.parentChip.navName + ' sub-views...';
            return;
        }
        if (ctx.kind === 'mode') {
            input.placeholder = (MODES[ctx.mode] && MODES[ctx.mode].placeholder) || '';
            return;
        }
        if (ctx.kind === 'sealed-actions') {
            input.placeholder = 'Pick an action below or press Backspace to change product...';
            return;
        }
        if (chips && chips.count() > 0) {
            input.placeholder = 'Add filters or press Enter to search...';
            return;
        }
        input.placeholder = DEFAULT_PLACEHOLDER;
    }

    function applyModeIndicator(ctx) {
        var label = '';
        if (ctx.kind === 'mode') {
            label = (MODES[ctx.mode] && MODES[ctx.mode].label) || '';
        }
        if (label) {
            modeTag.textContent = label;
            modeTag.setAttribute('data-mode', ctx.mode);
            modeTag.className = 'cp-mode-indicator active';
        } else {
            modeTag.textContent = '';
            modeTag.className = 'cp-mode-indicator';
            modeTag.removeAttribute('data-mode');
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  Result builders (per data source)
    // ════════════════════════════════════════════════════════════════

    function getRecentResults(query, limit) {
        var recent = getJSON(RECENT_KEY);
        var out = [];
        for (var i = 0; i < recent.length && out.length < limit; i++) {
            var r = recent[i];
            if (!query || scoreMatch(query, r.q, null) > 0) {
                out.push({
                    type: 'recent', title: r.q, subtitle: 'Recent search', icon: 'clock',
                    recentQuery: r.q,
                    action: (function (q) { return function () {
                        recordRecentSearch(q);
                        window.location.href = '/search?q=' + encodeURIComponent(q);
                    }; })(r.q)
                });
            }
        }
        return out;
    }

    function getNavResults(query) {
        var nav = palette.nav || [];
        var out = [];
        for (var i = 0; i < nav.length; i++) {
            var n = nav[i];
            if (!query || scoreMatch(query, n.name, null) > 0) {
                out.push({
                    type: 'nav', title: n.name, subtitle: 'Navigate to ' + n.name,
                    icon: n.icon || 'compass',
                    navName: n.name, navLink: n.link,
                    action: (function (link) { return function () { window.location.href = link; }; })(n.link),
                    score: query ? scoreMatch(query, n.name, null) : 0
                });
            }
        }
        if (query) out.sort(function (a, b) { return b.score - a.score; });
        return out;
    }

    function getStaticCommands(query) {
        var cmds = [
            {
                name: 'Toggle Theme',
                icon: (function () {
                    var p = localStorage.getItem('theme');
                    return p === 'dark' ? 'moon' : (p === 'light' ? 'sun' : 'sun-moon');
                })(),
                keywords: ['dark', 'light', 'night', 'day', 'theme', 'mode', 'system', 'auto'],
                action: function () {
                    var next;
                    if (window.BANTheme) {
                        next = window.BANTheme.cycle();
                    } else {
                        // Fallback: two-state toggle if nightmode.js isn't present.
                        next = localStorage.getItem('theme') === 'dark' ? 'light' : 'dark';
                        document.body.classList.toggle('dark-theme',  next === 'dark');
                        document.body.classList.toggle('light-theme', next === 'light');
                        localStorage.setItem('theme', next);
                    }
                    closePalette();
                    showToast('Theme: ' + next);
                }
            },
            { name: 'Random Card',   icon: 'dice-5',     keywords: ['random', 'surprise', 'lucky'],
              action: function () { window.location.href = '/random'; } },
            { name: 'Random Sealed', icon: 'package',    keywords: ['random', 'sealed', 'booster', 'pack'],
              action: function () { window.location.href = '/randomsealed'; } },
            { name: 'Open Guide',    icon: 'book-open',  keywords: ['guide', 'help', 'documentation', 'syntax'],
              action: function () { window.location.href = '/guide'; } },
            { name: 'Copy Page URL', icon: 'link',       keywords: ['copy', 'url', 'link', 'share', 'clipboard'],
              action: function () {
                  if (navigator.clipboard) {
                      navigator.clipboard.writeText(window.location.href)
                          .then(function () { showToast('URL copied to clipboard'); });
                  } else {
                      showToast('Clipboard not available');
                  }
                  closePalette();
              } }
        ];

        // Conditionally add "Save Current Search".
        var hasComposed   = chips && chips.count() > 0 && chips.composedQuery();
        if (hasComposed || currentPageQuery()) {
            cmds.push({
                name: 'Save Current Search', icon: 'bookmark-plus',
                keywords: ['save', 'bookmark', 'store', 'command'],
                action: function () { showSaveModal(); }
            });
        }

        var out = [];
        for (var i = 0; i < cmds.length; i++) {
            var c = cmds[i];
            if (!query || scoreMatch(query, c.name, c.keywords) > 0) {
                out.push({
                    type: 'command', title: c.name, subtitle: '', icon: c.icon, action: c.action,
                    score: query ? scoreMatch(query, c.name, c.keywords) : 0
                });
            }
        }
        if (query) out.sort(function (a, b) { return b.score - a.score; });
        return out;
    }

    function getCardResults(query, limit) {
        if (!S.cardNames || !query || query.length < 2) return [];
        var out = [];
        for (var i = 0; i < S.cardNames.length && out.length < limit; i++) {
            if (matchCardName(query, S.cardNames[i])) {
                var name = S.cardNames[i];
                out.push({
                    type: 'card', title: name, subtitle: 'Search for "' + name + '"',
                    icon: 'search', cardName: name,
                    action: (function (n) { return function () {
                        recordRecentSearch(n);
                        window.location.href = '/search?q=' + encodeURIComponent(n);
                    }; })(name)
                });
            }
        }
        return out;
    }

    function getHelpResults(query) {
        var sections = guide.sections || [];
        var out = [];
        for (var i = 0; i < sections.length && out.length < 10; i++) {
            var s = sections[i];
            if (!isSectionAllowed(s)) continue;

            var match = !query || scoreMatch(query, s.title, s.keywords) > 0;
            if (!match && s.summary) match = scoreMatch(query, s.summary, null) > 0;
            if (!match && s.snippets) {
                for (var j = 0; j < s.snippets.length; j++) {
                    if (s.snippets[j].toLowerCase().indexOf(query.toLowerCase()) >= 0) {
                        match = true; break;
                    }
                }
            }
            if (!match) continue;

            var isSyntax = s.category === 'Search Syntax';
            var snippetText = (isSyntax && s.snippets && s.snippets.length > 0)
                ? s.snippets.join('  ') : '';

            out.push({
                type: 'help',
                title: s.title,
                subtitle: s.summary || '',
                snippets: snippetText,
                icon: s.icon || 'help-circle',
                isSyntax: isSyntax,
                sectionId: s.id,
                action: isSyntax
                    ? (function (snip) { return function () {
                          if (navigator.clipboard && snip) {
                              navigator.clipboard.writeText(snip)
                                  .then(function () { showToast('Copied: ' + snip); });
                          }
                          closePalette();
                      }; })(s.snippets && s.snippets[0] ? s.snippets[0] : '')
                    : (function (id) { return function () { window.location.href = '/guide#' + id; }; })(s.id),
                altAction: isSyntax
                    ? (function (id) { return function () { window.location.href = '/guide#' + id; }; })(s.id)
                    : null,
                score: query ? scoreMatch(query, s.title, s.keywords) : 0
            });
        }
        if (query) out.sort(function (a, b) { return b.score - a.score; });
        return out;
    }

    function getSavedResults(query) {
        var saved = getJSON(SAVED_KEY);
        var out = [];
        for (var i = 0; i < saved.length; i++) {
            var s = saved[i];
            if (query && scoreMatch(query, s.name, s.query) === 0) continue;

            out.push({
                type: 'saved', title: s.name, subtitle: s.query,
                icon: s.icon || 'bookmark', savedId: s.id,
                action: (function (cmd) { return function () {
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
                    var navUrl = chipsNavURL(cmd.chips);
                    if (navUrl) { window.location.href = navUrl; return; }
                    recordRecentSearch(cmd.query);
                    window.location.href = '/search?q=' + encodeURIComponent(cmd.query);
                }; })(s),
                altAction: (function (cmd) { return function () {
                    // Shift+Enter: restore chips into the palette input for editing.
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
                        // Prefetch meta for restored chips so dependent narrowing/gating works.
                        for (var cj = 0; cj < cmd.chips.length; cj++) {
                            if (cmd.chips[cj].type === 'card' && cmd.chips[cj]._cardName) {
                                fetchCardMeta(cmd.chips[cj]._cardName);
                            } else if (cmd.chips[cj].type === 'sealed' && cmd.chips[cj]._sealedName) {
                                fetchSealedMeta(cmd.chips[cj]._sealedName);
                            }
                        }
                    } else if (cmd.query) {
                        // V1 saved command (no chips field) - restore as plain input text.
                        input.value = cmd.query;
                    }
                    input.focus();
                    handleInput();
                }; })(s)
            });
        }
        return out;
    }

    // ════════════════════════════════════════════════════════════════
    //  Item-list builders (per ctx kind)
    // ════════════════════════════════════════════════════════════════

    function buildProviderItem(prefix, provider, candidate) {
        var item = {
            type: 'filter-candidate',
            title:    candidate.label,
            subtitle: candidate.sublabel || '',
            icon:     candidate.icon || provider.icon,
            disabled: !!candidate.disabled,
            _providerPrefix:    prefix,
            _providerCandidate: candidate
        };
        if (candidate.keyrune) {
            var kr = String(candidate.keyrune).toLowerCase().replace(/[^a-z0-9]/g, '');
            item.iconHtml = '<i class="ss ss-' + kr + '"></i>';
        }
        if (candidate.iconColor) item.iconStyle = 'color: ' + candidate.iconColor;
        return item;
    }

    function buildProviderItems(ctx) {
        var prefix = ctx.prefix, provider = ctx.provider;
        var ctxArg = { chips: chips ? chips.all() : [], cardMeta: activeCardMeta() };
        var candidates = (provider.getCandidates(ctx.query, ctxArg) || []).slice(0, DROPDOWN_CAP);

        // Group by candidate.group, falling back to a single "<provider name>" bucket.
        var grouped = {}, order = [], ungrouped = [];
        for (var i = 0; i < candidates.length; i++) {
            var c = candidates[i];
            if (c.group) {
                if (!grouped[c.group]) { grouped[c.group] = []; order.push(c.group); }
                grouped[c.group].push(c);
            } else {
                ungrouped.push(c);
            }
        }

        var items = [];
        if (order.length === 0) {
            items.push({ type: 'header', title: provider.name });
            for (var j = 0; j < ungrouped.length; j++) {
                items.push(buildProviderItem(prefix, provider, ungrouped[j]));
            }
        } else {
            for (var g = 0; g < order.length; g++) {
                items.push({ type: 'header', title: provider.name + ' \u00b7 ' + order[g] });
                var list = grouped[order[g]];
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
        return items;
    }

    function buildSubViewItem(parentChip, entry) {
        return {
            type: 'nav-sub',
            title:    entry.label,
            subtitle: entry.group || '',
            icon: 'arrow-right',
            _subView:    entry,
            _parentChip: parentChip
        };
    }

    function buildSubViewItems(ctx) {
        var parentChip = ctx.parentChip, targets = ctx.targets, q = ctx.query;
        var items = [];

        function pushEntries(entries, headerLabel) {
            if (!entries || entries.length === 0) return;
            var filtered = providers ? providers.filterEntries(entries, q) : entries;
            if (filtered.length === 0) return;
            if (headerLabel) items.push({ type: 'header', title: headerLabel });
            for (var i = 0; i < filtered.length; i++) items.push(buildSubViewItem(parentChip, filtered[i]));
        }

        if (Array.isArray(targets)) {
            // Newspaper / Sleepers shape: flat array, optionally grouped by .group
            var byGroup = {}, orderedGroups = [], hadAnyGroup = false;
            for (var i = 0; i < targets.length; i++) {
                var g = targets[i].group || 'Views';
                if (targets[i].group) hadAnyGroup = true;
                if (!byGroup[g]) { byGroup[g] = []; orderedGroups.push(g); }
                byGroup[g].push(targets[i]);
            }
            if (hadAnyGroup) {
                for (var gi = 0; gi < orderedGroups.length; gi++) {
                    pushEntries(byGroup[orderedGroups[gi]], parentChip.navName + ' \u00b7 ' + orderedGroups[gi]);
                }
            } else {
                pushEntries(targets, parentChip.navName + ' Views');
            }
        } else {
            // Arbit/Reverse/Global shape: { filters: [...], sorts: [...] }
            pushEntries(targets.sorts,   parentChip.navName + ' \u00b7 Sort');
            pushEntries(targets.filters, parentChip.navName + ' \u00b7 Filters');
        }

        if (items.length === 0) {
            items.push({ type: 'header', title: parentChip.navName + ' - no matching sub-views' });
        }
        return items;
    }

    function buildModeItems(ctx) {
        var headerTitle = ({
            help:   'Help',
            nav:    'Pages',
            saved:  'Saved Commands',
            recent: 'Recent Searches'
        })[ctx.mode];
        var fetcher = ({
            help:   getHelpResults,
            nav:    getNavResults,
            saved:  getSavedResults,
            recent: function (q) { return getRecentResults(q, 50); }
        })[ctx.mode];
        var list = fetcher(ctx.query);
        return list.length ? [{ type: 'header', title: headerTitle }].concat(list) : [];
    }

    function buildSealedItems(ctx) {
        var query = ctx.query;
        if (!S.sealedNames) {
            ensureSealedNames();
            return [{ type: 'header', title: 'Sealed - loading...' }];
        }
        var matches = [];
        for (var i = 0; i < S.sealedNames.length && matches.length < DROPDOWN_CAP; i++) {
            if (!query || matchCardName(query, S.sealedNames[i])) {
                matches.push({
                    type:       'sealed-suggestion',
                    title:      S.sealedNames[i],
                    subtitle:   'Sealed product',
                    icon:       'package',
                    sealedName: S.sealedNames[i]
                });
            }
        }
        if (matches.length === 0 && query) {
            return [
                { type: 'header', title: 'Sealed' },
                { type: 'sealed-fallback', title: 'Search sealed for "' + query + '"',
                  icon: 'search', sealedQuery: query }
            ];
        }
        return [{ type: 'header', title: 'Sealed' }].concat(matches);
    }

    function buildUploadItems(ctx) {
        var query = ctx.query.trim();
        var rows  = [{ type: 'header', title: 'Upload' }];

        if (query) {
            var parsed = parseUploadURL(query);
            if (parsed) {
                rows.push({
                    type: 'upload-url', title: 'Upload from ' + parsed.label,
                    subtitle: query, icon: 'link', uploadURL: query
                });
            } else {
                rows.push({
                    type: 'upload-error', title: 'Unsupported URL',
                    subtitle: 'Allowed: TCGplayer collection, Moxfield deck, Google Sheets',
                    icon: 'alert-circle', disabled: true
                });
            }
        } else {
            rows.push({
                type: 'upload-hint', title: 'Type or paste a URL',
                subtitle: 'TCGplayer collection, Moxfield deck, or Google Sheets',
                icon: 'link', disabled: true
            });
        }

        rows.push({
            type: 'upload-file', title: 'Browse for file...',
            subtitle: 'CSV, XLS, or XLSX', icon: 'file-up'
        });

        var hashCount = countDataHashRows();
        if (hashCount > 0 && window.location.pathname !== '/upload') {
            rows.push({
                type: 'upload-page-results',
                title: 'Send ' + hashCount + ' result' + (hashCount === 1 ? '' : 's') + ' to Uploader',
                subtitle: 'Posts the hashes from the current page',
                icon: 'send'
            });
        }

        // On /upload results page: surface the same export buttons the page renders.
        // Results page exposes window.submitExport(field, newWindow); input page does not.
        if (window.location.pathname === '/upload' && typeof window.submitExport === 'function') {
            rows.push({ type: 'header', title: 'Export Results' });
            rows.push(
                { type: 'upload-export', title: 'Get CSV',              subtitle: 'All results as CSV',
                  icon: 'download',
                  exportField: 'download',       exportNewWindow: false },
                { type: 'upload-export', title: 'CardConduit Estimate', subtitle: 'Send to CardConduit (new tab)',
                  iconHtml: '<img src="/img/logo/cardconduit.svg" alt="">',
                  exportField: 'estimate',       exportNewWindow: true },
                { type: 'upload-export', title: 'Deckbox CSV',          subtitle: 'Deckbox-format CSV',
                  iconHtml: '<img src="/img/logo/deckbox.webp" alt="">',
                  exportField: 'deckbox',        exportNewWindow: false },
                { type: 'upload-export', title: 'TCGplayer CSV',        subtitle: 'TCGplayer-format CSV',
                  iconHtml: '<img src="/img/logo/tcgapp.png" alt="">',
                  exportField: 'tcgplayer_csv',  exportNewWindow: false }
            );
        }

        return rows;
    }

    function buildSealedActionItems(ctx) {
        var name = ctx.sealedChip._sealedName;
        var meta = S.sealedMetaCache[name];

        // View Contents is always shown; backend hasContents (GetDecklist) is too strict.
        var rows = [
            { type: 'sealed-action', title: 'Search', subtitle: 'Price grid for this product',
              icon: 'search', actionKey: 'search', actionLabel: 'Search', sealedName: name },
            { type: 'sealed-action', title: 'View Contents', subtitle: 'Cards inside this product',
              icon: 'list', actionKey: 'contents', actionLabel: 'View Contents', sealedName: name }
        ];
        if (!meta || meta.hasPicks) {
            rows.push({
                type: 'sealed-action', title: 'Pack Pull', subtitle: 'Simulate opening this product',
                icon: 'shuffle', actionKey: 'unpack', actionLabel: 'Pack Pull', sealedName: name
            });
        }
        return [{ type: 'header', title: 'Actions: ' + name }].concat(rows);
    }

    function buildSearchItems(query) {
        var items = [];

        // Always offer the direct-search row (supports inline syntax like s:3ED).
        var composed = chips ? chips.composedQuery() : query;
        if (composed) {
            items.push({
                type: 'search',
                title: 'Search: ' + composed,
                subtitle: 'Run full search with syntax support',
                icon: 'search',
                action: function () {
                    var q = chips ? chips.composedQuery() : composed;
                    recordRecentSearch(q);
                    window.location.href = '/search?q=' + encodeURIComponent(q);
                }
            });
        }

        var cmds  = getStaticCommands(query);
        var cards = getCardResults(query, DROPDOWN_CAP);
        var navs  = getNavResults(query);

        // Recent and Saved live behind their own gated panels (< and *).
        if (cmds.length)  items.push({ type: 'header', title: 'Commands' }, cmds[0],  cmds[1]  || null, cmds[2]  || null);
        if (cards.length) items.push({ type: 'header', title: 'Cards' });
        for (var i = 0; i < cards.length; i++) items.push(cards[i]);
        if (navs.length)  items.push({ type: 'header', title: 'Pages' }, navs[0], navs[1] || null, navs[2] || null);

        // Drop the trailing nulls produced above.
        return items.filter(Boolean);
    }

    // Enforces the global per-search row cap (excluding headers), preserving headers
    // only for groups that still have at least one surviving item beneath them.
    function capItems(items, cap) {
        var nonHeaders = [], headers = [];
        for (var i = 0; i < items.length; i++) {
            if (items[i].type === 'header') {
                headers.push({ item: items[i], nextIndex: nonHeaders.length });
            } else {
                nonHeaders.push(items[i]);
            }
        }
        if (nonHeaders.length > cap) nonHeaders = nonHeaders.slice(0, cap);

        var out = [], hi = 0;
        for (var y = 0; y < nonHeaders.length; y++) {
            while (hi < headers.length && headers[hi].nextIndex <= y) {
                out.push(headers[hi].item);
                hi++;
            }
            out.push(nonHeaders[y]);
        }
        return out;
    }

    // ════════════════════════════════════════════════════════════════
    //  Row-type registry
    //
    //  Each entry may define:
    //    render(item, idx, active) → HTML  (selectable rows)
    //    render(item)              → HTML  (headers; selectable: false)
    //    footer(item)              → { action, tab? }
    //    onEnter(item)             → void
    //    onShiftEnter(item)        → void  (optional)
    //    onTab(item)               → bool  (true = chip locked, clear input)
    //    onShiftDelete(item)       → void  (optional)
    // ════════════════════════════════════════════════════════════════

    // Generic row HTML used by most types. `rightHtml` is whatever sits on the
    // right side of the row (kbd hint, delete button, etc.) — pass '' for none.
    function rowHTML(item, idx, active, rightHtml) {
        var cls = 'cp-result' + (active ? ' active' : '') + (item.disabled ? ' disabled' : '');
        var aria = item.disabled ? ' aria-disabled="true"' : '';
        var iconBlock;
        if (item.iconHtml) {
            iconBlock = '<div class="cp-result-icon">' + item.iconHtml + '</div>';
        } else {
            var styleAttr = item.iconStyle ? ' style="' + esc(item.iconStyle) + '"' : '';
            iconBlock = '<div class="cp-result-icon"' + styleAttr + '>'
                      + '<i data-lucide="' + esc(item.icon || 'search') + '"></i></div>';
        }
        var body;
        if (item.snippets) {
            body = '<div class="cp-result-title">'  + esc(item.title) + '</div>'
                 + '<div class="cp-result-inline">' + esc(item.snippets) + '</div>';
        } else if (item.subtitle) {
            body = '<div class="cp-result-title">'    + esc(item.title)    + '</div>'
                 + '<div class="cp-result-subtitle">' + esc(item.subtitle) + '</div>';
        } else {
            body = '<div class="cp-result-title">'    + esc(item.title) + '</div>';
        }
        return '<div class="' + cls + '" role="option" data-index="' + idx + '"' + aria + '>'
             + iconBlock
             + '<div class="cp-result-body">' + body + '</div>'
             + '<div class="cp-result-right">' + (rightHtml || '') + '</div>'
             + '</div>';
    }

    var ROW_TYPES = {
        header: {
            selectable: false,
            render: function (item) {
                var key = categoryKeyFor(item.title);
                var ic  = categoryIconFor(item.title);
                return '<div class="cp-category-header" data-category="' + esc(key) + '">'
                     + (ic ? '<i data-lucide="' + ic + '"></i>' : '')
                     + '<span>' + esc(item.title) + '</span></div>';
            }
        },

        shortcut: {
            render: function (item, idx, active) {
                var right = '<kbd class="cp-shortcut">' + esc(item.shortcut) + '</kbd>';
                // Shortcuts row gets an extra utility class.
                return rowHTML(item, idx, active, right)
                    .replace('cp-result', 'cp-result cp-shortcut-row');
            },
            footer:  function () { return { action: 'Open' }; },
            onEnter: function (item) { item.action(); }
        },

        nav: {
            render: function (item, idx, active) {
                var right = isParentNav(item.navName)
                    ? '<kbd class="cp-shortcut cp-tab-hint">Tab</kbd>' : '';
                return rowHTML(item, idx, active, right);
            },
            footer: function (item) {
                return isParentNav(item.navName)
                    ? { action: 'Go to page', tab: 'Browse subpages' }
                    : { action: 'Go to page' };
            },
            onEnter: function (item) { window.location.href = item.navLink; },
            onTab: function (item) {
                if (!isParentNav(item.navName)) {
                    // Leaf nav: Tab behaves identically to Enter (avoids the leaky-NAV
                    // bug where a locked leaf chip would drop into general search).
                    window.location.href = item.navLink;
                    return false;
                }
                lockParentNavChip(item);
                return true;
            }
        },

        'nav-sub': {
            render: rowHTML,
            footer: function (item) {
                var pKey = item._parentChip && NAV_PARENTS[item._parentChip.navName];
                var isSingleton = pKey === 'newspaper' || pKey === 'sleepers';
                var isSort      = pKey && isArbitSortValue(pKey, item._subView.value);
                return (pKey && !isSingleton && !isSort)
                    ? { action: 'Open', tab: 'Add filter' }
                    : { action: 'Open' };
            },
            onEnter: function (item) {
                window.location.href = composeSubViewURL(item._parentChip, item._subView);
            },
            onTab: function (item) {
                lockSubViewChip(item);
                return true;
            }
        },

        card: {
            render:  rowHTML,
            footer:  function () { return { action: 'Search', tab: 'Add card chip' }; },
            onEnter: function (item) {
                recordRecentSearch(item.cardName);
                window.location.href = '/search?q=' + encodeURIComponent(item.cardName);
            },
            onTab: function (item) { lockCardChip(item); return true; }
        },

        'filter-candidate': {
            render:  rowHTML,
            footer:  function () { return { action: 'Search', tab: 'Lock filter' }; },
            onEnter: function (item) {
                if (item.disabled) return;
                lockFilterChip(item);
                input.value = '';
                runComposedQuery();
            },
            onTab:   function (item) {
                if (item.disabled) return false;
                lockFilterChip(item);
                return true;
            }
        },

        recent: {
            render:        rowHTML,
            footer:        function () { return { action: 'Run' }; },
            onEnter:       function (item) { item.action(); },
            onShiftDelete: function (item) {
                deleteRecentSearch(item.recentQuery);
                handleInput();
            }
        },

        saved: {
            render: function (item, idx, active) {
                var right = '<button class="cp-result-delete" data-saved-id="' + esc(item.savedId)
                          + '" title="Delete"><i data-lucide="trash-2"></i></button>';
                return rowHTML(item, idx, active, right);
            },
            footer:        function () { return { action: 'Run', tab: '<kbd>Shift+Enter</kbd> Restore chips' }; },
            onEnter:       function (item) { item.action(); },
            onShiftEnter:  function (item) { if (item.altAction) item.altAction(); },
            onShiftDelete: function (item) {
                deleteSavedCommandSilent(item.savedId);
                handleInput();
            }
        },

        help: {
            render: rowHTML,
            footer: function (item) {
                return item.isSyntax
                    ? { action: 'Copy snippet', tab: '<kbd>Shift+Enter</kbd> Open guide' }
                    : { action: 'Open guide' };
            },
            onEnter:      function (item) { item.action(); },
            onShiftEnter: function (item) { if (item.altAction) item.altAction(); }
        },

        command: {
            render:  rowHTML,
            footer:  function () { return { action: 'Run' }; },
            onEnter: function (item) { item.action(); }
        },

        search: {
            render:  rowHTML,
            footer:  function () { return { action: 'Search' }; },
            onEnter: function (item) { item.action(); }
        },

        'sealed-suggestion': {
            render:       rowHTML,
            footer:       function () {
                return {
                    action: 'Search',
                    tab: '<span class="cp-pair"><kbd>Shift+Enter</kbd> Contents</span>'
                       + '<span class="cp-pair"><kbd>Ctrl+Enter</kbd> Pack Pull</span>'
                       + '<span class="cp-pair"><kbd>Tab</kbd> Lock</span>'
                };
            },
            onEnter:      function (item) { sealedAction('search',   item.sealedName); },
            onShiftEnter: function (item) { sealedAction('contents', item.sealedName); },
            onCtrlEnter:  function (item) { sealedAction('unpack',   item.sealedName); },
            onTab:        function (item) { lockSealedChip(item); return true; }
        },

        'sealed-fallback': {
            render:  rowHTML,
            footer:  function () { return { action: 'Search' }; },
            onEnter: function (item) { sealedAction('search', item.sealedQuery); }
        },

        'sealed-action': {
            render:       rowHTML,
            footer:       function (item) { return { action: item.actionLabel }; },
            onEnter:      function (item) { sealedAction(item.actionKey, item.sealedName); },
            onShiftEnter: function (item) { sealedAction('contents',     item.sealedName); },
            onCtrlEnter:  function (item) { sealedAction('unpack',       item.sealedName); }
        },

        'upload-url': {
            render:  rowHTML,
            footer:  function () { return { action: 'Submit URL' }; },
            onEnter: function (item) { submitUploadURL(item.uploadURL); }
        },

        'upload-file': {
            render:  rowHTML,
            footer:  function () { return { action: 'Pick file' }; },
            onEnter: function (_item) { triggerUploadFilePicker(); }
        },

        'upload-page-results': {
            render:  rowHTML,
            footer:  function () { return { action: 'Send results' }; },
            onEnter: function (_item) { submitUploadPageResults(); }
        },

        'upload-error': {
            render:  rowHTML,
            footer:  function () { return { action: '' }; },
            onEnter: function () { /* no-op */ }
        },

        'upload-hint': {
            render:  rowHTML,
            footer:  function () { return { action: '' }; },
            onEnter: function () { /* no-op */ }
        },

        'upload-export': {
            render:  rowHTML,
            footer:  function (item) { return { action: item.title }; },
            onEnter: function (item) {
                if (typeof window.submitExport !== 'function') return;
                closePalette();
                window.submitExport(item.exportField, item.exportNewWindow);
            }
        }
    };

    // ════════════════════════════════════════════════════════════════
    //  Render loop
    // ════════════════════════════════════════════════════════════════

    function renderDefault() {
        var tiles = [{ type: 'header', title: 'Shortcuts' }];
        var keys = Object.keys(MODES);
        for (var i = 0; i < keys.length; i++) {
            var key = keys[i];
            var def = MODES[key];
            if (def.requiresNav && !NAV_NAMES[def.requiresNav]) continue;
            tiles.push({
                type:     'shortcut',
                title:    def.tile.title,
                subtitle: def.tile.subtitle,
                icon:     def.tile.icon,
                shortcut: def.prefix,
                action:   (function (p) { return function () { input.value = p; handleInput(); }; })(def.prefix)
            });
        }
        renderResults(tiles);
    }

    function renderResults(items) {
        S.items = [];
        S.activeIndex = -1;
        var html = '';
        var idx  = 0;
        var firstSelectableIdx = -1;

        for (var i = 0; i < items.length; i++) {
            var item = items[i];
            var def  = ROW_TYPES[item.type];
            if (!def) continue;

            if (def.selectable === false) {
                html += def.render(item);
                continue;
            }
            var active = idx === 0;
            html += def.render(item, idx, active);
            S.items.push(item);
            if (firstSelectableIdx === -1) firstSelectableIdx = idx;
            idx++;
        }

        resultsEl.innerHTML = html;

        // Auto-select first row UNLESS chips are locked and input is empty
        // (in that case Enter should run the chip composition, not the default item).
        var skipAutoSelect = chips && chips.count() > 0 && input.value.trim() === '';
        if (idx > 0 && !skipAutoSelect) {
            S.activeIndex = 0;
        } else {
            S.activeIndex = -1;
            // Strip any lingering active class.
            var actives = resultsEl.querySelectorAll('.cp-result.active');
            for (var ai = 0; ai < actives.length; ai++) actives[ai].classList.remove('active');
        }

        updateDeleteHint();
        updateFooterHints();

        if (typeof lucide !== 'undefined' && lucide.createIcons) {
            lucide.createIcons({ nodes: resultsEl.querySelectorAll('[data-lucide]') });
        }

        // Bind click handlers (and the inline saved-row delete button).
        var rows = resultsEl.querySelectorAll('.cp-result');
        for (var r = 0; r < rows.length; r++) {
            (function (rowIdx) {
                rows[rowIdx].addEventListener('click', function (e) {
                    var del = e.target.closest('.cp-result-delete');
                    if (del) {
                        e.stopPropagation();
                        deleteSavedCommand(del.getAttribute('data-saved-id'));
                        return;
                    }
                    var it = S.items[rowIdx];
                    if (!it || it.disabled) return;
                    S.activeIndex = rowIdx;
                    executeActive(false);
                });
            })(r);
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  Active-row navigation + footer/hint updates
    // ════════════════════════════════════════════════════════════════

    function setActive(index) {
        var els = resultsEl.querySelectorAll('.cp-result');
        for (var i = 0; i < els.length; i++) els[i].classList.remove('active');
        if (index >= 0 && index < els.length) {
            els[index].classList.add('active');
            els[index].scrollIntoView({ block: 'nearest' });
        }
        S.activeIndex = index;
        // Mark explicit user selection so the chips-locked Enter fallback knows
        // to execute the row instead of running the chip composition.
        if (index >= 0 && index < S.items.length && S.items[index]) {
            S.items[index]._userPicked = true;
        }
        updateDeleteHint();
        updateFooterHints();
    }

    function moveActive(delta) {
        if (S.items.length === 0) return;
        var next = (S.activeIndex < 0)
            ? (delta > 0 ? 0 : S.items.length - 1)
            : (S.activeIndex + delta);
        if (next >= S.items.length) next = 0;
        if (next < 0) next = S.items.length - 1;
        setActive(next);
    }

    function executeActive(shiftKey) {
        if (S.activeIndex < 0 || S.activeIndex >= S.items.length) return;
        var item = S.items[S.activeIndex];
        if (!item || item.disabled) return;
        var def = ROW_TYPES[item.type];
        if (!def) return;
        if (shiftKey && def.onShiftEnter) def.onShiftEnter(item);
        else if (def.onEnter)             def.onEnter(item);
    }

    function updateDeleteHint() {
        var hint = DOM.footer && DOM.footer.querySelector('.cp-footer-hint-delete');
        if (!hint) return;
        var item = (S.activeIndex >= 0 && S.activeIndex < S.items.length) ? S.items[S.activeIndex] : null;
        var canDelete = item && (item.type === 'recent' || item.type === 'saved');
        hint.style.display = canDelete ? '' : 'none';
    }

    function updateFooterHints() {
        var actionEl = DOM.footer && DOM.footer.querySelector('.cp-footer-action');
        var tabEl    = DOM.footer && DOM.footer.querySelector('.cp-footer-tab');
        if (!actionEl || !tabEl) return;

        var item = (S.activeIndex >= 0 && S.activeIndex < S.items.length) ? S.items[S.activeIndex] : null;
        var def  = item && ROW_TYPES[item.type];
        var hints = (def && def.footer) ? def.footer(item) : null;

        if (!hints) {
            actionEl.innerHTML = '<kbd>Enter</kbd> Select';
            tabEl.style.display = 'none';
            tabEl.innerHTML = '';
            return;
        }
        actionEl.innerHTML = hints.action ? '<kbd>Enter</kbd> ' + hints.action : '';
        if (hints.tab) {
            // hints.tab can be a plain label or a full "<kbd>X</kbd> Label" string.
            tabEl.innerHTML = /<kbd>/i.test(hints.tab) ? hints.tab : '<kbd>Tab</kbd> ' + hints.tab;
            tabEl.style.display = '';
        } else {
            tabEl.style.display = 'none';
            tabEl.innerHTML = '';
        }
    }

    // ════════════════════════════════════════════════════════════════
    //  handleInput — the dispatcher
    // ════════════════════════════════════════════════════════════════

    // kinds whose results bypass the GLOBAL_ITEM_CAP. Provider has its own internal
    // cap (DROPDOWN_CAP=30); sub-views and sealed-actions menus self-cap. Per-mode
    // skipCap lives on each MODES entry alongside its other metadata.
    var KINDS_SKIP_CAP = { provider: true, subview: true, 'sealed-actions': true, search: true };

    function handleInput() {
        var raw = input.value;
        var ctx = resolveContext(raw);

        applyPlaceholder(ctx);
        applyModeIndicator(ctx);

        // Render the default Shortcuts view only for kinds that have nothing meaningful
        // to show on empty input (no chip-locked context, no provider prefix). New stateful
        // kinds (subview, sealed-actions, future ones) opt out by NOT being listed here -
        // their builders are expected to handle the empty-query case themselves.
        if (!raw.trim() && (ctx.kind === 'mode' || ctx.kind === 'search')) {
            renderDefault();
            return;
        }

        var items;
        switch (ctx.kind) {
            case 'provider':       items = buildProviderItems(ctx); break;
            case 'subview':        items = buildSubViewItems(ctx);  break;
            case 'mode':
                items = ((MODES[ctx.mode] && MODES[ctx.mode].builder) || buildModeItems)(ctx);
                break;
            case 'sealed-actions': items = buildSealedActionItems(ctx); break;
            default:               items = buildSearchItems(ctx.query);
        }
        // Provider results are already capped at DROPDOWN_CAP (30) inside buildProviderItems;
        // sub-view results have no internal cap by design (full filter/sort menu). Mode-
        // specific builders (sealed/upload) self-cap. Everything else gets GLOBAL_ITEM_CAP.
        var skipCap = KINDS_SKIP_CAP[ctx.kind]
                   || (ctx.kind === 'mode' && MODES[ctx.mode] && MODES[ctx.mode].skipCap);
        var capped = skipCap ? items : capItems(items, GLOBAL_ITEM_CAP);
        renderResults(capped);
    }

    input.addEventListener('input', function () {
        if (S.inputTimer) clearTimeout(S.inputTimer);
        S.inputTimer = setTimeout(handleInput, 80);
    });

    // ════════════════════════════════════════════════════════════════
    //  Save modal
    // ════════════════════════════════════════════════════════════════

    function showSaveModal() {
        removeSaveModal();

        var queryToSave;
        if (chips && chips.count() > 0) {
            queryToSave = chips.composedQuery();
        } else {
            queryToSave = currentPageQuery();
        }
        if (!queryToSave) { showToast('No search to save'); return; }

        var backdrop = document.createElement('div');
        backdrop.className = 'cp-save-modal-backdrop';
        backdrop.id = 'cp-save-modal-backdrop';

        var modal = document.createElement('div');
        modal.className = 'cp-save-modal';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'cp-save-modal-title');
        modal.innerHTML =
            '<div class="cp-save-modal-title" id="cp-save-modal-title"></div>' +
            '<div class="cp-save-modal-preview"></div>' +
            '<input class="cp-save-modal-input" id="cp-save-modal-input" type="text" autocomplete="off">' +
            '<div class="cp-save-modal-hint"></div>';
        backdrop.appendChild(modal);
        DOM.overlay.appendChild(backdrop);

        var titleEl   = modal.querySelector('.cp-save-modal-title');
        var previewEl = modal.querySelector('.cp-save-modal-preview');
        var saveInput = modal.querySelector('#cp-save-modal-input');
        var hintEl    = modal.querySelector('.cp-save-modal-hint');

        requestAnimationFrame(function () { backdrop.classList.add('open'); });
        S.saveModalOpen = true;

        var pendingConflict = null;

        function enterNamingState() {
            pendingConflict = null;
            titleEl.textContent  = 'Save search';
            previewEl.textContent = queryToSave;
            previewEl.title       = queryToSave;
            saveInput.value       = '';
            saveInput.placeholder = 'Enter a name...';
            saveInput.maxLength   = MAX_NAME;
            hintEl.innerHTML = '<span><kbd>Enter</kbd> Save</span><span><kbd>Esc</kbd> Cancel</span>';
        }

        function enterConflictState(name, existing) {
            pendingConflict = { name: name, query: queryToSave };
            titleEl.textContent   = 'Overwrite saved search?';
            previewEl.textContent = '"' + name + '" already exists with: ' + existing.query;
            previewEl.title       = existing.query;
            saveInput.value       = '';
            saveInput.placeholder = 'y / n';
            saveInput.maxLength   = 3;
            hintEl.innerHTML = '<span><kbd>Y</kbd> Overwrite</span><span><kbd>Esc</kbd> Cancel</span>';
        }

        enterNamingState();
        saveInput.focus();

        saveInput.addEventListener('keydown', function (e) {
            // Stop propagation so the palette's document-level handlers do not
            // react to typing inside the modal.
            e.stopPropagation();

            if (e.key === 'Enter' || e.keyCode === 13) {
                e.preventDefault();
                if (pendingConflict) {
                    var ans = saveInput.value.trim().toLowerCase();
                    if (ans === 'y' || ans === 'yes') {
                        saveCommand(pendingConflict.name, pendingConflict.query, true);
                        removeSaveModal(); input.focus();
                    } else {
                        enterNamingState();
                    }
                    return;
                }
                var name = saveInput.value.trim();
                if (!name) { showToast('Please enter a name'); return; }
                var conflict = saveCommand(name, queryToSave, false);
                if (conflict) {
                    enterConflictState(name, conflict.existing);
                } else {
                    removeSaveModal(); input.focus();
                }
            } else if (e.key === 'Escape' || e.keyCode === 27) {
                e.preventDefault();
                removeSaveModal(); input.focus();
            } else if (e.key === 'Tab' || e.keyCode === 9) {
                e.preventDefault();
            }
        });

        // Click outside the modal card closes the modal.
        backdrop.addEventListener('click', function (e) {
            if (e.target === backdrop) { removeSaveModal(); input.focus(); }
        });
    }

    function removeSaveModal() {
        S.saveModalOpen = false;
        var bd = document.getElementById('cp-save-modal-backdrop');
        if (bd && bd.parentNode) bd.parentNode.removeChild(bd);
    }

    // Returns null on success, or { existing } if the user must confirm overwrite.
    function saveCommand(name, query, forceOverwrite) {
        var saved = getJSON(SAVED_KEY);

        var chipsSnapshot = [];
        if (chips && typeof chips.all === 'function') {
            var current = chips.all();
            for (var ci = 0; ci < current.length; ci++) {
                var c = current[ci];
                chipsSnapshot.push({
                    type: c.type, prefix: c.prefix, value: c.value, label: c.label, icon: c.icon,
                    navName: c.navName, navLink: c.navLink,
                    _cardName: c._cardName, _sealedName: c._sealedName,
                    _parentKey: c._parentKey, _urlParam: c._urlParam
                });
            }
        }

        // Same query already saved → silently rename + refresh.
        for (var i = 0; i < saved.length; i++) {
            if (saved[i].query === query) {
                saved[i].name     = name.substring(0, MAX_NAME);
                saved[i].chips    = chipsSnapshot;
                saved[i].lastUsed = Date.now();
                setJSON(SAVED_KEY, saved);
                showToast('Updated: ' + name);
                return null;
            }
        }

        // Same name with different query → confirm.
        for (var j = 0; j < saved.length; j++) {
            if (saved[j].name.toLowerCase() === name.toLowerCase()) {
                if (!forceOverwrite) return { existing: saved[j] };
                saved[j].query    = query;
                saved[j].chips    = chipsSnapshot;
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
            id:        'cmd_' + Date.now(),
            name:      name.substring(0, MAX_NAME),
            query:     query,
            chips:     chipsSnapshot,
            icon:      'bookmark',
            userEmail: palette.user || '',
            created:   Date.now(),
            lastUsed:  Date.now(),
            useCount:  0
        });
        setJSON(SAVED_KEY, saved);
        showToast('Saved: ' + name);
        return null;
    }

    function deleteSavedCommand(savedId) {
        var saved = getJSON(SAVED_KEY);
        var target = null;
        for (var i = 0; i < saved.length; i++) {
            if (saved[i].id === savedId) { target = saved[i]; break; }
        }
        if (!target) return;
        if (!window.confirm('Delete saved command "' + target.name + '"?')) return;
        setJSON(SAVED_KEY, saved.filter(function (s) { return s.id !== savedId; }));
        showToast('Command deleted');
        handleInput();
    }

    // Used by Shift+Delete (no confirmation prompt).
    function deleteSavedCommandSilent(savedId) {
        var saved = getJSON(SAVED_KEY);
        var target = null;
        for (var i = 0; i < saved.length; i++) {
            if (saved[i].id === savedId) { target = saved[i]; break; }
        }
        if (!target) return;
        setJSON(SAVED_KEY, saved.filter(function (s) { return s.id !== savedId; }));
        showToast('Deleted: ' + target.name);
    }

    // ════════════════════════════════════════════════════════════════
    //  Open / close
    // ════════════════════════════════════════════════════════════════

    function openPalette() {
        if (S.open) return;
        S.open = true;
        S.previousFocus = document.activeElement;
        DOM.overlay.classList.add('open');
        document.body.style.overflow = 'hidden';
        input.value = '';
        modeTag.textContent = '';
        modeTag.className   = 'cp-mode-indicator';
        modeTag.removeAttribute('data-mode');
        S.activeIndex = -1;
        renderDefault();
        input.focus();

        // Lazy-load card names on first open (fetchNames is provided externally).
        if (!S.cardNames && !S.cardNamesLoading && typeof fetchNames === 'function') {
            S.cardNamesLoading = true;
            fetchNames('false')
                .then(function (names) { S.cardNames = names || []; S.cardNamesLoading = false; })
                .catch(function ()      { S.cardNamesLoading = false; });
        }
    }

    function closePalette() {
        if (!S.open) return;
        S.open = false;
        DOM.overlay.classList.remove('open');
        document.body.style.overflow = '';
        removeSaveModal();
        if (S.previousFocus) { S.previousFocus.focus(); S.previousFocus = null; }
    }

    // ════════════════════════════════════════════════════════════════
    //  Keyboard handling
    // ════════════════════════════════════════════════════════════════

    // Document-level: open/close shortcut + "/" hotkey.
    document.addEventListener('keydown', function (e) {
        if (S.saveModalOpen) return;

        if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.keyCode === 75)) {
            e.preventDefault();
            S.open ? closePalette() : openPalette();
            return;
        }
        if (e.key === '/' && !S.open) {
            var tag = document.activeElement ? document.activeElement.tagName.toLowerCase() : '';
            var isInput    = tag === 'input' || tag === 'textarea' || tag === 'select';
            var isEditable = document.activeElement && document.activeElement.isContentEditable;
            if (!isInput && !isEditable) { e.preventDefault(); openPalette(); }
        }
    });

    // Input-level keymap. Each handler receives the keydown event.
    function handleEnterKey(e) {
        // Chips locked + empty input + active item not user-picked → run composition.
        if (chips && chips.count() > 0 && input.value.trim() === '') {
            var item = S.items[S.activeIndex];
            if (!item || !item._userPicked) {
                e.preventDefault();
                runComposedQuery();
                return;
            }
        }
        if (e.ctrlKey && S.activeIndex >= 0) {
            var ci = S.items[S.activeIndex];
            var cd = ci && ROW_TYPES[ci.type];
            if (cd && cd.onCtrlEnter) {
                e.preventDefault();
                cd.onCtrlEnter(ci);
                return;
            }
        }
        e.preventDefault();
        executeActive(e.shiftKey);
    }

    function handleTabKey(e) {
        // Shift+Tab inside the dialog: keep focus on the input (focus trap).
        if (e.shiftKey) { e.preventDefault(); input.focus(); return; }

        var item = S.items[S.activeIndex];
        if (!item || item.disabled || !chips) { e.preventDefault(); input.focus(); return; }
        var def = ROW_TYPES[item.type];
        if (!def || !def.onTab) { e.preventDefault(); input.focus(); return; }

        var locked = def.onTab(item);
        e.preventDefault();
        if (locked) {
            input.value = '';
            handleInput();
        } else {
            input.focus();
        }
    }

    function handleEdgeLeftKey(e) {
        // ArrowLeft at cursor 0, or Backspace on empty input, with no chip currently
        // active → activate last chip.
        if (!chips || chips.count() === 0 || chips.activeIndex() !== -1) return;
        var atStart = input.selectionStart === 0 && input.selectionEnd === 0;
        var isLeft  = (e.key === 'ArrowLeft' || e.keyCode === 37) && atStart;
        var isBack  = (e.key === 'Backspace' || e.keyCode === 8) && input.value === '';
        if (isLeft || isBack) {
            e.preventDefault();
            chips.activate(chips.count() - 1);
        }
    }

    function handleShiftDeleteKey(e) {
        if (!e.shiftKey) return;
        var item = S.items[S.activeIndex];
        if (!item) return;
        var def = ROW_TYPES[item.type];
        if (def && def.onShiftDelete) { e.preventDefault(); def.onShiftDelete(item); }
    }

    input.addEventListener('keydown', function (e) {
        if (S.saveModalOpen) return;

        // Ctrl/Cmd+S → save current search.
        if ((e.ctrlKey || e.metaKey) && (e.key === 's' || e.keyCode === 83)) {
            e.preventDefault();
            showSaveModal();
            return;
        }

        var key = e.key, code = e.keyCode;
        if (key === 'ArrowDown' || code === 40) { e.preventDefault(); moveActive(+1);  return; }
        if (key === 'ArrowUp'   || code === 38) { e.preventDefault(); moveActive(-1);  return; }
        if (key === 'Escape'    || code === 27) { e.preventDefault(); closePalette();  return; }
        if (key === 'Enter'     || code === 13) { handleEnterKey(e);                   return; }
        if (key === 'Tab'       || code === 9)  { handleTabKey(e);                     return; }
        if (key === 'Delete'    || code === 46) { handleShiftDeleteKey(e);             return; }
        if (key === 'ArrowLeft' || code === 37 || key === 'Backspace' || code === 8) {
            handleEdgeLeftKey(e);
            return;
        }
    });

    // Chip-container keymap (only fires when a chip is active, i.e. focus is on
    // the chip container rather than the input).
    DOM.chipBox.addEventListener('keydown', function (e) {
        if (!chips) return;
        var idx = chips.activeIndex();
        if (idx < 0) return;   // input handler owns this case

        if (e.key === 'ArrowLeft' || e.keyCode === 37) {
            e.preventDefault();
            if (idx > 0) chips.activate(idx - 1);
            return;
        }
        if (e.key === 'ArrowRight' || e.keyCode === 39) {
            e.preventDefault();
            if (idx < chips.count() - 1) chips.activate(idx + 1);
            else                         chips.activate(-1);
            return;
        }
        if (e.key === 'Delete' || e.keyCode === 46) {
            e.preventDefault();
            chips.remove(idx);
            chips.activate(idx < chips.count() ? idx : -1);
            return;
        }
        if (e.key === 'Backspace' || e.keyCode === 8) {
            e.preventDefault();
            chips.remove(idx);
            chips.activate(idx - 1 >= 0 ? idx - 1 : -1);
            return;
        }
        if (e.key === 'Escape' || e.keyCode === 27) {
            e.preventDefault();
            chips.activate(-1);
            return;
        }
        if (e.key === 'Enter' || e.keyCode === 13) {
            e.preventDefault();
            chips.activate(-1);
            // Execute the highlighted dropdown item, or run the composed query.
            var item = S.items[S.activeIndex];
            if (item && ROW_TYPES[item.type] && ROW_TYPES[item.type].onEnter) {
                ROW_TYPES[item.type].onEnter(item);
            } else if (chips.composedQuery()) {
                runComposedQuery();
            }
            return;
        }
        if (e.key === 'Tab' || e.keyCode === 9) {
            // Tab on active chip → unlock back into input for editing.
            e.preventDefault();
            var chip = chips.get(idx);
            if (!chip) return;
            chips.remove(idx);
            // For filter chips, restore "prefix + first value" so the dropdown shows
            // that provider again. Other chip types just drop their value into input.
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
            chips.activate(-1);
            input.setSelectionRange(input.value.length, input.value.length);
            handleInput();
        }
    });

    // Dialog-level focus trap + Escape outside the input.
    DOM.dialog.addEventListener('keydown', function (e) {
        if (S.saveModalOpen) return;
        if ((e.key === 'Tab' || e.keyCode === 9) && e.target !== input) {
            e.preventDefault();
            input.focus();
            return;
        }
        if ((e.key === 'Escape' || e.keyCode === 27) && e.target !== input) {
            e.preventDefault();
            closePalette();
        }
    });

})();