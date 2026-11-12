/*
 * Navbar v2: Tools dropdown, drag-drop tool customization (persisted to
 * localStorage), and context-aware search autocomplete wiring.
 * Renders nothing itself; enhances the server-rendered .navbar-v2 markup.
 */

// ── Tools dropdown open/close ───────────────────────────────
(function() {
    var btn = document.getElementById('tools-btn');
    var dd = document.getElementById('tools-dropdown');
    if (!btn || !dd) return;

    // Closed, the panel only fades out; inert keeps Tab and screen readers out.
    function isOpen() { return dd.classList.contains('open'); }
    function open() {
        dd.inert = false;
        dd.classList.add('open');
        btn.setAttribute('aria-expanded', 'true');
    }
    function shut() {
        if (dd.contains(document.activeElement)) btn.focus();
        dd.inert = true;
        dd.classList.remove('open');
        btn.setAttribute('aria-expanded', 'false');
    }

    btn.addEventListener('click', function(e) {
        e.stopPropagation();
        isOpen() ? shut() : open();
    });
    document.addEventListener('click', function(e) {
        if (isOpen() && !btn.contains(e.target) && !dd.contains(e.target)) shut();
    });
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && isOpen()) shut();
    });
})();

// ── Drag-and-drop: reorder + swap + promote/demote ──────────
(function() {
    var grid = document.getElementById('tools-grid');
    var navSections = document.querySelector('.nav2-sections');
    // Offline shows a fixed mode-selector nav; never mutate the saved layout there.
    if (!grid || !navSections || location.pathname === '/offline') return;

    var MAX_SECTION_BUTTONS = 5;

    // Build the entry registry from the server-provided, auth-gated nav list.
    // Home is excluded (the brand logo covers it).
    var ENTRIES = {};
    (window.__BAN_NAV || []).forEach(function(e) {
        if (e.tool === 'home') return;
        ENTRIES[e.tool] = { icon: e.icon, name: e.name, desc: e.desc, href: e.href, admin: e.admin };
    });

    function isTile(el)   { return el && el.classList.contains('tools-tile'); }
    function isNavBtn(el) { return el && el.classList.contains('nav2-section-btn') && !el.classList.contains('is-tools'); }
    function sectionCount() { return navSections.querySelectorAll('.nav2-section-btn:not(.is-tools)').length; }

    function paintSlot(el, tool) {
        var e = ENTRIES[tool];
        if (!e) return;
        el.setAttribute('data-tool', tool);
        el.setAttribute('href', e.href);
        if (isTile(el)) {
            el.classList.toggle('is-admin', !!e.admin);
            el.innerHTML =
                '<span class="tools-tile-icon">' + e.icon + '</span>' +
                '<span class="tools-tile-text">' +
                    '<span class="tools-tile-name">' + e.name + '</span>' +
                    '<span class="tools-tile-desc">' + e.desc + '</span>' +
                '</span>';
        } else if (isNavBtn(el)) {
            el.textContent = e.name;
        }
    }

    function swapEntries(a, b) {
        var ta = a.getAttribute('data-tool');
        var tb = b.getAttribute('data-tool');
        paintSlot(a, tb);
        paintSlot(b, ta);
    }

    // demote moves a section button's entry into the grid.
    function demote(btn) {
        grid.appendChild(createTile(btn.getAttribute('data-tool')));
        btn.remove();
    }

    function createTile(tool) {
        var a = document.createElement('a');
        a.className = 'tools-tile';
        if (ENTRIES[tool] && ENTRIES[tool].admin) a.classList.add('is-admin');
        attachSlotHandlers(a);
        paintSlot(a, tool);
        return a;
    }
    function createSectionBtn(tool) {
        var a = document.createElement('a');
        a.className = 'nav2-section-btn';
        attachSlotHandlers(a);
        paintSlot(a, tool);
        return a;
    }

    var dragged = null;
    var didDrag = false;
    var utility = document.querySelector('.nav2-utility');
    var dock = document.getElementById('tools-quick-dock');
    var quick = dock && dock.closest('.tools-quick');
    var draggedUtil = null;
    // At 900px and narrower the sections are hidden, the Tools button and
    // the strip with them, so the dock only holds while the bar is wide.
    var narrow = window.matchMedia ? window.matchMedia('(max-width: 900px)') : null;
    function isNarrow() { return !!(narrow && narrow.matches); }

    var STORAGE_KEY = 'mtgban_nav_layout_v1';
    function currentLayout() {
        return {
            sections: Array.from(navSections.querySelectorAll('.nav2-section-btn:not(.is-tools)'))
                .map(function(b) { return b.getAttribute('data-tool'); }),
            grid: Array.from(grid.querySelectorAll('.tools-tile'))
                .map(function(t) { return t.getAttribute('data-tool'); }),
            // Narrow, the icons are all on the bar whatever was saved: keep that.
            dock: isNarrow() ? savedDock() : Array.from(dock ? dock.querySelectorAll('[data-util]') : [])
                .map(function(u) { return u.getAttribute('data-util'); })
        };
    }
    // savedDock reads the saved dock list, less any entry that is not a
    // name of the bar's shape: the names go into selectors, as in the
    // restore script, and a saved list is written back from here.
    function savedDock() {
        try {
            var saved = JSON.parse(localStorage.getItem(STORAGE_KEY) || 'null');
            if (!saved || !Array.isArray(saved.dock)) return [];
            return saved.dock.filter(function(name) { return typeof name === 'string' && /^[a-z]+$/.test(name); });
        } catch (e) { return []; }
    }
    function saveLayout() {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(currentLayout())); } catch (e) {}
    }
    function clearIndicators() {
        document.querySelectorAll('.drop-before, .drop-after, .swap-target, .promote-target, .cap-reached, .demote-target, .dock-target').forEach(function(t) {
            t.classList.remove('drop-before', 'drop-after', 'swap-target', 'promote-target', 'cap-reached', 'demote-target', 'dock-target');
        });
    }

    var promoteSlot = null;
    function showPromoteSlot() {
        if (promoteSlot) return;
        if (sectionCount() >= MAX_SECTION_BUTTONS) return;
        promoteSlot = document.createElement('div');
        promoteSlot.className = 'nav2-promote-slot';
        promoteSlot.textContent = '+ Add';
        promoteSlot.addEventListener('dragover', function(e) {
            if (!dragged || !isTile(dragged)) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            promoteSlot.classList.add('hover');
        });
        promoteSlot.addEventListener('dragleave', function() { promoteSlot.classList.remove('hover'); });
        promoteSlot.addEventListener('drop', function(e) {
            if (!dragged || !isTile(dragged)) return;
            e.preventDefault();
            e.stopPropagation();
            if (sectionCount() >= MAX_SECTION_BUTTONS) return;
            var tool = dragged.getAttribute('data-tool');
            navSections.insertBefore(createSectionBtn(tool), navSections.querySelector('.nav2-tools-wrap'));
            dragged.remove();
            if (window.BAN && window.BAN.track) window.BAN.track('ui.nav.layout', 'promote');
            saveLayout();
        });
        navSections.insertBefore(promoteSlot, navSections.querySelector('.nav2-tools-wrap'));
    }
    function hidePromoteSlot() {
        if (!promoteSlot) return;
        promoteSlot.remove();
        promoteSlot = null;
    }

    function attachSlotHandlers(slot) {
        slot.setAttribute('draggable', 'true');
        slot.addEventListener('dragstart', function(e) {
            dragged = slot;
            didDrag = true;
            slot.classList.add('dragging');
            try {
                e.dataTransfer.effectAllowed = 'move';
                e.dataTransfer.setData('text/plain', slot.getAttribute('data-tool') || '');
            } catch (err) {}
            if (isTile(slot)) showPromoteSlot();
        });
        slot.addEventListener('dragend', function() {
            slot.classList.remove('dragging');
            clearIndicators();
            hidePromoteSlot();
            dragged = null;
            setTimeout(function() { didDrag = false; }, 60);
        });
        slot.addEventListener('dragover', function(e) {
            if (!dragged || dragged === slot) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            clearIndicators();
            if (isTile(dragged) && isTile(slot)) {
                var rect = slot.getBoundingClientRect();
                var after = (e.clientX - rect.left) > rect.width / 2;
                slot.classList.add(after ? 'drop-after' : 'drop-before');
            } else {
                slot.classList.add('swap-target');
            }
        });
        slot.addEventListener('dragleave', function(e) {
            if (e.target === slot) {
                slot.classList.remove('drop-before', 'drop-after', 'swap-target');
            }
        });
        slot.addEventListener('drop', function(e) {
            if (!dragged || dragged === slot) return;
            e.preventDefault();
            e.stopPropagation();
            if (isTile(dragged) && isTile(slot)) {
                var after = slot.classList.contains('drop-after');
                var was = dragged.nextSibling;
                clearIndicators();
                if (after) {
                    slot.parentNode.insertBefore(dragged, slot.nextSibling);
                } else {
                    slot.parentNode.insertBefore(dragged, slot);
                }
                // Dropped where it already was, nothing changed.
                if (dragged.nextSibling !== was && window.BAN && window.BAN.track) window.BAN.track('ui.nav.layout', 'reorder');
            } else {
                clearIndicators();
                swapEntries(dragged, slot);
                if (window.BAN && window.BAN.track) window.BAN.track('ui.nav.layout', 'swap');
            }
            saveLayout();
        });
        slot.addEventListener('click', function(e) {
            if (didDrag) { e.preventDefault(); e.stopPropagation(); }
        });
    }

    function onTargetSlot(target) { return target.closest('.nav2-section-btn, .tools-tile'); }

    navSections.addEventListener('dragover', function(e) {
        if (!dragged || !isTile(dragged)) return;
        if (onTargetSlot(e.target)) return;
        e.preventDefault();
        clearIndicators();
        if (sectionCount() >= MAX_SECTION_BUTTONS) {
            e.dataTransfer.dropEffect = 'none';
            navSections.classList.add('cap-reached');
        } else {
            e.dataTransfer.dropEffect = 'move';
            navSections.classList.add('promote-target');
        }
    });
    navSections.addEventListener('dragleave', function(e) {
        if (e.target === navSections) navSections.classList.remove('promote-target', 'cap-reached');
    });
    navSections.addEventListener('drop', function(e) {
        if (!dragged || !isTile(dragged)) return;
        if (onTargetSlot(e.target)) return;
        if (e.target === promoteSlot) return;
        if (sectionCount() >= MAX_SECTION_BUTTONS) { e.preventDefault(); clearIndicators(); return; }
        e.preventDefault();
        var tool = dragged.getAttribute('data-tool');
        navSections.insertBefore(createSectionBtn(tool), navSections.querySelector('.nav2-tools-wrap'));
        dragged.remove();
        clearIndicators();
        if (window.BAN && window.BAN.track) window.BAN.track('ui.nav.layout', 'promote');
        saveLayout();
    });

    grid.addEventListener('dragover', function(e) {
        if (!dragged || !isNavBtn(dragged)) return;
        if (onTargetSlot(e.target)) return;
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        clearIndicators();
        grid.classList.add('demote-target');
    });
    grid.addEventListener('dragleave', function(e) {
        if (e.target === grid) grid.classList.remove('demote-target');
    });
    grid.addEventListener('drop', function(e) {
        if (!dragged || !isNavBtn(dragged)) return;
        if (onTargetSlot(e.target)) return;
        e.preventDefault();
        demote(dragged);
        clearIndicators();
        if (window.BAN && window.BAN.track) window.BAN.track('ui.nav.layout', 'demote');
        saveLayout();
    });

    // Dropping a section button onto the Tools button itself demotes it
    // into the dropdown grid — no need to open the dropdown first. The
    // Tools button is highlighted while it's a valid drop target.
    var toolsBtn = document.getElementById('tools-btn');
    if (toolsBtn) {
        toolsBtn.addEventListener('dragover', function(e) {
            if (!(dragged && isNavBtn(dragged)) && !draggedUtil) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            clearIndicators();
            toolsBtn.classList.add('swap-target');
        });
        toolsBtn.addEventListener('dragleave', function(e) {
            if (e.target === toolsBtn) toolsBtn.classList.remove('swap-target');
        });
        toolsBtn.addEventListener('drop', function(e) {
            if (draggedUtil) {
                e.preventDefault();
                e.stopPropagation();
                if (draggedUtil.parentNode === dock) undockUtil(draggedUtil); else dockUtil(draggedUtil);
                return;
            }
            if (!dragged || !isNavBtn(dragged)) return;
            e.preventDefault();
            e.stopPropagation();
            demote(dragged);
            clearIndicators();
            if (window.BAN && window.BAN.track) window.BAN.track('ui.nav.layout', 'demote');
            saveLayout();
        });
    }

    // ── The bar's icons: drag them down to the Tools menu's strip and back ──
    // The elements themselves move, so their ids and handlers come along;
    // the inline restore script in the navbar partial moves them the same
    // way before paint. Back on the bar they take the order the server
    // rendered them in. The Tools button takes a drop either way. While
    // the bar is narrow every icon sits on it and the saved list waits.
    var UTIL_ORDER = ['backpack', 'account', 'guide', 'settings'];

    function dockUtil(el) {
        dock.appendChild(el);
        clearIndicators();
        if (window.BAN && window.BAN.track) window.BAN.track('ui.nav.layout', 'dock');
        saveLayout();
    }
    function placeUtil(el) {
        var at = UTIL_ORDER.indexOf(el.getAttribute('data-util'));
        var next = null;
        Array.from(utility.querySelectorAll('[data-util]')).some(function(u) {
            if (UTIL_ORDER.indexOf(u.getAttribute('data-util')) > at) { next = u; return true; }
            return false;
        });
        utility.insertBefore(el, next || utility.querySelector('.ban-nav-hamburger'));
    }
    function undockUtil(el) {
        placeUtil(el);
        clearIndicators();
        if (window.BAN && window.BAN.track) window.BAN.track('ui.nav.layout', 'undock');
        saveLayout();
    }
    function applyDock(wide) {
        if (!wide) {
            Array.from(dock.querySelectorAll('[data-util]')).forEach(placeUtil);
            return;
        }
        savedDock().forEach(function(name) {
            var el = document.querySelector('.nav2-utility [data-util="' + name + '"]');
            if (el) dock.appendChild(el);
        });
    }

    if (utility && dock && quick) {
        if (narrow && narrow.addEventListener) narrow.addEventListener('change', function(e) { applyDock(!e.matches); });

        Array.from(document.querySelectorAll('[data-util]')).forEach(function(el) {
            el.addEventListener('dragstart', function(e) {
                draggedUtil = el;
                didDrag = true;
                el.classList.add('dragging');
                try {
                    e.dataTransfer.effectAllowed = 'move';
                    e.dataTransfer.setData('text/plain', el.getAttribute('data-util') || '');
                } catch (err) {}
                // Show where it lands: the strip, or a slot on the bar.
                if (el.parentNode === dock) utility.classList.add('undock-ready');
                else if (!isNarrow() && toolsBtn && toolsBtn.getAttribute('aria-expanded') !== 'true') toolsBtn.click();
            });
            el.addEventListener('dragend', function() {
                el.classList.remove('dragging');
                utility.classList.remove('undock-ready');
                clearIndicators();
                draggedUtil = null;
                setTimeout(function() { didDrag = false; }, 60);
            });
            el.addEventListener('click', function(e) {
                if (didDrag) { e.preventDefault(); e.stopPropagation(); }
            });
        });

        quick.addEventListener('dragover', function(e) {
            if (!draggedUtil || draggedUtil.parentNode === dock) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            clearIndicators();
            quick.classList.add('dock-target');
        });
        quick.addEventListener('dragleave', function(e) {
            if (e.target === quick) quick.classList.remove('dock-target');
        });
        quick.addEventListener('drop', function(e) {
            if (!draggedUtil || draggedUtil.parentNode === dock) return;
            e.preventDefault();
            e.stopPropagation();
            dockUtil(draggedUtil);
        });

        utility.addEventListener('dragover', function(e) {
            if (!draggedUtil || draggedUtil.parentNode === utility) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            clearIndicators();
            utility.classList.add('dock-target');
        });
        utility.addEventListener('dragleave', function(e) {
            if (e.target === utility) utility.classList.remove('dock-target');
        });
        utility.addEventListener('drop', function(e) {
            if (!draggedUtil || draggedUtil.parentNode === utility) return;
            e.preventDefault();
            e.stopPropagation();
            undockUtil(draggedUtil);
        });
    }

    // Layout restoration lives entirely in the synchronous inline script in
    // templates/partials/navbar.html — it must run before the browser paints
    // to avoid flashing the default layout, which a deferred external script
    // can't do. Here we just attach drag handlers to whatever tiles/buttons it
    // produced (or the server's defaults, if there's no saved layout).
    Array.from(document.querySelectorAll('.tools-tile, .nav2-section-btn:not(.is-tools)')).forEach(attachSlotHandlers);
})();

// ── Drag hint tile: dismiss on click, remembered forever ────
(function() {
    var hint = document.getElementById('nav-hint');
    if (!hint) return;
    hint.addEventListener('click', function(e) {
        // Keep the Tools dropdown open. Without this, the click bubbles to the
        // document outside-click handler, which — now that the tile is being
        // removed — sees a target no longer inside the dropdown and closes it.
        e.stopPropagation();
        try { localStorage.setItem('mtgban_nav_hint_dismissed', '1'); } catch (err) {}
        hint.remove();
    });
})();

// ── Context-aware nav search autocomplete ───────────────────
(function() {
    var form = document.getElementById('nav-searchform');
    var input = document.getElementById('nav-searchbox');
    if (!form || !input || typeof autocomplete !== 'function') return;

    var sealed = location.pathname.indexOf('/sealed') === 0;
    form.action = sealed ? '/sealed' : '/search';
    // The banner, not the path: with the network down the service worker
    // answers /search and /sealed with this same shell.
    var onShell = !!document.getElementById('offline-banner');
    var preferOffline = !onShell && window.OfflinePrefer && OfflinePrefer.get();
    if (preferOffline) {
        // Keep the user in the fast local flow; the offline shell owns suggestions.
        form.action = '/offline';
    }
    // The offline shell owns the navbar box with local suggestions.
    if (!onShell && !preferOffline) {
        autocomplete(form, input, sealed ? 'true' : 'false');
    }

    // Keep the search bar focused on every page load so typing starts a
    // search immediately. The `autofocus` attribute covers fresh loads;
    // this also handles back/forward (bfcache) restores where it won't fire.
    function focusSearch() { input.focus(); }
    focusSearch();
    window.addEventListener('pageshow', function (e) { if (e.persisted) focusSearch(); });
})();

// ── Keep search/sealed navigation in the offline shell while preferring ──
(function() {
    // Manual offline: reroute /search and /sealed navigations to the local
    // shell so moving between pages does not drop back to the live site.
    document.addEventListener('click', function (e) {
        if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
        if (!(window.OfflinePrefer && OfflinePrefer.get())) return;
        var a = e.target.closest ? e.target.closest('a[href]') : null;
        if (!a || a.target === '_blank') return;
        var url;
        try { url = new URL(a.href, location.href); } catch (err) { return; }
        if (url.origin !== location.origin) return;
        if (url.pathname !== '/search' && url.pathname !== '/sealed') return;
        var q = url.searchParams.get('q') || '';
        // Only reroute actual card/name searches; leave bare nav, settings, and operator deep-links on the live site.
        if (!q || /^(container|contents|decklist|unpack):/.test(q)) return;
        e.preventDefault();
        var parts = [];
        if (q) parts.push('q=' + encodeURIComponent(q));
        if (url.pathname === '/sealed') parts.push('sealed=1');
        location.href = '/offline' + (parts.length ? '?' + parts.join('&') : '');
    });
})();

// ── On /offline, the navbar is a Singles/Sealed mode switch ──
(function() {
    if (location.pathname !== '/offline') return;
    var nav = document.querySelector('.navbar-v2');
    var sections = nav && nav.querySelector('.nav2-sections');
    if (!sections) return;
    // Presentational only: the layout system is disabled here, so nothing persists.
    nav.classList.add('offline-nav');

    var sealed = new URLSearchParams(location.search).get('sealed') === '1';
    var q = new URLSearchParams(location.search).get('q');
    var suffix = q ? '&q=' + encodeURIComponent(q) : '';

    function modeBtn(label, href, active) {
        var a = document.createElement('a');
        a.className = 'nav2-section-btn offline-mode-btn' + (active ? ' active' : '');
        a.setAttribute('href', href);
        if (active) a.setAttribute('aria-current', 'page');
        a.textContent = label;
        return a;
    }

    var wrap = sections.querySelector('.nav2-tools-wrap');
    sections.insertBefore(modeBtn('Search', '/offline' + (q ? '?q=' + encodeURIComponent(q) : ''), !sealed), wrap);
    sections.insertBefore(modeBtn('Sealed', '/offline?sealed=1' + suffix, sealed), wrap);

    // Match the CSS grey-out: keep the disabled tool nav out of the tab order.
    function disable(el) {
        el.setAttribute('aria-disabled', 'true');
        el.setAttribute('tabindex', '-1');
    }
    sections.querySelectorAll('.nav2-section-btn:not(.offline-mode-btn):not(.is-tools)').forEach(disable);
    var grid = document.getElementById('tools-grid');
    if (grid) grid.querySelectorAll('.tools-tile').forEach(disable);
})();
