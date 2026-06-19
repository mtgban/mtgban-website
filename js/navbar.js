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

    function isOpen() { return dd.classList.contains('open'); }
    function open() { dd.classList.add('open'); btn.setAttribute('aria-expanded', 'true'); }
    function shut() { dd.classList.remove('open'); btn.setAttribute('aria-expanded', 'false'); }

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
    if (!grid || !navSections) return;

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

    var STORAGE_KEY = 'mtgban_nav_layout_v1';
    function currentLayout() {
        return {
            sections: Array.from(navSections.querySelectorAll('.nav2-section-btn:not(.is-tools)'))
                .map(function(b) { return b.getAttribute('data-tool'); }),
            grid: Array.from(grid.querySelectorAll('.tools-tile'))
                .map(function(t) { return t.getAttribute('data-tool'); })
        };
    }
    function saveLayout() {
        try { localStorage.setItem(STORAGE_KEY, JSON.stringify(currentLayout())); } catch (e) {}
    }
    function clearIndicators() {
        document.querySelectorAll('.drop-before, .drop-after, .swap-target, .promote-target, .cap-reached, .demote-target').forEach(function(t) {
            t.classList.remove('drop-before', 'drop-after', 'swap-target', 'promote-target', 'cap-reached', 'demote-target');
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
                clearIndicators();
                if (after) {
                    slot.parentNode.insertBefore(dragged, slot.nextSibling);
                } else {
                    slot.parentNode.insertBefore(dragged, slot);
                }
            } else {
                clearIndicators();
                swapEntries(dragged, slot);
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
        var tool = dragged.getAttribute('data-tool');
        grid.appendChild(createTile(tool));
        dragged.remove();
        clearIndicators();
        saveLayout();
    });

    // Dropping a section button onto the Tools button itself demotes it
    // into the dropdown grid — no need to open the dropdown first. The
    // Tools button is highlighted while it's a valid drop target.
    var toolsBtn = document.getElementById('tools-btn');
    if (toolsBtn) {
        toolsBtn.addEventListener('dragover', function(e) {
            if (!dragged || !isNavBtn(dragged)) return;
            e.preventDefault();
            e.dataTransfer.dropEffect = 'move';
            clearIndicators();
            toolsBtn.classList.add('swap-target');
        });
        toolsBtn.addEventListener('dragleave', function(e) {
            if (e.target === toolsBtn) toolsBtn.classList.remove('swap-target');
        });
        toolsBtn.addEventListener('drop', function(e) {
            if (!dragged || !isNavBtn(dragged)) return;
            e.preventDefault();
            e.stopPropagation();
            var tool = dragged.getAttribute('data-tool');
            grid.appendChild(createTile(tool));
            dragged.remove();
            clearIndicators();
            saveLayout();
        });
    }

    // Layout restoration lives entirely in the synchronous inline script in
    // templates/partials/navbar.html — it must run before the browser paints
    // to avoid flashing the default layout, which a deferred external script
    // can't do. Here we just attach drag handlers to whatever tiles/buttons it
    // produced (or the server's defaults, if there's no saved layout).
    Array.from(document.querySelectorAll('.tools-tile, .nav2-section-btn:not(.is-tools)')).forEach(attachSlotHandlers);
})();

// ── Context-aware nav search autocomplete ───────────────────
(function() {
    var form = document.getElementById('nav-searchform');
    var input = document.getElementById('nav-searchbox');
    if (!form || !input || typeof autocomplete !== 'function') return;

    var sealed = location.pathname.indexOf('/sealed') === 0;
    form.action = sealed ? '/sealed' : '/search';
    autocomplete(form, input, sealed ? 'true' : 'false');

    // Keep the search bar focused on every page load so typing starts a
    // search immediately. The `autofocus` attribute covers fresh loads;
    // this also handles back/forward (bfcache) restores where it won't fire.
    function focusSearch() { input.focus(); }
    focusSearch();
    window.addEventListener('pageshow', function (e) { if (e.persisted) focusSearch(); });
})();
