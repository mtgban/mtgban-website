/*
 * The settings modal's rail and search box. The pure functions sit on
 * window.SettingsShell so bun can test them; bind() wires them to a body
 * that js/settings.js has just fetched and injected.
 */
(function () {
    'use strict';

    function normalize(q) { return (q || '').trim().toLowerCase(); }

    // entries: [{tab, title, text}], text already lowercased
    function filterEntries(entries, q) {
        q = normalize(q);
        if (!q) return entries.slice();
        return entries.filter(function (e) { return e.text.indexOf(q) >= 0; });
    }

    function countByTab(entries) {
        var counts = {};
        entries.forEach(function (e) { counts[e.tab] = (counts[e.tab] || 0) + 1; });
        return counts;
    }

    // The first hint the body has wins; with none, the first tab.
    function pickTab(available, hints) {
        for (var i = 0; i < hints.length; i++) {
            if (hints[i] && available.indexOf(hints[i]) >= 0) return hints[i];
        }
        return available.length ? available[0] : null;
    }

    // ?settings=1 opens the page's own tab; any other value names one.
    function tabFromQuery(search) {
        var v = new URLSearchParams(search).get('settings');
        if (!v || v === '1') return null;
        return v;
    }

    function escapeHtml(s) {
        return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    }

    // Every occurrence of q in text wrapped in <mark>, the rest escaped.
    function markup(text, q) {
        q = normalize(q);
        if (!q) return escapeHtml(text);
        var lower = text.toLowerCase(), out = '', i = 0, j;
        while ((j = lower.indexOf(q, i)) >= 0) {
            out += escapeHtml(text.slice(i, j)) + '<mark>' + escapeHtml(text.slice(j, j + q.length)) + '</mark>';
            i = j + q.length;
        }
        return out + escapeHtml(text.slice(i));
    }

    // ─── DOM glue ──────────────────────────────────────────────
    var TEXT_SELECTOR = 'h3, .section-desc, label, .settings-pill, option, .settings-field-row > span, h4, h5';
    // Elements whose text nodes get a <mark>; <option> text cannot hold one
    var MARK_SELECTOR = 'h3, .section-desc, .settings-pill, .settings-toggle > span:last-child, .settings-field-row > span, .settings-grid label, h4, h5';

    function indexSections(root) {
        var entries = [];
        root.querySelectorAll('.settings-pane').forEach(function (pane) {
            pane.querySelectorAll('.settings-section').forEach(function (section) {
                var h3 = section.querySelector('h3');
                var parts = [];
                // Set names would make every Editions section match
                section.querySelectorAll(TEXT_SELECTOR).forEach(function (el) {
                    if (el.closest('.editions-picker')) return;
                    parts.push(el.textContent);
                });
                entries.push({
                    tab: pane.dataset.tab,
                    el: section,
                    title: h3 ? h3.textContent : '',
                    text: parts.join(' ').toLowerCase(),
                });
            });
        });
        return entries;
    }

    // Only text nodes are wrapped, so inputs inside a label stay put
    function highlight(section, q) {
        section.querySelectorAll(MARK_SELECTOR).forEach(function (el) {
            if (el.closest('.editions-picker')) return;
            Array.prototype.slice.call(el.childNodes).forEach(function (node) {
                if (node.nodeType !== 3 || node.textContent.toLowerCase().indexOf(q) < 0) return;
                var span = document.createElement('span');
                span.className = 'settings-hl';
                span.dataset.orig = node.textContent;
                span.innerHTML = markup(node.textContent, q);
                node.replaceWith(span);
            });
        });
    }

    function clearHighlight(section) {
        section.querySelectorAll('.settings-hl').forEach(function (span) {
            span.replaceWith(document.createTextNode(span.dataset.orig));
        });
    }

    function bind(modal, opts) {
        opts = opts || {};
        var body = modal.querySelector('.settings-modal-body');
        var rail = body.querySelector('.settings-rail');
        var panes = Array.prototype.slice.call(body.querySelectorAll('.settings-pane'));
        var input = modal.querySelector('#settings-search');
        var countEl = modal.querySelector('#settings-search-count');
        if (!rail || !panes.length) return null;

        var entries = indexSections(body);
        var current = null;
        var searching = false;
        var saved = [];
        var hiddenTabs = {};
        // Re-applies the arbit scope picked before a search showed every pane
        var scopePicks = [];

        function buttons() { return Array.prototype.slice.call(rail.querySelectorAll('[data-tab]')); }
        function tabs() {
            return buttons().filter(function (b) { return !b.hidden; }).map(function (b) { return b.dataset.tab; });
        }
        function tabName(tab) {
            var b = rail.querySelector('[data-tab="' + tab + '"] .settings-rail-label');
            return b ? b.textContent : tab;
        }

        // First section open, the rest closed, per pane
        panes.forEach(function (pane) {
            pane.querySelectorAll('.settings-section').forEach(function (s, i) {
                s.classList.toggle('expanded', i === 0);
            });
        });

        function show(tab) {
            current = tab;
            buttons().forEach(function (b) {
                var on = b.dataset.tab === tab;
                b.classList.toggle('active', on);
                b.setAttribute('aria-selected', on ? 'true' : 'false');
            });
            panes.forEach(function (p) { p.hidden = p.dataset.tab !== tab; });
        }

        // A pane whose every section stays display:none loses its tab. Only
        // matters when the server shows Offline but the cookie lacks the
        // SearchOfflineMode flag that OfflineMode.available() reads (dev mode).
        function hideEmptyTabs() {
            panes.forEach(function (p) {
                var sections = p.querySelectorAll('.settings-section');
                var visible = Array.prototype.some.call(sections, function (s) { return s.style.display !== 'none'; });
                if (visible) return;
                hiddenTabs[p.dataset.tab] = true;
                p.hidden = true;
                var b = rail.querySelector('[data-tab="' + p.dataset.tab + '"]');
                if (!b) return;
                b.hidden = true;
                var gap = b.previousElementSibling;
                if (gap && gap.classList.contains('settings-rail-gap')) gap.hidden = true;
            });
            if (current && hiddenTabs[current]) show(tabs()[0]);
        }

        function crumb(e) {
            var c = e.el.querySelector('.settings-crumb');
            if (!c) {
                c = document.createElement('span');
                c.className = 'settings-crumb';
                c.textContent = tabName(e.tab);
                var header = e.el.querySelector('.settings-section-header');
                var chevron = header.querySelector('.settings-section-chevron');
                header.insertBefore(c, chevron);
            }
            c.hidden = false;
        }

        function leaveSearch() {
            searching = false;
            entries.forEach(function (e, i) {
                e.el.hidden = false;
                e.el.classList.toggle('expanded', saved[i]);
                clearHighlight(e.el);
                var c = e.el.querySelector('.settings-crumb');
                if (c) c.hidden = true;
            });
            scopePicks.forEach(function (restore) { restore(); });
            buttons().forEach(function (b) {
                b.classList.remove('nomatch');
                var n = b.querySelector('.settings-rail-count');
                if (n) n.hidden = true;
            });
            if (countEl) countEl.textContent = '';
            body.classList.remove('settings-searching');
            show(current);
        }

        function applySearch(q) {
            q = normalize(q);
            if (!q) {
                if (searching) leaveSearch();
                return;
            }
            if (!searching) {
                searching = true;
                saved = entries.map(function (e) { return e.el.classList.contains('expanded'); });
            }
            // A hidden tab's sections neither show nor count
            var matches = filterEntries(entries, q).filter(function (e) { return !hiddenTabs[e.tab]; });
            var counts = countByTab(matches);
            body.classList.add('settings-searching');
            panes.forEach(function (p) { p.hidden = !!hiddenTabs[p.dataset.tab]; });
            entries.forEach(function (e) {
                var hit = matches.indexOf(e) >= 0;
                e.el.hidden = !hit;
                if (hit) {
                    e.el.classList.add('expanded');
                    // A match may sit in a scope the pills are hiding
                    e.el.querySelectorAll('.settings-scope-pane').forEach(function (p) { p.hidden = false; });
                    e.el.querySelectorAll('[data-role="arbit-scope"]').forEach(function (p) { p.hidden = true; });
                    clearHighlight(e.el);
                    highlight(e.el, q);
                    crumb(e);
                } else {
                    clearHighlight(e.el);
                }
            });
            buttons().forEach(function (b) {
                var n = counts[b.dataset.tab] || 0;
                b.classList.toggle('nomatch', n === 0);
                b.classList.remove('active');
                var badge = b.querySelector('.settings-rail-count');
                if (badge) { badge.textContent = n; badge.hidden = false; }
            });
            if (countEl) countEl.textContent = matches.length + (matches.length === 1 ? ' match' : ' matches');
        }

        rail.addEventListener('click', function (e) {
            var b = e.target.closest('[data-tab]');
            if (!b) return;
            if (input && input.value) { input.value = ''; applySearch(''); }
            show(b.dataset.tab);
        });

        // The search box lives in the shell and outlasts a re-injected body:
        // listen once, through a reference each bind points at its own body
        if (input) input._settingsApply = applySearch;
        if (input && !input.dataset.bound) {
            var timer = null;
            input.addEventListener('input', function () {
                clearTimeout(timer);
                timer = setTimeout(function () { input._settingsApply(input.value); }, 80);
            });
            // Escape clears the box first; a second one reaches settings.js
            input.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && input.value) {
                    input.value = '';
                    input._settingsApply('');
                    e.stopPropagation();
                    e.preventDefault();
                }
            });
            input.dataset.bound = '1';
        }

        // Arbitrage: the scope pills pick which route's grid shows
        body.querySelectorAll('[data-role="arbit-scope"]').forEach(function (pills) {
            var section = pills.closest('.settings-section-body');
            var picked = null;
            function pick(scope) {
                picked = scope;
                pills.querySelectorAll('.settings-pill').forEach(function (p) {
                    p.classList.toggle('active', p.dataset.scope === scope);
                });
                section.querySelectorAll('.settings-scope-pane').forEach(function (pane) {
                    pane.hidden = pane.dataset.scope !== scope;
                });
            }
            pills.addEventListener('click', function (e) {
                var p = e.target.closest('.settings-pill');
                if (p) pick(p.dataset.scope);
            });
            var scopes = Array.prototype.map.call(pills.querySelectorAll('.settings-pill'), function (p) { return p.dataset.scope; });
            pick(pickTab(scopes, [opts.scope]));
            scopePicks.push(function () {
                pills.hidden = false;
                pick(picked);
            });
        });
        // A single route has no pills: show its pane
        body.querySelectorAll('.settings-section-body').forEach(function (section) {
            if (section.querySelector('[data-role="arbit-scope"]')) return;
            var only = section.querySelector('.settings-scope-pane');
            if (only) only.hidden = false;
        });

        // Before picking, so a hint naming a hidden tab falls through
        hideEmptyTabs();
        show(pickTab(tabs(), [opts.queryTab, opts.pageTab]));

        return { show: show, tabs: tabs, hideEmptyTabs: hideEmptyTabs, applySearch: applySearch };
    }

    window.SettingsShell = {
        filterEntries: filterEntries,
        countByTab: countByTab,
        pickTab: pickTab,
        tabFromQuery: tabFromQuery,
        markup: markup,
        indexSections: indexSections,
        bind: bind,
    };
})();
