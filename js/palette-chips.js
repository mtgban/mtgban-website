/* Palette Chips - chip-based input system for the command palette.
 * Exposes window.__palette_chips with a stateful chip container API.
 * Loaded before command-palette.js so the palette can consume it.
 */
(function () {
    'use strict';

    function createChipManager(containerEl, inputEl, onChange) {
        var chips = [];
        var activeIndex = -1;

        // Make container focusable so it can receive keyboard events when a chip is active
        if (containerEl.getAttribute('tabindex') === null) {
            containerEl.setAttribute('tabindex', '-1');
        }

        function render() {
            // Remove all chip elements but keep the trailing input
            var toRemove = [];
            for (var i = 0; i < containerEl.children.length; i++) {
                var el = containerEl.children[i];
                if (el !== inputEl) toRemove.push(el);
            }
            for (var r = 0; r < toRemove.length; r++) {
                toRemove[r].parentNode.removeChild(toRemove[r]);
            }
            for (var c = 0; c < chips.length; c++) {
                containerEl.insertBefore(renderChip(chips[c], c), inputEl);
            }
            if (typeof lucide !== 'undefined' && lucide.createIcons) {
                lucide.createIcons({ nodes: containerEl.querySelectorAll('[data-lucide]') });
            }
        }

        function renderChip(chip, idx) {
            var el = document.createElement('span');
            var classes = ['cp-chip', 'cp-chip-' + (chip.type || 'default')];
            if (idx === activeIndex) classes.push('active');
            el.className = classes.join(' ');
            el.setAttribute('role', 'listitem');
            el.setAttribute('data-chip-index', String(idx));
            el.setAttribute('aria-label', (chip.type || 'chip') + ': ' + (chip.label || chip.value));
            if (idx === activeIndex) {
                el.setAttribute('aria-current', 'true');
            }

            var iconEl = document.createElement('span');
            iconEl.className = 'cp-chip-icon';
            iconEl.innerHTML = '<i data-lucide="' + (chip.icon || 'tag') + '"></i>';
            el.appendChild(iconEl);

            var labelEl = document.createElement('span');
            labelEl.className = 'cp-chip-label';
            labelEl.textContent = chip.label || chip.value;
            el.appendChild(labelEl);

            var delBtn = document.createElement('button');
            delBtn.className = 'cp-chip-delete';
            delBtn.setAttribute('type', 'button');
            delBtn.setAttribute('tabindex', '-1');
            delBtn.setAttribute('aria-label', 'Remove chip');
            delBtn.innerHTML = '<i data-lucide="x"></i>';
            (function (index) {
                delBtn.addEventListener('click', function (e) {
                    e.stopPropagation();
                    remove(index);
                });
            })(idx);
            el.appendChild(delBtn);

            (function (index) {
                el.addEventListener('click', function (e) {
                    if (e.target === delBtn || delBtn.contains(e.target)) return;
                    activate(index);
                });
            })(idx);
            return el;
        }

        function add(chip) {
            if (chip.type === 'card') {
                // One card chip max; replace existing
                chips = chips.filter(function (c) { return c.type !== 'card'; });
                chips.unshift(chip);
            } else if (chip.prefix && chipMergePrefixes[chip.prefix]) {
                // List-like merge for supported prefixes
                var existingIdx = -1;
                for (var i = 0; i < chips.length; i++) {
                    if (chips[i].prefix === chip.prefix) { existingIdx = i; break; }
                }
                if (existingIdx >= 0) {
                    var existing = chips[existingIdx];
                    var existingValues = stripPrefixFromValue(existing.value, existing.prefix).split(',');
                    var incomingValues = stripPrefixFromValue(chip.value, chip.prefix).split(',');
                    var seen = {};
                    var merged = [];
                    var allValues = existingValues.concat(incomingValues);
                    for (var v = 0; v < allValues.length; v++) {
                        var tv = allValues[v].trim();
                        if (!tv) continue;
                        var key = tv.toLowerCase();
                        if (seen[key]) continue;
                        seen[key] = true;
                        merged.push(tv);
                    }
                    existing.value = existing.prefix + merged.join(',');
                    existing.label = chipLabelForMerged(existing.prefix, merged);
                } else {
                    chips.push(chip);
                }
            } else if (chip.prefix && chipSingletonPrefixes[chip.prefix]) {
                // Replace existing singleton of same prefix
                chips = chips.filter(function (c) { return c.prefix !== chip.prefix; });
                chips.push(chip);
            } else {
                chips.push(chip);
            }
            activeIndex = -1;
            render();
            if (onChange) onChange();
        }

        function stripPrefixFromValue(value, prefix) {
            if (prefix && value.indexOf(prefix) === 0) {
                return value.substring(prefix.length);
            }
            return value;
        }

        function remove(idx) {
            if (idx < 0 || idx >= chips.length) return;
            chips.splice(idx, 1);
            if (activeIndex >= chips.length) activeIndex = chips.length - 1;
            render();
            if (onChange) onChange();
        }

        function activate(idx) {
            if (idx < 0 || idx >= chips.length) {
                activeIndex = -1;
                if (inputEl && typeof inputEl.focus === 'function') inputEl.focus();
            } else {
                activeIndex = idx;
                if (containerEl && typeof containerEl.focus === 'function') containerEl.focus();
            }
            render();
        }

        function get(idx) {
            return chips[idx];
        }

        function all() {
            return chips.slice();
        }

        function clear() {
            chips = [];
            activeIndex = -1;
            render();
            if (onChange) onChange();
        }

        function composedQuery() {
            var parts = [];
            for (var i = 0; i < chips.length; i++) {
                parts.push(chips[i].value);
            }
            var rest = inputEl ? inputEl.value.trim() : '';
            if (rest) parts.push(rest);
            return parts.join(' ');
        }

        function activeIdx() { return activeIndex; }
        function count() { return chips.length; }

        render();

        return {
            add: add,
            remove: remove,
            activate: activate,
            get: get,
            all: all,
            clear: clear,
            composedQuery: composedQuery,
            activeIndex: activeIdx,
            count: count
        };
    }

    // Prefixes whose values accept comma-separated lists (merge on re-add)
    var chipMergePrefixes = {
        's:': true, 'e:': true,
        'r:': true,
        'c:': true, 'ci:': true,
        't:': true,
        'store:': true, 'seller:': true, 'vendor:': true,
        'is:': true, 'not:': true,
        'on:': true,
        'skip:': true
    };

    // Prefixes whose values are singletons (replace on re-add)
    var chipSingletonPrefixes = {
        'sort:': true,
        'sm:': true,
        'region:': true,
        'cond:': true, 'condr:': true, 'condb:': true
    };

    function chipLabelForMerged(prefix, values) {
        if (values.length === 1) return prefix + values[0];
        var prefixLabels = {
            's:': 'Sets', 'e:': 'Sets',
            'r:': 'Rarities',
            'c:': 'Colors', 'ci:': 'Color ID',
            't:': 'Types',
            'store:': 'Stores', 'seller:': 'Sellers', 'vendor:': 'Vendors',
            'is:': 'Tags', 'not:': 'Not',
            'on:': 'Lists',
            'skip:': 'Skip'
        };
        return (prefixLabels[prefix] || prefix) + ': ' + values.length;
    }

    window.__palette_chips = {
        create: createChipManager,
        mergePrefixes: chipMergePrefixes,
        singletonPrefixes: chipSingletonPrefixes
    };
})();
