// Edition combobox: typeahead replacement for the newspaper page's edition select.
(function () {
    'use strict';

    function init(combobox) {
        const display = combobox.querySelector('[data-role="display"]');
        const hidden = combobox.querySelector('[data-role="hidden"]');
        const clearBtn = combobox.querySelector('[data-role="clear"]');
        const items = combobox.querySelector('.autocomplete-items');
        if (!display || !hidden || !items) return;

        const itemEls = Array.from(items.querySelectorAll('[data-name]'));
        let activeIndex = -1;

        function visibleItems() {
            return itemEls.filter(el => el.style.display !== 'none');
        }

        function open() {
            combobox.classList.add('is-open');
            combobox.setAttribute('aria-expanded', 'true');
            items.scrollTop = 0;
            activeIndex = -1;
            updateActive();
        }

        function close() {
            combobox.classList.remove('is-open');
            combobox.setAttribute('aria-expanded', 'false');
            activeIndex = -1;
            updateActive();
        }

        function filter() {
            const q = display.value.trim().toLowerCase();
            itemEls.forEach(el => {
                const name = (el.dataset.name || '').toLowerCase();
                el.style.display = (!q || name.indexOf(q) >= 0) ? '' : 'none';
            });
            activeIndex = -1;
            updateActive();
        }

        function updateActive() {
            itemEls.forEach(el => el.classList.remove('autocomplete-active'));
            const vis = visibleItems();
            if (activeIndex >= 0 && activeIndex < vis.length) {
                vis[activeIndex].classList.add('autocomplete-active');
                vis[activeIndex].scrollIntoView({ block: 'nearest' });
            }
        }

        function select(name) {
            display.value = name;
            hidden.value = name;
            if (clearBtn) clearBtn.hidden = !name;
            const form = combobox.closest('form');
            if (form) form.submit();
        }

        function clearSelection() {
            display.value = '';
            hidden.value = '';
            if (clearBtn) clearBtn.hidden = true;
            const form = combobox.closest('form');
            if (form) form.submit();
        }

        display.addEventListener('focus', () => { filter(); open(); });

        display.addEventListener('input', () => {
            filter();
            if (!combobox.classList.contains('is-open')) open();
        });

        display.addEventListener('keydown', (e) => {
            const vis = visibleItems();
            if (e.key === 'ArrowDown') {
                e.preventDefault();
                if (!combobox.classList.contains('is-open')) open();
                if (vis.length === 0) return;
                activeIndex = (activeIndex + 1) % vis.length;
                updateActive();
            } else if (e.key === 'ArrowUp') {
                e.preventDefault();
                if (vis.length === 0) return;
                activeIndex = activeIndex <= 0 ? vis.length - 1 : activeIndex - 1;
                updateActive();
            } else if (e.key === 'Enter') {
                if (activeIndex >= 0 && vis[activeIndex]) {
                    e.preventDefault();
                    select(vis[activeIndex].dataset.name);
                }
            } else if (e.key === 'Escape') {
                e.preventDefault();
                close();
                display.blur();
            }
        });

        // mousedown on items: prevent display from losing focus before click fires
        items.addEventListener('mousedown', (e) => { e.preventDefault(); });

        items.addEventListener('click', (e) => {
            const el = e.target.closest('[data-name]');
            if (!el) return;
            select(el.dataset.name);
        });

        display.addEventListener('blur', () => { setTimeout(close, 120); });

        if (clearBtn) {
            clearBtn.addEventListener('mousedown', (e) => { e.preventDefault(); });
            clearBtn.addEventListener('click', (e) => {
                e.preventDefault();
                clearSelection();
            });
            clearBtn.hidden = !display.value;
        }
    }

    document.addEventListener('DOMContentLoaded', () => {
        document.querySelectorAll('.edition-combobox').forEach(init);
    });
})();
