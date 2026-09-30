(function () {
    // Card-action icons collapse into a kebab dropdown in the single-column
    // layout (see .qi-toggle / .qi-actions in search.css). Give each action a
    // visible text label from its title, and wire the toggle open/close.
    var groups = document.querySelectorAll('.result-quick-icons');
    if (!groups.length) return;

    groups.forEach(function (group) {
        var toggle = group.querySelector('.qi-toggle');
        var actions = group.querySelector('.qi-actions');
        if (!toggle || !actions) return;

        actions.querySelectorAll(':scope > a, :scope > span, :scope > button').forEach(function (el) {
            var title = el.getAttribute('title');
            if (!title || el.querySelector('.qi-label')) return;
            var label = document.createElement('span');
            label.className = 'qi-label';
            label.textContent = title;
            el.appendChild(label);
        });

        function close() {
            group.classList.remove('qi-open');
            toggle.setAttribute('aria-expanded', 'false');
        }

        toggle.addEventListener('click', function (e) {
            e.stopPropagation();
            var open = !group.classList.contains('qi-open');
            // Only one menu open at a time.
            groups.forEach(function (g) {
                g.classList.remove('qi-open');
                var t = g.querySelector('.qi-toggle');
                if (t) t.setAttribute('aria-expanded', 'false');
            });
            if (open) {
                group.classList.add('qi-open');
                toggle.setAttribute('aria-expanded', 'true');
            }
        });

        // Picking an action dismisses the menu.
        actions.addEventListener('click', close);
    });

    // Click anywhere else closes any open menu.
    document.addEventListener('click', function () {
        groups.forEach(function (g) {
            g.classList.remove('qi-open');
            var t = g.querySelector('.qi-toggle');
            if (t) t.setAttribute('aria-expanded', 'false');
        });
    });
})();
