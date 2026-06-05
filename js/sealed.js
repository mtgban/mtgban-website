(function() {
    // ── Scroll spy: highlight TOC item for currently visible section ──
    var sections = document.querySelectorAll('.sealed-section');
    var tocItems = document.querySelectorAll('.sealed-toc-item');

    if (sections.length && tocItems.length) {
        // Track which sections are currently intersecting
        var visibleSections = new Set();

        var observer = new IntersectionObserver(function(entries) {
            entries.forEach(function(entry) {
                if (entry.isIntersecting) {
                    visibleSections.add(entry.target.id);
                } else {
                    visibleSections.delete(entry.target.id);
                }
            });

            // Find the topmost visible section (by DOM order)
            var activeId = null;
            for (var i = 0; i < sections.length; i++) {
                if (visibleSections.has(sections[i].id)) {
                    activeId = sections[i].id;
                    break;
                }
            }

            if (activeId) {
                tocItems.forEach(function(item) { item.classList.remove('active'); });
                var target = document.querySelector('.sealed-toc-item[href="#' + activeId + '"]');
                if (target) target.classList.add('active');
            }
        }, { rootMargin: '-150px 0px -60% 0px', threshold: 0 });

        sections.forEach(function(section) { observer.observe(section); });

        // Smooth scroll on TOC click
        tocItems.forEach(function(item) {
            item.addEventListener('click', function(e) {
                e.preventDefault();
                var target = document.querySelector(item.getAttribute('href'));
                if (target) target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            });
        });
    }
})();
