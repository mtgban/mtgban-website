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

    // ── Client-side filter: filter edition cards by name ──
    var searchInput = document.querySelector('.sealed-search');
    if (searchInput) {
        searchInput.addEventListener('keyup', function(e) {
            // If Enter is pressed, submit as a sealed search query
            if (e.key === 'Enter') {
                var q = searchInput.value.trim();
                if (q) {
                    window.location.href = '/sealed?q=' + encodeURIComponent(q);
                }
                return;
            }

            var filter = searchInput.value.toUpperCase();
            var allSections = document.querySelectorAll('.sealed-section');

            allSections.forEach(function(section) {
                // Skip the FAQ section
                if (section.id === 'sealed-faq') return;

                var editions = section.querySelectorAll('.sealed-edition');
                var visibleCount = 0;

                editions.forEach(function(card) {
                    var text = card.textContent || card.innerText;
                    if (text.toUpperCase().indexOf(filter) > -1) {
                        card.classList.remove('hidden-by-filter');
                        visibleCount++;
                    } else {
                        card.classList.add('hidden-by-filter');
                    }
                });

                // Hide entire section if no editions match
                if (filter && visibleCount === 0) {
                    section.classList.add('hidden-by-filter');
                } else {
                    section.classList.remove('hidden-by-filter');
                }
            });
        });
    }

    // ── Surprise Me: navigate to a random sealed edition ──
    var surpriseBtn = document.getElementById('sealed-surprise');
    if (surpriseBtn) {
        surpriseBtn.addEventListener('click', function(e) {
            e.preventDefault();
            var editions = document.querySelectorAll('.sealed-edition:not(.hidden-by-filter)');
            if (editions.length) {
                var randomEdition = editions[Math.floor(Math.random() * editions.length)];
                window.location.href = randomEdition.href;
            }
        });
    }
})();
