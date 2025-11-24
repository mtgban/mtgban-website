(function() {
    'use strict';

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initSidebarTabs);
    } else {
        initSidebarTabs();
    }

    function initSidebarTabs() {
        const sidebar = document.querySelector('.syntax-sidebar');
        if (!sidebar) return;

        const items = sidebar.querySelectorAll('.sidebar-item');
        const sections = document.querySelectorAll('.syntax-section');

        items.forEach(item => {
            item.addEventListener('click', () => {
                const sectionId = item.dataset.section;
                
                // Update active states
                items.forEach(i => i.classList.remove('active'));
                sections.forEach(s => s.classList.remove('active'));
                
                item.classList.add('active');
                const targetSection = document.getElementById('section-' + sectionId);
                if (targetSection) {
                    targetSection.classList.add('active');
                }
            });
        });
    }
})();