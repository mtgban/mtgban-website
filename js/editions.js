(function() {
    'use strict';
    
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', initEditionsSidebar);
    } else {
        initEditionsSidebar();
    }

    function initEditionsSidebar() {
        // Toggle button setup
        const toggleBtn = document.querySelector('.editions-toggle');
        if (toggleBtn) {
            toggleBtn.addEventListener('click', function() {
                const sidebar = document.getElementById('editions-sidebar');
                sidebar.classList.toggle('expanded');
                this.classList.toggle('active');
            });
        }

        // Close sidebar when clicking a category on mobile
        document.querySelectorAll('#editions-sidebar .sidebar-item').forEach(item => {
            item.addEventListener('click', () => {
                if (window.innerWidth <= 768) {
                    document.getElementById('editions-sidebar').classList.remove('expanded');
                    document.querySelector('.editions-toggle')?.classList.remove('active');
                }
            });
        });

        // Sidebar navigation for editions
        document.querySelectorAll('.sidebar-item[data-group="editions"]').forEach(item => {
            item.addEventListener('click', () => {
                const container = item.closest('.syntax-body');
                container.querySelectorAll('.sidebar-item').forEach(i => i.classList.remove('active'));
                container.querySelectorAll('.syntax-section').forEach(s => s.classList.remove('active'));
                item.classList.add('active');
                document.getElementById('section-' + item.dataset.section).classList.add('active');
            });
        });

        // Filter function
        const filterInput = document.getElementById('filterInput');
        if (filterInput) {
            filterInput.addEventListener('keyup', function() {
                const filter = this.value.toLowerCase();
                document.querySelectorAll('.edition-item').forEach(item => {
                    const text = item.textContent.toLowerCase();
                    item.style.display = text.includes(filter) ? '' : 'none';
                });
            });
        }
    }
})();