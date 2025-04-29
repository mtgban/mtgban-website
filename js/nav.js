document.addEventListener('DOMContentLoaded', function() {
    const currentPath = window.location.pathname;
    const navItems = document.querySelectorAll('.nav-item');
    
    navItems.forEach(item => {
        const mainLink = item.querySelector('a').getAttribute('href');
        if (mainLink === currentPath) {
            item.classList.add('active');
            return;
        }
        
        const sublinks = item.querySelectorAll('.subpage-link');
        sublinks.forEach(sublink => {
            if (sublink.getAttribute('href') === currentPath) {
                item.classList.add('active');
                return;
            }
        });
    });
});