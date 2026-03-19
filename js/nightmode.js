// Select the theme preference from localStorage
const toggle = document.getElementById('theme-toggle');
const stored = localStorage.getItem('theme');
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

// If there is no local value, follow the system preference
let theme = stored || (prefersDark ? 'dark' : 'light');
document.body.classList.toggle('dark-theme', theme === 'dark');
toggle.title = theme === 'dark' ? 'Nightbound' : 'Daybound';

toggle.addEventListener('click', () => {
    theme = theme === 'dark' ? 'light' : 'dark';

    document.body.classList.toggle('dark-theme', theme === 'dark');

    toggle.title = theme === 'dark' ? 'Nightbound' : 'Daybound';
    localStorage.setItem("theme", theme);
});
