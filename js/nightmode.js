// Select the theme preference from localStorage
const toggle = document.getElementById('theme-toggle');
const slider = document.querySelector('span.slider');
const stored = localStorage.getItem('theme');
const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;

// If there is no local value, follow the system preference
let theme = stored || (prefersDark ? 'dark' : 'light');
document.body.classList.toggle('dark-theme', theme === 'dark');
toggle.checked = (theme === 'dark');
slider.title = theme === 'dark' ? 'Nightbound' : 'Daybound';

toggle.addEventListener('change', () => {
    theme = toggle.checked ? 'dark' : 'light';

    document.body.classList.toggle('dark-theme', theme === 'dark');

    slider.title = theme === 'dark' ? 'Nightbound' : 'Daybound';
    // Then save the choice in localStorage
    localStorage.setItem("theme", theme);
});
