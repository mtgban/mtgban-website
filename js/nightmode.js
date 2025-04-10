// Select the theme preference from localStorage
const themeSwitch = document.querySelector('input');
const themeTitle = document.querySelector('span[class="slider"]');

// Function to apply theme
function applyTheme(isDark) {
    if (isDark) {
        document.body.classList.add('dark-theme');
        themeSwitch.checked = true;
        themeTitle.title = "Nightbound";
    } else {
        document.body.classList.remove('dark-theme');
        themeSwitch.checked = false;
        themeTitle.title = "Daybound";
    }
}

// Initialize theme
function initTheme() {
    const savedTheme = localStorage.getItem("theme");
    
    if (savedTheme === "dark") {
        // Use saved dark preference
        applyTheme(true);
    } else if (savedTheme === "light") {
        // Use saved light preference
        applyTheme(false);
    } else {
        // No saved preference, check system preference
        const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
        applyTheme(prefersDark);
        localStorage.setItem("theme", prefersDark ? "dark" : "light");
    }
}

// Run initialization
initTheme();

// Handle toggle changes
themeSwitch.addEventListener('change', () => {
    document.body.classList.toggle('dark-theme');

    const isDark = document.body.classList.contains("dark-theme");
    themeTitle.title = isDark ? "Nightbound" : "Daybound";
    localStorage.setItem("theme", isDark ? "dark" : "light");
});