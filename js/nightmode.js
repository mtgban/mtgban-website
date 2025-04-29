const themeSwitch = document.querySelector('#nightmode-toggle');
const themeTitle = document.querySelector('span[class="slider"]');

function setTheme(darkMode) {
    themeSwitch.checked = darkMode;
    document.body.classList.toggle('dark-theme', darkMode);
    themeTitle.title = darkMode ? "Nightbound" : "Daybound";
}

const savedTheme = localStorage.getItem("theme");
if (savedTheme) {
    setTheme(savedTheme === "dark");
} else {
    const prefersDarkMode = window.matchMedia('(prefers-color-scheme: dark)').matches;
    setTheme(prefersDarkMode);
}

themeSwitch.addEventListener('change', () => {
    const isDarkMode = themeSwitch.checked;
    setTheme(isDarkMode);
    localStorage.setItem("theme", isDarkMode ? "dark" : "light");
});


window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
    if (localStorage.getItem("theme") === null) {
        setTheme(e.matches);
    }
});
