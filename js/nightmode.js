// Theme preference: 'light' | 'dark' | 'system' (unset behaves as 'system').
// 'system' follows the OS prefers-color-scheme and updates live. The toggle
// cycles through all three states (see cycle() for the OS-aware order). The
// current preference is mirrored onto <body data-theme-pref> so the CSS can
// show the matching icon.
(function () {
    var KEY = 'theme';
    var TITLES = { light: 'Daybound', dark: 'Nightbound', system: 'Match system' };
    var mq = window.matchMedia('(prefers-color-scheme: dark)');

    function pref() {
        var v = localStorage.getItem(KEY);
        return (v === 'light' || v === 'dark' || v === 'system') ? v : 'system';
    }

    function resolve(p) {
        p = p || pref();
        if (p === 'system') return mq.matches ? 'dark' : 'light';
        return p;
    }

    function apply(p) {
        p = p || pref();
        var resolved = resolve(p);
        document.body.classList.toggle('dark-theme', resolved === 'dark');
        document.body.classList.toggle('light-theme', resolved === 'light');
        document.body.setAttribute('data-theme-pref', p);
        document.querySelectorAll('.ban-theme-toggle').forEach(function (b) {
            b.title = TITLES[p];
        });
    }

    function set(p) {
        localStorage.setItem(KEY, p);
        apply(p);
    }

    // Cycle through all three states, but always leave 'system' by flipping
    // away from what it currently shows, so the first tap is a visible change:
    //   OS light  ->  system -> dark  -> light -> system
    //   OS dark   ->  system -> light -> dark  -> system
    function cycle() {
        var p = pref();
        var sysDark = mq.matches;
        var next;
        if (p === 'system') {
            next = sysDark ? 'light' : 'dark';
        } else if (sysDark) {
            next = p === 'light' ? 'dark' : 'system';
        } else {
            next = p === 'dark' ? 'light' : 'system';
        }
        set(next);
        return next;
    }

    // Apply immediately so the theme is correct before the rest of the page paints.
    apply();

    // Keep 'system' in sync with live OS changes.
    mq.addEventListener('change', function () {
        if (pref() === 'system') apply();
    });

    // Wire every theme toggle on the page (navbar, landing, etc.).
    document.querySelectorAll('.ban-theme-toggle').forEach(function (btn) {
        btn.addEventListener('click', cycle);
    });

    window.BANTheme = { pref: pref, resolve: resolve, apply: apply, set: set, cycle: cycle };
})();
