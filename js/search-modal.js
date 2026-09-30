(function() {
    var chartCtx = window.BAN_SEARCH_MODAL.ids;

    // Mirror localStorage.theme into the iframe body. The 'storage' event fires
    // in other same-origin documents when the parent's nightmode.js writes a
    // new value, so toggling the navbar moon button while the modal is open
    // flips the iframe content with it.
    function applyTheme() {
        // Resolve 'light' | 'dark' | 'system' the same way base-landing and
        // nightmode.js do — a bare truthiness check treats 'system' as light,
        // so a system-theme user on a dark OS would get a light iframe.
        var v = localStorage.getItem('theme');
        var pref = (v === 'light' || v === 'dark' || v === 'system') ? v : 'system';
        var dark = pref === 'dark' || (pref === 'system' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches);
        document.body.classList.toggle('dark-theme', dark);
        document.body.classList.toggle('light-theme', !dark);
    }
    applyTheme();
    window.addEventListener('storage', function(e) {
        if (e.key === 'theme' || e.key === null) applyTheme();
    });

    // Tag every same-origin link to /search or /sealed (including bare ?q=...)
    // with modal=1 and the active chart roster, so clicking around inside the
    // modal keeps the iframe in modal mode instead of escaping to a full page.
    function decorate() {
        document.querySelectorAll('a[href]').forEach(function(a) {
            if (a.dataset.modalDecorated === '1') return;
            var raw = a.getAttribute('href');
            if (!raw) return;
            if (raw.charAt(0) === '#') return;
            if (a.target === '_blank') return;
            // Parsed rather than pattern-matched: naming "javascript:" alone
            // left "data:" and "vbscript:" through, and sameSiteURL settles
            // the scheme and the origin in one answer. What it hands back is
            // already absolute, so building a URL from it cannot throw.
            var safe = sameSiteURL(raw);
            if (!safe) return;
            var url = new URL(safe);
            if (!/^\/(search|sealed)\/?$/.test(url.pathname)) return;
            if (chartCtx && !url.searchParams.has('chart')) {
                url.searchParams.set('chart', chartCtx);
            }
            url.searchParams.set('modal', '1');
            a.href = url.toString();
            a.dataset.modalDecorated = '1';
        });
    }
    decorate();
    new MutationObserver(decorate).observe(document.body, { childList: true, subtree: true });

    // Clicking a card's chart +/- batches it instead of committing immediately:
    // update the shared pending roster, flip the row control, toast, and let the
    // parent refresh its "Update chart" counter. The user commits from there.
    function setChartRowState(a, added) {
        if (added) {
            a.classList.remove('chart-add-link');
            a.classList.add('chart-remove-link');
            a.title = 'Remove from this chart';
            a.innerHTML = '&#128200;&#10134;';
        } else {
            a.classList.remove('chart-remove-link');
            a.classList.add('chart-add-link');
            a.title = 'Add to this chart';
            a.innerHTML = '&#128200;&#10133;';
        }
    }
    var chartToastEl;
    function showChartToast(msg) {
        if (!chartToastEl) {
            chartToastEl = document.createElement('div');
            chartToastEl.style.cssText = 'position:fixed;left:50%;bottom:18px;transform:translateX(-50%);background:rgba(0,0,0,0.85);color:#fff;padding:8px 16px;border-radius:999px;font-size:13px;z-index:99999;pointer-events:none;opacity:0;transition:opacity 0.2s;';
            document.body.appendChild(chartToastEl);
        }
        chartToastEl.textContent = msg;
        chartToastEl.style.opacity = '1';
        clearTimeout(chartToastEl._t);
        chartToastEl._t = setTimeout(function(){ chartToastEl.style.opacity = '0'; }, 1500);
    }
    document.addEventListener('click', function(e) {
        var add = e.target.closest('a.chart-add-link');
        var rm = e.target.closest('a.chart-remove-link');
        var a = add || rm;
        if (!a) return;
        var cardId = a.getAttribute('data-card-id');
        if (!cardId) return;
        e.preventDefault();

        var pending = (localStorage.getItem('chartAddPending') || '').split(',').filter(Boolean);
        var idx = pending.indexOf(cardId);
        var added = !!add;
        if (added) {
            if (idx === -1) {
                // Match the server-side cap so an over-cap card isn't silently
                // dropped on commit: refuse the add here and say why.
                if (pending.length >= window.BAN_SEARCH_MODAL.maxCards) {
                    showChartToast('Charts hold up to ' + window.BAN_SEARCH_MODAL.maxCards + ' cards');
                    return;
                }
                pending.push(cardId);
            }
        } else if (idx !== -1) {
            pending.splice(idx, 1);
        }
        localStorage.setItem('chartAddPending', pending.join(','));
        setChartRowState(a, added);

        var row = a.closest('[data-card-name]');
        var name = row ? (row.getAttribute('data-card-name') || 'Card') : 'Card';
        showChartToast(name + (added ? ' added to chart batch' : ' removed from chart batch'));

        if (window.parent && window.parent !== window) {
            window.parent.postMessage({ type: 'chart-batch-changed' }, window.location.origin);
        }
    });
})();
