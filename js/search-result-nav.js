(function() {
    var headers = document.querySelectorAll('.result-header');
    if (headers.length === 0) return;

    var searchbox = document.getElementById('searchbox') || document.getElementById('nav-searchbox');

    function stickyOffset() {
        var navbar = document.querySelector('.navbar-v2');
        var navHeight = navbar ? navbar.getBoundingClientRect().height :
            parseFloat(getComputedStyle(document.body).getPropertyValue('--nav-height'));
        var cover = document.querySelector('.result-header-cover');
        var coverHeight = cover ? cover.getBoundingClientRect().height : 21;
        return (Number.isFinite(navHeight) ? navHeight : 56) + coverHeight;
    }
    var currentIdx = 0;

    document.addEventListener('keydown', function(e) {
        // Tab: focus the search input
        if (e.key === 'Tab' && searchbox) {
            var tag = e.target.tagName;
            if (tag !== 'INPUT' && tag !== 'TEXTAREA') {
                e.preventDefault();
                searchbox.focus();
                searchbox.setSelectionRange(0, searchbox.value.length);
                return;
            }
        }

        // Escape: blur the search input. Inside the chart "Add a card"
        // modal, a second Escape (input already blurred) asks the parent
        // page to close the modal — keydown events don't cross the iframe
        // boundary, so the modal can only be dismissed from in here.
        if (e.key === 'Escape' && searchbox) {
            if (document.activeElement === searchbox) {
                searchbox.blur();
                return;
            }
            if (window.parent && window.parent !== window) {
                window.parent.postMessage({ type: 'chart-modal-close' }, window.location.origin);
            }
            return;
        }

        // Allow PgUp/PgDn to scroll even when searchbox is focused
        if (e.key !== 'PageDown' && e.key !== 'PageUp') {
            var tag = e.target.tagName;
            if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
            if (e.target.isContentEditable) return;
        }

        if (e.key === 'PageDown') {
            e.preventDefault();
            if (currentIdx < headers.length - 1) {
                currentIdx++;
            }
            // Scroll so the target header lands exactly at its sticky position
            var delta = headers[currentIdx].getBoundingClientRect().top - stickyOffset();
            window.scrollBy(0, delta);
        } else if (e.key === 'PageUp') {
            e.preventDefault();
            if (currentIdx <= 0) {
                currentIdx = 0;
                window.scrollTo(0, 0);
                return;
            }
            currentIdx--;
            // Stuck headers report rect.top=77 (sticky position), so
            // briefly scroll to top to measure the natural position
            var saved = window.scrollY;
            window.scrollTo(0, 0);
            var target = headers[currentIdx].getBoundingClientRect().top - stickyOffset();
            window.scrollTo(0, target);
        }

        // Drive the sidebar to the newly current header. Trusted: the
        // capture-phase keydown listener in search-sidebar.js just set
        // __lastKey, which would otherwise read as a phantom hover.
        if (typeof window.showHoverFor === 'function') window.showHoverFor(headers[currentIdx], true);
    });

    // Rows sliding under a still cursor never produce a mouseenter: browsers
    // recompute :hover on scroll but only synthesize pointer events on the
    // next real move, so the sidebar used to stay on whatever was hovered
    // last until the mouse was wiggled. Hit-test the pointer ourselves each
    // scroll frame and drive the row it actually lands on.
    var lastPointerTarget = null;
    function hoverRowUnderPointer() {
        if (typeof __mx !== 'number' || typeof __my !== 'number') return false;
        var el = document.elementFromPoint(__mx, __my);
        var row = el && el.closest ? el.closest('.result-header, .result-body') : null;
        if (!row || typeof window.showHoverFor !== 'function') {
            lastPointerTarget = null;
            return false;
        }
        if (row !== lastPointerTarget) {
            lastPointerTarget = row;
            window.showHoverFor(row, true);
        }
        return true;
    }

    // Update sidebar image when scrolling naturally
    var lastStuckIdx = -1;
    var scrollTick = false;
    window.addEventListener('scroll', function() {
        if (scrollTick) return;
        scrollTick = true;
        requestAnimationFrame(function() {
            scrollTick = false;
            var pointerHandled = hoverRowUnderPointer();
            // Find the last header that is stuck (rect.top ≈ sticky position)
            var stuckIdx = -1;
            var off = stickyOffset();
            for (var i = headers.length - 1; i >= 0; i--) {
                if (headers[i].getBoundingClientRect().top <= off + 2) {
                    stuckIdx = i;
                    break;
                }
            }
            if (stuckIdx >= 0 && stuckIdx !== lastStuckIdx) {
                lastStuckIdx = stuckIdx;
                currentIdx = stuckIdx;
                // Keyboard paging still needs currentIdx tracked, but the
                // row under the pointer wins the sidebar when there is one.
                if (!pointerHandled && typeof window.showHoverFor === 'function') {
                    window.showHoverFor(headers[stuckIdx], false);
                }
            }
        });
    });
})();
