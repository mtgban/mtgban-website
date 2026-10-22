// Typing on a page while no field has the caret starts a new search:
// the key moves focus to the search box, selected, so the character
// the browser then types replaces the old query.
(function() {
    // Without it an open dialog can't be told apart from a closed one.
    if (typeof Element.prototype.checkVisibility !== 'function') return;

    // An open dialog keeps its keys, even with focus left on the page.
    // Closed ones are display: none, visibility: hidden or opacity: 0,
    // on themselves or on an ancestor.
    function dialogOpen() {
        var dialogs = document.querySelectorAll('[role="dialog"], dialog[open]');
        for (var i = 0; i < dialogs.length; i++) {
            if (dialogs[i].checkVisibility({opacityProperty: true, visibilityProperty: true})) return true;
        }
        return false;
    }

    document.addEventListener('keydown', function(e) {
        if (e.defaultPrevented || e.isComposing || e.metaKey) return;
        // AltGr arrives as Ctrl+Alt on Windows, and it types characters.
        if (e.ctrlKey && !e.getModifierState('AltGraph')) return;
        // Printable keys only. Space still scrolls the page and "/"
        // still opens the command palette.
        if (e.key.length !== 1 || e.key === ' ' || e.key === '/') return;
        var t = e.target;
        if (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return;
        if (dialogOpen()) return;
        var box = document.getElementById('searchbox') || document.getElementById('nav-searchbox');
        if (!box || !box.checkVisibility()) return;
        box.focus();
        box.setSelectionRange(0, box.value.length);
    });
})();
