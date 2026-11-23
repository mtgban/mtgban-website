// Typing on a page while no field has the caret starts a new search:
// the key moves focus to the search box, selected, so the character
// the browser then types replaces the old query. A paste there goes
// into the box the same way.
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
    // search-sidebar.js asks the same before its backpack keys
    window.banDialogOpen = dialogOpen;

    // The search box input aimed at t should go to, null where t's own
    // field, an open dialog or a hidden box rules it out.
    function boxFor(t) {
        if (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName)) return null;
        if (dialogOpen()) return null;
        var box = document.getElementById('searchbox') || document.getElementById('nav-searchbox');
        return box && box.checkVisibility() ? box : null;
    }

    document.addEventListener('keydown', function(e) {
        if (e.defaultPrevented || e.isComposing || e.metaKey) return;
        // AltGr arrives as Ctrl+Alt on Windows, and it types characters.
        if (e.ctrlKey && !e.getModifierState('AltGraph')) return;
        // Printable keys only. Space still scrolls the page and "/"
        // still opens the command palette.
        if (e.key.length !== 1 || e.key === ' ' || e.key === '/') return;
        var box = boxFor(e.target);
        if (!box) return;
        if (window.BAN && window.BAN.track) window.BAN.track('ui.key', 'type_to_focus');
        box.focus();
        box.setSelectionRange(0, box.value.length);
    });

    document.addEventListener('paste', function(e) {
        if (e.defaultPrevented || !e.clipboardData) return;
        var text = e.clipboardData.getData('text/plain').replace(/\s+/g, ' ').trim();
        if (!text) return;
        var box = boxFor(e.target);
        if (!box) return;
        e.preventDefault();
        if (window.BAN && window.BAN.track) window.BAN.track('ui.key', 'paste_to_search');
        box.focus();
        box.setSelectionRange(0, box.value.length);
        // Unlike setting value, this keeps maxlength and undo, and fires
        // the input event the autocomplete listens for.
        if (document.execCommand('insertText', false, text)) return;
        box.value = box.maxLength > 0 ? text.slice(0, box.maxLength) : text;
        box.dispatchEvent(new Event('input', {bubbles: true}));
    });
})();
