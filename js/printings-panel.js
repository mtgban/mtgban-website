/* Where the editions overflow panel goes.
 *
 * The panel is position: fixed, which is the only way it escapes being
 * clipped: every box between it and the viewport either is a scroll box or
 * can become one, and an absolutely positioned panel is clipped by the first
 * of them. Fixed leaves it with no offsets of its own, so this decides them.
 *
 * Kept apart from the DOM work in templates/search.html so the arithmetic can
 * be tested without a browser - the part with the edge cases in it is the
 * part that decides which side of the row to hang from, and that is all
 * numbers. */

(function () {
    // What the panel is comfortable at, and the least it can be and still
    // read as a list of symbols rather than a sliver.
    var MAX_HEIGHT = 260;
    var MIN_HEIGHT = 120;
    // Clear of the row it hangs from, and of the window's own edge.
    var ROW_GAP = 6;
    var EDGE_GAP = 18;

    /* Given the symbol row's rectangle and the window's height, where the
     * panel goes. Returns viewport coordinates, ready for style.top et al.
     *
     * Below the row by default: that is where the boxes this is meant to
     * cover are. It goes above only when there is not enough room under the
     * row to read it AND there is more room over the card - which on this
     * column means a window too short to be showing those boxes anyway. */
    function placement(row, viewportHeight) {
        var below = viewportHeight - row.bottom - EDGE_GAP;
        var above = row.top - EDGE_GAP;
        var common = { left: row.left, width: row.width };

        if (below < MIN_HEIGHT && above > below) {
            // Floored at zero. A window shorter than the row's own offset
            // makes both of these negative, and a negative max-height is not
            // a short panel - it is an invalid declaration, dropped, leaving
            // the panel unbounded, which is the one thing placing it from
            // script is here to prevent. Collapsing is the honest failure.
            var room = Math.max(0, Math.min(MAX_HEIGHT, above));
            common.side = 'above';
            common.top = row.top - ROW_GAP - room;
            common.maxHeight = room;
            return common;
        }

        common.side = 'below';
        common.top = row.bottom + ROW_GAP;
        // Whatever is actually left under the row, capped at the size the
        // panel is comfortable at. The symbol list inside takes the
        // difference as a scroll, so a short window costs a scroll rather
        // than a cut.
        common.maxHeight = Math.max(0, Math.min(MAX_HEIGHT, below));
        return common;
    }

    self.PrintingsPanel = {
        placement: placement,
        MAX_HEIGHT: MAX_HEIGHT,
        MIN_HEIGHT: MIN_HEIGHT,
        ROW_GAP: ROW_GAP,
        EDGE_GAP: EDGE_GAP,
    };
})();
