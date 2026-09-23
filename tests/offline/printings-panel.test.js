const { test, expect, beforeAll } = require('bun:test');
const fs = require('fs');
const path = require('path');

// The module assigns to `self`, the way js/autocomplete.js does, so the
// browser gets it from the script tag and this gets it from an eval.
let panel;
beforeAll(() => {
    const src = fs.readFileSync(path.join(__dirname, '../../js/printings-panel.js'), 'utf8');
    const scope = { self: {} };
    new Function('self', src)(scope.self);
    panel = scope.self.PrintingsPanel;
    expect(panel, 'expected js/printings-panel.js to export self.PrintingsPanel').toBeTruthy();
});

// The symbol row as getBoundingClientRect reports it.
const row = (top, height = 26, left = 181, width = 300) => ({
    top, bottom: top + height, left, width,
});

test('it hangs below the row when there is room, which is the point of it', () => {
    // Below is where Available In and Export sit - the boxes the panel is
    // meant to cover. It should take that side whenever it can.
    const at = panel.placement(row(640), 1005);
    expect(at.side).toBe('below');
    expect(at.top).toBe(640 + 26 + panel.ROW_GAP);
    expect(at.left).toBe(181);
    expect(at.width).toBe(300);
});

test('it takes the room that is actually there, not a fixed height', () => {
    // A tall window gives it its full size; a shorter one gives it what is
    // left, and the symbol list inside scrolls the difference. Guessing a
    // number here instead is what used to run the panel past the column.
    const roomy = panel.placement(row(640), 1400);
    expect(roomy.maxHeight).toBe(panel.MAX_HEIGHT);

    const tight = panel.placement(row(640), 880);
    expect(tight.maxHeight).toBe(880 - 666 - panel.EDGE_GAP);
    expect(tight.maxHeight).toBeLessThan(panel.MAX_HEIGHT);
});

test('it never runs past the bottom of the window', () => {
    // The whole reason it is fixed and placed from script: nothing else is
    // bounding it, so this has to.
    for (const viewportHeight of [1400, 1200, 1005, 900, 820, 760, 700, 640]) {
        const at = panel.placement(row(640), viewportHeight);
        if (at.side !== 'below') continue;
        expect(
            at.top + at.maxHeight,
            `panel runs ${at.top + at.maxHeight - viewportHeight}px past the bottom at ${viewportHeight}px tall`,
        ).toBeLessThanOrEqual(viewportHeight);
    }
});

test('it flips above the card only when below is too short to read', () => {
    // Above means over the card, away from the boxes it is meant to cover, so
    // it is a last resort - taken only when there is not enough room under
    // the row AND more room over it.
    const flipped = panel.placement(row(640), 700);
    expect(flipped.side).toBe('above');
    expect(flipped.top + flipped.maxHeight).toBeLessThanOrEqual(640 - panel.ROW_GAP);
    expect(flipped.top).toBeGreaterThanOrEqual(0);

    // Right at the threshold it is still below: MIN_HEIGHT is the least that
    // reads as a list, and exactly that much is enough.
    const atThreshold = panel.placement(row(640), 640 + 26 + panel.EDGE_GAP + panel.MIN_HEIGHT);
    expect(atThreshold.side).toBe('below');
    expect(atThreshold.maxHeight).toBe(panel.MIN_HEIGHT);
});

test('a row near the top of the window does not flip into negative space', () => {
    // Both sides cramped: with less room above than below it stays below
    // rather than placing itself off the top of the screen.
    const at = panel.placement(row(40), 300);
    expect(at.side).toBe('below');
    expect(at.top).toBeGreaterThan(0);
});

test('it never returns a negative height', () => {
    // Both sides cramped is the case that produces one: a window shorter
    // than the row's own offset makes `below` and `above` both negative, and
    // whichever side wins carries the negative through. Found by this test,
    // not by sweeping a browser - no real window is this short.
    const cases = [
        [640, 640], [640, 500], [640, 300], [640, 100],
        [10, 50], [5, 40], [20, 60], [30, 70], [0, 20],
    ];
    for (const [rowTop, viewportHeight] of cases) {
        const at = panel.placement(row(rowTop), viewportHeight);
        expect(
            at.maxHeight,
            `negative height (row at ${rowTop}, window ${viewportHeight}) - CSS drops it and the panel goes unbounded`,
        ).toBeGreaterThanOrEqual(0);
    }
});

test('Set Value stashes on how much room is left, monotonically', () => {
    // The old signal asked whether .sidebar-body was OVERFLOWING. That worked
    // when the body was content-sized and scrolled, but it now answers a
    // squeeze by collapsing the boxes inside it - Available In first, then
    // Export - so it stops overflowing as it gets smaller. Measured on a real
    // sealed page at a fixed card size, sweeping the window down: the body
    // overflowed at 125px of room, did NOT at 75px (Export had just been
    // collapsed away, taking the overflow with it), and did again at 25px.
    // The tables came out from behind the hover trigger and went back as the
    // window moved.
    //
    // Room is monotonic in the squeeze, so this asserts that: once it stashes,
    // it stays stashed all the way down.
    let seenStash = false;
    for (let room = 600; room >= 0; room -= 5) {
        const stash = panel.shouldStashSetValue(room);
        if (stash) seenStash = true;
        expect(
            !(seenStash && !stash),
            `un-stashed at ${room}px of room after stashing higher up - the trigger flickers as the window moves`,
        ).toBe(true);
    }
    expect(seenStash, 'expected it to stash at some point on the way down').toBe(true);
});

test('Set Value sits inline while the column still has room for it', () => {
    // Above the threshold the tables belong in the flow, where they are
    // readable without hovering anything.
    expect(panel.shouldStashSetValue(panel.MIN_BODY_FOR_SET_VALUE)).toBe(false);
    expect(panel.shouldStashSetValue(panel.MIN_BODY_FOR_SET_VALUE - 1)).toBe(true);
    expect(panel.shouldStashSetValue(400)).toBe(false);
    expect(panel.shouldStashSetValue(0)).toBe(true);
});
