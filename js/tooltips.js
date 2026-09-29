// Every [title] on the page shows its text the moment the pointer is over
// it, in place of the browser's own tooltip, which waits a second and cannot
// be styled. The title, and any title on the elements it sits in, move to
// data-ban-title while the tooltip is up and come back when the pointer
// leaves: code that reads a title can fall back to data-ban-title, and code
// that removes one should remove both. Loaded after the other scripts, so
// their setup finds every title where it was.

// Pixels kept between the tooltip and the viewport edge, and between the
// tooltip and its element.
var BAN_TOOLTIP_MARGIN = 8;
var BAN_TOOLTIP_GAP = 6;

// banTooltipPlace returns where a tooltip of the given size goes for an
// element at rect (viewport coordinates): centred above it, or below it when
// there is no room above, kept inside the viewport's width.
function banTooltipPlace(rect, width, height, viewportWidth) {
    var below = rect.top - BAN_TOOLTIP_GAP - height < BAN_TOOLTIP_MARGIN;
    var top = below ? rect.bottom + BAN_TOOLTIP_GAP : rect.top - BAN_TOOLTIP_GAP - height;
    var left = rect.left + rect.width / 2 - width / 2;
    left = Math.min(left, viewportWidth - BAN_TOOLTIP_MARGIN - width);
    left = Math.max(left, BAN_TOOLTIP_MARGIN);
    return { left: left, top: top, below: below };
}

function installTitleTooltips(document, window) {
    var tip = null;
    var current = null;
    var observer = null;
    // current's titled ancestors, whose titles go aside with its own: the
    // browser shows the nearest title left under the pointer, a second late.
    var ancestors = [];
    // Set when the title is all that names the element (an icon), so it names
    // it as aria-label while it is aside.
    var labelled = false;
    // Set when the title describes an element named some other way, and
    // nothing else describes it, so the tooltip does while the title is aside.
    var described = false;

    function place() {
        // Measured from the corner: where the last tooltip sat would narrow
        // this one to the room that one left.
        tip.style.left = '0px';
        tip.style.top = '0px';
        var spot = banTooltipPlace(current.getBoundingClientRect(), tip.offsetWidth,
            tip.offsetHeight, document.documentElement.clientWidth);
        tip.style.left = spot.left + 'px';
        tip.style.top = spot.top + 'px';
    }

    function setAside(el, text) {
        el.setAttribute('data-ban-title', text);
        el.removeAttribute('title');
    }

    // Puts a title back unless the page set a new one or dropped it.
    function putBack(el) {
        var text = el.getAttribute('data-ban-title');
        if (text !== null && !el.hasAttribute('title')) {
            el.setAttribute('title', text);
        }
        el.removeAttribute('data-ban-title');
    }

    // Moves the title aside and shows it; a blank one shows nothing.
    function take(text) {
        setAside(current, text);
        if (labelled) {
            current.setAttribute('aria-label', text);
        }
        tip.textContent = text;
        tip.hidden = !text.trim();
        place();
    }

    // A script setting the title while the tooltip is up (a "Copied!" after a
    // click) takes over from the one being shown.
    function retitle() {
        var text = current.getAttribute('title');
        if (text !== null) {
            take(text);
        }
    }

    // A click or Escape puts the tooltip away but keeps the title aside until
    // the pointer leaves, so the browser's own tooltip does not pop up instead.
    function dismiss() {
        if (tip) {
            tip.hidden = true;
        }
    }

    function show(el) {
        var text = el.getAttribute('title');
        if (!text || !text.trim()) {
            return;
        }
        if (!tip) {
            tip = document.createElement('div');
            tip.id = 'ban-tooltip';
            tip.setAttribute('role', 'tooltip');
            document.body.appendChild(tip);
        }
        current = el;
        labelled = !el.hasAttribute('aria-label') && !el.textContent.trim();
        described = !labelled && !el.hasAttribute('aria-describedby');
        if (described) {
            el.setAttribute('aria-describedby', tip.id);
        }
        take(text);
        for (var up = el.parentElement; up; up = up.parentElement) {
            if (up.hasAttribute('title')) {
                setAside(up, up.getAttribute('title'));
                ancestors.push(up);
            }
        }
        observer = new window.MutationObserver(retitle);
        observer.observe(el, { attributes: true, attributeFilter: ['title'] });
    }

    function hide() {
        if (!current) {
            return;
        }
        observer.disconnect();
        putBack(current);
        ancestors.forEach(putBack);
        ancestors = [];
        if (labelled) {
            current.removeAttribute('aria-label');
        }
        if (described) {
            current.removeAttribute('aria-describedby');
        }
        current = null;
        tip.hidden = true;
    }

    document.addEventListener('pointerover', function (e) {
        if (e.pointerType === 'touch' || !e.target.closest) {
            return;
        }
        var el = e.target.closest('[title]');
        if (current && current.contains(e.target) && !(el && el !== current && current.contains(el))) {
            return;
        }
        hide();
        if (el) {
            show(el);
        }
    }, true);

    document.addEventListener('pointerout', function (e) {
        if (current && !(e.relatedTarget && current.contains(e.relatedTarget))) {
            hide();
        }
    }, true);

    document.addEventListener('pointerdown', dismiss, true);
    document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape') {
            dismiss();
        }
    });
    window.addEventListener('scroll', hide, true);
    window.addEventListener('blur', hide);
}

installTitleTooltips(document, window);
