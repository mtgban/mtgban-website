// Every [title] on the page shows its text the moment the pointer is over
// it, in place of the browser's own tooltip, which waits a second and cannot
// be styled. The title, and any title on the elements it sits in, move to
// data-ban-title while the tooltip is up and come back when the pointer
// leaves: code that reads a title can fall back to data-ban-title, and code
// that removes one should remove both. Loaded after the other scripts, so
// their setup finds every title where it was.
//
// An element may also carry data-tip, the same text with **marks** around
// what the tooltip sets in bold, and with tables: a line starting with | is a
// row of cells split on |, and one starting with |# a header row, which
// starts a new table. A table with a header sets its other columns as
// numbers, one without sets its first column as labels, and the text after a
// table is its footnote. Its title stays plain, the tables as sentences, for
// screen readers and for the browser's own tooltip (templates.go writes
// both).

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

// banTipBlocks splits a data-tip into its tables and the runs of lines
// around them.
function banTipBlocks(text) {
    var blocks = [];
    text.split('\n').forEach(function (line) {
        var last = blocks[blocks.length - 1];
        if (line.indexOf('|#') === 0) {
            blocks.push({ table: true, header: banTipCells(line.slice(2)), rows: [] });
        } else if (line.charAt(0) === '|') {
            if (!last || !last.table) {
                last = { table: true, header: null, rows: [] };
                blocks.push(last);
            }
            last.rows.push(banTipCells(line.slice(1)));
        } else {
            if (!last || last.table) {
                last = { table: false, lines: [] };
                blocks.push(last);
            }
            last.lines.push(line);
        }
    });
    return blocks;
}

function banTipCells(row) {
    return row.split('|').map(function (cell) {
        return cell.trim();
    });
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

    // Appends text to parent, what sits between ** marks in bold. It builds
    // text nodes, so nothing in the text is ever read as markup.
    function appendBold(parent, text) {
        text.split('**').forEach(function (part, i) {
            if (!part) {
                return;
            }
            var node = document.createTextNode(part);
            if (i % 2) {
                var bold = document.createElement('strong');
                bold.appendChild(node);
                node = bold;
            }
            parent.appendChild(node);
        });
    }

    // A table row of cells: after a header's first column numbers, a label as
    // a header-less table's first.
    function tableRow(tag, cells, headed) {
        var tr = document.createElement('tr');
        cells.forEach(function (text, i) {
            var cell = document.createElement(tag);
            if (headed && i > 0) {
                cell.className = 'tip-num';
            } else if (!headed && i === 0) {
                cell.className = 'tip-label';
            }
            appendBold(cell, text);
            tr.appendChild(cell);
        });
        return tr;
    }

    // Writes text into the tooltip: its tables as tables, the lines after
    // one as its footnote.
    function render(text) {
        tip.textContent = '';
        var blocks = banTipBlocks(text);
        if (!blocks.some(function (block) { return block.table; })) {
            appendBold(tip, text);
            return;
        }
        var afterTable = false;
        blocks.forEach(function (block) {
            if (!block.table) {
                var lines = document.createElement('div');
                if (afterTable) {
                    lines.className = 'tip-foot';
                }
                appendBold(lines, block.lines.join('\n'));
                tip.appendChild(lines);
                return;
            }
            afterTable = true;
            var table = document.createElement('table');
            table.className = 'tip-table';
            if (block.header) {
                table.appendChild(tableRow('th', block.header, true));
            }
            block.rows.forEach(function (cells) {
                table.appendChild(tableRow('td', cells, !!block.header));
            });
            tip.appendChild(table);
        });
    }

    // Moves the title aside and shows it, or its data-tip when it has one; a
    // blank title shows nothing.
    function take(text, rich) {
        setAside(current, text);
        if (labelled) {
            current.setAttribute('aria-label', text);
        }
        render(rich || text);
        tip.hidden = !text.trim();
        place();
    }

    // A script setting the title while the tooltip is up (a "Copied!" after a
    // click) takes over from the one being shown, data-tip included.
    function retitle() {
        var text = current.getAttribute('title');
        if (text !== null) {
            take(text, null);
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
        take(text, el.getAttribute('data-tip'));
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
