// Receives a card list from the window that opened this page and uploads it.
//
// A browser extension reading a storefront cannot post a list to the upload
// itself: the upload needs the session, this site's cookie is same-site, and a
// request made from another origin arrives without it. What it can do is open
// this page - an ordinary top-level navigation, so the session comes along -
// and hand the rows over window to window. This submits them from here, which
// is why they carry the session.
//
// Every message is held against the origins the server named and against the
// window that opened this one, so another frame on an allowed site cannot
// answer in its place.

(function () {
    "use strict";

    var READY = "mtgban-handoff-ready";
    var ROWS = "mtgban-handoff-rows";

    var root = document.getElementById("handoff");
    if (!root) {
        return;
    }

    // A reader with no signature, or whose tier does not carry the Upload
    // grant. The page has already said so; what matters here is that it
    // stays silent. An extension that heard this one announce itself would
    // hand over a list nothing can price - and on the storefronts this is
    // built for, gathering that list is minutes of somebody's afternoon.
    if (root.getAttribute("data-can-upload") !== "true") {
        return;
    }

    var status = document.getElementById("handoff-status");
    var statusText = document.getElementById("handoff-status-text");
    var guide = document.getElementById("handoff-guide");
    var form = document.getElementById("handoff-form");
    var rows = document.getElementById("handoff-rows");
    var source = document.getElementById("handoff-source");

    // The sites allowed to hand a list over, as the server named them. An
    // attribute that is missing or unreadable leaves the list empty, which is
    // a page listening to nobody rather than one listening to everybody.
    var allowed = [];
    try {
        var named = JSON.parse(root.getAttribute("data-handoff-origins") || "[]");
        if (Object.prototype.toString.call(named) === "[object Array]") {
            allowed = named;
        }
    } catch (err) {
        allowed = [];
    }

    // say writes the line about what is happening to the list. The spinner
    // beside it is the stylesheet's, and is shown and hidden with the line
    // it sits on rather than being driven from here.
    function say(message) {
        if (statusText) {
            statusText.textContent = message;
        }
    }

    // Opened by hand rather than by an extension: there is nobody to ask,
    // and the page is already showing the guide that says what it is for.
    var opener = window.opener;
    if (!opener || opener.closed) {
        return;
    }

    // Somebody to hear from. The page stops being documentation and starts
    // being a progress line - which is the whole of what it has to say
    // from here until it submits.
    if (status) {
        status.hidden = false;
    }
    if (guide) {
        guide.hidden = true;
    }

    // The columns a handed-over card is written into, and the header they
    // are written under. Fixed rather than built from whichever keys turn
    // up, so the header the upload parses is the same one every time and
    // can be pinned on the Go side - internal/docparse decides what each
    // of these names means, and a column nobody filled is an empty cell
    // rather than a different layout.
    var COLUMNS = [
        ["id", "uuid"],
        ["name", "card_name"],
        ["edition", "edition"],
        ["number", "number"],
        ["foil", "foil"],
        ["condition", "condition"],
        ["quantity", "quantity"],
        ["price", "price"],
        ["notes", "notes"],
    ];

    // A value written the way a CSV reader expects to find it. Card names
    // carry commas and quotation marks often enough that this is not a
    // nicety: "Tarmogoyf" with a comma in it splits into two columns and
    // moves every field after it one to the left.
    function field(value) {
        if (value === undefined || value === null) {
            return "";
        }
        if (value === true) {
            return "yes";
        }
        if (value === false) {
            return "no";
        }
        var written = String(value);
        if (/[",\r\n]/.test(written)) {
            return '"' + written.replace(/"/g, '""') + '"';
        }
        return written;
    }

    // asCSV turns the structured hand-over into the text one. A card is
    // kept when it names something to look up - an id or a name - and
    // dropped otherwise, because a row that identifies nothing is not a
    // card the upload can refuse informatively, it is a blank line.
    function asCSV(cards) {
        var lines = [];
        for (var i = 0; i < cards.length; i++) {
            var card = cards[i];
            if (!card || typeof card !== "object") {
                continue;
            }
            if (field(card.id) === "" && field(card.name) === "") {
                continue;
            }
            var row = [];
            for (var c = 0; c < COLUMNS.length; c++) {
                row.push(field(card[COLUMNS[c][0]]));
            }
            lines.push(row.join(","));
        }
        if (lines.length === 0) {
            return null;
        }
        var header = [];
        for (var h = 0; h < COLUMNS.length; h++) {
            header.push(COLUMNS[h][1]);
        }
        return { text: header.join(",") + "\n" + lines.join("\n") + "\n", rows: lines.length };
    }

    // listFrom reads whichever of the two shapes a hand-over came in.
    //
    // Text is the older one and what the Cardmarket extension sends: a CSV
    // or a decklist, parsed at the far end exactly as a paste would be. It
    // arrives as "csv" or as "text"; the first name is the one already in
    // the wild and is not going anywhere.
    //
    // Cards is the other: a list of objects naming a uuid, a quantity, a
    // condition and whatever else is known, for a sender that has resolved
    // its cards already and should not have to write a CSV by hand to say
    // so. It is turned into the text shape here, because the upload takes
    // text and this page is the one place that has to know both.
    function listFrom(data) {
        var text = typeof data.text === "string" ? data.text : data.csv;
        if (typeof text === "string" && text.trim() !== "") {
            var counted = typeof data.rows === "number" && data.rows > 0 ? data.rows : 0;
            return { text: text, rows: counted };
        }
        if (Object.prototype.toString.call(data.cards) === "[object Array]") {
            return asCSV(data.cards);
        }
        return null;
    }

    // Taken once. A second message is not a second upload.
    var taken = false;

    window.addEventListener("message", function (event) {
        if (
            taken ||
            allowed.indexOf(event.origin) === -1 ||
            event.source !== opener ||
            !event.data ||
            event.data.type !== ROWS
        ) {
            return;
        }
        var list = listFrom(event.data);
        if (!list) {
            return;
        }
        taken = true;

        rows.value = list.text;

        // Where the rows were read, for the results heading. Taken only
        // when it belongs to the origin that handed them over: the page it
        // names has to be a page on the site that sent it, or it is not
        // carried at all. What it is called is the server's to decide.
        if (source && typeof event.data.source === "string") {
            try {
                if (new URL(event.data.source).origin === event.origin) {
                    source.value = event.data.source;
                }
            } catch (err) {
                // Not a URL. The heading manages without one.
            }
        }

        // The sender knows how many cards it read; text does not say
        // whether its first line is a header or a card, so a count is
        // shown when it is given and not counted for otherwise. A
        // structured hand-over counts itself: the rows are objects there,
        // and the ones that named nothing have already been dropped.
        var count = list.rows;
        if (count > 0) {
            say("Pricing " + count + " row" + (count === 1 ? "" : "s") + "…");
        } else {
            say("Pricing your list…");
        }

        form.submit();
    });

    // Said once this is listening, so nothing is sent before there is
    // anywhere to put it.
    for (var i = 0; i < allowed.length; i++) {
        opener.postMessage({ type: READY }, allowed[i]);
    }
})();
