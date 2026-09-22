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
    var hint = document.getElementById("handoff-hint");
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

    // Opened by hand rather than by an extension: there is nobody to ask, so
    // say what this page is for and stop.
    var opener = window.opener;
    if (!opener || opener.closed) {
        status.textContent = "Nothing was handed to this page.";
        hint.hidden = false;
        return;
    }

    // Taken once. A second message is not a second upload.
    var taken = false;

    window.addEventListener("message", function (event) {
        if (
            taken ||
            allowed.indexOf(event.origin) === -1 ||
            event.source !== opener ||
            !event.data ||
            event.data.type !== ROWS ||
            typeof event.data.csv !== "string" ||
            event.data.csv.trim() === ""
        ) {
            return;
        }
        taken = true;

        rows.value = event.data.csv;

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

        // The sender knows how many cards it read; this page only sees text,
        // and text does not say whether its first line is a header or a card.
        // A count is shown when it is given and not counted for otherwise.
        var count = event.data.rows;
        if (typeof count === "number" && count > 0) {
            status.textContent =
                "Pricing " + count + " row" + (count === 1 ? "" : "s") + "…";
        } else {
            status.textContent = "Pricing your list…";
        }

        form.submit();
    });

    // Said once this is listening, so nothing is sent before there is
    // anywhere to put it.
    for (var i = 0; i < allowed.length; i++) {
        opener.postMessage({ type: READY }, allowed[i]);
    }
})();
