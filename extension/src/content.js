// Puts an export button on a Cardmarket page that lists offers.
//
// Nothing here touches an extension API. The parse is a DOM read, the file is
// handed over with a blob and an anchor, and both are plain web platform, so
// the same build runs unchanged on Chrome, Firefox and Safari and the
// manifest asks for no permission beyond being on the page at all.

(function (MKM) {
  "use strict";

  var BUTTON_ID = "ban-mkm-export";

  // The page path names the game: /<language>/<Game>/... for every game
  // Cardmarket sells.
  function gameFromPath(pathname) {
    var parts = pathname.split("/");
    return parts.length > 2 && parts[2] ? parts[2].toLowerCase() : "cardmarket";
  }

  function today() {
    var now = new Date();
    var month = String(now.getMonth() + 1).padStart(2, "0");
    var day = String(now.getDate()).padStart(2, "0");
    return now.getFullYear() + "-" + month + "-" + day;
  }

  function download(text, filename) {
    var blob = new Blob([text], { type: "text/csv;charset=utf-8" });
    var url = URL.createObjectURL(blob);
    var anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = filename;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    // Firefox needs the object to outlive the click it was created for.
    setTimeout(function () {
      URL.revokeObjectURL(url);
    }, 30000);
  }

  function say(button, message) {
    var note = button.querySelector(".ban-note");
    if (note) {
      note.textContent = message;
    }
  }

  function exportOffers(button) {
    var offers = MKM.parseOffers(document, "");
    var total = MKM.countRows(document);

    if (offers.length === 0) {
      // Told apart deliberately: a page with rows that all refused is not a
      // page with no rows, and only one of the two is worth reporting.
      say(
        button,
        total === 0
          ? "No offers on this page"
          : "None of the " + total + " offers here could be read"
      );
      return;
    }

    download(
      MKM.toCSV(offers),
      "mkm-" + gameFromPath(location.pathname) + "-" + today() + ".csv"
    );

    var skipped = total - offers.length;
    say(
      button,
      skipped > 0
        ? offers.length + " exported, " + skipped + " skipped"
        : offers.length + " exported"
    );
  }

  function label(button) {
    var count = MKM.countRows(document);
    var text = button.querySelector(".ban-label");
    if (text) {
      text.textContent = "Export " + count + " to BAN";
    }
    button.hidden = count === 0;
  }

  function install() {
    if (document.getElementById(BUTTON_ID)) {
      return;
    }

    var button = document.createElement("button");
    button.id = BUTTON_ID;
    button.type = "button";
    button.innerHTML =
      '<span class="ban-label"></span><span class="ban-note"></span>';
    button.addEventListener("click", function () {
      exportOffers(button);
    });
    document.body.appendChild(button);
    label(button);

    // The page fills its table after load and refills it on every filter, so
    // the count follows the table rather than the moment this ran.
    var pending = null;
    var observer = new MutationObserver(function () {
      if (pending !== null) {
        return;
      }
      pending = setTimeout(function () {
        pending = null;
        say(button, "");
        label(button);
      }, 300);
    });
    observer.observe(document.body, { childList: true, subtree: true });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", install);
  } else {
    install();
  }
})(globalThis.MKM);
